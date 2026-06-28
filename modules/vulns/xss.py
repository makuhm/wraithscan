"""
XSSTester — Reflected XSS vulnerability scanner.

Detection strategies:
1. Reflected unescaped  — payload appears in response body without HTML encoding
2. Attribute reflection — payload lands inside a tag attribute unescaped
3. DOM sink detection   — response contains dangerous JS sinks fed by URL input

Usage:
  python main.py -t "http://target?q=test" --confirm-legal vuln xss --param q
"""

import os
import re
import html
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from core.base_module import BaseModule

PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "xss_payloads.txt")

# Unique canary prefix — makes it easy to find our reflection in noisy pages
CANARY_PREFIX = "wrs_xss_"

# JS sinks that are dangerous when fed user-controlled input
DOM_SINK_PATTERNS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"\.src\s*=",
]
COMPILED_SINKS = [re.compile(p, re.IGNORECASE) for p in DOM_SINK_PATTERNS]

# HTML-encoded versions of our key characters — if these appear instead of
# the raw chars, the app is escaping properly and we should NOT flag it
HTML_ESCAPES = {
    "<":  ["&lt;",  "&#60;",  "&#x3c;", "&#x3C;"],
    ">":  ["&gt;",  "&#62;",  "&#x3e;", "&#x3E;"],
    '"':  ["&quot;","&#34;",  "&#x22;"],
    "'":  ["&#39;", "&#x27;", "&apos;"],
}


class XSSTester(BaseModule):

    def run(self, param=None, method="GET") -> list[dict]:
        payloads = self._load_payloads()
        self.logger.info(f"Loaded {len(payloads)} XSS payloads")

        params = self._discover_params(param)
        if not params:
            self.logger.warning("No parameters found to test.")
            return []

        self.logger.info(f"Testing params: {params} | method: {method}")

        # Baseline — clean request so we can spot DOM sinks separately
        baseline_resp = self._send({p: "wraithscan_baseline" for p in params}, method)
        baseline_body = baseline_resp.text if baseline_resp is not None else ""

        findings = []
        tested = set()

        for param_name in params:
            # Step 1: canary probe — does the app reflect input at all?
            canary = f"{CANARY_PREFIX}probe"
            canary_resp = self._send(
                {p: (canary if p == param_name else "test") for p in params}, method
            )
            if canary_resp is None:
                continue

            if canary not in canary_resp.text:
                self.logger.info(f"  ⏭  '{param_name}' — input not reflected, skipping")
                continue

            self.logger.info(f"  🔍 '{param_name}' reflects input — testing payloads")

            # Step 2: DOM sink check on baseline (not dependent on payload)
            dom_finding = self._check_dom_sinks(param_name, baseline_body, canary_resp.text)
            if dom_finding and dom_finding["evidence"] not in [f["evidence"] for f in findings]:
                findings.append(dom_finding)
                self.logger.info(f"  ⚠️  [DOM SINK] param='{param_name}' | {dom_finding['evidence']}")

            # Step 3: payload injection
            for pl in payloads:
                key = (param_name, pl["payload"][:40])
                if key in tested:
                    continue
                tested.add(key)

                finding = self._test_payload(param_name, pl, method, params)
                if finding:
                    findings.append(finding)
                    self.logger.info(
                        f"  🚨 [{finding['detection'].upper()}] param='{param_name}' "
                        f"context='{pl['context']}' | {pl['payload'][:60]}"
                    )
                    # One confirmed reflected XSS per param is enough
                    break

        if not findings:
            self.logger.info("  ✅ No XSS indicators found.")

        self.logger.info(f"Done. {len(findings)} potential XSS vulnerabilities found.")
        return findings

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _test_payload(self, param_name, pl, method, params) -> dict | None:
        payload = pl["payload"]
        injected = {p: (payload if p == param_name else "test") for p in params}

        resp = self._send(injected, method)
        if resp is None:
            return None

        body = resp.text

        # Check 1: unescaped reflection — raw payload in response body
        if self._is_unescaped(payload, body):
            return self._finding(
                param_name, payload, "reflected-unescaped",
                pl["context"], resp.status_code,
                f"Payload reflected unescaped in response body"
            )

        # Check 2: attribute reflection — payload lands inside a tag attribute
        if self._in_attribute(payload, body):
            return self._finding(
                param_name, payload, "reflected-in-attribute",
                pl["context"], resp.status_code,
                f"Payload reflected inside HTML attribute (potential attr XSS)"
            )

        return None

    def _is_unescaped(self, payload: str, body: str) -> bool:
        """
        Returns True only if the payload appears in the body WITHOUT
        its critical characters being HTML-encoded.
        """
        if payload not in body:
            return False

        # For each critical char in the payload, confirm it's not just
        # the HTML-encoded version that's present
        critical_chars = [c for c in "<>\"'" if c in payload]
        for char in critical_chars:
            for encoded in HTML_ESCAPES.get(char, []):
                # If the encoded version is there but the raw char isn't — it's escaped
                encoded_payload = payload.replace(char, encoded)
                if encoded_payload in body and payload not in body:
                    return False

        return True

    def _in_attribute(self, payload: str, body: str) -> bool:
        """
        Checks if the payload appears inside an HTML tag attribute value,
        which could allow event handler injection.
        """
        # Look for payload inside attribute quotes: value="...PAYLOAD..."
        pattern = re.compile(
            r'<[^>]+(?:value|src|href|action|data)[^>]*=["\'][^"\']*'
            + re.escape(payload[:20]),  # first 20 chars is enough signal
            re.IGNORECASE
        )
        return bool(pattern.search(body))

    def _check_dom_sinks(self, param_name, baseline_body, reflected_body) -> dict | None:
        """
        Flag dangerous JS sinks that appear near reflected input.
        Only reports if the sink appears in the reflected response but
        NOT in the baseline (i.e. it's influenced by the input).
        """
        for pattern in COMPILED_SINKS:
            in_reflected = pattern.search(reflected_body)
            in_baseline  = pattern.search(baseline_body)
            if in_reflected and not in_baseline:
                return self._finding(
                    param_name, "", "dom-sink",
                    "js", 200,
                    f"Dangerous JS sink '{pattern.pattern}' appears near reflected input"
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, params: dict, method: str):
        parsed = urlparse(self.target)
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        if method.upper() == "GET":
            return self.get(base + "?" + urlencode(params))
        return self.post(base, data=params)

    def _discover_params(self, explicit: str) -> list[str]:
        if explicit:
            return [explicit]
        qs = parse_qs(urlparse(self.target).query)
        return list(qs.keys()) if qs else ["q", "search", "query", "s", "input", "text", "name"]

    def _load_payloads(self) -> list[dict]:
        path = os.path.normpath(PAYLOAD_FILE)
        if not os.path.exists(path):
            self.logger.error(f"Payload file not found: {path}")
            return []
        payloads = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|||")]
                if len(parts) >= 2:
                    payloads.append({
                        "payload": parts[0],
                        "context": parts[1],
                        "notes":   parts[2] if len(parts) > 2 else "",
                    })
        return payloads

    def _finding(self, param, payload, detection, context, status, evidence) -> dict:
        return {
            "param":     param,
            "payload":   payload,
            "detection": detection,
            "context":   context,
            "status":    status,
            "evidence":  evidence,
            "target":    self.target,
        }
