"""
SQLiTester — SQL injection vulnerability scanner.
Strategies: error-based, boolean-based, time-based blind.
"""
import time, re, os
from core.base_module import BaseModule
from urllib.parse import urlencode

DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"mysql_fetch", r"unclosed quotation mark", r"incorrect syntax near",
    r"ora-[0-9]{4,5}", r"pg::syntaxerror", r"sqlite3?",
    r"sql syntax.*error", r"syntax error.*sql", r"database error",
    r"query failed", r"pdoexception", r"java\.sql\.sqlexception",
]
COMPILED_ERRORS = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]

TIME_THRESHOLD = 4.0
PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "sqli_payloads.txt")

BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
    ("' OR 'x'='x", "' OR 'x'='y"),
]

class SQLiTester(BaseModule):
    def run(self, param=None, method="GET"):
        payloads = self._load_payloads()
        self.logger.info(f"Loaded {len(payloads)} SQLi payloads")
        params = self._discover_params(param)
        if not params:
            self.logger.warning("No parameters to test.")
            return []
        self.logger.info(f"Testing params: {params} | method: {method}")
        baseline = self._baseline(params, method)
        findings, tested = [], set()

        for p in params:
            for pl in payloads:
                key = (p, pl["type"], pl["payload"][:30])
                if key in tested: continue
                tested.add(key)
                finding = self._test(p, pl, method, baseline, params)
                if finding:
                    findings.append(finding)
                    self.logger.info(f"  🚨 [{finding['detection'].upper()}] param='{p}' payload='{pl['payload'][:50]}'")
                    break  # one confirmed hit per param is enough

        if not findings:
            self.logger.info("  ✅ No SQLi indicators found.")
        self.logger.info(f"Done. {len(findings)} potential vulnerabilities found.")
        return findings

    def _test(self, param, pl, method, baseline, params):
        t = pl["type"]
        injected = {p: ("test" if p != param else pl["payload"]) for p in params}
        if t == "error":
            return self._error_based(param, pl["payload"], injected, method)
        elif t == "boolean":
            return self._boolean_based(param, pl["payload"], method, baseline, params)
        elif t == "time":
            return self._time_based(param, pl["payload"], injected, method)
        return None

    def _error_based(self, param, payload, injected, method):
        r = self._send(injected, method)
        if r is None: return None
        body = r.text.lower()
        for pat in COMPILED_ERRORS:
            if pat.search(body):
                return self._finding(param, payload, "error", r.status_code,
                    f"DB error pattern matched: '{pat.pattern}'")
        return None

    def _boolean_based(self, param, payload, method, baseline, params):
        pair = next(((t, f) for t, f in BOOL_PAIRS if payload.strip() == t), None)
        if not pair: return None
        true_p, false_p = pair
        ti = {p: ("test" if p != param else true_p)  for p in params}
        fi = {p: ("test" if p != param else false_p) for p in params}
        rt = self._send(ti, method)
        rf = self._send(fi, method)
        if rt is None or rf is None: return None
        bl = baseline.get("length", 0)
        lt, lf = len(rt.content), len(rf.content)
        delta = abs(lt - lf)
        if delta > 50 and abs(lf - bl) > abs(lt - bl):
            return self._finding(param, payload, "boolean", rt.status_code,
                f"Response length TRUE={lt}B vs FALSE={lf}B (delta={delta}B)")
        return None

    def _time_based(self, param, payload, injected, method):
        start = time.time()
        r = self._send(injected, method)
        elapsed = time.time() - start
        if elapsed >= TIME_THRESHOLD:
            return self._finding(param, payload, "time-based blind",
                r.status_code if r else 0,
                f"Response delayed {elapsed:.2f}s (threshold={TIME_THRESHOLD}s)")
        return None

    def _send(self, params, method):
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(self.target)
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        if method.upper() == "GET":
            return self.get(base + "?" + urlencode(params))
        return self.post(base, data=params)

    def _baseline(self, params, method):
        r = self._send({p: "test" for p in params}, method)
        return {"status": r.status_code, "length": len(r.content)} if r else {"status": 0, "length": 0}

    def _discover_params(self, explicit):
        if explicit: return [explicit]
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.target).query)
        return list(qs.keys()) if qs else ["id", "q", "search", "query", "user", "name"]

    def _load_payloads(self):
        path = os.path.normpath(PAYLOAD_FILE)
        if not os.path.exists(path):
            self.logger.error(f"Payload file not found: {path}")
            return []
        payloads = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = [p.strip() for p in line.split("|||")]
                if len(parts) >= 2:
                    payloads.append({"payload": parts[0], "type": parts[1],
                                     "notes": parts[2] if len(parts) > 2 else ""})
        return payloads

    def _finding(self, param, payload, detection, status, evidence):
        return {"param": param, "payload": payload, "detection": detection,
                "status": status, "evidence": evidence, "target": self.target}
