import socket
from core.base_module import BaseModule

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

class SubdomainEnumerator(BaseModule):
    def run(self, domain=None, resolve=True):
        if not domain:
            self.logger.error("No domain provided.")
            return []
        self.logger.info(f"Querying crt.sh for: {domain}")
        raw = self._fetch_crtsh(domain)
        if raw is None:
            self.logger.error("Failed to reach crt.sh.")
            return []
        subdomains = self._parse_subdomains(raw, domain)
        self.logger.info(f"Found {len(subdomains)} unique subdomains")
        findings = []
        for sub in sorted(subdomains):
            finding = {"subdomain": sub, "resolved": ""}
            if resolve:
                ip = self._resolve(sub)
                finding["resolved"] = ip or "unresolvable"
                icon = "✅" if ip else "❌"
                self.logger.info(f"  {icon} {sub} -> {ip or '(no DNS)'}")
            else:
                self.logger.info(f"  • {sub}")
            findings.append(finding)
        self.logger.info(f"Done. {len(findings)} subdomains enumerated.")
        return findings

    def _fetch_crtsh(self, domain):
        url = CRTSH_URL.format(domain=domain)
        resp = self.get(url)
        if resp is None or resp.status_code != 200:
            return None
        try:
            return resp.json()
        except Exception as e:
            self.logger.warning(f"crt.sh parse error: {e}")
            return None

    def _parse_subdomains(self, data, domain):
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name)
        return subs

    def _resolve(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
