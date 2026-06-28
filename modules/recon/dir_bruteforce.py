import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}

class DirBruteforcer(BaseModule):
    def run(self, wordlist="wordlists/common.txt", threads=10):
        words = self._load_wordlist(wordlist)
        if not words:
            self.logger.error(f"Wordlist empty or not found: {wordlist}")
            return []
        self.logger.info(f"Loaded {len(words)} entries | threads={threads}")
        wildcard_code = self._detect_wildcard()
        if wildcard_code:
            self.logger.warning(f"Wildcard HTTP {wildcard_code} detected — will filter")

        raw = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self._probe, w): w for w in words}
            for f in as_completed(futures):
                try:
                    r = f.result()
                    if r: raw.append(r)
                except Exception as e:
                    self.logger.debug(f"Error: {e}")

        findings = []
        for r in raw:
            if wildcard_code and r["status"] == wildcard_code:
                continue
            findings.append(r)
            icon = {200:"✅",301:"➡️",302:"➡️",403:"🔒",401:"🔐",500:"💥"}.get(r["status"],"❓")
            redir = f" -> {r['redirect']}" if r["redirect"] else ""
            self.logger.info(f"  {icon} [{r['status']}] {r['url']} ({r['length']}B){redir}")

        self.logger.info(f"Done. {len(findings)} paths found.")
        return findings

    def _probe(self, path):
        r = self.get(path)
        if r is None or r.status_code not in INTERESTING_CODES:
            return None
        return {"url": r.url, "path": path, "status": r.status_code,
                "length": len(r.content), "redirect": r.headers.get("Location", "")}

    def _detect_wildcard(self):
        r = self.get("zz_pentest_canary_404_zz")
        return 200 if r and r.status_code == 200 else None

    def _load_wordlist(self, path):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
