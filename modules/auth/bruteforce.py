"""
BruteForcer — Authentication brute-force module.

Detection strategies:
1. HTTP status code change   — 302 redirect on success vs 200 on failure
2. Response body keywords    — success/failure strings in response
3. Response length delta      — success responses are usually a different size

Safety: requires --confirm-legal flag. Built-in rate limiting via BaseModule throttle.

Usage:
  python main.py -t http://localhost:3000 --confirm-legal auth bruteforce \\
    --login-url http://localhost:3000/login \\
    --userlist wordlists/usernames.txt \\
    --passlist wordlists/passwords.txt \\
    --user-field username --pass-field password
"""

import os
from core.base_module import BaseModule

# Keywords that suggest a successful login in the response body
SUCCESS_KEYWORDS = [
    "dashboard", "welcome", "logout", "log out", "sign out",
    "my account", "profile", "your account", "successfully logged",
]

# Keywords that confirm a failed login
FAILURE_KEYWORDS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "try again", "bad credentials", "unauthorized", "not found",
    "authentication failed", "login failed",
]


class BruteForcer(BaseModule):

    def run(
        self,
        login_url: str = None,
        userlist: str = "wordlists/usernames.txt",
        passlist: str = "wordlists/passwords.txt",
        user_field: str = "username",
        pass_field: str = "password",
    ) -> list[dict]:

        if not login_url:
            self.logger.error("No login URL provided. Use --login-url.")
            return []

        usernames = self._load_wordlist(userlist)
        passwords = self._load_wordlist(passlist)

        if not usernames:
            self.logger.error(f"Username list empty or not found: {userlist}")
            return []
        if not passwords:
            self.logger.error(f"Password list empty or not found: {passlist}")
            return []

        self.logger.info(f"Login URL   : {login_url}")
        self.logger.info(f"User field  : {user_field} | Pass field: {pass_field}")
        self.logger.info(f"Usernames   : {len(usernames)} | Passwords: {len(passwords)}")
        self.logger.info(f"Total attempts: {len(usernames) * len(passwords)}")
        self.logger.warning("Rate limiting active — be patient and legal.")

        # Baseline — failed login fingerprint
        baseline = self._get_baseline(login_url, user_field, pass_field)
        if baseline is None:
            self.logger.error("Could not reach login URL for baseline request.")
            return []
        self.logger.info(f"Baseline: status={baseline['status']} length={baseline['length']}B")

        findings = []

        for username in usernames:
            for password in passwords:
                result = self._attempt(
                    login_url, user_field, pass_field,
                    username, password, baseline
                )
                if result:
                    findings.append(result)
                    self.logger.info(
                        f"  🔓 VALID CREDENTIALS FOUND — "
                        f"username='{username}' password='{password}' "
                        f"[{result['detection']}]"
                    )
                    # Stop testing this username once we find its password
                    break
                else:
                    self.logger.debug(f"  ✗ {username}:{password}")

        if not findings:
            self.logger.info("  🔒 No valid credentials found.")

        self.logger.info(f"Done. {len(findings)} valid credential(s) found.")
        return findings

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    def _attempt(
        self, login_url, user_field, pass_field,
        username, password, baseline
    ) -> dict | None:
        data = {user_field: username, pass_field: password}
        resp = self.post(login_url, data=data, allow_redirects=False)
        if resp is None:
            return None

        # Detection 1: redirect on success (302 vs 200 baseline)
        if baseline["status"] in (200, 401) and resp.status_code in (302, 303):
            return self._finding(username, password, "status-redirect",
                f"Login returned {resp.status_code} redirect (baseline was {baseline['status']})")

        # Detection 2: success keyword in body
        body_lower = resp.text.lower()
        for kw in SUCCESS_KEYWORDS:
            if kw in body_lower:
                # Make sure it wasn't in the baseline too
                if kw not in baseline["body"]:
                    return self._finding(username, password, "body-keyword",
                        f"Success keyword '{kw}' found in response body")

        # Detection 3: response length differs significantly from failed baseline
        length_delta = abs(len(resp.content) - baseline["length"])
        if length_delta > 200 and resp.status_code == 200:
            # Double-check: no failure keywords present
            has_failure = any(kw in body_lower for kw in FAILURE_KEYWORDS)
            if not has_failure:
                return self._finding(username, password, "length-delta",
                    f"Response length {len(resp.content)}B differs from baseline "
                    f"{baseline['length']}B by {length_delta}B with no failure keywords")

        return None

    def _get_baseline(self, login_url, user_field, pass_field) -> dict | None:
        """Send a clearly invalid login to fingerprint the failure response."""
        data = {user_field: "wraithscan_invalid_user_x7z", pass_field: "wraithscan_invalid_pass_x7z"}
        resp = self.post(login_url, data=data, allow_redirects=False)
        if resp is None:
            return None
        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "body":   resp.text.lower(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_wordlist(self, path: str) -> list[str]:
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]

    def _finding(self, username, password, detection, evidence) -> dict:
        return {
            "username":  username,
            "password":  password,
            "detection": detection,
            "evidence":  evidence,
            "target":    self.target,
        }
