from urllib.parse import urlparse

KNOWN_LEGAL_HOSTS = [
    "localhost", "127.0.0.1", "0.0.0.0",
    "juice-shop", "google-gruyere.appspot.com",
    "hackthebox.eu", "tryhackme.com",
    "bwapp", "dvwa", "webgoat",
]

def confirm_legal_target(target, flag_set):
    host = urlparse(target).hostname or ""
    for safe in KNOWN_LEGAL_HOSTS:
        if safe in host:
            return True
    return flag_set
