import yaml, os

DEFAULTS = {
    "user_agent": "PentestToolkit/1.0",
    "timeout": 10,
    "request_delay": 0.15,
    "proxy": None,
    "headers": {},
    "cookies": {},
    "threads": 10,
}

def load_config(path):
    config = DEFAULTS.copy()
    if os.path.exists(path):
        with open(path) as f:
            config.update(yaml.safe_load(f) or {})
    return config
