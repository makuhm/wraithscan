import requests, time, os
from abc import ABC, abstractmethod
from utils.report_writer import ReportWriter

class BaseModule(ABC):
    def __init__(self, target, config, logger):
        self.target = target.rstrip("/")
        self.config = config
        self.logger = logger
        self.session = self._build_session()
        self.report_writer = ReportWriter()

    def _build_session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": self.config.get("user_agent", "PentestToolkit/1.0")})
        s.headers.update(self.config.get("headers", {}))
        s.cookies.update(self.config.get("cookies", {}))
        proxy = self.config.get("proxy")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
            s.verify = False
        return s

    def get(self, path, **kwargs):
        url = path if path.startswith("http") else f"{self.target}/{path.lstrip('/')}"
        self._throttle()
        try:
            r = self.session.get(url, timeout=self.config.get("timeout", 10), **kwargs)
            self.logger.debug(f"GET {url} -> {r.status_code}")
            return r
        except requests.RequestException as e:
            self.logger.warning(f"GET {url} failed: {e}")
            return None

    def post(self, path, data=None, json=None, **kwargs):
        url = path if path.startswith("http") else f"{self.target}/{path.lstrip('/')}"
        self._throttle()
        try:
            r = self.session.post(url, data=data, json=json, timeout=self.config.get("timeout", 10), **kwargs)
            self.logger.debug(f"POST {url} -> {r.status_code}")
            return r
        except requests.RequestException as e:
            self.logger.warning(f"POST {url} failed: {e}")
            return None

    def _throttle(self):
        time.sleep(self.config.get("request_delay", 0.1))

    @abstractmethod
    def run(self, **kwargs):
        pass

    def report(self, findings, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        out = os.path.join(output_dir, f"{self.__class__.__name__}.md")
        self.report_writer.write_markdown(self.__class__.__name__, self.target, findings, out)
        self.logger.info(f"Report saved: {out}")
