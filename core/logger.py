import logging, sys

def setup_logger(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("pentest")
    logger.setLevel(level)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(h)
    return logger
