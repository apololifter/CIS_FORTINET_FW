"""Logging a consola + archivo, con filtro que oculta secretos."""
from __future__ import annotations

import logging
from pathlib import Path


class SecretFilter(logging.Filter):
    def __init__(self, secrets):
        super().__init__()
        self.secrets = [s for s in secrets if s and len(s) >= 3]

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            msg = record.getMessage()
            for s in self.secrets:
                msg = msg.replace(s, "***")
            record.msg, record.args = msg, None
        return True


def setup_logging(log_dir: Path, run_id: str, level: str = "INFO", secrets=()) -> Path:
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"collector_{run_id}.log"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    flt = SecretFilter(list(secrets))

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    fh.addFilter(flt)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    ch.addFilter(flt)
    root.addHandler(fh)
    root.addHandler(ch)
    # urllib3 en DEBUG podría registrar cuerpos de petición
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return log_file
