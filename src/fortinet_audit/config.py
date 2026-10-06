"""
Carga de configuración.

Prioridad (mayor a menor):
  1. Argumentos de línea de comandos
  2. Variables de entorno (FORTI_FW_*)  — también se leen desde un archivo .env
  3. config/config.yaml
  4. Valores por defecto

La API key SOLO se acepta por variable de entorno, .env o prompt interactivo.
Si aparece en config.yaml el collector se niega a correr, para que nunca
termine en un archivo que pueda subirse a Git.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv es opcional
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENV_HOST = "FORTI_FW_HOST"
ENV_PORT = "FORTI_FW_PORT"
ENV_KEY = "FORTI_FW_API_KEY"
ENV_VERIFY = "FORTI_FW_VERIFY_SSL"
ENV_VDOMS = "FORTI_FW_VDOMS"
_FORBIDDEN_YAML_KEYS = {"password", "api_key", "apikey", "api-key", "secret", "token", "access_token"}


class ConfigError(ValueError):
    pass


@dataclass
class Settings:
    host: str = ""
    port: int = 443
    api_key: str = field(default="", repr=False)
    verify_ssl: bool | str = True
    timeout: int = 60
    retries: int = 2
    retry_backoff: float = 2.0
    delay_between_requests: float = 0.3
    page_size: int = 1000
    max_pages: int = 500
    raw_dir: Path = PROJECT_ROOT / "data" / "raw"
    log_dir: Path = PROJECT_ROOT / "logs"
    log_level: str = "INFO"
    redact_secrets: bool = True
    sections: Optional[list[str]] = None      # None = todas
    exclude_entities: list[str] = field(default_factory=list)
    vdoms: list[str] = field(default_factory=list)  # vacío = autodetectar (cmdb/system/vdom)
    label: str = ""                           # nombre amigable del firewall (cliente/sitio)


def _bool(v) -> bool | str:
    if isinstance(v, bool):
        return v
    s = str(v).strip()
    if s.lower() in ("1", "true", "yes", "si", "sí", "on"):
        return True
    if s.lower() in ("0", "false", "no", "off"):
        return False
    return s  # ruta a un CA bundle


def _list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return [str(x).strip() for x in v if str(x).strip()]


def load_settings(config_path: Optional[Path] = None, env_file: Optional[Path] = None) -> Settings:
    if load_dotenv is not None:
        load_dotenv(env_file or PROJECT_ROOT / ".env", override=False)

    s = Settings()
    path = config_path or PROJECT_ROOT / "config" / "config.yaml"
    if path and Path(path).exists():
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        bad = _find_secret_keys(data)
        if bad:
            raise ConfigError(
                f"{path} contiene credenciales ({', '.join(bad)}). Muévelas a la variable de entorno "
                f"{ENV_KEY} o al archivo .env (ver README)."
            )
        fw = data.get("firewall", {}) or {}
        s.host = str(fw.get("host", s.host) or "")
        s.port = int(fw.get("port", s.port))
        s.verify_ssl = _bool(fw.get("verify_ssl", s.verify_ssl))
        s.label = str(fw.get("label", "") or "")
        s.vdoms = _list(fw.get("vdoms"))
        req = data.get("requests", {}) or {}
        s.timeout = int(req.get("timeout", s.timeout))
        s.retries = int(req.get("retries", s.retries))
        s.retry_backoff = float(req.get("retry_backoff", s.retry_backoff))
        s.delay_between_requests = float(req.get("delay_between_requests", s.delay_between_requests))
        s.page_size = int(req.get("page_size", s.page_size))
        s.max_pages = int(req.get("max_pages", s.max_pages))
        out = data.get("output", {}) or {}
        if out.get("raw_dir"):
            s.raw_dir = _resolve(out["raw_dir"])
        if out.get("log_dir"):
            s.log_dir = _resolve(out["log_dir"])
        s.log_level = str(out.get("log_level", s.log_level)).upper()
        s.redact_secrets = bool(out.get("redact_secrets", s.redact_secrets))
        col = data.get("collection", {}) or {}
        s.sections = col.get("sections") or None
        s.exclude_entities = list(col.get("exclude_entities") or [])

    # Variables de entorno
    s.host = os.environ.get(ENV_HOST, s.host)
    s.port = int(os.environ.get(ENV_PORT, s.port))
    s.api_key = os.environ.get(ENV_KEY, "").strip()
    if ENV_VERIFY in os.environ:
        s.verify_ssl = _bool(os.environ[ENV_VERIFY])
    if os.environ.get(ENV_VDOMS):
        s.vdoms = _list(os.environ[ENV_VDOMS])
    return s


def _resolve(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _find_secret_keys(obj, prefix: str = "") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if str(k).lower() in _FORBIDDEN_YAML_KEYS and v not in (None, ""):
                found.append(key)
            found += _find_secret_keys(v, key)
    return found
