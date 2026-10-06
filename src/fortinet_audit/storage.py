"""
Persistencia RAW. Estructura de una ejecución:

data/raw/<run_id>/
├── manifest.json                              # metadatos + estado por endpoint + cobertura
├── <seccion>/<api>.<ruta>.json                # objetos globales (una vez por firewall)
├── <seccion>/<vdom>/<api>.<ruta>.json         # objetos por VDOM
└── certificates/<vdom>/cmdb.certificate.local/<nombre>_<sha8>.pem   # certificados públicos

Cada JSON es un sobre {"meta": {...}, "response": <respuesta FortiOS completa>}.
`response` es el JSON tal como lo devolvió FortiOS (results, serial, version,
build, vdom, revision...), con los secretos redactados. Si hubo paginación,
`results` contiene todas las páginas unidas y meta.pagination lo indica.

El formato del sobre es estable (schema_version) para que normalizer.py lo lea
sin depender del collector.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from .catalog import NOT_AVAILABLE, Entity
from .client import ApiResult
from .redact import redact_obj

SCHEMA_VERSION = "1.0"
# Campos que contienen material PÚBLICO en PEM, por entidad de certificados.
_PEM_FIELDS = {"cmdb/certificate/local": ("certificate",), "cmdb/certificate/remote": ("remote",),
               "cmdb/certificate/ca": ("ca",), "cmdb/certificate/crl": ("crl",)}
_PEM_BLOCK_RE = re.compile(r"-----BEGIN (CERTIFICATE|X509 CRL)-----.*?-----END \1-----", re.S)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))[:60] or "sin_nombre"


# --- Soporte de rutas largas en Windows (evita el límite MAX_PATH de 260) --- #
def _lp(path: Path) -> str:
    """Devuelve la ruta como str, con el prefijo \\\\?\\ en Windows para
    permitir rutas de más de 260 caracteres (común en carpetas sincronizadas a la nube)."""
    p = os.path.abspath(str(path))
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        p = "\\\\?\\" + p
    return p


def _mkdirs(path: Path) -> None:
    os.makedirs(_lp(path), exist_ok=True)


def _write_text(path: Path, text: str) -> None:
    with open(_lp(path), "w", encoding="utf-8") as f:
        f.write(text)


class RawStore:
    def __init__(self, base_dir: Path, run_id: str, redact: bool = True):
        self.run_dir = Path(base_dir) / run_id
        _mkdirs(self.run_dir)
        self.redact = redact

    def entity_dir(self, entity: Entity, vdom: Optional[str]) -> Path:
        d = self.run_dir / entity.section
        if entity.scope == "vdom" and vdom:
            d = d / _safe_name(vdom)
        return d

    # ------------------------------------------------------------------ #
    def save(self, entity: Entity, res: ApiResult) -> dict:
        out_dir = self.entity_dir(entity, res.vdom)
        _mkdirs(out_dir)

        meta = {
            "schema_version": SCHEMA_VERSION,
            "entity": entity.key,
            "api": entity.api,
            "path": entity.path,
            "section": entity.section,
            "scope": entity.scope,
            "vdom": res.vdom,
            "cis_controls": list(entity.cis),
            "purpose": entity.purpose,
            "cli_equivalent": entity.cli or None,
            "documentation": entity.doc_ref,
            "best_effort": entity.best_effort,
            "endpoint": res.endpoint,
            "params": res.extra.get("params", {}),
            "extracted_at_utc": res.started_utc,
            "duration_ms": res.duration_ms,
            "attempts": res.attempts,
            "http_status": res.http_status,
            "content_type": res.content_type,
            "firewall_http_date": res.firewall_http_date or NOT_AVAILABLE,
            "serial": res.serial or NOT_AVAILABLE,
            "fortios_version": res.version or NOT_AVAILABLE,
            "build": res.build if res.build is not None else NOT_AVAILABLE,
            "config_revision": res.revision or NOT_AVAILABLE,
            "status": res.status,
            "record_count": res.record_count,
            "api_status": res.api_status,
            "error": res.error,
            "note": res.extra.get("note"),
            "visibility": res.extra.get("visibility"),
            "secrets_redacted": self.redact,
            "pagination": {"enabled": entity.paginate, "pages": res.pages, "note": res.pagination_note},
        }

        files: dict[str, str] = {}
        response: Any = res.parsed
        if response is not None:
            response = redact_obj(response, enabled=self.redact, record_secret_fields=entity.secret_fields)
            if res.status == "OK" and entity.key in _PEM_FIELDS:
                files.update(self._save_public_pems(entity, out_dir, response))
        elif res.raw_text:
            response = {"non_json_body": res.raw_text}

        envelope = {"meta": meta, "response": response if response is not None else NOT_AVAILABLE}
        json_path = out_dir / f"{entity.file_stem}.json"
        _write_text(json_path, json.dumps(envelope, indent=2, ensure_ascii=False))
        files["json"] = json_path.relative_to(self.run_dir).as_posix()
        meta["files"] = files
        return meta

    # ------------------------------------------------------------------ #
    def _save_public_pems(self, entity: Entity, out_dir: Path, response: dict) -> dict:
        """Guarda los certificados públicos (PEM) como archivos sueltos para que el
        normalizer pueda leer emisor/expiración con cualquier librería X.509.
        Las llaves privadas nunca llegan aquí (se eliminan en redact_obj)."""
        files: dict[str, str] = {}
        results = response.get("results")
        if not isinstance(results, list):
            return files
        pem_dir = out_dir / entity.file_stem
        for rec in results:
            if not isinstance(rec, dict):
                continue
            for fld in _PEM_FIELDS[entity.key]:
                val = rec.get(fld)
                if not isinstance(val, str):
                    continue
                blocks = [m.group(0) for m in _PEM_BLOCK_RE.finditer(val)]
                if not blocks:
                    continue
                data = "\n".join(blocks) + "\n"
                sha = hashlib.sha256(data.encode()).hexdigest()
                _mkdirs(pem_dir)
                p = pem_dir / f"{_safe_name(rec.get('name'))}_{sha[:8]}.pem"
                _write_text(p, data)
                files[f"pem:{rec.get('name')}"] = p.relative_to(self.run_dir).as_posix()
        return files

    # ------------------------------------------------------------------ #
    def write_json(self, name: str, data: Any) -> Path:
        path = self.run_dir / name
        _write_text(path, json.dumps(data, indent=2, ensure_ascii=False))
        return path
