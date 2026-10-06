"""
Redacción de secretos en las respuestas RAW.

La REST API de FortiOS devuelve algunos secretos, normalmente cifrados con la
clave del equipo ("ENC xxxx..."): contraseñas de administradores y usuarios, PSK
de IPsec, secretos RADIUS/TACACS+, password de bind LDAP, password HA, claves
NTP/OSPF/BGP, llaves privadas de certificados, comunidades SNMP. Aunque vengan
cifrados, guardarlos en disco (y más aún en carpetas sincronizadas a la nube)
crea un riesgo nuevo, así que por defecto se reemplaza el VALOR conservando el
campo:

    valor no vacío -> "***REDACTED***"   (se sabe que está configurado)
    valor vacío    -> ""                 (se sabe que NO está configurado)

Así el cis_engine puede evaluar "¿el túnel usa PSK?" sin tener la PSK.
Se desactiva con `redact_secrets: false` / --no-redact, EXCEPTO las llaves
privadas, que nunca se guardan.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

REDACTED = "***REDACTED***"
REDACTED_WEAK_DEFAULT = "***REDACTED:WEAK_DEFAULT***"
WEAK_DEFAULT_VALUES = frozenset({"public", "private"})

# Nombres de campo (comparación exacta, sin mayúsculas) cuyo valor es secreto.
SECRET_KEYS = frozenset(k.lower() for k in (
    "password", "passwd", "old-password", "psksecret", "psksecret-remote", "ppk-secret",
    "secret", "secondary-secret", "tertiary-secret", "key", "secondary-key", "tertiary-key",
    "api-key", "auth-pwd", "priv-pwd", "scep-password", "proxy-password", "sso-password",
    "authentication-key", "key-string", "md5-key", "auth-password", "private-key",
    "passphrase", "preshared-key", "client-secret", "seed", "enc-key", "auth-key",
    "authkey", "enckey", "key-inbound", "key-outbound", "token", "access-token",
))

# Llaves privadas: se eliminan SIEMPRE (también con --no-redact).
ALWAYS_SECRET_KEYS = frozenset({"private-key"})
_PRIVATE_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)

# 'execute backup config|full-config ftp|sftp <archivo> <servidor> [<usuario>] [<password>] [<pass-backup>]'
_BACKUP_CMD_RE = re.compile(r"^(\s*execute\s+backup\s+\S+\s+s?ftp\b)(.*)$", re.I | re.M)


def is_secret(key: str, extra: Iterable[str] = ()) -> bool:
    k = str(key).lower()
    return k in SECRET_KEYS or k in {e.lower() for e in extra}


def redact_obj(obj: Any, *, enabled: bool = True, record_secret_fields: Iterable[str] = (),
               _depth: int = 0) -> Any:
    """Redacta recursivamente el sobre JSON de FortiOS.

    `record_secret_fields` son campos secretos sólo para ESTA entidad (p.ej. 'name'
    en system.snmp/community) y se aplican sólo en el primer nivel de cada registro
    de `results`, para no tocar campos homónimos anidados.
    """
    extra = tuple(record_secret_fields)
    if isinstance(obj, dict) and _depth == 0 and "results" in obj:
        out = {k: v for k, v in obj.items() if k != "results"}
        res = obj["results"]
        if isinstance(res, list):
            out["results"] = [_redact_record(r, enabled, extra) for r in res]
        else:
            out["results"] = _redact_record(res, enabled, extra)
        return out
    return _redact(obj, enabled)


def _redact_record(rec: Any, enabled: bool, extra: tuple) -> Any:
    if not isinstance(rec, dict):
        return _redact(rec, enabled)
    out = {}
    for k, v in rec.items():
        if enabled and k.lower() in {e.lower() for e in extra}:
            # Un valor por defecto conocido (comunidad SNMP "public") no es secreto
            # y es un hallazgo en sí: se marca sin exponer otros valores.
            weak = isinstance(v, str) and v.strip().lower() in WEAK_DEFAULT_VALUES
            out[k] = REDACTED_WEAK_DEFAULT if weak else _mask(v)
        else:
            out[k] = _redact({k: v}, enabled)[k]
    return out


def _redact(obj: Any, enabled: bool) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in ALWAYS_SECRET_KEYS or (enabled and kl in SECRET_KEYS):
                out[k] = _mask(v)
            elif enabled and kl == "script" and isinstance(v, str):
                out[k] = redact_script(v)
            else:
                out[k] = _redact(v, enabled)
        return out
    if isinstance(obj, list):
        return [_redact(v, enabled) for v in obj]
    if isinstance(obj, str) and "PRIVATE KEY-----" in obj:
        return _PRIVATE_PEM_RE.sub(REDACTED, obj)
    return obj


def _mask(v: Any) -> Any:
    if v is None or v == "":
        return v
    if isinstance(v, list):
        return [_mask(x) for x in v]
    if isinstance(v, dict):
        return {k: _mask(x) for k, x in v.items()}
    return REDACTED


def redact_script(text: str) -> str:
    """En scripts de auto-script, oculta usuario/password de 'execute backup ... ftp/sftp'
    conservando archivo y servidor (destino del backup = dato de auditoría)."""
    def _sub(m: re.Match) -> str:
        args = m.group(2).split()
        # args: <archivo> <servidor> [<usuario>] [<password>] [<pass-backup>]
        kept = args[:2] + [REDACTED for _ in args[2:]]
        return m.group(1) + (" " + " ".join(kept) if kept else "")
    return _BACKUP_CMD_RE.sub(_sub, text)
