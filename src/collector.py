#!/usr/bin/env python3
"""
FortiGate (FortiOS) — Collector (fase 1: SOLO EXTRACCIÓN)

    FortiOS REST API  ->  Collector  ->  RAW JSON  (data/raw/<run_id>/)

No evalúa CIS, no puntúa, no saca conclusiones y no modifica el firewall:
sólo envía peticiones GET (ver fortinet_audit/client.py).

Uso:
    python src/collector.py                      # usa config/config.yaml + variables de entorno
    python src/collector.py --list-entities      # muestra qué se va a consultar
    python src/collector.py --dry-run            # valida config sin conectarse
    python src/collector.py --sections administrators firewall_policies
    python src/collector.py --vdoms root DMZ     # VDOMs a auditar (default: autodetectar)

Códigos de salida:
    0 = todo extraído (NOT_SUPPORTED no cuenta como error)
    1 = extracción parcial (errores por endpoint, o RESTRICTED: FortiOS ocultó objetos por permisos)
    2 = error fatal (config, API key, trusthost, conectividad)
"""
from __future__ import annotations

import argparse
import getpass
import logging
import platform
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fortinet_audit import __version__  # noqa: E402
from fortinet_audit.catalog import (ENTITIES, FIELD_SOURCES, GLOBAL_SETTINGS_ENTITY,  # noqa: E402
                                    NOT_AVAILABLE, SECTIONS, STATUS_ENTITY, VDOM_ENTITY, Entity)
from fortinet_audit.client import AuthenticationError, FortiOSClient  # noqa: E402
from fortinet_audit.config import ConfigError, Settings, load_settings  # noqa: E402
from fortinet_audit.logging_setup import setup_logging  # noqa: E402
from fortinet_audit.storage import RawStore  # noqa: E402

log = logging.getLogger("fortinet_audit.collector")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collector de solo lectura para FortiGate (FortiOS REST API).")
    p.add_argument("--config", type=Path, help="Ruta a config.yaml (default: config/config.yaml)")
    p.add_argument("--env-file", type=Path, help="Ruta a archivo .env (default: .env en la raíz)")
    p.add_argument("--host", help="Override del host/IP del firewall")
    p.add_argument("--port", type=int, help="Override del puerto HTTPS de administración (default 443)")
    p.add_argument("--prompt-api-key", action="store_true",
                   help="Pedir la API key de forma interactiva (no queda en el historial ni en disco)")
    p.add_argument("--vdoms", nargs="+", help="VDOMs a auditar (default: autodetectar con cmdb/system/vdom)")
    p.add_argument("--sections", nargs="+", choices=SECTIONS, help="Limitar a estas secciones")
    p.add_argument("--insecure", action="store_true",
                   help="No validar el certificado TLS del firewall (solo laboratorio)")
    p.add_argument("--no-redact", action="store_true",
                   help="Guardar secretos sin redactar (NO recomendado; las llaves privadas nunca se guardan)")
    p.add_argument("--list-entities", action="store_true", help="Listar endpoints y salir")
    p.add_argument("--dry-run", action="store_true", help="Validar configuración sin conectarse")
    p.add_argument("-v", "--verbose", action="store_true", help="Log DEBUG")
    return p.parse_args(argv)


def select_entities(s: Settings) -> list[Entity]:
    excl = {e.strip().lower() for e in s.exclude_entities}
    out = [e for e in ENTITIES if e.key.lower() not in excl]
    if s.sections:
        out = [e for e in out if e.section in s.sections]
    return out


def make_run_id(s: Settings, now: datetime) -> str:
    # Sanea cualquier carácter inválido en nombres de archivo/carpeta (Windows incluido)
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", s.label or s.host or "fortigate").strip("_")[:60]
    return f"{base or 'fortigate'}_{now.strftime('%Y%m%dT%H%M%SZ')}"


def build_plan(entities: list[Entity], vdoms: list[str]) -> list[tuple[Entity, str | None]]:
    """Globales una vez; por-VDOM una vez por cada VDOM."""
    plan: list[tuple[Entity, str | None]] = []
    for e in entities:
        if e.scope == "global":
            plan.append((e, None))
        else:
            plan.extend((e, v) for v in vdoms)
    return plan


def discover_vdoms(client: FortiOSClient, store: RawStore, manifest: dict) -> tuple[list[str], dict]:
    """Lee cmdb/system/vdom (global). Si falla, usa 'root' y lo deja registrado."""
    res = client.get(VDOM_ENTITY, None)
    meta = store.save(VDOM_ENTITY, res)
    names = []
    results = (res.parsed or {}).get("results")
    if res.status == "OK" and isinstance(results, list):
        names = [r.get("name") for r in results if isinstance(r, dict) and r.get("name")]
    if not names:
        manifest["vdom_discovery"] = {"source": "fallback", "detail":
                                      f"cmdb/system/vdom no disponible ({res.status} {res.error or ''}); "
                                      "se audita sólo 'root'"}
        return ["root"], meta
    manifest["vdom_discovery"] = {"source": "cmdb/system/vdom", "found": names}
    return names, meta


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.list_entities:
        for e in ENTITIES:
            flag = " (best-effort)" if e.best_effort else ""
            print(f"{e.section:20} {e.scope:6} {e.key:42} CIS {','.join(e.cis):10}{flag}")
        return 0

    try:
        s = load_settings(args.config, args.env_file)
    except ConfigError as exc:
        print(f"[CONFIG] {exc}", file=sys.stderr)
        return 2

    if args.host:
        s.host = args.host
    if args.port:
        s.port = args.port
    if args.vdoms:
        s.vdoms = args.vdoms
    if args.sections:
        s.sections = args.sections
    if args.insecure:
        s.verify_ssl = False
    if args.no_redact:
        s.redact_secrets = False
    if args.verbose:
        s.log_level = "DEBUG"
    if args.prompt_api_key and not args.dry_run:
        s.api_key = getpass.getpass(f"API key del REST API admin para {s.host}: ").strip()

    now = datetime.now(timezone.utc)
    run_id = make_run_id(s, now)
    log_file = setup_logging(s.log_dir, run_id, s.log_level, secrets=[s.api_key])

    missing = [n for n, v in (("host", s.host), ("api_key", s.api_key)) if not v]
    if args.dry_run:
        missing = [m for m in missing if m != "api_key"]
    if missing:
        log.error("Falta configuración obligatoria: %s. Ver README (variables FORTI_FW_*).", ", ".join(missing))
        return 2

    entities = select_entities(s)
    log.info("Collector v%s | run_id=%s | firewall=%s:%s | endpoints=%d | VDOMs=%s | redacción=%s",
             __version__, run_id, s.host, s.port, len(entities), ",".join(s.vdoms) or "auto",
             "ON" if s.redact_secrets else "OFF")
    if s.verify_ssl is False:
        log.warning("Validación TLS DESACTIVADA. Usa verify_ssl con un CA bundle en producción.")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.dry_run:
        for e, v in build_plan(entities, s.vdoms or ["<vdom>"]):
            log.info("[DRY-RUN] GET %-55s %s", e.url_path, f"vdom={v}" if v else "(global)")
        log.info("[DRY-RUN] Configuración válida. No se realizó ninguna conexión.")
        return 0

    client = FortiOSClient(s.host, s.port, s.api_key, verify_ssl=s.verify_ssl, timeout=s.timeout,
                           retries=s.retries, retry_backoff=s.retry_backoff,
                           delay_between_requests=s.delay_between_requests,
                           page_size=s.page_size, max_pages=s.max_pages)
    store = RawStore(s.raw_dir, run_id, redact=s.redact_secrets)

    manifest = {
        "schema_version": "1.0",
        "run_id": run_id,
        "collector_version": __version__,
        "vendor": "Fortinet",
        "platform": "FortiGate / FortiOS",
        "phase": "collection_only",
        "started_at_utc": now.isoformat(timespec="seconds"),
        "finished_at_utc": None,
        "target": {"label": s.label or None, "host": s.host, "port": s.port,
                   "api_base": client.base_url + "/api/v2", "auth": "REST API admin (Bearer token)"},
        "collector_host": {"hostname": socket.gethostname(), "os": platform.platform(),
                           "python": platform.python_version()},
        "settings": {"verify_ssl": bool(s.verify_ssl), "redact_secrets": s.redact_secrets,
                     "sections": s.sections or "all", "excluded": s.exclude_entities,
                     "page_size": s.page_size, "vdoms_requested": s.vdoms or "auto"},
        "firewall_identity": {},
        "vdoms": [],
        "endpoints": [],
        "summary": {},
        "field_sources": FIELD_SOURCES,
        "not_available": [],
    }

    # 1) Login = GET monitor/system/status (fatal si falla)
    try:
        login = client.test_login(STATUS_ENTITY)
    except AuthenticationError as exc:
        log.error("No se pudo autenticar contra la REST API: %s", exc)
        log.error("Revisa: REST API admin creado, API key vigente, IP del collector en trusthost, "
                  "HTTPS habilitado en la interfaz, puerto admin-sport.")
        manifest["fatal_error"] = str(exc)
        manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        store.write_json("manifest.json", manifest)
        return 2
    st = (login.parsed or {}).get("results") or {}
    st = st if isinstance(st, dict) else {}
    manifest["firewall_identity"] = {
        "hostname": st.get("hostname") or NOT_AVAILABLE,
        "model": st.get("model") or NOT_AVAILABLE,
        "model_name": st.get("model_name") or NOT_AVAILABLE,
        "model_number": st.get("model_number") or NOT_AVAILABLE,
        "serial": login.serial or NOT_AVAILABLE,
        "fortios_version": login.version or NOT_AVAILABLE,
        "build": login.build if login.build is not None else NOT_AVAILABLE,
        "firmware": f"{login.version} build{login.build}" if login.version else NOT_AVAILABLE,
        "firewall_http_date": login.firewall_http_date or NOT_AVAILABLE,
        "timezone": NOT_AVAILABLE,
        "vdom_mode": NOT_AVAILABLE,
    }
    log.info("Login OK | %s | %s | serial=%s | FortiOS %s",
             manifest["firewall_identity"]["hostname"], manifest["firewall_identity"]["model"],
             manifest["firewall_identity"]["serial"], manifest["firewall_identity"]["firmware"])

    counts = {"OK": 0, "EMPTY": 0, "RESTRICTED": 0, "NOT_SUPPORTED": 0, "ERROR": 0}

    def record(meta: dict, i: int, total: int) -> None:
        status = meta["status"]
        counts[status] = counts.get(status, 0) + 1
        label = meta["entity"] + (f" [{meta['vdom']}]" if meta.get("vdom") else "")
        if status == "OK":
            pg = meta["pagination"]["pages"]
            log.info("[%03d/%03d] %-55s OK     registros=%s%s  %dms", i, total, label,
                     meta["record_count"], f" páginas={pg}" if pg and pg > 1 else "", meta["duration_ms"])
        elif status == "EMPTY":
            log.info("[%03d/%03d] %-55s VACÍO", i, total, label)
        elif status == "RESTRICTED":
            log.warning("[%03d/%03d] %-55s RESTRINGIDO  %s", i, total, label, meta.get("note"))
        elif status == "NOT_SUPPORTED":
            log.info("[%03d/%03d] %-55s N/A    %s", i, total, label, meta.get("note"))
        else:
            log.warning("[%03d/%03d] %-55s ERROR  %s", i, total, label, meta["error"])
        manifest["endpoints"].append({k: meta.get(k) for k in (
            "entity", "section", "scope", "vdom", "status", "record_count", "http_status", "error", "note", "visibility",
            "extracted_at_utc", "duration_ms", "endpoint", "params", "pagination", "config_revision", "files")})

    # 2) El propio monitor/system/status se guarda como evidencia
    status_meta = store.save(STATUS_ENTITY, login)

    # 3) VDOMs: configurados o autodetectados
    vdom_meta = None
    if s.vdoms:
        vdoms = s.vdoms
        manifest["vdom_discovery"] = {"source": "config", "found": vdoms}
    else:
        vdoms, vdom_meta = discover_vdoms(client, store, manifest)
    manifest["vdoms"] = vdoms
    log.info("VDOMs a auditar: %s", ", ".join(vdoms))

    plan = [(e, v) for e, v in build_plan(entities, vdoms)
            if e.key != STATUS_ENTITY.key and not (vdom_meta is not None and e.key == VDOM_ENTITY.key)]
    total = len(plan) + 1 + (1 if vdom_meta is not None else 0)
    i = 1
    record(status_meta, i, total)
    if vdom_meta is not None:
        i += 1
        record(vdom_meta, i, total)

    # 4) Un GET por endpoint (y por VDOM); un error no detiene el resto
    for e, v in plan:
        i += 1
        try:
            res = client.get(e, v)
            meta = store.save(e, res)
        except Exception as exc:  # nunca abortar la extracción completa
            log.exception("[%03d/%03d] %s ERROR inesperado: %s", i, total, e.key, exc)
            counts["ERROR"] += 1
            manifest["endpoints"].append({"entity": e.key, "section": e.section, "vdom": v,
                                          "status": "ERROR", "error": f"{type(exc).__name__}: {exc}"})
            continue
        if e.key == GLOBAL_SETTINGS_ENTITY.key and res.status == "OK":
            g = (res.parsed or {}).get("results") or {}
            if isinstance(g, list):
                g = g[0] if g else {}
            fi = manifest["firewall_identity"]
            fi["timezone"] = g.get("timezone") or NOT_AVAILABLE
            fi["vdom_mode"] = g.get("vdom-mode") or NOT_AVAILABLE
            if fi["hostname"] == NOT_AVAILABLE and g.get("hostname"):
                fi["hostname"] = g["hostname"]
        record(meta, i, total)

    # 5) Registro explícito de lo que la API no entrega
    for section, fields in FIELD_SOURCES.items():
        for fname, src in fields.items():
            if str(src).startswith(NOT_AVAILABLE):
                manifest["not_available"].append({"section": section, "field": fname, "detail": src})

    manifest["summary"] = {"requested": total, **counts}
    manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    mpath = store.write_json("manifest.json", manifest)

    log.info("-" * 78)
    log.info("Resumen: %d consultas | %d OK | %d vacías | %d restringidas | %d no soportadas | %d con error",
             total, counts["OK"], counts["EMPTY"], counts["RESTRICTED"], counts["NOT_SUPPORTED"], counts["ERROR"])
    if counts["RESTRICTED"]:
        log.warning("Visibilidad RESTRINGIDA (el perfil del REST API admin no ve todos los objetos): %s",
                    ", ".join(x["entity"] + (f"[{x['vdom']}]" if x.get("vdom") else "")
                              for x in manifest["endpoints"] if x["status"] == "RESTRICTED"))
        log.warning("Los datos de esos endpoints están INCOMPLETOS. Pide al cliente un accprofile con "
                    "'set scope global' para el REST API admin y vuelve a extraer.")
    if counts["ERROR"]:
        log.info("Con error: %s", ", ".join(
            x["entity"] + (f"[{x['vdom']}]" if x.get("vdom") else "")
            for x in manifest["endpoints"] if x["status"] == "ERROR"))
    if counts["NOT_SUPPORTED"]:
        log.info("No soportadas en esta versión/modelo: %s", ", ".join(sorted({
            x["entity"] for x in manifest["endpoints"] if x["status"] == "NOT_SUPPORTED"})))
    log.info("No disponibles vía REST API: %s",
             ", ".join(f"{x['section']}.{x['field']}" for x in manifest["not_available"]))
    log.info("RAW: %s", store.run_dir)
    log.info("Manifest: %s", mpath)
    log.info("Log: %s", log_file)
    return 1 if counts["ERROR"] or counts["RESTRICTED"] else 0


if __name__ == "__main__":
    sys.exit(main())
