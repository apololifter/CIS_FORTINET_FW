"""
Cliente de SOLO LECTURA para la FortiOS REST API (FortiGate).

    GET https://<firewall>:<puerto>/api/v2/cmdb/<ruta>?vdom=<vdom>
    GET https://<firewall>:<puerto>/api/v2/monitor/<ruta>?vdom=<vdom>
    Authorization: Bearer <API key de un REST API admin>

Garantías de solo lectura (defensa en profundidad):
  * El cliente sólo tiene un método de transporte, `_http_get`, que llama a
    session.get. No existe código para POST/PUT/DELETE.
  * Antes de enviar se valida que la ruta sea /api/v2/cmdb|monitor/..., con
    caracteres permitidos, y que no esté en FORBIDDEN_PREFIXES.
  * La API key viaja SOLO en la cabecera Authorization (nunca en la URL ni en
    parámetros: así no queda en logs de proxies ni del propio FortiGate), no se
    guarda en los RAW y un filtro la borra de los logs.
  * La garantía real es del lado del firewall: el REST API admin debe tener un
    accprofile con todo en "read" y trusthost restringido a la IP del auditor.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from .catalog import FORBIDDEN_PREFIXES, Entity

log = logging.getLogger("fortinet_audit.client")

_PATH_RE = re.compile(r"^(cmdb|monitor)/[A-Za-z0-9][A-Za-z0-9._+/-]{0,120}$")
_VDOM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
_RETRY_HTTP = {429, 502, 503, 504}
NOT_SUPPORTED_HTTP = {404, 405}


class ReadOnlyViolation(RuntimeError):
    """Se intentó construir/enviar algo distinto de un GET permitido."""


class AuthenticationError(RuntimeError):
    """API key inválida, IP fuera de trusthost o API inaccesible (errores fatales)."""


@dataclass
class ApiResult:
    entity: str
    endpoint: str
    vdom: Optional[str]
    started_utc: str
    duration_ms: int = 0
    http_status: Optional[int] = None
    content_type: Optional[str] = None
    firewall_http_date: Optional[str] = None
    status: str = "ERROR"          # OK | EMPTY | RESTRICTED | NOT_SUPPORTED | ERROR
    api_status: Optional[str] = None   # campo "status" del sobre FortiOS (success/error)
    error: Optional[str] = None
    parsed: Optional[dict] = None      # sobre completo de FortiOS (results unidos si hubo paginación)
    record_count: Optional[int] = None
    serial: Optional[str] = None
    version: Optional[str] = None
    build: Optional[Any] = None
    revision: Optional[str] = None
    attempts: int = 0
    pages: int = 0
    pagination_note: Optional[str] = None
    raw_text: Optional[str] = None     # cuerpo no-JSON (errores)
    extra: dict = field(default_factory=dict)


class FortiOSClient:
    def __init__(self, host: str, port: int, api_key: str, *,
                 verify_ssl: bool | str = True, timeout: int = 60, retries: int = 2,
                 retry_backoff: float = 2.0, delay_between_requests: float = 0.3,
                 page_size: int = 1000, max_pages: int = 500,
                 session: Optional[requests.Session] = None):
        if not host:
            raise ValueError("host vacío")
        # Tolera "https://10.0.0.1/", "10.0.0.1:8443", etc.
        host = re.sub(r"^\s*\w+://", "", host).strip().strip("/")
        if ":" in host and not host.startswith("["):
            h, _, hostport = host.rpartition(":")
            if hostport.isdigit():
                host, port = h, int(hostport)
        self.base_url = f"https://{host}:{port}"
        self._api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_backoff = retry_backoff
        self.delay = delay_between_requests
        self.page_size = max(1, int(page_size))
        self.max_pages = max(1, int(max_pages))
        self.session = session or requests.Session()
        self.session.headers.update({"Accept": "application/json",
                                     "User-Agent": "fortinet-cis-collector/0.1 (read-only)"})

    # ------------------------------------------------------------------ #
    # Validación (único camino para construir una URL)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate(entity: Entity, vdom: Optional[str]) -> None:
        key = entity.key
        if not _PATH_RE.match(key) or ".." in key or "//" in key:
            raise ReadOnlyViolation(f"Ruta de endpoint inválida: {key!r}")
        low = key.lower()
        for p in FORBIDDEN_PREFIXES:
            if low == p or low.startswith(p + "/") or low.startswith(p + "?"):
                raise ReadOnlyViolation(f"Endpoint bloqueado por política de solo lectura: {key}")
        if vdom is not None and not _VDOM_RE.match(vdom):
            raise ReadOnlyViolation(f"Nombre de VDOM inválido: {vdom!r}")
        for k, _ in entity.params:
            if k.lower() in ("access_token", "method", "action"):
                raise ReadOnlyViolation(f"Parámetro no permitido: {k}")

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}"}

    # ------------------------------------------------------------------ #
    # Transporte: SOLO GET
    # ------------------------------------------------------------------ #
    def _http_get(self, url: str, params: dict) -> requests.Response:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 2):
            try:
                resp = self.session.get(url, params=params, headers=self._auth_headers(),
                                        verify=self.verify_ssl, timeout=self.timeout)
                if resp.status_code in _RETRY_HTTP and attempt <= self.retries:
                    log.warning("HTTP %s en %s (intento %s/%s), reintentando", resp.status_code,
                                url, attempt, self.retries + 1)
                    time.sleep(self.retry_backoff * attempt)
                    continue
                resp._attempts = attempt  # type: ignore[attr-defined]
                return resp
            except requests.exceptions.SSLError:
                raise
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                log.warning("Fallo de conexión (intento %s/%s): %s", attempt, self.retries + 1,
                            type(exc).__name__)
                if attempt <= self.retries:
                    time.sleep(self.retry_backoff * attempt)
        assert last_exc is not None
        raise last_exc

    # ------------------------------------------------------------------ #
    # Operaciones públicas
    # ------------------------------------------------------------------ #
    def test_login(self, status_entity: Entity) -> ApiResult:
        """GET monitor/system/status. Lanza AuthenticationError si el token/trusthost falla."""
        res = self.get(status_entity, None, _login=True)
        if res.status != "OK":
            hint = ""
            if res.http_status == 401:
                hint = " (API key inválida o expirada)"
            elif res.http_status == 403:
                hint = " (IP del collector fuera del trusthost del REST API admin, o perfil sin permisos)"
            raise AuthenticationError((res.error or "Login fallido") + hint)
        return res

    def get(self, entity: Entity, vdom: Optional[str], _login: bool = False) -> ApiResult:
        started = datetime.now(timezone.utc)
        url = self.base_url + entity.url_path
        res = ApiResult(entity=entity.key, endpoint=f"GET {url}", vdom=vdom,
                        started_utc=started.isoformat(timespec="milliseconds"))
        try:
            self._validate(entity, vdom)
        except ReadOnlyViolation as exc:
            res.error = str(exc)
            return res

        res.extra["best_effort"] = entity.best_effort
        base_params = dict(entity.params)
        if vdom is not None:
            base_params["vdom"] = vdom
        res.extra["params"] = dict(base_params)

        t0 = time.monotonic()
        try:
            if entity.paginate:
                self._get_paginated(url, base_params, res)
            else:
                self._get_once(url, base_params, res)
        except requests.exceptions.SSLError as exc:
            res.error = f"SSL: {exc.__class__.__name__}: {exc}"
        except requests.RequestException as exc:
            res.error = f"{exc.__class__.__name__}: {exc}"
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        if self.delay and not _login:
            time.sleep(self.delay)
        return res

    # ------------------------------------------------------------------ #
    def _get_once(self, url: str, params: dict, res: ApiResult) -> None:
        resp = self._http_get(url, params)
        env = self._handle_response(resp, res)
        res.pages = 1
        if env is not None:
            res.parsed = env
            self._classify(res, env.get("results"))

    def _get_paginated(self, url: str, params: dict, res: ApiResult) -> None:
        """cmdb soporta ?start=&count=. Si el equipo ignora la paginación (devuelve
        lo mismo en la página 2), se detecta y se conserva sólo una copia."""
        start, merged, first_env, matched_total = 0, [], None, 0
        while True:
            resp = self._http_get(url, {**params, "start": start, "count": self.page_size})
            env = self._handle_response(resp, res)
            if env is None:          # error / not supported: se registra y se corta
                if res.pages:        # error a mitad de paginación: se marca parcial
                    res.error = f"Paginación interrumpida en página {res.pages + 1}: {res.error}"
                    res.status = "ERROR"
                return
            results = env.get("results")
            if isinstance(results, list) and not results and merged:
                break                # página final vacía (total múltiplo de page_size)
            res.pages += 1
            if first_env is None:
                first_env = env
            if not isinstance(results, list):   # objeto único (p.ej. system/global)
                res.parsed = env
                self._classify(res, results)
                return
            if res.pages > 1 and results and merged and results[0] == merged[0]:
                res.pagination_note = "El equipo ignoró start/count; se conservó una sola copia."
                res.pages -= 1
                break
            merged.extend(results)
            try:
                matched_total += int(env.get("matched_count", len(results)))
            except (TypeError, ValueError):
                matched_total += len(results)
            if len(results) < self.page_size:
                break
            if res.pages >= self.max_pages:
                res.pagination_note = f"Se alcanzó max_pages={self.max_pages}; resultado posiblemente TRUNCADO."
                log.warning("%s: %s", res.entity, res.pagination_note)
                break
            start += self.page_size
        env = dict(first_env or {})
        env["results"] = merged
        if "matched_count" in env:
            # FortiOS informa matched_count/next_idx POR PÁGINA; el sobre unido lleva el total.
            env["matched_count"] = matched_total
            env.pop("next_idx", None)
        res.parsed = env
        self._classify(res, merged)

    # ------------------------------------------------------------------ #
    def _handle_response(self, resp: requests.Response, res: ApiResult) -> Optional[dict]:
        res.attempts += getattr(resp, "_attempts", 1)
        res.http_status = resp.status_code
        res.content_type = resp.headers.get("Content-Type")
        res.firewall_http_date = resp.headers.get("Date") or res.firewall_http_date

        env: Optional[dict] = None
        try:
            data = resp.json()
            env = data if isinstance(data, dict) else {"results": data}
        except (ValueError, json.JSONDecodeError):
            res.raw_text = _safe_text(resp)

        if env is not None:
            res.api_status = env.get("status") or res.api_status
            res.serial = env.get("serial") or res.serial
            res.version = env.get("version") or res.version
            res.build = env.get("build") if env.get("build") is not None else res.build
            res.revision = env.get("revision") or res.revision

        if resp.status_code in NOT_SUPPORTED_HTTP or (resp.status_code == 400 and res.extra.get("best_effort")):
            res.status = "NOT_SUPPORTED"
            res.error = None
            res.extra["note"] = (f"HTTP {resp.status_code}: el endpoint no existe en esta versión/modelo "
                                 f"o la función no está habilitada")
            res.record_count = 0
            if env is not None:
                res.parsed = env
            return None
        if resp.status_code != 200:
            detail = ""
            if env is not None:
                detail = str(env.get("error") or env.get("cli_error") or env.get("status") or "")
            res.status = "ERROR"
            res.error = f"HTTP {resp.status_code}" + (f": {detail}" if detail else "")
            if resp.status_code == 403:
                res.error += " (permiso denegado por el accprofile del REST API admin)"
            if env is not None:
                res.parsed = env
            return None
        if env is None:
            res.status, res.error = "ERROR", "Respuesta no es JSON"
            return None
        if str(env.get("status", "success")).lower() not in ("success", ""):
            res.status = "ERROR"
            res.error = f"API status={env.get('status')} http_status={env.get('http_status')} " \
                        f"error={env.get('error')}"
            res.parsed = env
            return None
        return env

    @staticmethod
    def _classify(res: ApiResult, results: Any) -> None:
        if results is None or results == [] or results == {}:
            res.status, res.record_count = "EMPTY", 0
        elif isinstance(results, list):
            res.status, res.record_count = "OK", len(results)
        else:
            res.status, res.record_count = "OK", 1
        FortiOSClient._check_visibility(res)

    @staticmethod
    def _check_visibility(res: ApiResult) -> None:
        """FortiOS filtra en silencio los objetos que el perfil del REST API admin no
        puede ver (p.ej. administradores con más privilegios): responde 200 con
        'size' = objetos existentes y 'matched_count' = objetos visibles. Sin filtro
        propio, matched_count < size significa visibilidad RESTRINGIDA, no tabla vacía."""
        env = res.parsed or {}
        size, matched = env.get("size"), env.get("matched_count")
        if size is None or matched is None or "filter" in res.extra.get("params", {}):
            return
        try:
            size, matched = int(size), int(matched)
        except (TypeError, ValueError):
            return
        if matched < size:
            res.extra["visibility"] = {"size": size, "matched_count": matched}
            res.extra["note"] = (f"FortiOS ocultó objetos por permisos del perfil: {matched} de {size} "
                                 f"visibles. Revisar accprofile/scope del REST API admin.")
            res.status = "RESTRICTED"


def _safe_text(resp: requests.Response) -> str:
    try:
        return resp.text[:20000]
    except Exception:
        return ""
