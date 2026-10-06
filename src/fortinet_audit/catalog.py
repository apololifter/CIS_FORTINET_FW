"""
Catálogo de endpoints de la FortiOS REST API (FortiGate) usados por el collector.

La REST API de FortiOS tiene dos familias de endpoints, ambos consultados sólo con GET:

    /api/v2/cmdb/<ruta>      configuración (equivale a "show" en CLI: config <ruta>)
    /api/v2/monitor/<ruta>   estado en tiempo de ejecución (equivale a "get/diagnose")

Una ruta cmdb se traduce directo a la CLI: "vpn.ipsec/phase1-interface" es
"config vpn ipsec phase1-interface". Esa equivalencia queda en `cli` para que el
auditor pueda validar cualquier dato en consola.

La referencia oficial de la API está en Fortinet Developer Network (FNDN, requiere
cuenta): https://fndn.fortinet.net  ->  FortiOS  ->  REST API Reference.
La referencia CLI es pública: https://docs.fortinet.com/product/fortigate

`scope`:
    global = objeto global (una sola consulta por firewall)
    vdom   = objeto por VDOM (una consulta por cada VDOM auditado, parámetro ?vdom=)

`best_effort=True` marca endpoints que no existen en todas las versiones/modelos
(p.ej. policy6 sólo existe en 6.x; SSL-VPN se retiró en algunos modelos 7.6).
Si responden 404/405 quedan como NOT_SUPPORTED (no como error).

Este archivo es DATOS, no lógica: el normalizer y el cis_engine futuros pueden
importarlo para saber de qué archivo RAW sale cada dato, sin tocar el collector.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

API_BASE = "/api/v2"
CLI_DOCS = "https://docs.fortinet.com/product/fortigate"
API_DOCS = "https://fndn.fortinet.net (FortiOS REST API Reference)"
NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass(frozen=True)
class Entity:
    api: str                 # "cmdb" | "monitor"
    path: str                # ruta bajo /api/v2/<api>/, p.ej. "firewall/policy"
    section: str             # sección funcional (carpeta de salida)
    scope: str               # "global" | "vdom"
    cis: tuple = ()          # CIS Controls para los que se recolecta (solo referencia)
    purpose: str = ""        # qué dato aporta
    secret_fields: tuple = ()  # campos secretos propios de esta entidad (además de los globales)
    params: tuple = ()       # parámetros GET fijos ((clave, valor), ...)
    best_effort: bool = False  # puede no existir en esta versión/modelo

    @property
    def key(self) -> str:
        """Identificador único: 'cmdb/firewall/policy'."""
        return f"{self.api}/{self.path}"

    @property
    def url_path(self) -> str:
        # '+' de "user/tacacs+" debe ir codificado (%2B)
        return f"{API_BASE}/{self.api}/{quote(self.path, safe='/._-')}"

    @property
    def file_stem(self) -> str:
        """Nombre de archivo RAW: 'cmdb.firewall.policy'."""
        raw = f"{self.api}.{self.path.replace('/', '.')}"
        return re.sub(r"[^A-Za-z0-9._-]", "_", raw.replace("+", "plus"))

    @property
    def paginate(self) -> bool:
        return self.api == "cmdb"

    @property
    def cli(self) -> str:
        if self.api != "cmdb":
            return ""
        return "config " + self.path.replace(".", " ").replace("/", " ")

    @property
    def doc_ref(self) -> str:
        return f"{API_DOCS} -> {self.api} {self.path}"


def _e(api, path, section, scope, cis, purpose, **kw) -> Entity:
    return Entity(api, path, section, scope, tuple(cis), purpose, **kw)


# --------------------------------------------------------------------------- #
# Endpoints a recolectar (sólo GET)
# --------------------------------------------------------------------------- #
ENTITIES: list[Entity] = [
    # 1. Firewall / sistema --------------------------------------------------
    _e("monitor", "system/status", "firewall", "global", ("4", "12"),
       "Hostname, modelo (model, model_name, model_number); serial, versión FortiOS y build vienen "
       "en el sobre de toda respuesta"),
    _e("cmdb", "system/global", "firewall", "global", ("4", "5", "8"),
       "Hostname, timezone, puertos admin (admin-sport/admin-ssh-port/admin-telnet-port), "
       "admin-https-redirect, admintimeout, admin-lockout-threshold/duration, strong-crypto, "
       "admin-https-ssl-versions, pre/post-login-banner, vdom-mode, revision-backup-on-logout"),
    _e("monitor", "system/firmware", "firewall", "global", ("4", "12"),
       "Firmware en ejecución y versiones disponibles en FortiGuard"),
    _e("monitor", "license/status", "firewall", "global", ("12", "13"),
       "Estado de licencias/contratos FortiGuard (IPS, AV, Web Filter, App Control)"),
    _e("cmdb", "system/vdom", "firewall", "global", ("12",),
       "VDOMs definidos (se usa también para descubrir qué VDOMs auditar)"),
    _e("cmdb", "system/settings", "firewall", "vdom", ("4", "12", "13"),
       "Por VDOM: opmode (NAT/transparente), ngfw-mode (profile/policy), central-nat, "
       "inspection-mode, gui features"),
    _e("cmdb", "system/fortiguard", "firewall", "global", ("12", "13"),
       "Actualización FortiGuard: servidores, frecuencia de actualización (7.2+), puerto, protocolo",
       secret_fields=("proxy-password",)),
    _e("cmdb", "system.autoupdate/schedule", "firewall", "global", ("12", "13"),
       "Frecuencia de actualización de firmas (FortiOS <= 7.0; en 7.2+ está en system/fortiguard)",
       best_effort=True),

    # 2. Administradores -----------------------------------------------------
    _e("cmdb", "system/admin", "administrators", "global", ("5", "6"),
       "Administradores: nombre, accprofile (rol), vdom, trusthost1..10/ip6-trusthost, two-factor, "
       "fortitoken, remote-auth/wildcard/remote-group, guest-auth"),
    _e("cmdb", "system/accprofile", "administrators", "global", ("5", "6"),
       "Perfiles de administración (roles): permisos por área (sysgrp, netgrp, fwgrp, loggrp, "
       "vpngrp, utmgrp, authgrp...), scope global/vdom"),
    _e("cmdb", "system/api-user", "administrators", "global", ("5", "6"),
       "Administradores REST API: accprofile, vdom, trusthost, cors, peer-auth (la API key se redacta)",
       secret_fields=("api-key",)),
    _e("cmdb", "system/password-policy", "administrators", "global", ("5",),
       "Política de contraseñas de administradores (largo, complejidad, expiración, reuse)"),
    _e("monitor", "system/current-admins", "administrators", "global", ("5", "8"),
       "Sesiones de administración activas al momento de la extracción", best_effort=True),

    # 3. Administración / acceso al dispositivo --------------------------------
    _e("cmdb", "firewall/local-in-policy", "administration", "vdom", ("4", "12", "13"),
       "Local-in policies: restricción de tráfico hacia el propio FortiGate (gestión, VPN, etc.)"),
    _e("cmdb", "system.snmp/sysinfo", "administration", "global", ("4", "12"),
       "Agente SNMP: estado, contacto, ubicación"),
    _e("cmdb", "system.snmp/community", "administration", "global", ("4", "12"),
       "Comunidades SNMP v1/v2c y hosts permitidos (el nombre ES la comunidad: se redacta)",
       secret_fields=("name",)),
    _e("cmdb", "system.snmp/user", "administration", "global", ("4", "12"),
       "Usuarios SNMPv3: nivel de seguridad, protocolos auth/priv, hosts permitidos"),
    _e("cmdb", "system/central-management", "administration", "global", ("4", "8"),
       "Gestión central: FortiManager / FortiCloud (tipo, servidor, include-default-servers)"),

    # 4. Usuarios / autenticación -------------------------------------------
    _e("cmdb", "user/local", "users", "vdom", ("5", "6"),
       "Usuarios locales: estado, tipo (password/ldap/radius), two-factor, fortitoken"),
    _e("cmdb", "user/group", "users", "vdom", ("5", "6"),
       "Grupos de usuarios (firewall/SSO), miembros y servidores remotos asociados"),
    _e("cmdb", "user/ldap", "users", "vdom", ("5", "6"),
       "Servidores LDAP: servidor, puerto, secure (ldaps/starttls), cn, dn, tipo de bind"),
    _e("cmdb", "user/radius", "users", "vdom", ("5", "6"),
       "Servidores RADIUS (secretos redactados)"),
    _e("cmdb", "user/tacacs+", "users", "vdom", ("5", "6"),
       "Servidores TACACS+ (claves redactadas)"),
    _e("cmdb", "user/saml", "users", "vdom", ("5", "6"),
       "Proveedores SAML (SSO / MFA externo)", best_effort=True),
    _e("cmdb", "user/fortitoken", "users", "vdom", ("6",),
       "Tokens FortiToken registrados y su estado"),
    _e("cmdb", "user/setting", "users", "vdom", ("5", "6"),
       "Parámetros de autenticación: timeout, lockout, puertos de auth, cert de auth"),

    # 5. Interfaces / red -----------------------------------------------------
    _e("cmdb", "system/interface", "network", "global", ("4", "12"),
       "Interfaces: IP/máscara, vdom, tipo, vlanid + interface padre (VLAN), status, role, "
       "allowaccess (HTTPS/SSH/SNMP/PING/HTTP/TELNET/FGFM), alias"),
    _e("monitor", "system/interface", "network", "vdom", ("12",),
       "Estado en tiempo real de interfaces (link up/down, velocidad, contadores)",
       params=(("include_vlan", "true"),), best_effort=True),
    _e("cmdb", "system/zone", "network", "vdom", ("4", "12"),
       "Zonas, interfaces miembro, intrazone allow/deny"),
    _e("cmdb", "system/dns", "network", "global", ("4", "12"),
       "Servidores DNS del firewall, protocolo (DoT/DoH)"),
    _e("cmdb", "system/sdwan", "network", "vdom", ("12",),
       "SD-WAN: miembros, health-checks, reglas", best_effort=True),

    # 6. Routing --------------------------------------------------------------
    _e("cmdb", "router/static", "routing", "vdom", ("12",),
       "Rutas estáticas IPv4: destino, gateway, interfaz, distancia, estado, blackhole"),
    _e("cmdb", "router/static6", "routing", "vdom", ("12",), "Rutas estáticas IPv6"),
    _e("cmdb", "router/policy", "routing", "vdom", ("12",), "Policy routes (PBR)"),
    _e("cmdb", "router/bgp", "routing", "vdom", ("12",), "BGP: AS, vecinos, redes (passwords redactadas)"),
    _e("cmdb", "router/ospf", "routing", "vdom", ("12",), "OSPF: áreas, interfaces, autenticación"),
    _e("monitor", "router/ipv4", "routing", "vdom", ("12",),
       "Tabla de ruteo activa (rutas instaladas, gateways, interfaces)", best_effort=True),

    # 7. Objetos ---------------------------------------------------------------
    _e("cmdb", "firewall/address", "objects", "vdom", ("12", "13"),
       "Address objects IPv4: subnet, iprange, fqdn, geography, wildcard, dynamic"),
    _e("cmdb", "firewall/address6", "objects", "vdom", ("12", "13"), "Address objects IPv6"),
    _e("cmdb", "firewall/addrgrp", "objects", "vdom", ("12", "13"), "Address groups IPv4 (incl. exclude)"),
    _e("cmdb", "firewall/addrgrp6", "objects", "vdom", ("12", "13"), "Address groups IPv6"),
    _e("cmdb", "firewall.wildcard-fqdn/custom", "objects", "vdom", ("12", "13"), "Wildcard FQDN"),
    _e("cmdb", "firewall.wildcard-fqdn/group", "objects", "vdom", ("12", "13"), "Grupos wildcard FQDN"),
    _e("cmdb", "firewall.service/custom", "objects", "vdom", ("4", "12"),
       "Servicios: protocolo, puertos TCP/UDP/SCTP, ICMP, categoría"),
    _e("cmdb", "firewall.service/group", "objects", "vdom", ("4", "12"), "Grupos de servicios"),
    _e("cmdb", "firewall.schedule/recurring", "objects", "vdom", ("4", "13"), "Schedules recurrentes"),
    _e("cmdb", "firewall.schedule/onetime", "objects", "vdom", ("4", "13"),
       "Schedules únicos (reglas temporales, fecha de expiración)"),
    _e("cmdb", "firewall.schedule/group", "objects", "vdom", ("4", "13"), "Grupos de schedules"),

    # 8. Firewall policies -------------------------------------------------------
    _e("cmdb", "firewall/policy", "firewall_policies", "vdom", ("4", "8", "12", "13"),
       "Políticas: policyid, name, status, srcintf/dstintf, srcaddr/dstaddr (+negate), service, "
       "action, schedule, nat/ippool/poolname, logtraffic/logtraffic-start, utm-status, "
       "av-profile, ips-sensor, webfilter-profile, application-list, ssl-ssh-profile, "
       "dnsfilter-profile, users/groups, comments; el orden de la respuesta = orden de evaluación"),
    _e("monitor", "firewall/policy", "firewall_policies", "vdom", ("13",),
       "Contadores por política: hits, bytes, sesiones, último uso (detectar reglas sin uso)",
       best_effort=True),
    _e("cmdb", "firewall/security-policy", "firewall_policies", "vdom", ("4", "12", "13"),
       "Security policies (ngfw-mode policy-based)", best_effort=True),
    _e("cmdb", "firewall/proxy-policy", "firewall_policies", "vdom", ("4", "12", "13"),
       "Políticas de proxy explícito / transparente"),
    _e("cmdb", "firewall/DoS-policy", "firewall_policies", "vdom", ("13",),
       "Políticas DoS (anomalías, umbrales, acción)"),
    _e("cmdb", "firewall/policy6", "firewall_policies", "vdom", ("4", "12", "13"),
       "Políticas IPv6 separadas (sólo FortiOS 6.x; en 7.x están unificadas en firewall/policy)",
       best_effort=True),

    # 9. NAT / VIP ---------------------------------------------------------------
    _e("cmdb", "firewall/vip", "nat", "vdom", ("4", "12"),
       "VIP/DNAT: extip (IP pública), mappedip (IP interna), extintf, portforward, protocol, "
       "extport/mappedport, src-filter, type (static-nat/load-balance/server-load-balance)"),
    _e("cmdb", "firewall/vip6", "nat", "vdom", ("4", "12"), "VIP IPv6"),
    _e("cmdb", "firewall/vipgrp", "nat", "vdom", ("4", "12"), "Grupos de VIP"),
    _e("cmdb", "firewall/ippool", "nat", "vdom", ("4", "12"),
       "IP pools (SNAT): tipo (overload/one-to-one/fixed-port-range), startip/endip"),
    _e("cmdb", "firewall/central-snat-map", "nat", "vdom", ("4", "12"),
       "Central SNAT (si system/settings central-nat=enable)"),

    # 10. VPN ---------------------------------------------------------------------
    _e("cmdb", "vpn.ipsec/phase1-interface", "vpn", "vdom", ("6", "12"),
       "IPsec fase 1 (route-based): remote-gw, ike-version, proposal, dhgrp, authmethod, "
       "peertype/peer, mode-cfg, xauth/authusrgrp, dpd (PSK redactada)"),
    _e("cmdb", "vpn.ipsec/phase2-interface", "vpn", "vdom", ("6", "12"),
       "IPsec fase 2: src/dst subnet o selectores, proposal, pfs, dhgrp, keylife"),
    _e("cmdb", "vpn.ipsec/phase1", "vpn", "vdom", ("6", "12"), "IPsec fase 1 (policy-based)"),
    _e("cmdb", "vpn.ipsec/phase2", "vpn", "vdom", ("6", "12"), "IPsec fase 2 (policy-based)"),
    _e("cmdb", "vpn.ssl/settings", "vpn", "vdom", ("6", "12"),
       "SSL-VPN: estado, puerto, servercert, source-interface/source-address, tunnel-ip-pools, "
       "authentication-rule (grupos -> portal), ssl-min-proto-ver, reqclientcert, idle-timeout",
       best_effort=True),
    _e("cmdb", "vpn.ssl.web/portal", "vpn", "vdom", ("6", "12"),
       "Portales SSL-VPN: tunnel-mode, split-tunneling + redes permitidas, web-mode, ip-pools",
       best_effort=True),
    _e("monitor", "vpn/ipsec", "vpn", "vdom", ("12",),
       "Estado en vivo de túneles IPsec (up/down, bytes, selectores)", best_effort=True),
    _e("monitor", "vpn/ssl", "vpn", "vdom", ("6", "12"),
       "Usuarios SSL-VPN conectados al momento de la extracción", best_effort=True),

    # 11. IPS ------------------------------------------------------------------------
    _e("cmdb", "ips/sensor", "ips", "vdom", ("13",),
       "Sensores IPS: entries (severidad, OS, acción, status), exempt-ip, block-malicious-url"),
    _e("cmdb", "ips/global", "ips", "global", ("13",),
       "Configuración IPS global: fail-open, database, traffic-submit, engine"),
    _e("cmdb", "ips/settings", "ips", "vdom", ("13",), "Opciones IPS por VDOM (packet-log, etc.)"),

    # 12. Web Filter ------------------------------------------------------------------
    _e("cmdb", "webfilter/profile", "web_filter", "vdom", ("13",),
       "Perfiles Web Filter: ftgd-wf (categorías y acción), web (urlfilter-table, safe-search), "
       "override, options, log"),
    _e("cmdb", "webfilter/urlfilter", "web_filter", "vdom", ("13",),
       "Static URL filter: entries con action exempt/allow/block/monitor (EXCEPCIONES)"),
    _e("cmdb", "webfilter/ftgd-local-cat", "web_filter", "vdom", ("13",), "Categorías locales"),
    _e("cmdb", "webfilter/ftgd-local-rating", "web_filter", "vdom", ("13",),
       "Re-categorización local de URLs (puede usarse como excepción)"),
    _e("cmdb", "webfilter/override", "web_filter", "vdom", ("13",),
       "Overrides administrativos de Web Filter (excepciones por usuario/IP)", best_effort=True),
    _e("cmdb", "dnsfilter/profile", "web_filter", "vdom", ("13",),
       "Perfiles DNS Filter: categorías, domain-filter, block-botnet"),

    # 13. Application Control -----------------------------------------------------
    _e("cmdb", "application/list", "application_control", "vdom", ("13",),
       "Sensores Application Control: entries (category/application/acción), "
       "unknown-application-action, deep-app-inspection"),
    _e("cmdb", "application/group", "application_control", "vdom", ("13",), "Grupos de aplicaciones"),

    # 14. SSL Inspection ------------------------------------------------------------
    _e("cmdb", "firewall/ssl-ssh-profile", "ssl_inspection", "vdom", ("13",),
       "Perfiles SSL/SSH: deep vs certificate-inspection por protocolo, ssl-exempt (EXCEPCIONES: "
       "categorías, addresses, wildcard-fqdn), server-cert, untrusted/expired actions, "
       "min-allowed-ssl-version"),

    # 15. Otros perfiles de seguridad (usados por las políticas) ---------------------
    _e("cmdb", "antivirus/profile", "security_profiles", "vdom", ("13",),
       "Perfiles Antivirus por protocolo, outbreak-prevention, ems-threat-feed"),
    _e("cmdb", "antivirus/settings", "security_profiles", "vdom", ("13",), "Configuración AV"),
    _e("cmdb", "antivirus/exempt-list", "security_profiles", "vdom", ("13",),
       "Exclusiones de antivirus (hash/archivo)", best_effort=True),

    # 16. Logging -------------------------------------------------------------------
    _e("cmdb", "log/setting", "logging", "vdom", ("8",),
       "Logging por VDOM: fwpolicy-implicit-log, local-in-allow/deny-*, resolve-ip, brief-traffic-format"),
    _e("cmdb", "log/eventfilter", "logging", "vdom", ("8",),
       "Tipos de eventos registrados (system, vpn, user, router, wireless, ...)"),
    _e("cmdb", "log.disk/setting", "logging", "global", ("8",), "Log en disco local: estado, retención, rotación"),
    _e("cmdb", "log.memory/setting", "logging", "global", ("8",), "Log en memoria"),
    _e("cmdb", "log.fortianalyzer/setting", "logging", "global", ("8",),
       "FortiAnalyzer #1: estado, servidor, enc-algorithm, upload-option, reliable, serial"),
    _e("cmdb", "log.fortianalyzer2/setting", "logging", "global", ("8",), "FortiAnalyzer #2"),
    _e("cmdb", "log.fortianalyzer3/setting", "logging", "global", ("8",), "FortiAnalyzer #3"),
    _e("cmdb", "log.fortianalyzer-cloud/setting", "logging", "global", ("8",),
       "FortiAnalyzer Cloud", best_effort=True),
    _e("cmdb", "log.fortianalyzer/filter", "logging", "global", ("8",),
       "Filtro de logs enviados a FortiAnalyzer (severidad, tipos)"),
    _e("cmdb", "log.syslogd/setting", "logging", "global", ("8",),
       "Syslog/SIEM #1: estado, servidor, puerto, mode (udp/reliable/legacy-reliable), enc-algorithm, format"),
    _e("cmdb", "log.syslogd2/setting", "logging", "global", ("8",), "Syslog/SIEM #2"),
    _e("cmdb", "log.syslogd3/setting", "logging", "global", ("8",), "Syslog/SIEM #3"),
    _e("cmdb", "log.syslogd4/setting", "logging", "global", ("8",), "Syslog/SIEM #4"),
    _e("cmdb", "log.syslogd/filter", "logging", "global", ("8",), "Filtro de logs enviados a syslog #1"),
    _e("cmdb", "log.fortiguard/setting", "logging", "global", ("8",),
       "Envío de logs a FortiGuard Cloud / FortiAnalyzer Cloud", best_effort=True),
    _e("monitor", "log/fortianalyzer", "logging", "global", ("8",),
       "Estado de conexión con FortiAnalyzer al momento de la extracción", best_effort=True),

    # 17. NTP ---------------------------------------------------------------------------
    _e("cmdb", "system/ntp", "ntp", "global", ("8",),
       "NTP: ntpsync, type (fortiguard/custom), servidores, autenticación, syncinterval, server-mode"),
    _e("monitor", "system/ntp/status", "ntp", "global", ("8",),
       "Estado de sincronización NTP (servidor activo, stratum, offset)", best_effort=True),

    # 18. Backups ---------------------------------------------------------------------
    _e("monitor", "system/config-revision", "backup", "global", ("11",),
       "Revisiones de configuración guardadas en el equipo (fecha, admin, comentario)", best_effort=True),
    _e("cmdb", "system/auto-script", "backup", "global", ("11",),
       "Scripts programados (p.ej. 'execute backup config ftp/sftp ...'): intervalo, repetición "
       "(credenciales de los comandos de backup se redactan)"),
    _e("cmdb", "system/automation-trigger", "backup", "global", ("8", "11"),
       "Automation stitches - triggers (programados, por evento)"),
    _e("cmdb", "system/automation-action", "backup", "global", ("8", "11"),
       "Automation stitches - acciones (cli-script, email, webhook...)"),
    _e("cmdb", "system/automation-stitch", "backup", "global", ("8", "11"),
       "Automation stitches - relación trigger -> acción"),

    # 19. HA ------------------------------------------------------------------------------
    _e("cmdb", "system/ha", "ha", "global", ("11", "12"),
       "HA: mode (standalone/a-p/a-a), group-name/id, priority, override, hbdev, monitor, "
       "session-pickup, ha-mgmt-interfaces (password redactada)"),
    _e("monitor", "system/ha-peer", "ha", "global", ("11", "12"),
       "Miembros del cluster: serial, hostname, prioridad, rol", best_effort=True),
    _e("monitor", "system/ha-checksums", "ha", "global", ("11", "12"),
       "Checksums de configuración por miembro (detecta cluster fuera de sincronía)", best_effort=True),
    _e("monitor", "system/ha-statistics", "ha", "global", ("11", "12"),
       "Estadísticas por miembro (uptime, sesiones, CPU/memoria)", best_effort=True),

    # 20. Certificados ---------------------------------------------------------------------
    _e("cmdb", "certificate/local", "certificates", "vdom", ("12",),
       "Certificados locales: certificado público (PEM), source, range, enroll-protocol, "
       "auto-regenerate-days. La clave privada NUNCA se guarda"),
    _e("cmdb", "certificate/ca", "certificates", "vdom", ("12",), "CAs (incluye CAs de SSL inspection)"),
    _e("cmdb", "certificate/remote", "certificates", "vdom", ("12",), "Certificados remotos (públicos)"),
    _e("cmdb", "certificate/crl", "certificates", "vdom", ("12",), "CRLs"),
    _e("cmdb", "vpn.certificate/setting", "certificates", "vdom", ("12",),
       "Verificación de certificados: OCSP, CRL, strict, cn-match, algoritmos"),
    _e("monitor", "system/available-certificates", "certificates", "global", ("12",),
       "Inventario de certificados con emisor, validez y fecha de expiración",
       params=(("scope", "global"),), best_effort=True),
]

ENTITY_BY_KEY = {e.key: e for e in ENTITIES}
SECTIONS = sorted({e.section for e in ENTITIES})
STATUS_ENTITY = ENTITY_BY_KEY["monitor/system/status"]
VDOM_ENTITY = ENTITY_BY_KEY["cmdb/system/vdom"]
GLOBAL_SETTINGS_ENTITY = ENTITY_BY_KEY["cmdb/system/global"]


# --------------------------------------------------------------------------- #
# Mapa de cobertura de los datos exigidos -> de dónde salen.
# Se escribe en el manifest para que quede trazado qué NO entrega la API.
# "api/ruta:campo" = fuente; NOT_AVAILABLE = la REST API no lo expone.
# --------------------------------------------------------------------------- #
FIELD_SOURCES: dict[str, dict[str, object]] = {
    "firewall": {
        "hostname": "monitor/system/status:results.hostname (también cmdb/system/global:hostname)",
        "model": "monitor/system/status:results.model / model_name / model_number",
        "serial": "Sobre de cualquier respuesta: 'serial'",
        "fortios_version": "Sobre de cualquier respuesta: 'version' (p.ej. v7.4.4)",
        "firmware_build": "Sobre de cualquier respuesta: 'build' / monitor/system/firmware",
        "datetime": "Cabecera HTTP 'Date' de la respuesta del firewall",
        "timezone": "cmdb/system/global:timezone",
    },
    "administrators": {
        "username": "cmdb/system/admin:name / cmdb/system/api-user:name",
        "role_profile": "cmdb/system/admin:accprofile",
        "permissions": "cmdb/system/accprofile:* (sysgrp, netgrp, fwgrp, loggrp, vpngrp, utmgrp, authgrp...)",
        "mfa": "cmdb/system/admin:two-factor (disable/fortitoken/email/sms) + fortitoken",
        "remote_auth": "cmdb/system/admin:remote-auth / wildcard / remote-group",
        "status": "cmdb/system/admin (no hay campo de estado: un admin existe o no) / "
                  "monitor/system/current-admins (sesiones activas)",
        "last_login": NOT_AVAILABLE + " (sólo en logs de eventos; no está en cmdb)",
    },
    "administration": {
        "https_ssh_snmp_per_interface": "cmdb/system/interface:allowaccess",
        "ports": "cmdb/system/global:admin-sport, admin-port, admin-ssh-port, admin-telnet-port",
        "admin_tls": "cmdb/system/global:admin-https-ssl-versions / strong-crypto",
        "trusted_hosts": "cmdb/system/admin:trusthost1..10, ip6-trusthost1..10 / "
                         "cmdb/system/api-user:trusthost",
        "local_in_restrictions": "cmdb/firewall/local-in-policy:*",
        "snmp": "cmdb/system.snmp/sysinfo / community / user",
    },
    "network": {
        "interfaces": "cmdb/system/interface:name, ip (ip + máscara), vdom, type, status, role",
        "vlans": "cmdb/system/interface:type=vlan, vlanid, interface (padre)",
        "zones": "cmdb/system/zone:* (+ cmdb/system/interface:role)",
        "link_status": "monitor/system/interface:link",
    },
    "routing": {
        "static_routes": "cmdb/router/static:dst, gateway, device, distance, status",
        "active_routes": "monitor/router/ipv4",
    },
    "objects": {
        "addresses": "cmdb/firewall/address:* / address6", "address_groups": "cmdb/firewall/addrgrp:* / addrgrp6",
        "fqdn": "cmdb/firewall/address:type=fqdn / cmdb/firewall.wildcard-fqdn/*",
        "services": "cmdb/firewall.service/custom", "service_groups": "cmdb/firewall.service/group",
    },
    "firewall_policies": {
        "id": "cmdb/firewall/policy:policyid",
        "order": "Orden de la respuesta de cmdb/firewall/policy (orden de evaluación)",
        "fields": "cmdb/firewall/policy:* (name, srcintf, dstintf, srcaddr, dstaddr, service, action, "
                  "nat, ippool, poolname, logtraffic, utm-status, ips-sensor, webfilter-profile, "
                  "application-list, ssl-ssh-profile, av-profile)",
        "hit_count_last_used": "monitor/firewall/policy",
    },
    "nat": {
        "dnat_vip": "cmdb/firewall/vip:extip (pública), mappedip (interna), extport, mappedport, portforward",
        "snat": "cmdb/firewall/policy:nat + ippool/poolname / cmdb/firewall/ippool / "
                "cmdb/firewall/central-snat-map (si central-nat)",
    },
    "vpn": {
        "ipsec": "cmdb/vpn.ipsec/phase1-interface + phase2-interface (+ phase1/phase2 policy-based)",
        "ssl_vpn": "cmdb/vpn.ssl/settings + cmdb/vpn.ssl.web/portal",
        "users_groups": "cmdb/vpn.ssl/settings:authentication-rule / cmdb/user/group / cmdb/user/local / "
                        "cmdb/vpn.ipsec/phase1-interface:authusrgrp",
        "allowed_networks": "cmdb/vpn.ssl.web/portal:split-tunneling-routing-address / "
                            "cmdb/firewall/policy (srcintf=ssl.<vdom> o túnel IPsec) / phase2 selectores",
        "tunnel_runtime_status": "monitor/vpn/ipsec / monitor/vpn/ssl",
    },
    "ips": {"profiles": "cmdb/ips/sensor", "policies": "cmdb/firewall/policy:ips-sensor (+ utm-status)"},
    "web_filter": {
        "profiles_categories": "cmdb/webfilter/profile:ftgd-wf",
        "exceptions": "cmdb/webfilter/urlfilter (action=exempt/allow) / ftgd-local-rating / override",
        "policies": "cmdb/firewall/policy:webfilter-profile",
    },
    "application_control": {"profiles": "cmdb/application/list",
                            "policies": "cmdb/firewall/policy:application-list"},
    "ssl_inspection": {"profiles": "cmdb/firewall/ssl-ssh-profile",
                       "policies": "cmdb/firewall/policy:ssl-ssh-profile",
                       "exceptions": "cmdb/firewall/ssl-ssh-profile:ssl-exempt"},
    "logging": {
        "local": "cmdb/log.disk/setting / log.memory/setting / log/setting / log/eventfilter",
        "fortianalyzer": "cmdb/log.fortianalyzer{,2,3,-cloud}/setting (+ monitor/log/fortianalyzer)",
        "fortimanager": "cmdb/system/central-management",
        "syslog_siem": "cmdb/log.syslogd{,2,3,4}/setting + filter",
        "per_policy_logging": "cmdb/firewall/policy:logtraffic",
    },
    "ntp": {"servers": "cmdb/system/ntp:ntpserver / type", "sync_status": "monitor/system/ntp/status"},
    "backup": {
        "on_device_revisions": "monitor/system/config-revision / cmdb/system/global:revision-backup-on-logout",
        "scheduled_backup": "cmdb/system/auto-script (execute backup ...) / system/automation-* ",
        "fortimanager_revisions": "cmdb/system/central-management (FortiManager guarda revisiones)",
        "last_external_backup": NOT_AVAILABLE + " (FortiOS no registra backups externos en la API; "
                                "validar en FortiManager/servidor destino)",
    },
    "ha": {"config": "cmdb/system/ha", "members_and_roles": "monitor/system/ha-peer",
           "sync": "monitor/system/ha-checksums", "statistics": "monitor/system/ha-statistics"},
    "certificates": {"inventory": "cmdb/certificate/local, ca, remote, crl",
                     "expiration": "monitor/system/available-certificates / se parsea del PEM público "
                                   "guardado (normalizer)",
                     "usage": "cmdb/system/global:admin-server-cert / vpn.ssl/settings:servercert / "
                              "firewall/ssl-ssh-profile:server-cert / vpn.ipsec/phase1-interface:certificate"},
    "exceptions": {
        "web_filter": "cmdb/webfilter/urlfilter (exempt) / webfilter/ftgd-local-rating / webfilter/override",
        "ssl_inspection": "cmdb/firewall/ssl-ssh-profile:ssl-exempt",
        "ips": "cmdb/ips/sensor:entries.exempt-ip",
        "antivirus": "cmdb/antivirus/exempt-list",
        "policies_without_inspection": "cmdb/firewall/policy (utm-status=disable / sin perfiles)",
        "trusted_sources": "cmdb/system/admin:trusthost* / system/api-user:trusthost / firewall/local-in-policy",
        "dos_bypass": "cmdb/firewall/DoS-policy",
    },
}

# Prefijos de endpoints que existen pero el collector NUNCA consulta, aunque sean GET:
# descargan la configuración completa con secretos/llaves, o no son configuración.
FORBIDDEN_PREFIXES = (
    "monitor/system/config/backup",        # backup completo (secretos y llaves privadas)
    "monitor/system/config/restore",
    "monitor/system/config-revision/file",  # contenido de una revisión = config completa
    "monitor/system/config-script",
    "monitor/system/debug",
    "monitor/system/com-log",
    "monitor/system/vmlicense",
    "monitor/system/sniffer",
    "monitor/system/crash-log",
    "monitor/license/database",
    "monitor/system/certificate/download",
)
