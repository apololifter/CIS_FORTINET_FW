# Endpoints utilizados

La FortiOS REST API expone dos familias de endpoints, y el collector usa **sólo `GET`** en ambas:

```
GET https://<firewall>:<puerto>/api/v2/cmdb/<ruta>?vdom=<vdom>      # configuración
GET https://<firewall>:<puerto>/api/v2/monitor/<ruta>?vdom=<vdom>   # estado en ejecución
Authorization: Bearer <API key del REST API admin>
```

Cada fila es un endpoint (un archivo RAW). Los de alcance **vdom** se consultan una vez por cada VDOM auditado y se guardan en `<sección>/<vdom>/`; los **global**, una sola vez en `<sección>/`.

- **CLI equivalente**: toda ruta `cmdb` es la misma ruta de la CLI (`vpn.ipsec/phase1-interface` = `config vpn ipsec phase1-interface`), útil para validar evidencia en consola.
- **Referencia oficial**: FortiOS REST API Reference en Fortinet Developer Network (https://fndn.fortinet.net, requiere cuenta) y CLI Reference pública (https://docs.fortinet.com/product/fortigate).
- **best-effort**: el endpoint no existe en todas las versiones/modelos. Si responde 404/405 queda como `NOT_SUPPORTED`, no como error.
- **Paginación**: los endpoints `cmdb` se piden con `start`/`count` (por defecto 1000 por página) y se unen; si el equipo ignora la paginación se detecta y se conserva una sola copia.

## firewall

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `monitor/system/status` | global | 4, 12 | Hostname, modelo (model, model_name, model_number); serial, versión FortiOS y build vienen en el sobre de toda respuesta | — |
| `cmdb/system/global` | global | 4, 5, 8 | Hostname, timezone, puertos admin (admin-sport/admin-ssh-port/admin-telnet-port), admin-https-redirect, admintimeout, admin-lockout-threshold/duration, strong-crypto, admin-https-ssl-versions, pre/post-login-banner, vdom-mode, revision-backup-on-logout | `config system global` |
| `monitor/system/firmware` | global | 4, 12 | Firmware en ejecución y versiones disponibles en FortiGuard | — |
| `monitor/license/status` | global | 12, 13 | Estado de licencias/contratos FortiGuard (IPS, AV, Web Filter, App Control) | — |
| `cmdb/system/vdom` | global | 12 | VDOMs definidos (se usa también para descubrir qué VDOMs auditar) | `config system vdom` |
| `cmdb/system/settings` | vdom | 4, 12, 13 | Por VDOM: opmode (NAT/transparente), ngfw-mode (profile/policy), central-nat, inspection-mode, gui features | `config system settings` |
| `cmdb/system/fortiguard` | global | 12, 13 | Actualización FortiGuard: servidores, frecuencia de actualización (7.2+), puerto, protocolo | `config system fortiguard` |
| `cmdb/system.autoupdate/schedule` *(best-effort)* | global | 12, 13 | Frecuencia de actualización de firmas (FortiOS <= 7.0; en 7.2+ está en system/fortiguard) | `config system autoupdate schedule` |

## administrators

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/system/admin` | global | 5, 6 | Administradores: nombre, accprofile (rol), vdom, trusthost1..10/ip6-trusthost, two-factor, fortitoken, remote-auth/wildcard/remote-group, guest-auth | `config system admin` |
| `cmdb/system/accprofile` | global | 5, 6 | Perfiles de administración (roles): permisos por área (sysgrp, netgrp, fwgrp, loggrp, vpngrp, utmgrp, authgrp...), scope global/vdom | `config system accprofile` |
| `cmdb/system/api-user` | global | 5, 6 | Administradores REST API: accprofile, vdom, trusthost, cors, peer-auth (la API key se redacta) | `config system api-user` |
| `cmdb/system/password-policy` | global | 5 | Política de contraseñas de administradores (largo, complejidad, expiración, reuse) | `config system password-policy` |
| `monitor/system/current-admins` *(best-effort)* | global | 5, 8 | Sesiones de administración activas al momento de la extracción | — |

## administration

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/firewall/local-in-policy` | vdom | 4, 12, 13 | Local-in policies: restricción de tráfico hacia el propio FortiGate (gestión, VPN, etc.) | `config firewall local-in-policy` |
| `cmdb/system.snmp/sysinfo` | global | 4, 12 | Agente SNMP: estado, contacto, ubicación | `config system snmp sysinfo` |
| `cmdb/system.snmp/community` | global | 4, 12 | Comunidades SNMP v1/v2c y hosts permitidos (el nombre ES la comunidad: se redacta) | `config system snmp community` |
| `cmdb/system.snmp/user` | global | 4, 12 | Usuarios SNMPv3: nivel de seguridad, protocolos auth/priv, hosts permitidos | `config system snmp user` |
| `cmdb/system/central-management` | global | 4, 8 | Gestión central: FortiManager / FortiCloud (tipo, servidor, include-default-servers) | `config system central-management` |

## users

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/user/local` | vdom | 5, 6 | Usuarios locales: estado, tipo (password/ldap/radius), two-factor, fortitoken | `config user local` |
| `cmdb/user/group` | vdom | 5, 6 | Grupos de usuarios (firewall/SSO), miembros y servidores remotos asociados | `config user group` |
| `cmdb/user/ldap` | vdom | 5, 6 | Servidores LDAP: servidor, puerto, secure (ldaps/starttls), cn, dn, tipo de bind | `config user ldap` |
| `cmdb/user/radius` | vdom | 5, 6 | Servidores RADIUS (secretos redactados) | `config user radius` |
| `cmdb/user/tacacs+` | vdom | 5, 6 | Servidores TACACS+ (claves redactadas) | `config user tacacs+` |
| `cmdb/user/saml` *(best-effort)* | vdom | 5, 6 | Proveedores SAML (SSO / MFA externo) | `config user saml` |
| `cmdb/user/fortitoken` | vdom | 6 | Tokens FortiToken registrados y su estado | `config user fortitoken` |
| `cmdb/user/setting` | vdom | 5, 6 | Parámetros de autenticación: timeout, lockout, puertos de auth, cert de auth | `config user setting` |

## network

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/system/interface` | global | 4, 12 | Interfaces: IP/máscara, vdom, tipo, vlanid + interface padre (VLAN), status, role, allowaccess (HTTPS/SSH/SNMP/PING/HTTP/TELNET/FGFM), alias | `config system interface` |
| `monitor/system/interface` *(best-effort)* | vdom | 12 | Estado en tiempo real de interfaces (link up/down, velocidad, contadores) | — |
| `cmdb/system/zone` | vdom | 4, 12 | Zonas, interfaces miembro, intrazone allow/deny | `config system zone` |
| `cmdb/system/dns` | global | 4, 12 | Servidores DNS del firewall, protocolo (DoT/DoH) | `config system dns` |
| `cmdb/system/sdwan` *(best-effort)* | vdom | 12 | SD-WAN: miembros, health-checks, reglas | `config system sdwan` |

## routing

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/router/static` | vdom | 12 | Rutas estáticas IPv4: destino, gateway, interfaz, distancia, estado, blackhole | `config router static` |
| `cmdb/router/static6` | vdom | 12 | Rutas estáticas IPv6 | `config router static6` |
| `cmdb/router/policy` | vdom | 12 | Policy routes (PBR) | `config router policy` |
| `cmdb/router/bgp` | vdom | 12 | BGP: AS, vecinos, redes (passwords redactadas) | `config router bgp` |
| `cmdb/router/ospf` | vdom | 12 | OSPF: áreas, interfaces, autenticación | `config router ospf` |
| `monitor/router/ipv4` *(best-effort)* | vdom | 12 | Tabla de ruteo activa (rutas instaladas, gateways, interfaces) | — |

## objects

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/firewall/address` | vdom | 12, 13 | Address objects IPv4: subnet, iprange, fqdn, geography, wildcard, dynamic | `config firewall address` |
| `cmdb/firewall/address6` | vdom | 12, 13 | Address objects IPv6 | `config firewall address6` |
| `cmdb/firewall/addrgrp` | vdom | 12, 13 | Address groups IPv4 (incl. exclude) | `config firewall addrgrp` |
| `cmdb/firewall/addrgrp6` | vdom | 12, 13 | Address groups IPv6 | `config firewall addrgrp6` |
| `cmdb/firewall.wildcard-fqdn/custom` | vdom | 12, 13 | Wildcard FQDN | `config firewall wildcard-fqdn custom` |
| `cmdb/firewall.wildcard-fqdn/group` | vdom | 12, 13 | Grupos wildcard FQDN | `config firewall wildcard-fqdn group` |
| `cmdb/firewall.service/custom` | vdom | 4, 12 | Servicios: protocolo, puertos TCP/UDP/SCTP, ICMP, categoría | `config firewall service custom` |
| `cmdb/firewall.service/group` | vdom | 4, 12 | Grupos de servicios | `config firewall service group` |
| `cmdb/firewall.schedule/recurring` | vdom | 4, 13 | Schedules recurrentes | `config firewall schedule recurring` |
| `cmdb/firewall.schedule/onetime` | vdom | 4, 13 | Schedules únicos (reglas temporales, fecha de expiración) | `config firewall schedule onetime` |
| `cmdb/firewall.schedule/group` | vdom | 4, 13 | Grupos de schedules | `config firewall schedule group` |

## firewall_policies

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/firewall/policy` | vdom | 4, 8, 12, 13 | Políticas: policyid, name, status, srcintf/dstintf, srcaddr/dstaddr (+negate), service, action, schedule, nat/ippool/poolname, logtraffic/logtraffic-start, utm-status, av-profile, ips-sensor, webfilter-profile, application-list, ssl-ssh-profile, dnsfilter-profile, users/groups, comments; el orden de la respuesta = orden de evaluación | `config firewall policy` |
| `monitor/firewall/policy` *(best-effort)* | vdom | 13 | Contadores por política: hits, bytes, sesiones, último uso (detectar reglas sin uso) | — |
| `cmdb/firewall/security-policy` *(best-effort)* | vdom | 4, 12, 13 | Security policies (ngfw-mode policy-based) | `config firewall security-policy` |
| `cmdb/firewall/proxy-policy` | vdom | 4, 12, 13 | Políticas de proxy explícito / transparente | `config firewall proxy-policy` |
| `cmdb/firewall/DoS-policy` | vdom | 13 | Políticas DoS (anomalías, umbrales, acción) | `config firewall DoS-policy` |
| `cmdb/firewall/policy6` *(best-effort)* | vdom | 4, 12, 13 | Políticas IPv6 separadas (sólo FortiOS 6.x; en 7.x están unificadas en firewall/policy) | `config firewall policy6` |

## nat

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/firewall/vip` | vdom | 4, 12 | VIP/DNAT: extip (IP pública), mappedip (IP interna), extintf, portforward, protocol, extport/mappedport, src-filter, type (static-nat/load-balance/server-load-balance) | `config firewall vip` |
| `cmdb/firewall/vip6` | vdom | 4, 12 | VIP IPv6 | `config firewall vip6` |
| `cmdb/firewall/vipgrp` | vdom | 4, 12 | Grupos de VIP | `config firewall vipgrp` |
| `cmdb/firewall/ippool` | vdom | 4, 12 | IP pools (SNAT): tipo (overload/one-to-one/fixed-port-range), startip/endip | `config firewall ippool` |
| `cmdb/firewall/central-snat-map` | vdom | 4, 12 | Central SNAT (si system/settings central-nat=enable) | `config firewall central-snat-map` |

## vpn

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/vpn.ipsec/phase1-interface` | vdom | 6, 12 | IPsec fase 1 (route-based): remote-gw, ike-version, proposal, dhgrp, authmethod, peertype/peer, mode-cfg, xauth/authusrgrp, dpd (PSK redactada) | `config vpn ipsec phase1-interface` |
| `cmdb/vpn.ipsec/phase2-interface` | vdom | 6, 12 | IPsec fase 2: src/dst subnet o selectores, proposal, pfs, dhgrp, keylife | `config vpn ipsec phase2-interface` |
| `cmdb/vpn.ipsec/phase1` | vdom | 6, 12 | IPsec fase 1 (policy-based) | `config vpn ipsec phase1` |
| `cmdb/vpn.ipsec/phase2` | vdom | 6, 12 | IPsec fase 2 (policy-based) | `config vpn ipsec phase2` |
| `cmdb/vpn.ssl/settings` *(best-effort)* | vdom | 6, 12 | SSL-VPN: estado, puerto, servercert, source-interface/source-address, tunnel-ip-pools, authentication-rule (grupos -> portal), ssl-min-proto-ver, reqclientcert, idle-timeout | `config vpn ssl settings` |
| `cmdb/vpn.ssl.web/portal` *(best-effort)* | vdom | 6, 12 | Portales SSL-VPN: tunnel-mode, split-tunneling + redes permitidas, web-mode, ip-pools | `config vpn ssl web portal` |
| `monitor/vpn/ipsec` *(best-effort)* | vdom | 12 | Estado en vivo de túneles IPsec (up/down, bytes, selectores) | — |
| `monitor/vpn/ssl` *(best-effort)* | vdom | 6, 12 | Usuarios SSL-VPN conectados al momento de la extracción | — |

## ips

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/ips/sensor` | vdom | 13 | Sensores IPS: entries (severidad, OS, acción, status), exempt-ip, block-malicious-url | `config ips sensor` |
| `cmdb/ips/global` | global | 13 | Configuración IPS global: fail-open, database, traffic-submit, engine | `config ips global` |
| `cmdb/ips/settings` | vdom | 13 | Opciones IPS por VDOM (packet-log, etc.) | `config ips settings` |

## web_filter

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/webfilter/profile` | vdom | 13 | Perfiles Web Filter: ftgd-wf (categorías y acción), web (urlfilter-table, safe-search), override, options, log | `config webfilter profile` |
| `cmdb/webfilter/urlfilter` | vdom | 13 | Static URL filter: entries con action exempt/allow/block/monitor (EXCEPCIONES) | `config webfilter urlfilter` |
| `cmdb/webfilter/ftgd-local-cat` | vdom | 13 | Categorías locales | `config webfilter ftgd-local-cat` |
| `cmdb/webfilter/ftgd-local-rating` | vdom | 13 | Re-categorización local de URLs (puede usarse como excepción) | `config webfilter ftgd-local-rating` |
| `cmdb/webfilter/override` *(best-effort)* | vdom | 13 | Overrides administrativos de Web Filter (excepciones por usuario/IP) | `config webfilter override` |
| `cmdb/dnsfilter/profile` | vdom | 13 | Perfiles DNS Filter: categorías, domain-filter, block-botnet | `config dnsfilter profile` |

## application_control

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/application/list` | vdom | 13 | Sensores Application Control: entries (category/application/acción), unknown-application-action, deep-app-inspection | `config application list` |
| `cmdb/application/group` | vdom | 13 | Grupos de aplicaciones | `config application group` |

## ssl_inspection

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/firewall/ssl-ssh-profile` | vdom | 13 | Perfiles SSL/SSH: deep vs certificate-inspection por protocolo, ssl-exempt (EXCEPCIONES: categorías, addresses, wildcard-fqdn), server-cert, untrusted/expired actions, min-allowed-ssl-version | `config firewall ssl-ssh-profile` |

## security_profiles

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/antivirus/profile` | vdom | 13 | Perfiles Antivirus por protocolo, outbreak-prevention, ems-threat-feed | `config antivirus profile` |
| `cmdb/antivirus/settings` | vdom | 13 | Configuración AV | `config antivirus settings` |
| `cmdb/antivirus/exempt-list` *(best-effort)* | vdom | 13 | Exclusiones de antivirus (hash/archivo) | `config antivirus exempt-list` |

## logging

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/log/setting` | vdom | 8 | Logging por VDOM: fwpolicy-implicit-log, local-in-allow/deny-*, resolve-ip, brief-traffic-format | `config log setting` |
| `cmdb/log/eventfilter` | vdom | 8 | Tipos de eventos registrados (system, vpn, user, router, wireless, ...) | `config log eventfilter` |
| `cmdb/log.disk/setting` | global | 8 | Log en disco local: estado, retención, rotación | `config log disk setting` |
| `cmdb/log.memory/setting` | global | 8 | Log en memoria | `config log memory setting` |
| `cmdb/log.fortianalyzer/setting` | global | 8 | FortiAnalyzer #1: estado, servidor, enc-algorithm, upload-option, reliable, serial | `config log fortianalyzer setting` |
| `cmdb/log.fortianalyzer2/setting` | global | 8 | FortiAnalyzer #2 | `config log fortianalyzer2 setting` |
| `cmdb/log.fortianalyzer3/setting` | global | 8 | FortiAnalyzer #3 | `config log fortianalyzer3 setting` |
| `cmdb/log.fortianalyzer-cloud/setting` *(best-effort)* | global | 8 | FortiAnalyzer Cloud | `config log fortianalyzer-cloud setting` |
| `cmdb/log.fortianalyzer/filter` | global | 8 | Filtro de logs enviados a FortiAnalyzer (severidad, tipos) | `config log fortianalyzer filter` |
| `cmdb/log.syslogd/setting` | global | 8 | Syslog/SIEM #1: estado, servidor, puerto, mode (udp/reliable/legacy-reliable), enc-algorithm, format | `config log syslogd setting` |
| `cmdb/log.syslogd2/setting` | global | 8 | Syslog/SIEM #2 | `config log syslogd2 setting` |
| `cmdb/log.syslogd3/setting` | global | 8 | Syslog/SIEM #3 | `config log syslogd3 setting` |
| `cmdb/log.syslogd4/setting` | global | 8 | Syslog/SIEM #4 | `config log syslogd4 setting` |
| `cmdb/log.syslogd/filter` | global | 8 | Filtro de logs enviados a syslog #1 | `config log syslogd filter` |
| `cmdb/log.fortiguard/setting` *(best-effort)* | global | 8 | Envío de logs a FortiGuard Cloud / FortiAnalyzer Cloud | `config log fortiguard setting` |
| `monitor/log/fortianalyzer` *(best-effort)* | global | 8 | Estado de conexión con FortiAnalyzer al momento de la extracción | — |

## ntp

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/system/ntp` | global | 8 | NTP: ntpsync, type (fortiguard/custom), servidores, autenticación, syncinterval, server-mode | `config system ntp` |
| `monitor/system/ntp/status` *(best-effort)* | global | 8 | Estado de sincronización NTP (servidor activo, stratum, offset) | — |

## backup

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `monitor/system/config-revision` *(best-effort)* | global | 11 | Revisiones de configuración guardadas en el equipo (fecha, admin, comentario) | — |
| `cmdb/system/auto-script` | global | 11 | Scripts programados (p.ej. 'execute backup config ftp/sftp ...'): intervalo, repetición (credenciales de los comandos de backup se redactan) | `config system auto-script` |
| `cmdb/system/automation-trigger` | global | 8, 11 | Automation stitches - triggers (programados, por evento) | `config system automation-trigger` |
| `cmdb/system/automation-action` | global | 8, 11 | Automation stitches - acciones (cli-script, email, webhook...) | `config system automation-action` |
| `cmdb/system/automation-stitch` | global | 8, 11 | Automation stitches - relación trigger -> acción | `config system automation-stitch` |

## ha

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/system/ha` | global | 11, 12 | HA: mode (standalone/a-p/a-a), group-name/id, priority, override, hbdev, monitor, session-pickup, ha-mgmt-interfaces (password redactada) | `config system ha` |
| `monitor/system/ha-peer` *(best-effort)* | global | 11, 12 | Miembros del cluster: serial, hostname, prioridad, rol | — |
| `monitor/system/ha-checksums` *(best-effort)* | global | 11, 12 | Checksums de configuración por miembro (detecta cluster fuera de sincronía) | — |
| `monitor/system/ha-statistics` *(best-effort)* | global | 11, 12 | Estadísticas por miembro (uptime, sesiones, CPU/memoria) | — |

## certificates

| Endpoint | Alcance | CIS | Qué obtiene | CLI equivalente |
|---|---|---|---|---|
| `cmdb/certificate/local` | vdom | 12 | Certificados locales: certificado público (PEM), source, range, enroll-protocol, auto-regenerate-days. La clave privada NUNCA se guarda | `config certificate local` |
| `cmdb/certificate/ca` | vdom | 12 | CAs (incluye CAs de SSL inspection) | `config certificate ca` |
| `cmdb/certificate/remote` | vdom | 12 | Certificados remotos (públicos) | `config certificate remote` |
| `cmdb/certificate/crl` | vdom | 12 | CRLs | `config certificate crl` |
| `cmdb/vpn.certificate/setting` | vdom | 12 | Verificación de certificados: OCSP, CRL, strict, cn-match, algoritmos | `config vpn certificate setting` |
| `monitor/system/available-certificates` *(best-effort)* | global | 12 | Inventario de certificados con emisor, validez y fecha de expiración | — |

## Datos que la REST API no entrega

| Bloque | Dato | Detalle / alternativa |
|---|---|---|
| administrators | last_login | NOT_AVAILABLE (sólo en logs de eventos; no está en cmdb) |
| backup | last_external_backup | NOT_AVAILABLE (FortiOS no registra backups externos en la API; validar en FortiManager/servidor destino) |

## Endpoints que el collector se niega a consultar

Aunque son `GET`, el cliente los bloquea (lanzan `ReadOnlyViolation`) porque descargan la configuración completa con secretos y llaves, o no son configuración:

- `monitor/system/config/backup`
- `monitor/system/config/restore`
- `monitor/system/config-revision/file`
- `monitor/system/config-script`
- `monitor/system/debug`
- `monitor/system/com-log`
- `monitor/system/vmlicense`
- `monitor/system/sniffer`
- `monitor/system/crash-log`
- `monitor/license/database`
- `monitor/system/certificate/download`
