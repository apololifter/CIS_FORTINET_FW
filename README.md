# CIS_FORTINET_FW — Collector de auditoría CIS para FortiGate (FortiOS)

Extrae, **en modo solo lectura**, la configuración de un FortiGate mediante la REST API
oficial de FortiOS y la guarda en RAW (JSON) para evaluarla después contra CIS Controls
4, 5, 6, 8, 11, 12 y 13.

> Esta fase **no** evalúa CIS, no calcula puntajes, no emite PASS/FAIL ni conclusiones y
> **no modifica** el firewall. Sólo envía peticiones `GET`.

```
FortiOS REST API → Collector → RAW JSON   ← implementado (esta fase)
                                  ↓
                             Normalizer → Security Data Model → CIS Checks → Evidence → Report   ← fases siguientes
```

Misma arquitectura que [CIS_SOPHOS_FW](https://github.com/apololifter/CIS_SOPHOS_FW): sólo cambia
la fuente de extracción y los objetos específicos de Fortinet. El formato RAW (sobre `meta` +
`response`, `manifest.json`, `schema_version: 1.0`) es el mismo contrato entre fases.

---

## Autenticación: aquí SÍ hay API Key

A diferencia de la XML API de Sophos, FortiOS tiene **API Key real**: un *REST API admin*
(`config system api-user`) con un token que se envía en la cabecera
`Authorization: Bearer <token>`. El collector **nunca** la pone en la URL (`?access_token=`),
porque quedaría en logs de proxies y del propio FortiGate.

### Preparar el FortiGate (una sola vez)

1. **Perfil de administración de solo lectura** (*System → Admin Profiles*). Con VDOMs,
   el perfil debe ser de alcance global para poder leer objetos globales y todos los VDOMs:

   ```
   config system accprofile
       edit "ro_audit"
           set scope global
           set secfabgrp read
           set ftviewgrp read
           set authgrp read
           set sysgrp read
           set netgrp read
           set loggrp read
           set fwgrp read
           set vpngrp read
           set utmgrp read
           set wanoptgrp read
           set wifi read
       next
   end
   ```

2. **REST API admin dedicado**, restringido a la IP del equipo auditor (*System →
   Administrators → Create New → REST API Admin*). No uses `admin`.

   ```
   config system api-user
       edit "api_audit"
           set accprofile "ro_audit"
           set vdom "root"            # con VDOMs: agrega todos los que se auditarán
           config trusthost
               edit 1
                   set ipv4-trusthost 192.0.2.10 255.255.255.255
               next
           end
       next
   end
   execute api-user generate-key api_audit
   ```

   El token se muestra **una sola vez**: cópialo directo a `.env` o úsalo con
   `--prompt-api-key`.

3. **HTTPS de administración** habilitado en la interfaz por la que llega el auditor
   (`set allowaccess https` en `config system interface`). El puerto es `admin-sport`
   (`config system global`), por defecto 443.

4. **MFA:** el REST API admin no usa MFA; la protección compensatoria es token +
   trusthost (una IP /32) + perfil read-only. Documenta esa excepción en el informe.

> El perfil read-only es la garantía real. El collector además se bloquea a sí mismo:
> sólo puede hacer `GET` y rechaza endpoints peligrosos (ver *Seguridad del collector*).

---

## Estructura

```
CIS_FORTINET_FW/
├── src/
│   ├── collector.py               # CLI / orquestación (punto de entrada)
│   └── fortinet_audit/
│       ├── catalog.py             # endpoints + mapa dato→fuente (datos, no lógica)
│       ├── client.py              # cliente REST API de SOLO LECTURA (GET + Bearer)
│       ├── storage.py             # escritura RAW + manifest + PEM públicos
│       ├── redact.py              # redacción de secretos
│       ├── config.py              # config.yaml + variables de entorno
│       └── logging_setup.py
├── config/config.example.yaml
├── data/raw/                      # salida RAW (gitignored)
├── data/normalized/               # para normalizer.py (fase 2)
├── logs/                          # logs por ejecución (gitignored)
├── reports/                       # fase futura
├── tests/                         # pytest + FortiGate simulado
├── docs/
│   ├── ENDPOINTS.md               # endpoints consultados y qué obtiene cada uno
│   └── examples/                  # ejemplo de salida RAW (datos ficticios)
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Instalación (Windows / PowerShell)

```
cd C:\Proyectos\CIS_FORTINET_FW
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Requiere Python 3.10 o superior.

## Configuración

```
Copy-Item config\config.example.yaml config\config.yaml
Copy-Item .env.example .env
notepad .env          # completa FORTI_FW_HOST / FORTI_FW_API_KEY
notepad config\config.yaml
```

| Variable              | Uso                                                        |
|-----------------------|------------------------------------------------------------|
| `FORTI_FW_HOST`       | IP/FQDN de administración                                  |
| `FORTI_FW_PORT`       | Puerto HTTPS de admin (`admin-sport`, por defecto 443)     |
| `FORTI_FW_API_KEY`    | Token del REST API admin (sólo env / `.env` / `--prompt-api-key`) |
| `FORTI_FW_VDOMS`      | VDOMs separados por coma (vacío = autodetectar)            |
| `FORTI_FW_VERIFY_SSL` | `true`, `false` o ruta a un CA `.pem`                      |

Si pones `password`, `api_key`, `secret` o `token` en `config.yaml`, el collector se niega a correr.

> Si el proyecto está en una carpeta sincronizada con la nube (OneDrive, Drive, etc.), `.env`
> y `data/raw` se subirían a la nube aunque estén fuera de Git. En ese caso usa
> `--prompt-api-key` en lugar de `.env` y apunta `output.raw_dir` a una carpeta local fuera
> de la carpeta sincronizada.

### VDOMs

- **Sin VDOMs** (`vdom-mode no-vdom`): todo se lee del VDOM `root`.
- **Multi-VDOM**: con `vdoms: []` el collector lee `cmdb/system/vdom` y audita todos. Los
  objetos globales (admins, interfaces, HA, logging, NTP...) se piden una vez; los de VDOM
  (políticas, objetos, VPN, perfiles...) una vez por VDOM, en `<sección>/<vdom>/`.

### TLS

El FortiGate suele usar el certificado `Fortinet_Factory` (autofirmado). Opciones, de mejor a peor:

1. Exportar el certificado/CA de administración y usar `verify_ssl: "C:/ruta/fgt_ca.pem"`.
2. `--insecure` / `verify_ssl: false` sólo en laboratorio (queda advertido en el log).

---

## Ejecución

```
# Ver qué se va a consultar (no conecta)
python src\collector.py --list-entities

# Validar configuración (no conecta)
python src\collector.py --dry-run

# Extracción completa
python src\collector.py

# Pidiendo la API key en pantalla (sin .env)
python src\collector.py --prompt-api-key

# Sólo algunas secciones / VDOMs
python src\collector.py --sections administrators administration firewall_policies
python src\collector.py --vdoms root DMZ
```

Códigos de salida: `0` todo extraído · `1` parcial (errores en algunos endpoints) · `2` fatal
(config/API key/trusthost/conectividad). Un endpoint que no existe en la versión del equipo
(HTTP 404/405) queda como `NOT_SUPPORTED` y **no** cuenta como error.

### Salida

```
data/raw/<label>_<YYYYMMDDTHHMMSSZ>/
├── manifest.json                          # metadatos, identidad, VDOMs, estado por endpoint, NOT_AVAILABLE
├── firewall/monitor.system.status.json    # global: { "meta": {...}, "response": {...sobre FortiOS...} }
├── firewall/cmdb.system.global.json
├── firewall_policies/root/cmdb.firewall.policy.json      # por VDOM
├── firewall_policies/DMZ/cmdb.firewall.policy.json
├── ...
└── certificates/root/cmdb.certificate.local/<nombre>_<sha8>.pem   # certificados públicos
logs/collector_<run_id>.log
```

Cada JSON RAW incluye en `meta`: endpoint, VDOM, parámetros, CLI equivalente, timestamp UTC
de extracción, duración, HTTP status, fecha del firewall (cabecera `Date`), serial, versión
FortiOS, build, revisión de configuración (`revision` de cmdb), estado
(`OK`/`EMPTY`/`NOT_SUPPORTED`/`ERROR`), error y paginación. `response` es el JSON **completo**
devuelto por FortiOS (con secretos redactados): no se descarta nada.

La identidad del equipo (hostname, modelo, serial, FortiOS/build, hora, timezone, modo VDOM)
queda resumida en `manifest.json → firewall_identity`.

Ejemplos reales de salida (con datos ficticios) en [`docs/examples/`](docs/examples).

---

## Cobertura de la información obligatoria

| Bloque | De dónde sale (detalle en `docs/ENDPOINTS.md`) |
|---|---|
| Firewall | `monitor/system/status` (+ serial/versión/build del sobre), `cmdb/system/global`, `monitor/system/firmware`, cabecera `Date` |
| Administradores | `cmdb/system/admin`, `system/accprofile`, `system/api-user`, `system/password-policy`, `monitor/system/current-admins` |
| Administración | `cmdb/system/interface:allowaccess`, `system/global` (puertos), trusthosts de admin/api-user, `firewall/local-in-policy`, `system.snmp/*` |
| Interfaces | `cmdb/system/interface` (IP/máscara, VLAN, vdom, estado), `system/zone`, `monitor/system/interface` |
| Routing | `cmdb/router/static`, `static6`, `policy`, `bgp`, `ospf`, `monitor/router/ipv4` |
| Objetos | `cmdb/firewall/address(6)`, `addrgrp(6)`, `firewall.wildcard-fqdn/*`, `firewall.service/*`, schedules |
| Firewall Policies | `cmdb/firewall/policy` (policyid, perfiles UTM, NAT, logtraffic), `monitor/firewall/policy` (hits/último uso) |
| NAT/VIP | `cmdb/firewall/vip(6)`, `vipgrp`, `ippool`, `central-snat-map` |
| VPN | `cmdb/vpn.ipsec/*`, `vpn.ssl/settings`, `vpn.ssl.web/portal`, `user/group`, `monitor/vpn/ipsec`, `monitor/vpn/ssl` |
| IPS | `cmdb/ips/sensor`, `ips/global`, `ips/settings` + `firewall/policy:ips-sensor` |
| Web Filter | `cmdb/webfilter/profile`, `urlfilter` (excepciones), `ftgd-local-*`, `override`, `dnsfilter/profile` |
| Application Control | `cmdb/application/list`, `application/group` + `firewall/policy:application-list` |
| SSL Inspection | `cmdb/firewall/ssl-ssh-profile` (incl. `ssl-exempt`) + `firewall/policy:ssl-ssh-profile` |
| Logging | `cmdb/log/setting`, `log.disk`, `log.memory`, `log.fortianalyzer*`, `log.syslogd*`, `system/central-management` (FortiManager) |
| NTP | `cmdb/system/ntp`, `monitor/system/ntp/status` |
| Backups | `monitor/system/config-revision`, `system/auto-script`, `system/automation-*`, `system/global:revision-backup-on-logout` |
| HA | `cmdb/system/ha`, `monitor/system/ha-peer`, `ha-checksums` (sincronía), `ha-statistics` |
| Certificados | `cmdb/certificate/*` (+ PEM públicos en disco), `monitor/system/available-certificates` (expiración) |
| Excepciones | `webfilter/urlfilter` (exempt), `ssl-ssh-profile:ssl-exempt`, `ips/sensor:exempt-ip`, `antivirus/exempt-list`, trusthosts, `local-in-policy`, `DoS-policy` |

Datos que la REST API **no** entrega (quedan como `NOT_AVAILABLE` en el manifest): último login
de administradores (sólo en logs de eventos) y confirmación de backups externos (validar en
FortiManager o en el servidor destino).

---

## Seguridad del collector

- **Solo lectura por construcción:** el cliente sólo tiene `session.get`; no existe código
  para POST/PUT/DELETE. Las rutas se validan con regex (sin `..`, `//`, query strings) y
  contra una lista de endpoints bloqueados aunque sean GET: descarga de backup completo,
  contenido de revisiones de configuración, debug, sniffer, etc.
- **API key:** viaja sólo en la cabecera `Authorization` (nunca en URL ni parámetros), no se
  escribe en RAW y un filtro la elimina de los logs.
- **Secretos en la configuración del firewall:** FortiOS devuelve (cifrados, `ENC ...`)
  passwords de admins y usuarios, PSK de IPsec, secretos RADIUS/TACACS+, bind LDAP, password
  HA, claves NTP/OSPF/BGP, hash de la API key, usuarios SNMPv3 y comunidades SNMP. Por
  defecto se reemplaza el **valor** por `***REDACTED***` conservando el campo (se sabe *si*
  está configurado, no *cuál* es). Una comunidad SNMP `public`/`private` queda marcada como
  `***REDACTED:WEAK_DEFAULT***` porque es un hallazgo en sí. `--no-redact` lo desactiva.
- **Scripts de backup:** en `system/auto-script`, los comandos `execute backup ... ftp/sftp`
  conservan archivo y servidor destino, pero usuario y contraseña se redactan.
- **Certificados:** se guardan los certificados públicos como `.pem` para que el normalizer
  calcule expiración y emisor. Las **llaves privadas nunca se escriben a disco**, ni siquiera
  con `--no-redact`.
- **Errores aislados:** si un endpoint falla (permiso, timeout, versión) se registra en su
  JSON y en el manifest, y la extracción continúa.

---

## Pruebas

```
pytest -q
```

Las pruebas usan un FortiGate simulado (`tests/mock_fortigate.py`) y verifican: que sólo se
usa GET y la API key va únicamente en la cabecera, bloqueo de rutas inválidas y prohibidas,
clasificación OK/EMPTY/RESTRICTED/NOT_SUPPORTED/ERROR, paginación (incluido un equipo que la ignora),
token inválido (401) e IP fuera de trusthost (403), multi-VDOM, redacción de secretos en RAW
y logs, scripts de backup, y que las llaves privadas nunca se guardan.

---

## Endpoints

Ver [`docs/ENDPOINTS.md`](docs/ENDPOINTS.md): 115 endpoints, qué obtiene cada uno, su CLI
equivalente, cuáles son *best-effort* según versión, y la lista de datos que la REST API
**no** entrega.

## Próximas fases (sin tocar el collector)

- `src/normalizer.py`: lee `data/raw/<run_id>/manifest.json` + `catalog.FIELD_SOURCES` y
  escribe `data/normalized/<run_id>.json` (modelo de datos de seguridad, común a Sophos y Fortinet).
- `src/cis_engine.py`: evalúa el modelo normalizado y genera evidencia/reportes.

El contrato entre fases es el formato RAW (`schema_version: 1.0`) y `catalog.py`.
