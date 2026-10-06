"""
FortiGate simulado para pruebas offline. Reemplaza requests.Session y responde a
GET /api/v2/... con JSON con la forma de FortiOS 7.4 (sobre con results, serial,
version, build, vdom, revision). Registra cada llamada para verificar que nunca
hubo POST/PUT/DELETE y que la API key viajó sólo en la cabecera.

Datos ficticios (rangos de documentación RFC 5737, seriales inventados).
"""
from __future__ import annotations

import json
from urllib.parse import unquote, urlparse

import requests

SERIAL = "FGT60FTK00000000"
VERSION = "v7.4.4"
BUILD = 2662
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFAKECERTIFICATEDATA0000\n-----END CERTIFICATE-----\n"
CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIFAKECACERTIFICATEDATA111\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFAKEPRIVATEKEYDATA\n-----END ENCRYPTED PRIVATE KEY-----\n"


def _policies(vdom):
    if vdom != "root":
        return [{"policyid": 10, "name": "DMZ-to-Internet", "uuid": "00000000-0000-0000-0000-000000000010",
                 "status": "enable", "srcintf": [{"name": "vlan10"}], "dstintf": [{"name": "wan1"}],
                 "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}], "service": [{"name": "HTTPS"}],
                 "action": "accept", "schedule": "always", "nat": "enable", "logtraffic": "utm",
                 "utm-status": "disable", "comments": ""}]
    return [
        {"policyid": 1, "name": "LAN-to-Internet", "uuid": "00000000-0000-0000-0000-000000000001",
         "status": "enable", "srcintf": [{"name": "internal"}], "dstintf": [{"name": "wan1"}],
         "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}], "srcaddr-negate": "disable",
         "service": [{"name": "ALL"}], "action": "accept", "schedule": "always", "nat": "enable",
         "ippool": "disable", "poolname": [], "logtraffic": "all", "logtraffic-start": "disable",
         "utm-status": "enable", "inspection-mode": "flow", "av-profile": "default", "ips-sensor": "default",
         "webfilter-profile": "default", "application-list": "default", "dnsfilter-profile": "default",
         "ssl-ssh-profile": "certificate-inspection", "groups": [], "users": [], "comments": ""},
        {"policyid": 2, "name": "Publicar-Web", "uuid": "00000000-0000-0000-0000-000000000002",
         "status": "enable", "srcintf": [{"name": "wan1"}], "dstintf": [{"name": "internal"}],
         "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "VIP-WEB"}], "service": [{"name": "HTTPS"}],
         "action": "accept", "schedule": "always", "nat": "disable", "logtraffic": "all",
         "utm-status": "enable", "ips-sensor": "protect_http_server", "ssl-ssh-profile": "deep-inspection",
         "comments": "Servidor web publicado"},
        {"policyid": 3, "name": "Any-Any-Temp", "uuid": "00000000-0000-0000-0000-000000000003",
         "status": "disable", "srcintf": [{"name": "any"}], "dstintf": [{"name": "any"}],
         "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}],
         "action": "accept", "schedule": "Temp-Proveedor", "nat": "disable", "logtraffic": "disable",
         "utm-status": "disable", "comments": "Temporal soporte proveedor"},
        {"policyid": 4, "name": "SSLVPN-to-LAN", "uuid": "00000000-0000-0000-0000-000000000004",
         "status": "enable", "srcintf": [{"name": "ssl.root"}], "dstintf": [{"name": "internal"}],
         "srcaddr": [{"name": "SSLVPN_TUNNEL_ADDR1"}], "dstaddr": [{"name": "MGMT-Net"}],
         "groups": [{"name": "VPN-Users"}], "service": [{"name": "ALL"}], "action": "accept",
         "schedule": "always", "nat": "disable", "logtraffic": "all", "utm-status": "disable"},
    ]


def _addresses(n):
    base = [
        {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
        {"name": "MGMT-Net", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0", "comment": "Gestión"},
        {"name": "FQDN-updates", "type": "fqdn", "fqdn": "update.example.com"},
        {"name": "Geo-CL", "type": "geography", "country": "CL"},
        {"name": "SSLVPN_TUNNEL_ADDR1", "type": "iprange", "start-ip": "10.212.134.200", "end-ip": "10.212.134.210"},
    ]
    return base + [{"name": f"SRV-{i:03d}", "type": "ipmask", "subnet": f"198.51.100.{i % 250 + 1} 255.255.255.255"}
                   for i in range(1, n + 1)]


SERVICES = [{"name": n, "protocol": p, "tcp-portrange": t, "udp-portrange": u, "category": c}
            for n, p, t, u, c in (
                ("ALL", "IP", "", "", "General"), ("HTTP", "TCP/UDP/SCTP", "80", "", "Web Access"),
                ("HTTPS", "TCP/UDP/SCTP", "443", "", "Web Access"), ("SSH", "TCP/UDP/SCTP", "22", "", "Remote Access"),
                ("TELNET", "TCP/UDP/SCTP", "23", "", "Remote Access"), ("DNS", "TCP/UDP/SCTP", "53", "53", "Network Services"),
                ("RDP", "TCP/UDP/SCTP", "3389", "", "Remote Access"), ("SMB", "TCP/UDP/SCTP", "445", "", "File Access"),
                ("SNMP", "TCP/UDP/SCTP", "161-162", "161-162", "Network Services"),
                ("NTP", "TCP/UDP/SCTP", "123", "123", "Network Services"), ("PING", "ICMP", "", "", "Network Services"),
                ("TCP-8443", "TCP/UDP/SCTP", "8443", "", "Uncategorized"))]

SAMPLES = {
    "monitor/system/status": {"model_name": "FortiGate", "model_number": "60F", "model": "FGT60F",
                              "hostname": "FGT-LAB-01", "log_disk_status": "available"},
    "cmdb/system/global": {"hostname": "FGT-LAB-01", "timezone": "America/Santiago", "admin-sport": 443,
                           "admin-port": 80, "admin-ssh-port": 22, "admin-telnet-port": 23,
                           "admin-https-redirect": "enable", "admintimeout": 15, "admin-lockout-threshold": 3,
                           "admin-lockout-duration": 60, "strong-crypto": "enable",
                           "admin-https-ssl-versions": "tlsv1-2 tlsv1-3", "pre-login-banner": "disable",
                           "post-login-banner": "disable", "vdom-mode": "multi-vdom",
                           "revision-backup-on-logout": "enable", "revision-image-auto-backup": "disable",
                           "admin-server-cert": "Fortinet_Factory", "admin-scp": "disable"},
    "monitor/system/firmware": {"current": {"version": VERSION, "major": 7, "minor": 4, "patch": 4, "build": BUILD,
                                            "platform-id": "FGT60F", "source": "fortinet"},
                                "available": [{"version": "v7.4.8", "major": 7, "minor": 4, "patch": 8,
                                               "build": 2795, "maturity": "M"}]},
    "monitor/license/status": {"ips": {"status": "licensed", "expires": 1798761600},
                               "antivirus": {"status": "licensed", "expires": 1798761600},
                               "web_filtering": {"status": "licensed", "expires": 1798761600},
                               "appctrl": {"status": "licensed", "expires": 1798761600}},
    "cmdb/system/vdom": [{"name": "root", "short-name": "root", "vcluster-id": 0},
                         {"name": "DMZ", "short-name": "DMZ", "vcluster-id": 0}],
    "cmdb/system/settings": {"opmode": "nat", "ngfw-mode": "profile-based", "central-nat": "disable",
                             "inspection-mode": "flow"},
    "cmdb/system/fortiguard": {"protocol": "https", "port": "443", "fortiguard-anycast": "enable",
                               "auto-firmware-upgrade": "disable", "update-server-location": "automatic",
                               "proxy-password": "ENC fgdproxy00"},
    "cmdb/system/admin": [
        {"name": "admin", "accprofile": "super_admin", "vdom": [{"name": "root"}],
         "trusthost1": "0.0.0.0 0.0.0.0", "trusthost2": "0.0.0.0 0.0.0.0", "two-factor": "disable",
         "remote-auth": "disable", "wildcard": "disable", "password": "ENC SH2adminhash0000"},
        {"name": "noc.jperez", "accprofile": "prof_admin", "vdom": [{"name": "root"}],
         "trusthost1": "192.0.2.0 255.255.255.0", "trusthost2": "0.0.0.0 0.0.0.0", "two-factor": "fortitoken",
         "fortitoken": "FTKMOB0000000001", "remote-auth": "disable", "password": "ENC SH2nochash1111"},
        {"name": "ldap-admins", "accprofile": "prof_admin", "vdom": [{"name": "root"}], "remote-auth": "enable",
         "wildcard": "enable", "remote-group": "GRP-FW-ADMINS", "two-factor": "disable",
         "trusthost1": "192.0.2.0 255.255.255.0", "password": ""},
    ],
    "cmdb/system/accprofile": [
        {"name": "super_admin", "scope": "global", **{g: "read-write" for g in (
            "secfabgrp", "ftviewgrp", "authgrp", "sysgrp", "netgrp", "loggrp", "fwgrp", "vpngrp", "utmgrp")}},
        {"name": "ro_audit", "scope": "global", **{g: "read" for g in (
            "secfabgrp", "ftviewgrp", "authgrp", "sysgrp", "netgrp", "loggrp", "fwgrp", "vpngrp", "utmgrp",
            "wanoptgrp", "wifi")}},
    ],
    "cmdb/system/api-user": [{"name": "api_audit", "accprofile": "ro_audit",
                              "vdom": [{"name": "root"}, {"name": "DMZ"}], "api-key": "ENC SH2apikeyhash9999",
                              "trusthost": [{"id": 1, "type": "ipv4-trusthost",
                                             "ipv4-trusthost": "192.0.2.10 255.255.255.255"}],
                              "cors-allow-origin": "", "peer-auth": "disable"}],
    "cmdb/system/password-policy": {"status": "enable", "apply-to": "admin-password", "minimum-length": 12,
                                    "min-lower-case-letter": 1, "min-upper-case-letter": 1,
                                    "min-non-alphanumeric": 1, "min-number": 1, "expire-status": "disable",
                                    "reuse-password": "disable"},
    "monitor/system/current-admins": [{"admin": "api_audit", "from": "192.0.2.10", "profile": "ro_audit",
                                       "method": "https", "login_time": 1791315000}],
    "cmdb/firewall/local-in-policy": [{"policyid": 1, "intf": [{"name": "wan1"}], "srcaddr": [{"name": "all"}],
                                       "dstaddr": [{"name": "all"}], "action": "deny",
                                       "service": [{"name": "SSH"}, {"name": "SNMP"}], "schedule": "always",
                                       "status": "enable"}],
    "cmdb/system.snmp/sysinfo": {"status": "enable", "contact-info": "noc@example.com", "location": "Datacenter LAB"},
    "cmdb/system.snmp/community": [
        {"id": 1, "name": "public", "status": "enable", "query-v1-status": "enable", "query-v2c-status": "enable",
         "hosts": [{"id": 1, "ip": "0.0.0.0 0.0.0.0"}]},
        {"id": 2, "name": "Sup3rC0mmunity", "status": "enable", "query-v1-status": "disable",
         "query-v2c-status": "enable", "hosts": [{"id": 1, "ip": "192.0.2.20 255.255.255.255"}]},
    ],
    "cmdb/system.snmp/user": [{"name": "snmpv3-nms", "status": "enable", "security-level": "auth-priv",
                               "auth-proto": "sha256", "auth-pwd": "ENC snmpauth000", "priv-proto": "aes256",
                               "priv-pwd": "ENC snmppriv000", "notify-hosts": "192.0.2.20"}],
    "cmdb/system/central-management": {"type": "fortimanager", "fmg": "\"192.0.2.40\"", "mode": "normal",
                                       "include-default-servers": "enable", "fmg-update-port": "8890"},
    "cmdb/user/local": [{"name": "jperez", "status": "enable", "type": "password", "passwd": "ENC userpw0001",
                         "two-factor": "fortitoken", "fortitoken": "FTKMOB0000000002"},
                        {"name": "vpn.guest", "status": "enable", "type": "password", "passwd": "ENC userpw0002",
                         "two-factor": "disable"}],
    "cmdb/user/group": [{"name": "VPN-Users", "group-type": "firewall",
                         "member": [{"name": "jperez"}, {"name": "LDAP-CORP"}],
                         "match": [{"id": 1, "server-name": "LDAP-CORP",
                                    "group-name": "CN=VPN,OU=Groups,DC=example,DC=com"}]}],
    "cmdb/user/ldap": [{"name": "LDAP-CORP", "server": "192.0.2.30", "port": 636, "secure": "ldaps",
                        "cnid": "sAMAccountName", "dn": "DC=example,DC=com", "type": "regular",
                        "username": "CN=svc_fw,OU=Svc,DC=example,DC=com", "password": "ENC ldapbindpw"}],
    "cmdb/user/radius": [{"name": "RADIUS-NPS", "server": "192.0.2.31", "secret": "ENC radiussecret",
                          "auth-type": "ms_chap_v2"}],
    "cmdb/user/tacacs+": [],
    "cmdb/user/saml": [],
    "cmdb/user/fortitoken": [{"serial-number": "FTKMOB0000000001", "status": "active"},
                             {"serial-number": "FTKMOB0000000002", "status": "active"}],
    "cmdb/user/setting": {"auth-timeout": 5, "auth-invalid-max": 5, "auth-lockout-threshold": 3,
                          "auth-lockout-duration": 0, "auth-cert": "Fortinet_Factory"},
    "cmdb/system/interface": [
        {"name": "wan1", "vdom": "root", "type": "physical", "status": "up", "role": "wan", "mode": "static",
         "ip": "203.0.113.10 255.255.255.248", "allowaccess": "ping https ssh fgfm", "alias": "Internet"},
        {"name": "internal", "vdom": "root", "type": "hard-switch", "status": "up", "role": "lan",
         "ip": "192.0.2.1 255.255.255.0", "allowaccess": "ping https ssh snmp http", "alias": "LAN"},
        {"name": "vlan10", "vdom": "DMZ", "type": "vlan", "vlanid": 10, "interface": "internal", "status": "up",
         "role": "dmz", "ip": "198.51.100.1 255.255.255.0", "allowaccess": "ping"},
        {"name": "ha", "vdom": "root", "type": "physical", "status": "up", "ip": "0.0.0.0 0.0.0.0", "allowaccess": ""},
        {"name": "ssl.root", "vdom": "root", "type": "tunnel", "status": "up", "ip": "0.0.0.0 0.0.0.0"},
    ],
    "monitor/system/interface": {"wan1": {"name": "wan1", "link": True, "speed": 1000, "duplex": 1},
                                 "internal": {"name": "internal", "link": True, "speed": 1000, "duplex": 1}},
    "cmdb/system/zone": [{"name": "LAN-ZONE", "intrazone": "deny", "interface": [{"interface-name": "internal"}]}],
    "cmdb/system/dns": {"primary": "192.0.2.53", "secondary": "198.51.100.53", "protocol": "cleartext"},
    "cmdb/system/sdwan": {"status": "disable", "members": [], "health-check": [], "service": []},
    "cmdb/router/static": [
        {"seq-num": 1, "status": "enable", "dst": "0.0.0.0 0.0.0.0", "gateway": "203.0.113.9", "device": "wan1",
         "distance": 10, "blackhole": "disable"},
        {"seq-num": 2, "status": "enable", "dst": "198.51.100.0 255.255.255.0", "gateway": "192.0.2.254",
         "device": "internal", "distance": 10, "blackhole": "disable"},
    ],
    "cmdb/router/static6": [], "cmdb/router/policy": [],
    "cmdb/router/bgp": {"as": 0, "router-id": "0.0.0.0", "neighbor": []},
    "cmdb/router/ospf": {"router-id": "0.0.0.0", "area": [], "ospf-interface": []},
    "monitor/router/ipv4": [{"ip_mask": "0.0.0.0/0", "gateway": "203.0.113.9", "interface": "wan1",
                             "type": "static", "distance": 10},
                            {"ip_mask": "192.0.2.0/24", "gateway": "0.0.0.0", "interface": "internal",
                             "type": "connect", "distance": 0}],
    "cmdb/firewall/address6": [], "cmdb/firewall/addrgrp6": [],
    "cmdb/firewall/addrgrp": [{"name": "GRP-SERVERS", "member": [{"name": "SRV-001"}, {"name": "SRV-002"}],
                               "exclude": "disable"}],
    "cmdb/firewall.wildcard-fqdn/custom": [{"name": "wild-example", "wildcard-fqdn": "*.example.com"}],
    "cmdb/firewall.wildcard-fqdn/group": [],
    "cmdb/firewall.service/custom": SERVICES,
    "cmdb/firewall.service/group": [{"name": "Web Access", "member": [{"name": "HTTP"}, {"name": "HTTPS"}]}],
    "cmdb/firewall.schedule/recurring": [{"name": "always",
                                          "day": "sunday monday tuesday wednesday thursday friday saturday"}],
    "cmdb/firewall.schedule/onetime": [{"name": "Temp-Proveedor", "start": "2026/09/01 00:00",
                                        "end": "2026/12/31 23:59", "expiration-days": 3}],
    "cmdb/firewall.schedule/group": [],
    "monitor/firewall/policy": [{"policyid": 1, "hit_count": 152340, "bytes": 98765432100, "active_sessions": 312,
                                 "last_used": 1791315000, "first_used": 1760000000},
                                {"policyid": 2, "hit_count": 8812, "bytes": 1234567, "last_used": 1791314000},
                                {"policyid": 3, "hit_count": 0, "bytes": 0},
                                {"policyid": 4, "hit_count": 45, "bytes": 99887, "last_used": 1791200000}],
    "cmdb/firewall/security-policy": [], "cmdb/firewall/proxy-policy": [],
    "cmdb/firewall/DoS-policy": [{"policyid": 1, "status": "enable", "interface": "wan1",
                                  "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                                  "service": [{"name": "ALL"}],
                                  "anomaly": [{"name": "tcp_syn_flood", "status": "enable", "log": "enable",
                                               "action": "block", "threshold": 2000}]}],
    "cmdb/firewall/vip": [{"name": "VIP-WEB", "type": "static-nat", "extip": "203.0.113.11",
                           "mappedip": [{"range": "192.0.2.80"}], "extintf": "wan1", "portforward": "enable",
                           "protocol": "tcp", "extport": "443", "mappedport": "443", "src-filter": []}],
    "cmdb/firewall/vip6": [], "cmdb/firewall/vipgrp": [],
    "cmdb/firewall/ippool": [{"name": "POOL-WAN", "type": "overload", "startip": "203.0.113.12",
                              "endip": "203.0.113.12"}],
    "cmdb/firewall/central-snat-map": [],
    "cmdb/vpn.ipsec/phase1-interface": [
        {"name": "S2S-Sucursal", "type": "static", "interface": "wan1", "ike-version": "2",
         "remote-gw": "198.51.100.200", "peertype": "any", "authmethod": "psk", "psksecret": "ENC ipsecpsk0001",
         "proposal": "aes256-sha256", "dhgrp": "14 21", "dpd": "on-idle", "mode-cfg": "disable"},
        {"name": "FCT-Dialup", "type": "dynamic", "interface": "wan1", "ike-version": "1", "authmethod": "psk",
         "psksecret": "ENC ipsecpsk0002", "xauthtype": "auto", "authusrgrp": "VPN-Users", "mode-cfg": "enable",
         "proposal": "aes128-sha1 3des-sha1", "dhgrp": "5"},
    ],
    "cmdb/vpn.ipsec/phase2-interface": [{"name": "S2S-Sucursal-p2", "phase1name": "S2S-Sucursal",
                                         "proposal": "aes256-sha256", "pfs": "enable", "dhgrp": "14",
                                         "src-subnet": "192.0.2.0 255.255.255.0",
                                         "dst-subnet": "198.51.100.0 255.255.255.0", "keylifeseconds": 43200}],
    "cmdb/vpn.ipsec/phase1": [], "cmdb/vpn.ipsec/phase2": [],
    "cmdb/vpn.ssl/settings": {"status": "enable", "port": 10443, "servercert": "Fortinet_Factory",
                              "source-interface": [{"name": "wan1"}], "source-address": [{"name": "all"}],
                              "tunnel-ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1"}], "ssl-min-proto-ver": "tls1-2",
                              "reqclientcert": "disable", "idle-timeout": 300, "default-portal": "no-access",
                              "authentication-rule": [{"id": 1, "groups": [{"name": "VPN-Users"}],
                                                       "portal": "full-access", "source-address": []}]},
    "cmdb/vpn.ssl.web/portal": [{"name": "full-access", "tunnel-mode": "enable", "split-tunneling": "enable",
                                 "split-tunneling-routing-address": [{"name": "MGMT-Net"}], "web-mode": "enable",
                                 "ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1"}]},
                                {"name": "no-access", "tunnel-mode": "disable", "web-mode": "disable"}],
    "monitor/vpn/ipsec": [{"name": "S2S-Sucursal", "rgwy": "198.51.100.200",
                           "proxyid": [{"p2name": "S2S-Sucursal-p2", "status": "up"}]}],
    "monitor/vpn/ssl": [{"user_name": "jperez", "remote_host": "198.51.100.77", "subsessions": []}],
    "cmdb/ips/sensor": [
        {"name": "default", "block-malicious-url": "disable",
         "entries": [{"id": 1, "severity": "medium high critical", "status": "default", "action": "default",
                      "exempt-ip": []}]},
        {"name": "protect_http_server", "block-malicious-url": "enable",
         "entries": [{"id": 1, "location": "server", "severity": "high critical", "action": "block",
                      "exempt-ip": [{"id": 1, "src-ip": "192.0.2.15 255.255.255.255",
                                     "dst-ip": "0.0.0.0 0.0.0.0"}]}]},
    ],
    "cmdb/ips/global": {"fail-open": "disable", "database": "extended", "traffic-submit": "disable"},
    "cmdb/ips/settings": {"packet-log-history": 1, "packet-log-memory": 256},
    "cmdb/webfilter/profile": [{"name": "default", "web": {"urlfilter-table": 1, "safe-search": "disable"},
                                "ftgd-wf": {"filters": [{"id": 1, "category": 26, "action": "block", "log": "enable"},
                                                        {"id": 2, "category": 61, "action": "block"},
                                                        {"id": 3, "category": 86, "action": "monitor"}]},
                                "log-all-url": "disable", "web-content-log": "enable"}],
    "cmdb/webfilter/urlfilter": [{"id": 1, "name": "Excepciones-Corp", "entries": [
        {"id": 1, "url": "*.example.com", "type": "wildcard", "action": "exempt", "status": "enable",
         "exempt": "av web-content activex-java-cookie dlp fortiguard range-block antiphish all"},
        {"id": 2, "url": "malo.example.net", "type": "simple", "action": "block", "status": "enable"}]}],
    "cmdb/webfilter/ftgd-local-cat": [],
    "cmdb/webfilter/ftgd-local-rating": [{"url": "intranet.example.com", "rating": "140", "status": "enable"}],
    "cmdb/webfilter/override": [],
    "cmdb/dnsfilter/profile": [{"name": "default", "block-botnet": "enable",
                                "ftgd-dns": {"filters": [{"id": 1, "category": 26, "action": "block"}]}}],
    "cmdb/application/list": [{"name": "default", "unknown-application-action": "pass",
                               "deep-app-inspection": "enable",
                               "entries": [{"id": 1, "category": [{"id": 2}, {"id": 6}], "action": "block"},
                                           {"id": 2, "application": [], "action": "pass"}]}],
    "cmdb/application/group": [],
    "cmdb/firewall/ssl-ssh-profile": [
        {"name": "certificate-inspection", "caname": "Fortinet_CA_SSL",
         "https": {"ports": "443", "status": "certificate-inspection", "expired-server-cert": "allow",
                   "untrusted-server-cert": "allow", "unsupported-ssl-version": "allow"}, "ssl-exempt": []},
        {"name": "deep-inspection", "caname": "Fortinet_CA_SSL", "untrusted-caname": "Fortinet_CA_Untrusted",
         "https": {"ports": "443", "status": "deep-inspection", "min-allowed-ssl-version": "tls-1.2",
                   "expired-server-cert": "block", "untrusted-server-cert": "block"},
         "ssl-exempt": [{"id": 1, "type": "fortiguard-category", "fortiguard-category": 31},
                        {"id": 2, "type": "address", "address": "MGMT-Net"},
                        {"id": 3, "type": "wildcard-fqdn", "wildcard-fqdn": "wild-example"}]},
    ],
    "cmdb/antivirus/profile": [{"name": "default", "http": {"av-scan": "block"},
                                "outbreak-prevention-archive-scan": "enable"}],
    "cmdb/antivirus/settings": {"machine-learning-detection": "enable", "grayware": "enable"},
    "cmdb/antivirus/exempt-list": [],
    "cmdb/log/setting": {"fwpolicy-implicit-log": "disable", "local-in-allow": "disable",
                         "local-in-deny-unicast": "enable", "resolve-ip": "disable"},
    "cmdb/log/eventfilter": {"event": "enable", "system": "enable", "vpn": "enable", "user": "enable",
                             "router": "enable"},
    "cmdb/log.disk/setting": {"status": "enable", "max-log-file-size": 100, "roll-schedule": "daily",
                              "diskfull": "overwrite", "upload": "disable"},
    "cmdb/log.memory/setting": {"status": "disable"},
    "cmdb/log.fortianalyzer/setting": {"status": "enable", "server": "192.0.2.45",
                                       "serial": [{"name": "FAZ-VM0000000001"}], "enc-algorithm": "high",
                                       "upload-option": "realtime", "reliable": "enable",
                                       "certificate-verification": "enable"},
    "cmdb/log.fortianalyzer2/setting": {"status": "disable", "server": ""},
    "cmdb/log.fortianalyzer3/setting": {"status": "disable", "server": ""},
    "cmdb/log.fortianalyzer-cloud/setting": {"status": "disable"},
    "cmdb/log.fortianalyzer/filter": {"severity": "information", "forward-traffic": "enable",
                                      "local-traffic": "enable", "anomaly": "enable"},
    "cmdb/log.syslogd/setting": {"status": "enable", "server": "192.0.2.50", "mode": "udp", "port": 514,
                                 "facility": "local7", "format": "default", "enc-algorithm": "disable"},
    "cmdb/log.syslogd2/setting": {"status": "disable"}, "cmdb/log.syslogd3/setting": {"status": "disable"},
    "cmdb/log.syslogd4/setting": {"status": "disable"},
    "cmdb/log.syslogd/filter": {"severity": "information", "forward-traffic": "enable", "local-traffic": "enable"},
    "monitor/log/fortianalyzer": {"connected": True, "registered": True, "server": "192.0.2.45"},
    "cmdb/system/ntp": {"ntpsync": "enable", "type": "custom", "syncinterval": 60, "server-mode": "disable",
                        "ntpserver": [{"id": 1, "server": "ntp.shoa.cl", "authentication": "enable",
                                       "key-type": "SHA1", "key": "ENC ntpkey0000", "key-id": 1},
                                      {"id": 2, "server": "pool.ntp.org", "authentication": "disable"}]},
    "monitor/system/ntp/status": [{"server": "ntp.shoa.cl", "reachable": True, "selected": True, "stratum": 2}],
    "monitor/system/config-revision": {"revisions": [{"id": 3, "time": 1791158400, "admin": "admin",
                                                      "comment": "Antes de upgrade 7.4.4"}]},
    "cmdb/system/auto-script": [{"name": "backup-semanal", "interval": 604800, "repeat": 0, "start": "auto",
                                 "script": "execute backup config sftp FGT-LAB-01.conf 192.0.2.60 "
                                           "backupuser B4ckupP4ss!"}],
    "cmdb/system/automation-trigger": [{"name": "Semanal-Domingo", "trigger-type": "scheduled",
                                        "trigger-frequency": "weekly", "trigger-weekday": "sunday",
                                        "trigger-hour": 2}],
    "cmdb/system/automation-action": [{"name": "Email-Config-Change", "action-type": "email",
                                       "email-to": [{"name": "noc@example.com"}]}],
    "cmdb/system/automation-stitch": [{"name": "Config-Change-Alert", "status": "enable", "trigger": "Config Change",
                                       "actions": [{"id": 1, "action": "Email-Config-Change"}]}],
    "cmdb/system/ha": {"mode": "a-p", "group-name": "FGT-LAB-HA", "group-id": 10, "priority": 200,
                       "override": "disable", "hbdev": "\"ha\" 50", "session-pickup": "enable",
                       "monitor": "\"wan1\" \"internal\"", "password": "ENC hapassword00",
                       "ha-mgmt-status": "disable", "encryption": "disable", "authentication": "disable"},
    "monitor/system/ha-peer": [{"serial_no": SERIAL, "hostname": "FGT-LAB-01", "priority": 200, "vcluster_id": 0},
                               {"serial_no": "FGT60FTK00000001", "hostname": "FGT-LAB-02", "priority": 100,
                                "vcluster_id": 0}],
    "monitor/system/ha-checksums": [{"is_manage_primary": 1, "serial_no": SERIAL,
                                     "checksum": {"global": "a1b2c3", "root": "d4e5f6", "all": "0a0b0c"}},
                                    {"is_manage_primary": 0, "serial_no": "FGT60FTK00000001",
                                     "checksum": {"global": "a1b2c3", "root": "d4e5f6", "all": "0a0b0c"}}],
    "monitor/system/ha-statistics": [{"serial_no": SERIAL, "sessions": 1200, "cpu_usage": 4, "mem_usage": 38},
                                     {"serial_no": "FGT60FTK00000001", "sessions": 1180, "cpu_usage": 3,
                                      "mem_usage": 36}],
    "cmdb/certificate/local": [
        {"name": "Fortinet_Factory", "source": "factory", "range": "global", "certificate": CERT_PEM,
         "private-key": KEY_PEM, "password": "ENC certpass0001", "auto-regenerate-days": 0},
        {"name": "VPN-Public", "source": "user", "range": "vdom", "certificate": CERT_PEM.replace("0000", "1111"),
         "private-key": KEY_PEM, "password": "ENC certpass0002", "enroll-protocol": "none"},
    ],
    "cmdb/certificate/ca": [{"name": "Fortinet_CA_SSL", "source": "factory", "range": "global", "ca": CA_PEM}],
    "cmdb/certificate/remote": [], "cmdb/certificate/crl": [],
    "cmdb/vpn.certificate/setting": {"ocsp-status": "disable", "strict-ocsp-check": "disable",
                                     "cn-match": "substring", "check-ca-cert": "enable",
                                     "crl-verification": {"expiry": "ignore", "leaf-crl-absence": "ignore",
                                                          "chain-crl-absence": "ignore"}},
    "monitor/system/available-certificates": [
        {"name": "Fortinet_Factory", "type": "local-cer", "is_local_ca_cert": False,
         "valid_from": 1600000000, "valid_to": 2000000000, "issuer": {"CN": "FGT60F", "O": "Fortinet"}},
        {"name": "VPN-Public", "type": "local-cer", "valid_from": 1760000000, "valid_to": 1793000000,
         "issuer": {"CN": "Example CA", "O": "Example"}},
    ],
}
UNSUPPORTED = {"cmdb/system.autoupdate/schedule"}                           # 404 (no existe en 7.4)
BAD_REQUEST = {"cmdb/firewall/policy6"}                                     # 400 (así responde 7.4.10 real)
PERMISSION_DENIED = {"cmdb/log.fortiguard/setting"}                          # 403 simulado
IGNORES_PAGING = {"cmdb/firewall.service/custom"}                            # devuelve todo siempre


class FakeResponse(requests.Response):
    def __init__(self, body, status: int = 200):
        super().__init__()
        self._content = (json.dumps(body) if not isinstance(body, (bytes, str)) else body)
        if isinstance(self._content, str):
            self._content = self._content.encode()
        self.status_code = status
        self.headers["Content-Type"] = "application/json"
        self.headers["Date"] = "Tue, 06 Oct 2026 18:30:00 GMT"


class FakeSession:
    def __init__(self, api_key="f4k3T0k3nAbCdEf0123456789", allowed=True, n_addresses=25, restrict_admins=False):
        self.api_key = api_key
        self.allowed = allowed
        self.n_addresses = n_addresses
        self.restrict_admins = restrict_admins
        self.headers = {}
        self.calls: list[dict] = []

    # Cualquier método distinto de GET es un fallo de la garantía de solo lectura.
    def _forbidden(self, method, *a, **k):
        self.calls.append({"method": method})
        raise AssertionError(f"El collector intentó un {method}")

    def post(self, *a, **k): return self._forbidden("POST", *a, **k)
    def put(self, *a, **k): return self._forbidden("PUT", *a, **k)
    def delete(self, *a, **k): return self._forbidden("DELETE", *a, **k)
    def patch(self, *a, **k): return self._forbidden("PATCH", *a, **k)
    def request(self, method, *a, **k): return self._forbidden(method.upper(), *a, **k)

    def get(self, url, params=None, headers=None, verify=True, timeout=None):
        params = dict(params or {})
        self.calls.append({"method": "GET", "url": url, "params": params, "headers": dict(headers or {})})
        if (headers or {}).get("Authorization") != f"Bearer {self.api_key}":
            return FakeResponse(b"", 401)
        if not self.allowed:
            return FakeResponse(b"<html>Forbidden</html>", 403)
        path = unquote(urlparse(url).path)
        assert path.startswith("/api/v2/"), path
        key = path[len("/api/v2/"):]
        vdom = params.get("vdom", "root")
        api, _, rest = key.partition("/")
        envelope = {"http_method": "GET", "vdom": vdom, "path": rest.rpartition("/")[0],
                    "name": rest.rpartition("/")[2], "serial": SERIAL, "version": VERSION, "build": BUILD}
        if key in UNSUPPORTED:
            return FakeResponse({**envelope, "status": "error", "http_status": 404}, 404)
        if key in BAD_REQUEST:
            return FakeResponse({**envelope, "status": "error", "http_status": 400}, 400)
        if key in PERMISSION_DENIED:
            return FakeResponse({**envelope, "status": "error", "http_status": 403}, 403)
        if key == "cmdb/firewall/policy":
            results = _policies(vdom)
        elif key == "cmdb/firewall/address":
            results = _addresses(self.n_addresses)
        elif key in SAMPLES:
            results = SAMPLES[key]
        else:
            return FakeResponse({**envelope, "status": "error", "http_status": 404}, 404)
        total = len(results) if isinstance(results, list) else 1
        matched = total
        if self.restrict_admins and key == "cmdb/system/admin":
            # Como FortiOS 7.4 real: perfil sin visibilidad -> 200 OK, results vacío,
            # size = objetos existentes, matched_count = objetos visibles.
            results, matched = [], 0
        if api == "cmdb" and isinstance(results, list) and key not in IGNORES_PAGING and "count" in params:
            start, count = int(params.get("start", 0)), int(params["count"])
            results = results[start:start + count]
            matched = min(matched, len(results)) if matched == total else matched  # por página, como FortiOS
        body = {**envelope, "results": results, "status": "success", "http_status": 200}
        if api == "cmdb":
            body["revision"] = "f1e2d3c4b5a6978877665544332211aa"
            body.update(size=total, matched_count=matched, limit_reached=False)
        return FakeResponse(body)
