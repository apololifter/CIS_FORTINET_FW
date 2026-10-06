"""Pruebas offline del collector (no requieren firewall). Ejecutar: pytest -q"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import collector  # noqa: E402
from mock_fortigate import FakeSession  # noqa: E402
from fortinet_audit import client as client_mod  # noqa: E402
from fortinet_audit.catalog import ENTITIES, ENTITY_BY_KEY, FORBIDDEN_PREFIXES, Entity  # noqa: E402
from fortinet_audit.client import FortiOSClient, ReadOnlyViolation  # noqa: E402
from fortinet_audit.redact import REDACTED, REDACTED_WEAK_DEFAULT, redact_script  # noqa: E402

TOKEN = "f4k3T0k3nAbCdEf0123456789"


def make_client(session=None, page_size=1000, key=TOKEN):
    return FortiOSClient("fw.test", 443, key, delay_between_requests=0, page_size=page_size,
                         session=session or FakeSession())


# --------------------------- solo lectura ---------------------------------- #
def test_only_get_is_used_and_token_only_in_header():
    s = FakeSession()
    c = make_client(s)
    c.get(ENTITY_BY_KEY["cmdb/firewall/policy"], "root")
    call = s.calls[-1]
    assert call["method"] == "GET"
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in call["url"] and TOKEN not in json.dumps(call["params"])
    assert "access_token" not in call["params"]


@pytest.mark.parametrize("bad", ["cmdb/../system/admin", "cmdb//x", "other/system/status",
                                 "cmdb/firewall/policy?x=1", "cmdb/a b"])
def test_rejects_invalid_paths(bad):
    api, _, path = bad.partition("/")
    with pytest.raises(ReadOnlyViolation):
        FortiOSClient._validate(Entity(api, path, "x", "global"), None)


def test_rejects_forbidden_endpoints():
    for p in FORBIDDEN_PREFIXES:
        api, _, path = p.partition("/")
        with pytest.raises(ReadOnlyViolation):
            FortiOSClient._validate(Entity(api, path, "x", "global"), None)
    # sub-rutas de un prefijo prohibido también se bloquean
    with pytest.raises(ReadOnlyViolation):
        FortiOSClient._validate(Entity("monitor", "system/config/backup/x", "x", "global"), None)


def test_rejects_bad_vdom_and_params():
    with pytest.raises(ReadOnlyViolation):
        FortiOSClient._validate(ENTITY_BY_KEY["cmdb/firewall/policy"], "root&x=1")
    with pytest.raises(ReadOnlyViolation):
        FortiOSClient._validate(Entity("cmdb", "firewall/policy", "x", "vdom",
                                       params=(("access_token", "x"),)), "root")


def test_no_write_methods_exist():
    names = {n.lower() for n in dir(FortiOSClient) if not n.startswith("__")}
    assert not any(w in n for n in names for w in ("post", "put", "patch", "delete", "set", "update", "create"))


def test_catalog_keys_unique_and_allowed():
    keys = [e.key for e in ENTITIES]
    assert len(keys) == len(set(keys))
    for e in ENTITIES:
        FortiOSClient._validate(e, "root" if e.scope == "vdom" else None)
        assert e.scope in ("global", "vdom") and e.api in ("cmdb", "monitor")
    assert ENTITY_BY_KEY["cmdb/user/tacacs+"].url_path.endswith("user/tacacs%2B")
    assert ENTITY_BY_KEY["cmdb/vpn.ipsec/phase1-interface"].cli == "config vpn ipsec phase1-interface"


# --------------------------- clasificación / paginación -------------------- #
def test_ok_empty_notsupported_error():
    c = make_client()
    r = c.get(ENTITY_BY_KEY["cmdb/firewall/policy"], "root")
    assert r.status == "OK" and r.record_count == 4 and r.serial == "FGT60FTK00000000"
    assert c.get(ENTITY_BY_KEY["cmdb/user/tacacs+"], "root").status == "EMPTY"
    r = c.get(ENTITY_BY_KEY["cmdb/firewall/policy6"], "root")   # 400 en 7.4 + best_effort
    assert r.status == "NOT_SUPPORTED" and r.error is None
    r = c.get(ENTITY_BY_KEY["cmdb/log.fortiguard/setting"], None)
    assert r.status == "ERROR" and "403" in r.error
    r = c.get(ENTITY_BY_KEY["cmdb/system/global"], None)
    assert r.status == "OK" and r.record_count == 1


def test_restricted_visibility_is_not_reported_as_empty():
    # Caso real (FortiOS 7.4.10): perfil read-only scope vdom -> admins ocultos
    c = make_client(FakeSession(restrict_admins=True))
    r = c.get(ENTITY_BY_KEY["cmdb/system/admin"], None)
    assert r.status == "RESTRICTED" and r.record_count == 0
    assert r.extra["visibility"] == {"size": 3, "matched_count": 0}
    # tablas completamente visibles siguen OK / EMPTY
    assert c.get(ENTITY_BY_KEY["cmdb/system/accprofile"], None).status == "OK"
    assert c.get(ENTITY_BY_KEY["cmdb/user/tacacs+"], "root").status == "EMPTY"


def test_pagination_merges_pages():
    c = make_client(FakeSession(n_addresses=25), page_size=10)
    r = c.get(ENTITY_BY_KEY["cmdb/firewall/address"], "root")
    assert r.status == "OK" and r.record_count == 30 and r.pages == 3     # no RESTRICTED
    assert r.parsed["matched_count"] == r.parsed["size"] == 30
    names = [x["name"] for x in r.parsed["results"]]
    assert len(names) == len(set(names))


def test_pagination_ignored_by_device_is_detected():
    c = make_client(page_size=10)
    r = c.get(ENTITY_BY_KEY["cmdb/firewall.service/custom"], "root")
    assert r.record_count == 12 and r.pagination_note


def test_login_bad_token_raises():
    c = make_client(key="wrong")
    with pytest.raises(client_mod.AuthenticationError, match="401"):
        c.test_login(ENTITY_BY_KEY["monitor/system/status"])


def test_trusthost_denied_raises():
    c = make_client(FakeSession(allowed=False))
    with pytest.raises(client_mod.AuthenticationError, match="trusthost"):
        c.test_login(ENTITY_BY_KEY["monitor/system/status"])


def test_redact_script_keeps_destination():
    out = redact_script("execute backup config sftp fw.conf 192.0.2.60 backupuser S3cr3t!\nexecute date")
    assert "S3cr3t!" not in out and "backupuser" not in out
    assert "fw.conf 192.0.2.60" in out and "execute date" in out


# --------------------------- end to end ----------------------------------- #
@pytest.fixture
def run(tmp_path, monkeypatch):
    fake = FakeSession(n_addresses=25)
    monkeypatch.setattr(client_mod.requests, "Session", lambda: fake)
    monkeypatch.setenv("FORTI_FW_HOST", "fw.test")
    monkeypatch.setenv("FORTI_FW_API_KEY", TOKEN)
    monkeypatch.delenv("FORTI_FW_VDOMS", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"firewall:\n  label: lab\noutput:\n  raw_dir: {tmp_path/'raw'}\n  log_dir: {tmp_path/'logs'}\n"
                   "requests:\n  delay_between_requests: 0\n  page_size: 10\n", encoding="utf-8")
    rc = collector.main(["--config", str(cfg)])
    run_dir = next((tmp_path / "raw").iterdir())
    return rc, run_dir, fake, tmp_path


def test_end_to_end(run):
    rc, run_dir, fake, tmp = run
    assert rc == 1  # log.fortiguard/setting simulado con 403 -> parcial
    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    n_global = sum(1 for e in ENTITIES if e.scope == "global")
    n_vdom = sum(1 for e in ENTITIES if e.scope == "vdom")
    assert m["vdoms"] == ["root", "DMZ"]
    assert m["summary"]["requested"] == n_global + 2 * n_vdom
    assert m["summary"]["ERROR"] == 1
    assert m["summary"]["NOT_SUPPORTED"] == 1 + 2  # autoupdate (global) + policy6 x 2 VDOMs
    fi = m["firewall_identity"]
    assert fi["serial"] == "FGT60FTK00000000" and fi["model"] == "FGT60F"
    assert fi["hostname"] == "FGT-LAB-01" and fi["timezone"] == "America/Santiago"
    assert fi["firmware"] == "v7.4.4 build2662" and fi["vdom_mode"] == "multi-vdom"
    assert any(x["field"] == "last_login" for x in m["not_available"])
    # cada endpoint tiene su JSON con meta + response, por VDOM cuando corresponde
    for e in ENTITIES:
        for v in (["root", "DMZ"] if e.scope == "vdom" else [None]):
            p = run_dir / e.section / (v or "") / f"{e.file_stem}.json"
            env = json.loads(p.read_text(encoding="utf-8"))
            assert env["meta"]["entity"] == e.key and env["meta"]["vdom"] == v
            assert env["meta"]["extracted_at_utc"]
    pol = json.loads((run_dir / "firewall_policies" / "DMZ" / "cmdb.firewall.policy.json").read_text("utf-8"))
    assert pol["response"]["results"][0]["policyid"] == 10
    # nunca se usó un método distinto de GET
    assert {c["method"] for c in fake.calls} == {"GET"}


def test_secrets_redacted_everywhere(run):
    rc, run_dir, fake, tmp = run
    blob = "".join(p.read_text(encoding="utf-8", errors="ignore")
                   for p in list(run_dir.rglob("*")) + list((tmp / "logs").rglob("*")) if p.is_file())
    for secret in (TOKEN, "ENC SH2adminhash0000", "ENC ipsecpsk0001", "ENC radiussecret", "ENC ldapbindpw",
                   "ENC hapassword00", "ENC ntpkey0000", "ENC SH2apikeyhash9999", "Sup3rC0mmunity",
                   "ENC snmpauth000", "B4ckupP4ss!", "PRIVATE KEY", "MIIFAKEPRIVATEKEYDATA", "ENC certpass0001"):
        assert secret not in blob, secret
    p1 = json.loads((run_dir / "vpn" / "root" / "cmdb.vpn.ipsec.phase1-interface.json").read_text("utf-8"))
    rec = p1["response"]["results"][0]
    assert rec["psksecret"] == REDACTED
    assert rec["proposal"] == "aes256-sha256"           # lo no secreto se conserva íntegro
    snmp = json.loads((run_dir / "administration" / "cmdb.system.snmp.community.json").read_text("utf-8"))
    assert snmp["response"]["results"][0]["name"] == REDACTED_WEAK_DEFAULT   # "public" queda marcado
    adm = json.loads((run_dir / "administrators" / "cmdb.system.admin.json").read_text("utf-8"))
    assert adm["response"]["results"][2]["password"] == ""                   # vacío = no configurado


def test_public_certificates_saved_private_keys_never(run):
    rc, run_dir, fake, tmp = run
    d = run_dir / "certificates" / "root" / "cmdb.certificate.local"
    pems = list(d.glob("*.pem"))
    assert len(pems) == 2 and all("BEGIN CERTIFICATE" in p.read_text() for p in pems)
    assert not list(run_dir.rglob("*.key"))


def test_no_redact_still_drops_private_keys(tmp_path, monkeypatch):
    fake = FakeSession()
    monkeypatch.setattr(client_mod.requests, "Session", lambda: fake)
    monkeypatch.setenv("FORTI_FW_HOST", "fw.test")
    monkeypatch.setenv("FORTI_FW_API_KEY", TOKEN)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"output:\n  raw_dir: {tmp_path/'raw'}\n  log_dir: {tmp_path/'logs'}\n"
                   "requests:\n  delay_between_requests: 0\n", encoding="utf-8")
    collector.main(["--config", str(cfg), "--no-redact", "--sections", "certificates", "--vdoms", "root"])
    blob = "".join(p.read_text("utf-8") for p in (tmp_path / "raw").rglob("*.json"))
    assert "PRIVATE KEY" not in blob and "ENC certpass0001" in blob


def test_yaml_with_api_key_is_rejected(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("firewall:\n  host: x\n  api_key: abc123\n", encoding="utf-8")
    assert collector.main(["--config", str(cfg), "--dry-run"]) == 2


def test_fatal_on_bad_token(tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod.requests, "Session", lambda: FakeSession())
    monkeypatch.setenv("FORTI_FW_HOST", "fw.test")
    monkeypatch.setenv("FORTI_FW_API_KEY", "token-incorrecto")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"output:\n  raw_dir: {tmp_path/'raw'}\n  log_dir: {tmp_path/'logs'}\n", encoding="utf-8")
    assert collector.main(["--config", str(cfg)]) == 2
    m = json.loads(next((tmp_path / "raw").glob("*/manifest.json")).read_text("utf-8"))
    assert "fatal_error" in m
