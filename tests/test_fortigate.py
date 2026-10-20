"""FortiGate: API-Zugriff, Auflösung der Objekte, Maskierung, Seiten und LLM-Cache."""

import json

import httpx
import pytest

from doku_agent.config import FortiGateDevice
from doku_agent.connectors.fortigate import FortiGateClient
from doku_agent.egress import EgressBlocked, EgressGuard, allowed_hosts
from doku_agent.generators import fortigate_docs as fd
from tests.conftest import FakeLLM, make_config

TABLES = {
    "cmdb/system/global": {"hostname": "FGT-ZENTRALE"},
    "cmdb/firewall/policy": [
        {"policyid": 3, "name": "LAN-Internet", "status": "enable", "srcintf": [{"name": "internal"}],
         "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "LAN-Netz"}], "dstaddr": [{"name": "all"}],
         "service": [{"name": "Web"}], "action": "accept", "nat": "enable", "ippool": "disable",
         "schedule": "always", "logtraffic": "utm", "utm-status": "enable", "av-profile": "default",
         "webfilter-profile": "", "ssl-ssh-profile": "certificate-inspection", "comments": "Surfen"},
        {"policyid": 7, "name": "Webserver", "status": "disable", "srcintf": [{"name": "wan1"}],
         "dstintf": [{"name": "dmz"}], "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "VIP-Web"}],
         "service": [{"name": "HTTPS"}], "action": "accept", "nat": "disable", "logtraffic": "all"},
        {"policyid": 1, "name": "Block-Geo", "srcintf": [{"name": "wan1"}], "dstintf": [{"name": "any"}],
         "srcaddr": [{"name": "Land-RU"}], "srcaddr-negate": "disable", "dstaddr": [{"name": "all"}],
         "service": [{"name": "ALL"}], "action": "deny", "logtraffic": "disable"},
    ],
    "cmdb/firewall/address": [
        {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
        {"name": "LAN-Netz", "type": "ipmask", "subnet": "10.10.0.0 255.255.0.0", "associated-interface": "internal"},
        {"name": "Land-RU", "type": "geography", "country": "RU"},
        {"name": "Unbenutzt", "type": "fqdn", "fqdn": "alt.example.com"},
    ],
    "cmdb/firewall/addrgrp": [{"name": "Server", "member": [{"name": "LAN-Netz"}]}],
    "cmdb/firewall.service/custom": [
        {"name": "HTTPS", "category": "Web Access", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "ALL", "category": "General", "protocol": "IP", "protocol-number": 0},
        {"name": "DNS", "category": "Network Services", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53",
         "udp-portrange": "53"},
        {"name": "App-8080", "category": "", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8080-8090:1024-65535"},
    ],
    "cmdb/firewall.service/group": [{"name": "Web", "member": [{"name": "HTTPS"}, {"name": "App-8080"}]}],
    "cmdb/firewall/vip": [{"name": "VIP-Web", "type": "static-nat", "extintf": "wan1", "extip": "203.0.113.10",
                           "mappedip": [{"range": "10.20.0.5"}], "portforward": "enable", "protocol": "tcp",
                           "extport": "443", "mappedport": "8443"}],
    "cmdb/firewall/ippool": [],
    "cmdb/system/interface": [
        {"name": "internal", "vdom": "root", "ip": "10.10.0.1 255.255.0.0", "type": "hard-switch", "role": "lan",
         "allowaccess": "ping https ssh", "status": "up", "mode": "static"},
        {"name": "vlan20", "vdom": "root", "ip": "10.20.0.1 255.255.255.0", "type": "vlan", "vlanid": 20,
         "interface": "internal", "role": "dmz", "status": "up"},
        {"name": "fremd", "vdom": "kunde", "ip": "192.168.9.1 255.255.255.0", "type": "vlan"},
        {"name": "ppp1", "vdom": "root", "type": "physical", "password": "ENC Zm9vYmFy", "username": "isp"},
    ],
    "cmdb/router/static": [{"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "gateway": "198.51.100.1", "device": "wan1",
                            "distance": 10, "status": "enable"}],
    "cmdb/vpn.ipsec/phase1-interface": [
        {"name": "Filiale-Graz", "interface": "wan1", "type": "static", "remote-gw": "198.51.100.77",
         "ike-version": "2", "authmethod": "psk", "psksecret": "ENC aGVpbWxpY2g=", "proposal": "aes256-sha256",
         "dhgrp": "14", "ppk-secret": "klartext-geheim"}],
    "cmdb/vpn.ipsec/phase2-interface": [
        {"name": "Filiale-Graz-p2", "phase1name": "Filiale-Graz", "src-addr-type": "name", "src-name": "LAN-Netz",
         "dst-addr-type": "subnet", "dst-subnet": "10.50.0.0 255.255.255.0", "proposal": "aes256-sha256",
         "pfs": "enable", "dhgrp": "14", "keylifeseconds": 43200}],
}


class FakeFortiGate:
    def __init__(self):
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == "Bearer fgt-token"
        assert request.method == "GET"
        path = request.url.path.removeprefix("/api/v2/")
        if path not in TABLES:
            return httpx.Response(404, json={"status": "error", "http_status": 404})
        results = TABLES[path]
        return httpx.Response(200, json={"http_method": "GET", "results": results, "vdom": "root",
                                         "status": "success", "serial": "FGT60FTK1234", "version": "v7.4.5",
                                         "build": 2702})


@pytest.fixture
def fgt(ctx):
    fake = FakeFortiGate()
    dev = FortiGateDevice(name="fw-zentrale", url="https://fw.test:8443", token="fgt-token")
    ctx.cfg.fortigate.enabled = True
    ctx.cfg.fortigate.devices = [dev]
    ctx._clients["fortigate:fw-zentrale"] = FortiGateClient(dev, EgressGuard({"fw.test"}),
                                                            transport=httpx.MockTransport(fake.handler))
    return fake


def _explain_all(batch_prompt):
    rules = json.loads(batch_prompt.split("Regeln (JSON):\n", 1)[1])
    return {"regeln": [{"id": r["id"], "erklaerung": f"Erklärung {r['id']}."} for r in rules]}


class ExplainingLLM(FakeLLM):
    def json(self, system, user, schema):
        self.calls.append(("json", user))
        return _explain_all(user)


def test_allowlist_contains_configured_firewalls(tmp_path):
    cfg = make_config(tmp_path, fortigate={"enabled": True, "devices": [
        {"name": "fw1", "url": "https://fw1.example.local:8443", "token": "t"}]})
    assert "fw1.example.local" in allowed_hosts(cfg)
    with pytest.raises(EgressBlocked):
        EgressGuard.from_config(cfg).client("https://fw2.example.local")


def test_mask_obj_removes_secrets_and_encrypted_values():
    masked = fd.mask_obj({"psksecret": "ENC abc", "ppk-secret": "klar", "name": "x", "nat": "enable",
                          "list": [{"password": "pw", "passwd-policy": "enable"}], "comment": "ENC xyz"})
    assert masked == {"psksecret": "***", "ppk-secret": "***", "name": "x", "nat": "enable",
                      "list": [{"password": "***", "passwd-policy": "enable"}], "comment": "***"}


def test_cidr_and_services():
    assert fd.cidr("10.0.0.0 255.255.255.0") == "10.0.0.0/24"
    assert fd.cidr("10.0.0.1 255.255.255.255") == "10.0.0.1"
    assert fd.cidr("10.10.0.1 255.255.0.0") == "10.10.0.1/16"
    assert fd.service_ports({"protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"}) == "TCP 53; UDP 53"
    assert fd.service_ports({"protocol": "TCP/UDP/SCTP", "tcp-portrange": "8080-8090:1024-65535"}) == "TCP 8080-8090"
    assert fd.service_ports({"protocol": "IP", "protocol-number": 0}) == "alle Dienste"


def test_policy_page_resolves_objects_and_explains_each_rule(ctx, fgt):
    ctx.__dict__["llm"] = ExplainingLLM(text_answer="Das LAN darf ins Internet.")
    results = fd.document_fortigate(ctx, sections=["policies"])
    prop = ctx.store.get_proposal(results[0])
    content = prop.payload["content"]
    assert prop.payload["path"] == "netzwerk/firewall/fw-zentrale/regeln"
    assert prop.payload["title"] == "FortiGate fw-zentrale: Regeln"
    assert "firewall" in prop.payload["tags"] and "fortigate" in prop.payload["tags"]
    # Reihenfolge wie auf der Firewall, nicht nach ID sortiert
    assert content.index("| 1 | 3 | LAN-Internet") < content.index("| 2 | 7 | Webserver") < content.index("| 3 | 1 | Block-Geo")
    assert "LAN-Netz (10.10.0.0/16)" in content and "all (beliebig)" in content
    assert "Web (Gruppe: HTTPS, App-8080)" in content and "Land-RU (Land RU)" in content
    assert "VIP-Web (VIP: 203.0.113.10:443 → 10.20.0.5:8443 (TCP))" in content
    assert "erlauben (deaktiviert)" in content and "verwerfen" in content
    assert "av: default" in content and "ssl: certificate-inspection" in content
    for pid in ("3", "7", "1"):
        assert f"Erklärung {pid}." in content
    assert "Das LAN darf ins Internet." in content and "FortiOS | v7.4.5 (Build 2702)" in content
    assert "FGT60FTK1234" in content
    # Zweiter Lauf: alles aus dem Cache, kein LLM-Aufruf
    ctx.__dict__["llm"] = FakeLLM()
    fd.document_fortigate(ctx, sections=["policies"])
    assert ctx.llm.calls == []
    assert all(r.url.params.get("vdom") in (None, "root") for r in fgt.requests)


def test_secrets_never_reach_llm_or_wiki(ctx, fgt):
    ctx.__dict__["llm"] = llm = ExplainingLLM(text_answer="Zusammenfassung.")
    results = fd.document_fortigate(ctx)
    assert len(results) == 6  # Regeln, NAT, Objekte, Netzwerk, VPN, Prüfung
    everything = json.dumps([ctx.store.get_proposal(r).payload for r in results], ensure_ascii=False)
    prompts = json.dumps(llm.calls, ensure_ascii=False)
    for secret in ("aGVpbWxpY2g", "klartext-geheim", "Zm9vYmFy"):
        assert secret not in everything and secret not in prompts


def test_nat_objects_network_vpn_pages(ctx, fgt):
    ctx.__dict__["llm"] = ExplainingLLM(text_answer="Kurz.")
    pages = {ctx.store.get_proposal(pid).payload["path"]: ctx.store.get_proposal(pid).payload["content"]
             for pid in fd.document_fortigate(ctx, sections=["nat", "objects", "network", "vpn"])}
    nat = pages["netzwerk/firewall/fw-zentrale/nat"]
    assert "| VIP-Web | static-nat | wan1 | 203.0.113.10:443 → 10.20.0.5:8443 (TCP) | – | 7 |" in nat
    assert "| 3 | LAN-Internet | internal → wan1 | Interface-IP |" in nat
    objects = pages["netzwerk/firewall/fw-zentrale/objekte"]
    assert "| LAN-Netz | ipmask | 10.10.0.0/16 | internal | – | 1, 3 |" not in objects  # nur Regel 3 nutzt LAN-Netz
    assert "| LAN-Netz | ipmask | 10.10.0.0/16 | internal | – | 3 |" in objects
    assert "| Unbenutzt | fqdn | FQDN alt.example.com | – | – | – |" in objects
    assert "| App-8080 | – | TCP 8080-8090 | – | 3 |" in objects  # über die Gruppe "Web" verwendet
    assert "DNS" not in objects  # vordefiniert und unbenutzt
    network = pages["netzwerk/firewall/fw-zentrale/netzwerk"]
    assert "| vlan20 | – | vlan | 20 auf internal | 10.20.0.1/24 |" in network
    assert "fremd" not in network  # andere VDOM
    assert "0.0.0.0/0 (Standard) | 198.51.100.1 | wan1" in network
    vpn = pages["netzwerk/firewall/fw-zentrale/vpn"]
    assert "| Filiale-Graz | wan1 | 198.51.100.77 | IKEv2 | Pre-Shared Key | aes256-sha256 | 14 |" in vpn
    assert "| Filiale-Graz-p2 | Filiale-Graz | LAN-Netz (10.10.0.0/16) | 10.50.0.0/24 |" in vpn


def test_multiple_vdoms_get_own_pages(ctx, fgt):
    ctx.cfg.fortigate.devices[0].vdoms = ["root", "kunde"]
    ctx.__dict__["llm"] = ExplainingLLM()
    paths = [ctx.store.get_proposal(p).payload["path"] for p in fd.document_fortigate(ctx, sections=["network"])]
    assert paths == ["netzwerk/firewall/fw-zentrale-root/netzwerk", "netzwerk/firewall/fw-zentrale-kunde/netzwerk"]
    assert {r.url.params.get("vdom") for r in fgt.requests} >= {"root", "kunde"}


def test_unreachable_firewall_fails_job(ctx):
    def down(request):
        raise httpx.ConnectError("weg")

    dev = FortiGateDevice(name="fw-x", url="https://fw.test", token="fgt-token")
    ctx.cfg.fortigate.enabled = True
    ctx.cfg.fortigate.devices = [dev]
    ctx._clients["fortigate:fw-x"] = FortiGateClient(dev, EgressGuard({"fw.test"}), transport=httpx.MockTransport(down))
    with pytest.raises(RuntimeError, match="Keine FortiGate erreichbar"):
        fd.document_fortigate(ctx)


def _audit_data(policies, interfaces=()):
    return fd.FortiData("fw", "root", {}, policies=policies, addresses=TABLES["cmdb/firewall/address"],
                        addrgrps=TABLES["cmdb/firewall/addrgrp"], services=TABLES["cmdb/firewall.service/custom"],
                        service_groups=TABLES["cmdb/firewall.service/group"], vips=TABLES["cmdb/firewall/vip"],
                        interfaces=list(interfaces))


def _p(pid, src, dst, svc, action="accept", sintf="internal", dintf="wan1", **extra):
    return {"policyid": pid, "name": f"r{pid}", "srcintf": [{"name": sintf}], "dstintf": [{"name": dintf}],
            "srcaddr": [{"name": n} for n in src], "dstaddr": [{"name": n} for n in dst],
            "service": [{"name": n} for n in svc], "action": action, "schedule": "always", "logtraffic": "all", **extra}


def test_audit_finds_shadowed_broad_unlogged_and_unprotected_rules():
    data = _audit_data([
        _p(20, ["LAN-Netz"], ["all"], ["Web"], **{"utm-status": "enable"}),
        _p(21, ["Server"], ["all"], ["HTTPS"], action="deny"),            # Server ⊆ LAN-Netz, HTTPS ⊆ Web
        _p(22, ["LAN-Netz"], ["all"], ["DNS"]),                           # DNS nicht in Web -> nicht verdeckt
        _p(30, ["all"], ["all"], ["ALL"], sintf="wan1", dintf="internal", logtraffic="disable"),
        _p(31, ["Land-RU"], ["all"], ["ALL"], action="deny", sintf="wan1", dintf="internal"),  # verdeckt durch 30
        _p(40, ["LAN-Netz"], ["VIP-Web"], ["HTTPS"], status="disable"),
    ], interfaces=[{"name": "wan1", "role": "wan"}, {"name": "internal", "role": "lan"}])
    f = fd.audit(data)
    assert [r[:3] for r in f["shadowed"]] == [["21", "r21", "20"], ["31", "r31", "30"]]
    assert "greift nie" in f["shadowed"][0][3]
    assert [r[0] for r in f["any_any"]] == ["30"]
    assert [r[0] for r in f["no_log"]] == ["30"]
    assert {r[0] for r in f["no_profile"]} == {"22", "30"}  # 20 hat Sicherheitsprofil (utm-status)
    assert f["disabled"] == [["40", "r40"]]
    assert ["Adresse", "Unbenutzt"] in f["unused"] and ["Dienst", "App-8080"] not in f["unused"]


def test_audit_respects_negation_and_ranges():
    tables = dict(TABLES)
    data = _audit_data([
        _p(1, ["LAN-Netz"], ["all"], ["HTTPS"], **{"dstaddr-negate": "enable"}),
        _p(2, ["LAN-Netz"], ["all"], ["HTTPS"]),                           # 1 ist negiert -> kein Vergleich
        _p(3, ["Unbenutzt"], ["all"], ["HTTPS"]),                          # FQDN: nur bei gleichem Namen abgedeckt
    ])
    data.addresses = tables["cmdb/firewall/address"]
    f = fd.audit(data)
    assert f["shadowed"] == []


def test_machine_rules_only_specific_objects():
    data = _audit_data([
        _p(3, ["LAN-Netz"], ["all"], ["Web"]),                                   # LAN-Netz ist /16
        _p(7, ["all"], ["VIP-Web"], ["HTTPS"], sintf="wan1", dintf="dmz"),
        _p(8, ["Server"], ["all"], ["DNS"]),                                     # Gruppe mit LAN-Netz
    ])
    data.addresses = TABLES["cmdb/firewall/address"] + [{"name": "web-host", "type": "ipmask",
                                                         "subnet": "10.20.0.5 255.255.255.255"}]
    data.policies.append(_p(9, ["admin-pc"], ["web-host"], ["HTTPS"]))
    data.addresses.append({"name": "admin-pc", "type": "iprange", "start-ip": "10.10.9.1", "end-ip": "10.10.9.5"})
    rows = fd.machine_rules(data, ["10.20.0.5"], 24)
    assert [(r[1], r[2]) for r in rows] == [("7 r7", "eingehend"), ("9 r9", "eingehend")]
    assert rows[0][6].startswith("VIP VIP-Web") and rows[1][6] == "web-host"
    assert rows[1][3] == "admin-pc (10.10.9.1–10.10.9.5)"
    assert fd.machine_rules(data, ["10.10.0.50"], 24) == []                 # nur über /16 erfasst
    wide = fd.machine_rules(data, ["10.10.0.50"], 16)
    assert [(r[1], r[6]) for r in wide] == [("3 r3", "LAN-Netz"), ("8 r8", "Server → LAN-Netz")]


def test_ipv4_and_ipv6_objects_with_same_name_stay_apart(ctx, fgt, monkeypatch):
    # FortiOS liefert "all" als address (0.0.0.0/0) und als address6 (::/0)
    monkeypatch.setitem(TABLES, "cmdb/firewall/address6", [{"name": "all", "type": "ipprefix", "ip6": "::/0"},
                                                           {"name": "LAN-Netz", "type": "ipprefix", "ip6": "fd00::/64"}])
    data = fd.fetch(ctx.fortigate("fw-zentrale"), "root", ["audit"])
    data.policies = [_p(30, ["all"], ["all"], ["ALL"], sintf="wan1", dintf="internal"),
                     _p(31, ["LAN-Netz"], ["all"], ["HTTPS"], srcaddr6=[{"name": "LAN-Netz"}])]
    assert [r[0] for r in fd.audit(data)["any_any"]] == ["30"]
    view = fd.policy_view(data.policies[1], fd.Resolver(data))
    assert view["quelle"] == ["LAN-Netz (10.10.0.0/16)", "LAN-Netz (fd00::/64)"]


def test_machine_rules_skip_negated_side():
    data = _audit_data([_p(5, ["LAN-Netz"], ["web-host"], ["HTTPS"], **{"dstaddr-negate": "enable"})])
    data.addresses = TABLES["cmdb/firewall/address"] + [{"name": "web-host", "type": "ipmask",
                                                         "subnet": "10.20.0.5 255.255.255.255"}]
    assert fd.machine_rules(data, ["10.20.0.5"], 24) == []  # "alles außer web-host"


def test_steckbrief_lists_firewall_rules(ctx, fgt, fake_wiki):
    from doku_agent.connectors.netbox import NetboxClient
    from doku_agent.generators.netbox_docs import document_object
    from tests.conftest import FakeNetbox

    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    dev = nbf.add("dcim/devices", {"name": "web01"})
    itf = nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0"})
    nbf.add("ipam/ip-addresses", {"address": "10.20.0.5/24", "assigned_object_id": itf["id"]})
    content = ctx.store.get_proposal(document_object(ctx, "device", dev["id"])).payload["content"]
    assert "## Firewall-Regeln" in content and "| fw-zentrale | 7 Webserver | eingehend |" in content

    # Firewall nicht erreichbar: Abschnitt bleibt unverändert (wird nicht geleert)
    ctx.__dict__.pop("_fortigate_rules_cache", None)
    ctx._clients["fortigate:fw-zentrale"] = FortiGateClient(
        ctx.cfg.fortigate.devices[0], EgressGuard({"fw.test"}),
        transport=httpx.MockTransport(lambda r: httpx.Response(500, text="weg")))
    dev2 = nbf.add("dcim/devices", {"name": "web02"})
    itf2 = nbf.add("dcim/interfaces", {"device": dev2["id"], "name": "eth0"})
    nbf.add("ipam/ip-addresses", {"address": "10.20.0.6/24", "assigned_object_id": itf2["id"]})
    content = ctx.store.get_proposal(document_object(ctx, "device", dev2["id"])).payload["content"]
    assert "Firewall-Regeln" not in content
