from copy import deepcopy
from types import SimpleNamespace
import httpx
import pytest
from sqlalchemy import select
from app.db import utcnow
from app.models import Router, Device, NetworkPlan, Alert
from app.mikrotik.connector import RouterOS, STACKS, PATHS, redact, snapshot_hash
from app.mikrotik.planner import allocate_address, reservation_plan, disconnect_plan, verify_operations
from app.services.network import execute_plan


def fixture(stack="wifi"):
    snapshot = {p: [] for p in PATHS}
    snapshot["system/resource"] = [{"version": "7.20", "board-name": "fixture-only"}]
    snapshot["system/package"] = [{"name": "routeros"}, {"name": "wifi-qcom" if stack=="wifi" else "wireless"}]
    snapshot["ip/dhcp-server"] = [{"name": "lan", "interface": "bridge"}]
    snapshot["ip/dhcp-server/network"] = [{"address": "192.168.88.0/24"}]
    snapshot["ip/address"] = [{"address": "192.168.88.1/24"}]
    snapshot["ip/pool"] = [{"ranges": "192.168.88.100-192.168.88.200"}]
    snapshot["ip/dhcp-server/lease"] = [{".id":"*A", "address":"192.168.88.20", "mac-address":"00:AA:BB:CC:DD:EE", "server":"lan", "dynamic":"false", "comment":"manual"}]
    interface, acl, reg = STACKS[stack]
    snapshot[interface] = [{"name": "wifi1"}]
    snapshot[acl] = [{".id": "*1", "mac-address": "00:AA:BB:CC:DD:EE", "private-passphrase": "preserve-me", "comment": "manual"}]
    snapshot[reg] = []
    return snapshot


@pytest.mark.parametrize("stack", list(STACKS))
async def test_discovery_all_wireless_stacks_and_secret_redaction(stack):
    snapshot = fixture(stack)
    def handler(request):
        path = request.url.path.removeprefix("/rest/")
        return httpx.Response(200, json=snapshot[path]) if path in snapshot else httpx.Response(400, json={"message":"no such command prefix"})
    async with RouterOS("https://192.168.88.1", "reader", "secret", transport=httpx.MockTransport(handler)) as router:
        result = await router.discovery()
    assert result["capabilities"]["stacks"] == [stack]
    assert "preserve-me" not in str(redact(result))
    assert snapshot_hash(snapshot) == snapshot_hash(deepcopy(snapshot))
    assert snapshot[STACKS[stack][1]][0]["private-passphrase"] == "preserve-me"


def test_allocator_excludes_pools_existing_and_reserved():
    s = SimpleNamespace(cidr="192.168.88.0/24", allocation_start="192.168.88.20", allocation_end="192.168.88.105", exclusions=["192.168.88.22/31"])
    snapshot = fixture()
    assert allocate_address(s,snapshot,["192.168.88.21"]) == "192.168.88.24"
    s.allocation_start = "192.168.88.100"
    with pytest.raises(ValueError): allocate_address(s,snapshot,[])


def test_quarantine_minimal_and_ownership_preserved():
    s = fixture()
    device = SimpleNamespace(id="uuid", primary_mac="00:11:22:33:44:55")
    original = deepcopy(s)
    ops = disconnect_plan(device,s,{"stacks":["wifi"]})
    assert len(ops) == 1 and ops[0]["data"]["action"] == "reject" and ops[0]["data"]["place-before"] == "*1"
    assert s == original
    after = deepcopy(s)
    after["interface/wifi/access-list"].insert(0,{".id":"*2", **{k:v for k,v in ops[0]["data"].items() if k!='place-before'}})
    assert verify_operations(ops,after)
    assert not verify_operations(ops,s)
    assert after["interface/wifi/access-list"][1]["private-passphrase"] == "preserve-me"


async def test_api_failure_never_reports_enforcement_success(app, monkeypatch):
    import app.services.network as service
    with app.state.sessions() as db:
        d = Device(hostname="PC",primary_mac="00:11:22:33:44:55")
        r = Router(name="Lab",base_url="https://192.168.88.1",username="test",secret=app.state.vault.seal("secret"),write_enabled=True)
        db.add_all([d,r]);db.flush()
        snapshot=fixture()
        p=NetworkPlan(router_id=r.id, device_id=d.id,generation=0,snapshot_hash=snapshot_hash(snapshot),operations=disconnect_plan(d,snapshot,{"stacks":["wifi"]}),reason="Test isolation")
        db.add(p);db.commit()
        app.state.settings.router_writes_enabled=True
        class Failure:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def discovery(self):raise httpx.ConnectError("unreachable")
        monkeypatch.setattr(service,"connector",lambda *args:Failure())
        result=await execute_plan(app,db,p,"test")
        assert result["state"]=="ERROR"
        assert db.get(Device,d.id).network_state=="ERROR"
        assert db.scalar(select(Alert).where(Alert.code=="network.enforcement_failed"))


def test_developer_registration_is_preview_and_never_compliant(admin,app):
    import json
    with app.state.sessions.begin() as db:
        r=Router(name="Lab",base_url="https://192.168.88.1",username="reader",secret=app.state.vault.seal("secret"),snapshot=app.state.vault.seal(json.dumps(fixture())),last_seen=utcnow())
        db.add(r);db.flush();router_id=r.id
    subnet=admin.post('/api/v1/mikrotik/subnets',json={"router_id":router_id,"cidr":"192.168.88.0/24","dhcp_server":"lan","allocation_start":"192.168.88.30","allocation_end":"192.168.88.50","confirm_range_exclusively_managed":True})
    assert subnet.status_code==200,subnet.text
    result=admin.post('/api/v1/mikrotik/developer-devices',json={"mac":"00:11:22:33:44:55","subnet_id":subnet.json()['id']})
    assert result.status_code==200,result.text
    assert result.json()['device']['state']=='UNVERIFIED' and result.json()['authorization']=='NOT_GRANTED'
    assert admin.post('/api/v1/mikrotik/plans/'+result.json()['plan_id']+'/apply').status_code==409
