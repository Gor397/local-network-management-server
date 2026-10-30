import json
from copy import deepcopy
import pytest
from sqlalchemy import select
from app.db import utcnow
from app.models import Router,Subnet,Device,NetworkPlan
from app.mikrotik.connector import STACKS
from app.mikrotik.planner import verify_operations
from app.services.admission import admission_plan
from test_suro import infrastructure_factory
from types import SimpleNamespace


@pytest.fixture
def profile_setup(admin,app,infrastructure_factory):
    identifier=infrastructure_factory()
    with app.state.sessions.begin() as db:
        subnet=Subnet(router_id=identifier,cidr='192.168.88.0/24',dhcp_server='lan',allocation_start='192.168.88.30',allocation_end='192.168.88.40',profile='developer')
        db.add(subnet);db.flush();subnet_id=subnet.id
    group=admin.post('/api/v1/mikrotik/groups',json={'name':'Developer APs','router_ids':[identifier]}).json()['id']
    p=admin.post('/api/v1/mikrotik/network-profiles',json={'name':'Developer Wi-Fi','subnet_id':subnet_id,'ap_group_id':group,'ssid':'Office'})
    assert p.status_code==201,p.text
    return identifier,p.json()['id']


def test_mac_and_profile_registration_combines_dhcp_and_admission_without_touching_passwords(admin,app,profile_setup):
    identifier,profile=profile_setup
    response=admin.post('/api/v1/mikrotik/developer-devices',json={'mac':'00:11:22:33:44:55','profile_id':profile})
    assert response.status_code==200,response.text
    result=response.json();assert len(result['plan_ids'])==1
    assert result['device']['compliance_score'] is None and result['device']['state']=='UNVERIFIED'
    with app.state.sessions() as db:
        plan=db.get(NetworkPlan,result['plan_ids'][0]);assert len(plan.operations)==2
        assert {o['path'] for o in plan.operations}=={'ip/dhcp-server/lease','interface/wifi/access-list'}
        assert plan.result['admission']['scope']=='wireless_admission_only'
        before=json.loads(app.state.vault.open(db.get(Router,identifier).snapshot))
        assert before['interface/wifi/access-list'][0]['private-passphrase']=='preserve-me'
        assert all('private-passphrase' not in op['data'] for op in plan.operations)


def test_existing_manual_accept_and_unique_password_are_reused():
    device=SimpleNamespace(id='device',primary_mac='00:11:22:33:44:55');profile=SimpleNamespace(id='profile',ssid='Office',vlan_id=None)
    snapshot={'interface/wifi':[{'name':'wifi1','configuration.ssid':'Office','disabled':'false'}],'interface/wifi/access-list':[{'.id':'*A','mac-address':device.primary_mac,'action':'accept','private-passphrase':'preserve this secret'}]}
    original=deepcopy(snapshot);operations,requirements=admission_plan(device,profile,snapshot,{'stacks':['wifi']})
    assert operations==[] and requirements['reused_rules'][0]['id']=='*A' and snapshot==original
    snapshot['interface/wifi/access-list'][0]['action']='reject'
    with pytest.raises(ValueError,match='manual_admission_conflict'):admission_plan(device,profile,snapshot,{'stacks':['wifi']})


def test_multiple_radio_accepts_are_verified_without_accepting_earlier_conflicting_rules():
    operations=[];rows=[]
    for n in range(2):
        values={'mac-address':'00:11:22:33:44:55','interface':f'wifi{n}','action':'accept','disabled':'false','comment':f'owned-{n}'}
        operations.append({'method':'PUT','path':'interface/wifi/access-list','data':values,'priority_mode':'before_conflicts'})
        rows.append({'.id':f'*{n}',**values})
    assert verify_operations(operations,{'interface/wifi/access-list':rows})
    rows.insert(0,{'.id':'*DENY','action':'reject','mac-address':'00:00:00:00:00:00'})
    assert not verify_operations(operations,{'interface/wifi/access-list':rows})


async def test_admission_is_not_success_before_router_readback(admin,app,profile_setup,monkeypatch):
    from app.services.network import execute_plan
    import app.services.network as service
    identifier,profile=profile_setup
    result=admin.post('/api/v1/mikrotik/developer-devices',json={'mac':'00:11:22:33:44:55','profile_id':profile}).json()
    with app.state.sessions() as db:
        plan=db.get(NetworkPlan,result['plan_ids'][0]);r=db.get(Router,identifier);snapshot=json.loads(app.state.vault.open(r.snapshot))
        class Api:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def discovery(self):return {'snapshot':deepcopy(snapshot)}
            async def apply(self,operation):
                assert operation['method']=='PUT'
                row={'.id':'*NEW'+str(len(snapshot[operation['path']])),**{k:v for k,v in operation['data'].items() if k!='place-before'}}
                if operation['path']=='ip/dhcp-server/lease':row['dynamic']='false'
                snapshot[operation['path']].insert(0,row);return row
        monkeypatch.setattr(service,'connector',lambda *args:Api());app.state.settings.router_writes_enabled=True
        outcome=await execute_plan(app,db,plan,'test-admin')
        assert outcome['state']=='VERIFIED',outcome
        d=db.get(Device,result['device']['id']);assert d.network_state=='ADMISSION_CONFIGURATION_VERIFIED' and d.device_class=='DEVELOPER'
        assert snapshot['interface/wifi/access-list'][1]['private-passphrase']=='preserve-me'


def test_unobserved_vlan_capability_is_rejected(admin,profile_setup):
    p=admin.get('/api/v1/mikrotik/network-profiles').json()[0]
    response=admin.post('/api/v1/mikrotik/network-profiles',json={'name':'Unverified VLAN','subnet_id':p['subnet_id'],'ap_group_id':p['ap_group_id'],'ssid':'Office','vlan_id':20})
    assert response.status_code==409 and response.json()['error']['code']=='network.profile_vlan_unverified'
