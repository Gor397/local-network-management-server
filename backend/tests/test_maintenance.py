from app.models import Device, BackgroundJob
from test_agent_protocol import enrolled, signed_request


def test_typed_maintenance_is_approval_gated_and_signed(admin,app,enrolled):
    d,key,fp,version=enrolled
    path='/api/v1/devices/'+d['id']+'/maintenance'
    assert admin.post(path,json={'operation':'system.reboot','reason':'Approved maintenance window'}).status_code==409
    with app.state.sessions.begin() as db:db.get(Device,d['id']).mode='MAINTENANCE'
    assert admin.post(path,json={'operation':'shell.execute','reason':'Cannot execute arbitrary policy command'}).status_code==422
    assert admin.post(path,json={'operation':'windows.locale','reason':'Change language'}).status_code==422
    created=admin.post(path,json={'operation':'windows.locale','language':'hy-AM','reason':'Armenian language resources installed offline'})
    assert created.status_code==200
    response=signed_request(admin,key,fp,'GET','/api/v1/agent/maintenance/next')
    assert response.status_code==200 and response.json()['job']['algorithm']=='RS256'
    assert signed_request(admin,key,fp,'GET','/api/v1/agent/maintenance/next').json()['job'] is None
    result=signed_request(admin,key,fp,'POST','/api/v1/agent/maintenance/'+created.json()['id']+'/result',{'state':'PENDING_USER_LOGON','details':{'language':'hy-AM'}})
    assert result.status_code==200
