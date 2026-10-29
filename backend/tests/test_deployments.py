import hashlib
from datetime import timedelta
from sqlalchemy import select
from app.models import DeploymentTask, Device, SoftwarePackage, SshTarget
from app.db import utcnow
from test_agent_protocol import enrolled, signed_request


def upload_package(admin, content=b"simulated signed installer", sha=None):
    sha=sha or hashlib.sha256(content).hexdigest()
    start=admin.post('/api/v1/packages/uploads',json={"name":"Offline app","filename":"app.msi","sha256":sha,"size":len(content),"kind":"msi","publisher_thumbprint":"A"*40,"product_code":"{12345678-1234-1234-1234-123456789ABC}"})
    assert start.status_code==201,start.text
    if start.json().get('deduplicated'):return start.json()['package_id']
    upload_id=start.json()['upload_id']
    mid=len(content)//2
    assert admin.put(f'/api/v1/packages/uploads/{upload_id}?offset=0',content=content[:mid],headers={'content-type':'application/octet-stream'}).status_code==200
    assert admin.put(f'/api/v1/packages/uploads/{upload_id}?offset=0',content=content[:mid],headers={'content-type':'application/octet-stream'}).status_code==409
    assert admin.get('/api/v1/packages/uploads/'+upload_id).json()['offset']==mid
    assert admin.put(f'/api/v1/packages/uploads/{upload_id}?offset={mid}',content=content[mid:],headers={'content-type':'application/octet-stream'}).status_code==200
    complete=admin.post('/api/v1/packages/uploads/'+upload_id+'/complete')
    return complete


def test_package_hash_resume_dedup_and_approval(admin,app):
    result=upload_package(admin)
    assert result.status_code==200,result.text
    package_id=result.json()['package_id']
    assert upload_package(admin)==package_id
    assert admin.post('/api/v1/packages/'+package_id+'/approve',json={'reason':'Publisher reviewed in isolated lab'}).status_code==200
    assert admin.get('/api/v1/packages').json()[0]['approved'] is True
    assert upload_package(admin,b'tampered',sha='0'*64).status_code==422


def test_deployment_signed_manifest_concurrency_range_and_audit(admin,app,enrolled):
    d,key,fp,v=enrolled
    package_id=upload_package(admin).json()['package_id']
    app.state.settings.deployment_enabled=True
    assert admin.post('/api/v1/deployments',json={'package_id':package_id,'device_ids':[d['id']],'reason':'Lab rollout'}).status_code==409
    admin.post('/api/v1/packages/'+package_id+'/approve',json={'reason':'Lab signature approved'})
    deployment=admin.post('/api/v1/deployments',json={'package_id':package_id,'device_ids':[d['id']],'reason':'Staged offline deployment'})
    assert deployment.status_code==201,deployment.text
    # Audit mode cannot install software.
    assert signed_request(admin,key,fp,'GET','/api/v1/agent/deployments/next').json()['task'] is None
    with app.state.sessions.begin() as db:db.get(Device,d['id']).mode='APPROVED_REMEDIATION'
    result=signed_request(admin,key,fp,'GET','/api/v1/agent/deployments/next')
    assert result.status_code==200 and result.json()['task']['algorithm']=='RS256'
    assert signed_request(admin,key,fp,'GET','/api/v1/agent/deployments/next').json()['task'] is None
    download=signed_request(admin,key,fp,'GET','/api/v1/agent/packages/'+package_id,headers={'range':'bytes=5-10'})
    assert download.status_code==206 and download.content==b'simulated signed installer'[5:11]
    with app.state.sessions() as db:
        task=db.scalar(select(DeploymentTask).where(DeploymentTask.deployment_id==deployment.json()['id']))
        task_id=task.id
    assert signed_request(admin,key,fp,'POST',f'/api/v1/agent/deployments/{task_id}/result',{'attempt':1,'state':'SUCCEEDED','verified':False}).status_code==422
    assert signed_request(admin,key,fp,'POST',f'/api/v1/agent/deployments/{task_id}/result',{'attempt':1,'state':'REBOOT_REQUIRED','exit_code':3010}).status_code==200
    assert any(a['action']=='deployment.created' for a in admin.get('/api/v1/audit').json())


def test_repository_and_ssh_are_not_public(client):
    assert client.get('/api/v1/packages').status_code==401
    assert client.get('/api/v1/ssh/sessions').status_code==401
    assert client.get('/api/v1/agent/packages/anything').status_code==401


def test_ssh_rejects_unmanaged_and_disabled(admin,app):
    d=admin.post('/api/v1/devices',json={'hostname':'Dev','primary_mac':'00:11:22:33:44:55','device_class':'DEVELOPER'}).json()
    assert admin.post('/api/v1/devices/'+d['id']+'/ssh-sessions',json={'reason':'Troubleshooting'}).status_code==409
    app.state.settings.ssh_enabled=True
    assert admin.post('/api/v1/devices/'+d['id']+'/ssh-sessions',json={'reason':'Troubleshooting'}).status_code==409
