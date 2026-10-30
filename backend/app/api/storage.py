from typing import Literal
from datetime import timedelta
from fastapi import APIRouter,Depends,HTTPException,Request
from pydantic import BaseModel,Field
from sqlalchemy import select
from app.auth.dependencies import db_session,require,audit
from app.models import MigrationAssessment,Device
from app.security.crypto import canonical,digest
from app.services.devices import device_or_404
from app.services import storage as service
from app.db import utcnow

router=APIRouter(tags=['approved storage workflows'])

class Reason(BaseModel):
    reason:str=Field(min_length=5,max_length=2000)

@router.post('/devices/{device_id}/storage-workflows')
def create(device_id:str,body:Reason,admin=Depends(require('approve',mfa=True)),db=Depends(db_session)):
    device=device_or_404(db,device_id)
    if device.device_class=='DEVELOPER' or not device.policy_version_id:raise HTTPException(409,'device.managed_policy_required')
    flow=MigrationAssessment(device_id=device.id,inventory_hash=digest(canonical(device.inventory)),status='ASSESSING',report={'workflow':True,'reason':body.reason})
    db.add(flow);db.flush();job=service.queue(db,flow,device,'assess',{})
    audit(db,admin.id,'storage.assessment_requested',flow.id,reason=body.reason)
    return {'id':flow.id,'job_id':job.id,'state':flow.status}

@router.get('/devices/{device_id}/storage-workflows')
def list_workflows(device_id:str,admin=Depends(require('manage')),db=Depends(db_session)):
    return [{'id':f.id,'state':f.status,'report':f.report,'backup_verified_at':f.backup_verified_at,'approved_by':f.approved_by,'created_at':f.created_at} for f in db.scalars(select(MigrationAssessment).where(MigrationAssessment.device_id==device_id).order_by(MigrationAssessment.created_at.desc()).limit(50)) if f.report.get('workflow')]

class Backup(Reason):
    backup_drive:str=Field(pattern=r'^[A-BE-Z]$')

@router.post('/storage-workflows/{identifier}/backup')
def backup(identifier:str,body:Backup,admin=Depends(require('approve',mfa=True)),db=Depends(db_session)):
    flow=service.workflow(db,identifier);d=device_or_404(db,flow.device_id)
    if flow.status!='ASSESSED' or d.mode not in ('MAINTENANCE','APPROVED_REMEDIATION'):raise HTTPException(409,'storage.approved_mode_required')
    job=service.queue(db,flow,d,'backup',{'backup_drive':body.backup_drive,'assessment':flow.report['assessment']});flow.status='BACKING_UP'
    audit(db,admin.id,'storage.backup_approved',flow.id,reason=body.reason,target_drive=body.backup_drive)
    return {'job_id':job.id,'state':flow.status}

class Preview(Reason):
    create_d_gib:int|None=Field(default=None,ge=20,le=2048)
    folders:list[Literal['Documents','Downloads','Desktop','Pictures','Videos','Music']]=Field(default_factory=list,max_length=6)

@router.post('/storage-workflows/{identifier}/preview')
def preview(identifier:str,body:Preview,admin=Depends(require('approve',mfa=True)),db=Depends(db_session)):
    flow=service.workflow(db,identifier);plan=service.preview(flow,body.create_d_gib,body.folders)
    audit(db,admin.id,'storage.preview_created',flow.id,reason=body.reason,plan_hash=flow.report['plan_hash'])
    return {'state':flow.status,'plan':plan,'plan_hash':flow.report['plan_hash']}

class Approval(Reason):
    plan_hash:str
    confirm_disk_id:str
    confirm_backup_job_id:str
    confirm_restore_reviewed:bool

@router.post('/storage-workflows/{identifier}/approve')
def approve(identifier:str,body:Approval,request:Request,admin=Depends(require('approve',mfa=True)),db=Depends(db_session)):
    flow=service.workflow(db,identifier);d=device_or_404(db,flow.device_id)
    if not request.app.state.settings.storage_changes_enabled:raise HTTPException(409,'storage.writes_disabled')
    if flow.status!='PLAN_PREVIEW' or d.mode not in ('MAINTENANCE','APPROVED_REMEDIATION'):raise HTTPException(409,'storage.approved_mode_required')
    if not flow.backup_verified_at or flow.backup_verified_at<utcnow()-timedelta(hours=6):raise HTTPException(409,'storage.backup_expired')
    if body.plan_hash!=flow.report['plan_hash'] or body.confirm_disk_id!=flow.report['assessment']['disk_id'] or body.confirm_backup_job_id!=flow.report['backup_job_id'] or not body.confirm_restore_reviewed:raise HTTPException(409,'storage.confirmation_mismatch')
    job=service.queue(db,flow,d,'apply',flow.report['plan']);flow.status='APPROVED';flow.approved_by=admin.id
    audit(db,admin.id,'storage.migration_approved',flow.id,job_id=job.id,plan_hash=body.plan_hash,reason=body.reason)
    return {'state':flow.status,'job_id':job.id}
