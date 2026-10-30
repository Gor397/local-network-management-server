"""Approval-bound storage workflow state machine. No operation is part of ordinary policy reconciliation."""
from datetime import timedelta
from typing import Literal
from pydantic import BaseModel,Field,ConfigDict
from sqlalchemy import select
from fastapi import HTTPException
from app.db import utcnow
from app.models import MigrationAssessment,BackgroundJob,PolicyVersion
from app.security.crypto import canonical,digest
from app.auth.dependencies import audit

FOLDERS=('Documents','Downloads','Desktop','Pictures','Videos','Music')

class Assessment(BaseModel):
    model_config=ConfigDict(extra='forbid')
    layout_fingerprint:str=Field(pattern=r'^[a-fA-F0-9]{64}$')
    disk_id:str=Field(min_length=1,max_length=256)
    disk_number:int=Field(ge=0)
    c_partition_number:int=Field(ge=1)
    c_size_bytes:int=Field(gt=0)
    c_free_bytes:int=Field(ge=0)
    shrink_min_bytes:int|None=Field(default=None,ge=0)
    c_healthy:bool
    c_ntfs:bool
    c_unencrypted:bool
    disk_online:bool
    disk_gpt:bool
    d_available:bool
    d_in_use:bool
    user_sid:str|None=Field(default=None,pattern=r'^S-1-5-[0-9-]+$')
    profile_path:str|None=Field(default=None,max_length=512)
    known_folders:dict[str,str]=Field(default_factory=dict,max_length=6)
    partitions:list[dict]=Field(default_factory=list,max_length=128)


def workflow(db,identifier,device_id=None):
    flow=db.scalar(select(MigrationAssessment).where(MigrationAssessment.id==identifier).with_for_update())
    if not flow or not flow.report.get('workflow') or device_id and flow.device_id!=device_id:raise HTTPException(404,'storage.workflow_not_found')
    return flow


def queue(db,flow,device,operation,parameters):
    policy=db.get(PolicyVersion,device.policy_version_id)
    if not policy:raise HTTPException(409,'device.managed_policy_required')
    job=BackgroundJob(device_id=device.id,kind='MAINTENANCE',data={'operation':'storage.'+operation,'workflow_id':flow.id,'policy_version_id':device.policy_version_id,
        'user_account':policy.document['user_account'],'parameters':parameters})
    db.add(job);db.flush();flow.report={**flow.report,'job_id':job.id}
    return job


def preview(flow,create_d_gib,folders):
    if flow.status not in ('BACKUP_VERIFIED','PLAN_PREVIEW'):raise HTTPException(409,'storage.verified_backup_required')
    if not flow.backup_verified_at or flow.backup_verified_at<utcnow()-timedelta(hours=6):raise HTTPException(409,'storage.backup_expired')
    actual=Assessment.model_validate(flow.report['assessment'])
    if create_d_gib and folders:raise HTTPException(422,'storage.separate_phases_required')
    if not create_d_gib and not folders:raise HTTPException(422,'storage.no_changes')
    if not actual.c_healthy or not actual.c_ntfs or not actual.disk_online:raise HTTPException(409,'storage.manual_intervention_required')
    if create_d_gib:
        size=create_d_gib*1024**3
        if actual.d_in_use or not actual.disk_gpt or not actual.c_unencrypted or actual.shrink_min_bytes is None or actual.c_size_bytes-size-1024**2<actual.shrink_min_bytes or actual.c_free_bytes-size<30*1024**3:
            raise HTTPException(409,'storage.manual_intervention_required')
    if folders and (not actual.d_available or not actual.user_sid or any(f not in actual.known_folders for f in folders)):
        raise HTTPException(409,'storage.manual_intervention_required')
    plan={'layout_fingerprint':actual.layout_fingerprint,'disk_id':actual.disk_id,'create_d_gib':create_d_gib,'folders':folders,
        'assessment':actual.model_dump(),'backup':flow.report['backup'],'backup_job_id':flow.report['backup_job_id']}
    flow.report={**flow.report,'plan':plan,'plan_hash':digest(canonical(plan))};flow.status='PLAN_PREVIEW'
    return plan


def receive_result(db,job,body):
    flow=workflow(db,job.data['workflow_id'],job.device_id)
    if flow.report.get('job_id')!=job.id:raise HTTPException(409,'storage.stale_job')
    details=body.details
    if body.state!='SUCCEEDED':
        flow.status='MANUAL_INTERVENTION_REQUIRED' if body.state=='MANUAL_INTERVENTION_REQUIRED' else 'RECOVERY_REQUIRED'
        flow.report={**flow.report,'last_result':details};return
    operation=job.data['operation']
    if operation=='storage.assess':
        actual=Assessment.model_validate(details['assessment'])
        flow.report={**flow.report,'assessment':actual.model_dump()};flow.status='ASSESSED'
    elif operation=='storage.backup':
        backup=details.get('backup',{})
        if not backup.get('restore_test_passed') or not backup.get('canary_sha256') or backup.get('layout_fingerprint')!=flow.report['assessment']['layout_fingerprint']:
            raise HTTPException(422,'storage.restore_verification_required')
        flow.report={**flow.report,'backup':backup,'backup_job_id':job.id};flow.backup_verified_at=utcnow();flow.status='BACKUP_VERIFIED'
    elif operation=='storage.apply':
        if not details.get('verified'):raise HTTPException(422,'storage.verification_required')
        flow.report={**flow.report,'last_result':details};flow.status='SUCCEEDED'
    audit(db,job.device_id,'storage.phase_result',flow.id,phase=operation,state=flow.status)
