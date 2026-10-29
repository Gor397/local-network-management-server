def assess(inventory):
    volumes = inventory.get("volumes", [])
    has_d = any(v.get("drive") == "D" for v in volumes)
    disk = inventory.get("storage_readiness", {})
    blockers = [key for key in ("backup_restore_tested", "filesystem_healthy", "shrink_supported", "recovery_key_escrowed") if not disk.get(key)]
    return {
        "current": {"users": inventory.get("users", []), "volumes": volumes, "firewall": inventory.get("firewall", {})},
        "safe_automatic_changes": ["inventory.refresh"],
        "approval_required": [] if has_d else ["storage.create_data_volume", "storage.migrate_known_folders"],
        "unsupported_or_unsafe": blockers,
        "status": "REVIEW_REQUIRED" if has_d else "MANUAL_INTERVENTION_REQUIRED",
        "estimated_risk": "LOW" if has_d else "HIGH",
        "backup_requirements": ["Verified backup of affected volumes", "Successful restore test", "BitLocker recovery material escrow", "Out-of-band administrator access"],
        "destructive_execution_available": False,
    }
