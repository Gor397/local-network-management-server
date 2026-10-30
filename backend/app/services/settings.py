from app.models import SystemSetting

MONITORING_KEYS = (
    "low_resource_mode",
    "network_health_seconds",
    "network_inventory_seconds",
    "network_poll_concurrency",
    "telemetry_retention_days",
    "recovery_enabled",
)


def apply_monitoring(db, settings):
    stored = db.get(SystemSetting, "monitoring")
    if stored:
        for key in MONITORING_KEYS:
            if key in stored.value:
                setattr(settings, key, stored.value[key])
