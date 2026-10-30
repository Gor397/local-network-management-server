"""Server-wide operation modes. Enforced at execution and transport, not only in the dashboard.

read_only        discovery/monitoring only; no router writes, no endpoint changes, agents audit only
dry_run          like read_only, but plan execution returns the exact operations it would send
controlled_test  writes only to routers/devices named in TEST_ROUTERS / TEST_DEVICES
production       writes to routers whose per-router write switch is enabled
"""
from urllib.parse import urlparse

MODES = ("read_only", "dry_run", "controlled_test", "production")
# RouterOS commands that only observe state. Everything else is treated as a write.
READ_COMMANDS = frozenset({"ping", "interface/monitor-traffic", "file/read"})


def operation_mode(settings):
    # Legacy installations only had ROUTER_WRITES_ENABLED; keep their behavior when no mode is set.
    return settings.operation_mode or ("production" if settings.router_writes_enabled else "read_only")


def blocks_all_changes(settings):
    """Explicit read_only/dry_run code, or None. Unset OPERATION_MODE keeps legacy endpoint behavior."""
    return "safety." + settings.operation_mode if settings.operation_mode in ("read_only", "dry_run") else None


def _listed(value, *candidates):
    names = {item.strip().lower() for item in value.split(",") if item.strip()}
    return any(c and c.lower() in names for c in candidates)


def router_write_block(settings, router):
    """Return an error code when a write to this router is not permitted, otherwise None."""
    mode = operation_mode(settings)
    if mode in ("read_only", "dry_run"):
        return "safety." + mode
    if getattr(router, "transport", None) == "API":
        return "network.plaintext_read_only"
    if getattr(router, "transport", None) == "CAPSMAN":
        return "router.managed_by_controller"
    if router.archived or not router.write_enabled:
        return "network.writes_disabled"
    if mode == "controlled_test" and not _listed(settings.test_routers, router.id, router.name, urlparse(router.base_url).hostname):
        return "safety.not_test_router"
    return None


def ensure_router_write(settings, router):
    code = router_write_block(settings, router)
    if code:
        raise ValueError(code)


def endpoint_change_block(settings, device):
    """Return an error code when a Windows endpoint may not receive changes, otherwise None."""
    # Without an explicit mode, endpoint changes stay governed by DEPLOYMENT_ENABLED and device modes.
    if blocks := blocks_all_changes(settings):
        return blocks
    if settings.operation_mode == "controlled_test" and not _listed(settings.test_devices, device.id, device.hostname):
        return "safety.not_test_device"
    return None


def agent_mode(settings, device):
    # Agents remediate only in CONTINUOUS/APPROVED_REMEDIATION; outside the permitted scope they only audit.
    return "AUDIT" if endpoint_change_block(settings, device) and device.mode in ("CONTINUOUS", "APPROVED_REMEDIATION", "MAINTENANCE") else device.mode


class GuardedRouter:
    """Wraps a RouterOS adapter so no write can leave the server in a non-writing mode, whatever the caller."""

    def __init__(self, inner, settings, router):
        self.inner, self.settings, self.router = inner, settings, router

    async def __aenter__(self):
        await self.inner.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.inner.__aexit__(*args)

    async def read(self, *args, **kwargs):
        return await self.inner.read(*args, **kwargs)

    async def discovery(self):
        return await self.inner.discovery()

    async def command(self, path, data=None):
        if path not in READ_COMMANDS:
            ensure_router_write(self.settings, self.router)
        return await self.inner.command(path, data)

    async def configure(self, path, record_id, data):
        ensure_router_write(self.settings, self.router)
        return await self.inner.configure(path, record_id, data)

    async def apply(self, operation):
        ensure_router_write(self.settings, self.router)
        return await self.inner.apply(operation)
