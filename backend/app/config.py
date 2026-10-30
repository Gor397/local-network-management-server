from pathlib import Path
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://lantern@db/lantern"
    data_dir: Path = Path("data")
    public_origin: str = "https://localhost"
    # Only the onboarding proxy may state the browser's address (X-Suro-Client-Ip) for /onboard/status.
    trusted_proxy_networks: str = "127.0.0.1/32,172.16.0.0/12"
    # The Suro server's LAN IPv4 that gated computers may always reach; defaults to the IP in PUBLIC_ORIGIN.
    management_address: str = ""
    cookie_secure: bool = True
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    encryption_key: str
    low_resource_mode: bool = True
    router_writes_enabled: bool = False
    # See services/safety.py. Empty keeps the legacy ROUTER_WRITES_ENABLED behavior.
    operation_mode: Literal["", "read_only", "dry_run", "controlled_test", "production"] = ""
    test_routers: str = ""
    test_devices: str = ""
    # Unencrypted RouterOS API (8728) for routers without an API-SSL certificate. Read-only even when enabled.
    router_plaintext_api_allowed: bool = False
    deployment_enabled: bool = False
    ssh_enabled: bool = False
    mfa_required: bool = False
    mfa_login_required: bool = False
    network_poll_concurrency: int = 2
    network_health_seconds: int = 60
    network_inventory_seconds: int = 900
    telemetry_retention_days: int = 7
    recovery_enabled: bool = False
    heartbeat_deadline_seconds: int = 300
    evidence_ttl_seconds: int = 300
    max_upload_bytes: int = 8 * 1024**3
    upload_chunk_bytes: int = 4 * 1024**2
    deployment_concurrency: int = 2
    transfer_bytes_per_second: int = 2 * 1024**2
    transfer_global_bytes_per_second: int = 2 * 1024**2
    transfer_concurrency: int = 2
    upload_retention_days: int = 7
    health_retention_days: int = 7
    router_allowed_networks: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    ssh_allowed_networks: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

    @property
    def poll_seconds(self):
        return 120 if self.low_resource_mode else 60
