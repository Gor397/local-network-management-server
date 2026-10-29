from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://lantern@db/lantern"
    data_dir: Path = Path("data")
    public_origin: str = "https://localhost"
    cookie_secure: bool = True
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    encryption_key: str
    low_resource_mode: bool = True
    router_writes_enabled: bool = False
    deployment_enabled: bool = False
    ssh_enabled: bool = False
    heartbeat_deadline_seconds: int = 300
    evidence_ttl_seconds: int = 300
    max_upload_bytes: int = 8 * 1024**3
    upload_chunk_bytes: int = 4 * 1024**2
    deployment_concurrency: int = 2
    transfer_bytes_per_second: int = 2 * 1024**2
    health_retention_days: int = 7
    router_allowed_networks: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    ssh_allowed_networks: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

    @property
    def poll_seconds(self):
        return 120 if self.low_resource_mode else 60
