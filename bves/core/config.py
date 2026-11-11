"""Central configuration, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    """Immutable application settings."""

    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int
    ipfs_api_url: str
    rpc_url: str
    deployment_file: str
    signer_private_key: str
    master_key_file: str
    master_key_b64: str
    incoming_dir: str
    batch_size: int
    batch_window_seconds: int
    api_url: str
    investigator_password: str
    auditor_password: str
    admin_password: str


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings object."""
    return Settings(
        database_url=_env("DATABASE_URL", "sqlite:///./bves.db"),
        jwt_secret=_env("JWT_SECRET", "change-me-in-.env"),
        jwt_expire_minutes=int(_env("JWT_EXPIRE_MINUTES", "60")),
        ipfs_api_url=_env("IPFS_API_URL", "http://localhost:5001"),
        rpc_url=_env("RPC_URL", "http://localhost:8545"),
        deployment_file=_env("DEPLOYMENT_FILE", "shared/deployment.json"),
        signer_private_key=_env("SIGNER_PRIVATE_KEY", ""),
        master_key_file=_env("MASTER_KEY_FILE", "shared/master.key"),
        master_key_b64=_env("MASTER_KEY_B64", ""),
        incoming_dir=_env("INCOMING_DIR", "incoming"),
        batch_size=int(_env("BATCH_SIZE", "4")),
        batch_window_seconds=int(_env("BATCH_WINDOW_SECONDS", "30")),
        api_url=_env("API_URL", "http://localhost:8000"),
        investigator_password=_env("INVESTIGATOR_PASSWORD", "investigator123"),
        auditor_password=_env("AUDITOR_PASSWORD", "auditor123"),
        admin_password=_env("ADMIN_PASSWORD", "admin123"),
    )
