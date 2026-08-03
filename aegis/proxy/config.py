"""Proxy configuration.

Defaults point at the bundled mock model server so the whole system runs offline with no
API key. Set AEGIS_UPSTREAM_BASE_URL and AEGIS_UPSTREAM_API_KEY to use a real provider;
any OpenAI-compatible endpoint works, including Groq.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    upstream_base_url: str = "http://127.0.0.1:8100/v1"
    upstream_api_key: str = ""
    request_timeout_seconds: float = 60.0

    #: Retain assembled context in the trace store. Required by Phase 2's ablation engine,
    #: which needs the exact bytes the model saw in order to remove segments from them.
    retain_context: bool = True

    max_traces: int = 1000


settings = ProxySettings()
