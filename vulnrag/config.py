from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNRAG_", env_file=".env")

    nvd_start_date: str = "2019-01-01"
    nvd_api_key: str | None = None
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    collection: str = "vulnerabilities"
    embed_model: str = "bge-m3"
    embed_dim: int = 1024
    llm_model: str = "qwen2.5:3b"
    ollama_host: str = "http://localhost:11434"
    top_k: int = 8
    sync_state_path: str = "sync_state.json"
