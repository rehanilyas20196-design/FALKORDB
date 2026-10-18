"""
GraphGuard AI - Project Configuration

Location:
    backend/app/config.py

Loads shared settings from environment variables and the optional
`backend/.env` file. Default values mirror `backend/.env.example`.

Command (run from repository root):
    python -m uvicorn backend.main:app --reload
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Optional local overrides. The file is not required; when it is
# absent, environment variables and the defaults below are used.
ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    """Application settings consumed by API, DB, and AI modules."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # GraphGuard AI - Backend configuration (.env.example)
    FALKORDB_HOST: str = "localhost"
    FALKORDB_PORT: int = 6379
    FALKORDB_PASSWORD: str = ""
    FALKORDB_GRAPH: str = "graphguard"

    # Google Gemini AI
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-pro"

    # Allowed frontend origins. Kept in sync with the fallback
    # used in backend/main.py so http://localhost:5173 is allowed.
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"


settings = Settings()
