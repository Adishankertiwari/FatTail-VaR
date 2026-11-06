"""
config.py
=========
Secrets are NEVER hard-coded or committed. They come from environment variables:

  * locally      : a `.env` file that is listed in .gitignore (loaded by `python-dotenv`)
  * Azure        : App Service > Configuration > Application settings, ideally as
                   Key Vault references:  @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/<name>/)

Required variables
------------------
  DB_SERVER        e.g. myserver.database.windows.net
  DB_NAME          e.g. evt_risk
  DB_USER          SQL login that is a member of the `app_runtime` role
  DB_PASSWORD
  JWT_SECRET       >= 32 random chars   (python -c "import secrets; print(secrets.token_urlsafe(48))")
  AZURE_STORAGE_CONNECTION_STRING        (or AZURE_STORAGE_ACCOUNT_URL + managed identity)

Optional
--------
  BLOB_CONTAINER=raw-csv-uploads   JWT_EXPIRE_MINUTES=30   CORS_ORIGINS=https://app.example.com
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

import pyodbc

try:                                    # optional: only used for local development
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _require(name: str) -> str:
    """Fail fast at start-up if a mandatory secret is missing or empty."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    db_server: str
    db_name: str
    db_user: str
    db_password: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int
    blob_container: str
    blob_connection_string: Optional[str]
    blob_account_url: Optional[str]
    cors_origins: list[str]


def load_settings() -> Settings:
    jwt_secret = _require("JWT_SECRET")
    if len(jwt_secret) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters.")

    blob_conn = os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or None
    blob_url = os.environ.get("AZURE_STORAGE_ACCOUNT_URL") or None
    if not (blob_conn or blob_url):
        raise RuntimeError("Set AZURE_STORAGE_CONNECTION_STRING or AZURE_STORAGE_ACCOUNT_URL.")

    return Settings(
        db_server=_require("DB_SERVER"),
        db_name=_require("DB_NAME"),
        db_user=_require("DB_USER"),
        db_password=_require("DB_PASSWORD"),
        jwt_secret=jwt_secret,
        jwt_algorithm="HS256",
        jwt_expire_minutes=int(os.environ.get("JWT_EXPIRE_MINUTES", "30")),
        blob_container=os.environ.get("BLOB_CONTAINER", "raw-csv-uploads"),
        blob_connection_string=blob_conn,
        blob_account_url=blob_url,
        cors_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()],
    )


settings = load_settings()


def _odbc_escape(value: str) -> str:
    """Wrap in {} and double any '}' so special characters cannot break the connection string."""
    return "{" + value.replace("}", "}}") + "}"


def _connection_string() -> str:
    return (
        "Driver={ODBC Driver 18 for SQL Server};"
        f"Server=tcp:{settings.db_server},1433;"
        f"Database={settings.db_name};"
        f"Uid={_odbc_escape(settings.db_user)};"
        f"Pwd={_odbc_escape(settings.db_password)};"
        "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"   # TLS enforced, cert validated
    )


@contextmanager
def get_connection() -> Iterator[pyodbc.Connection]:
    """
    Transactional connection (autocommit OFF).
    Caller must conn.commit(); any exception rolls the whole unit of work back.
    """
    conn = pyodbc.connect(_connection_string(), autocommit=False)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
