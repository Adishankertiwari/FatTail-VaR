"""
blob_storage.py
===============
DP-900 non-relational store: the RAW uploaded CSV is archived byte-for-byte in
Azure Blob Storage BEFORE it is parsed. Benefits: immutable audit trail,
re-processing after a parser fix, and cheap storage for unstructured objects.

Requires: pip install azure-storage-blob azure-identity
The container (private access level, no anonymous reads) is created by IaC/portal.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from azure.storage.blob import BlobServiceClient, ContentSettings

from config import settings


def _service_client() -> BlobServiceClient:
    if settings.blob_connection_string:
        return BlobServiceClient.from_connection_string(settings.blob_connection_string)

    # Preferred in Azure: passwordless auth via the App Service managed identity
    # (grant the identity the "Storage Blob Data Contributor" role on the container).
    account_url = settings.blob_account_url
    if account_url is None:
        raise RuntimeError("Set AZURE_STORAGE_ACCOUNT_URL when no connection string is configured.")

    from azure.identity import DefaultAzureCredential
    return BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())


def upload_raw_csv(raw_bytes: bytes, ticker: str, uploaded_by: str) -> str:
    """
    Upload the untouched CSV and return the blob name (not a public URL).

    `ticker` and `uploaded_by` MUST already be validated against strict regexes
    (they become part of the blob path / metadata).
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    blob_name = f"raw/{ticker}/{timestamp}_{uuid4().hex}.csv"      # unique => never overwrites

    blob = _service_client().get_blob_client(container=settings.blob_container, blob=blob_name)
    blob.upload_blob(
        raw_bytes,
        overwrite=False,
        content_settings=ContentSettings(content_type="text/csv"),
        metadata={
            "uploaded_by": uploaded_by,
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),       # integrity evidence
            "ticker": ticker,
        },
    )
    return blob_name
