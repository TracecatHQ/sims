"""Functions to download alerts from your SIEM.

Only Datadog Cloud SIEM is currently supported.
"""

import os
from datetime import datetime
from pathlib import Path

import httpx
import orjson
import polars as pl

from helloworldkitty.config import HWK__ALERTS_DIR

HWK__ALERTS_DIR.mkdir(parents=True, exist_ok=True)


def label_alerts(alerts: str, malicious_ids: list[str]):
    """Label alerts as malicious or not based on an identifier."""
    return alerts.with_columns(is_bad=pl.col("accessKeyId").is_in(malicious_ids))


def get_datadog_alerts(start: datetime, end: datetime, limit: int = 1000) -> Path:
    """Get alerts from Datadog.

    Only CloudTrail alerts are downloaded.
    """
    site = os.environ.get("DD_SITE", "api.datadoghq.com")
    url = f"https://{site}/api/v2/security_monitoring/signals/search"
    dd_api_key = os.environ["DD_API_KEY"]
    dd_app_key = os.environ["DD_APP_KEY"]
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "DD-API-KEY": dd_api_key,
        "DD-APPLICATION-KEY": dd_app_key,
    }
    body = {
        "filter": {
            # Assume UTC
            "from": start.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "to": end.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            # As per the NOTE, only cloudtrail is supported currently
            "query": "source:cloudtrail",
        },
        "page": {"limit": limit},
    }
    with httpx.Client() as client:
        rsp = client.post(url, headers=headers, data=orjson.dumps(body))
        rsp.raise_for_status()

    events = rsp.json()["data"]
    path = HWK__ALERTS_DIR / "datadog.parquet"
    (
        pl.from_dicts(events)
        .unnest("attributes")
        .unnest("attributes")
        # We use access key ID as the label for good / bad event
        .select(
            [
                # User
                pl.col("userIdentity").struct.field("arn"),
                pl.col("userIdentity").struct.field("accessKeyId"),
                # Timestamp
                pl.col("timestamp"),
                # Rule ID
                pl.col("workflow").struct.field("rule").struct.field("defaultRuleId"),
                # Rule name
                pl.col("workflow").struct.field("rule").struct.field("name"),
            ]
        )
        .write_parquet(path)
    )
    return path
