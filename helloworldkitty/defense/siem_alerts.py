"""Functions to download alerts from your SIEM.

Only Datadog Cloud SIEM is currently supported.
"""

import os
from datetime import datetime
from pathlib import Path

import httpx
import orjson
import polars as pl

from helloworldkitty.config import TRACECAT__ALERTS_DIR

TRACECAT__ALERTS_DIR.mkdir(parents=True, exist_ok=True)


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
    path = TRACECAT__ALERTS_DIR / "datadog.parquet"
    (
        pl.from_dicts(events)
        .unnest("attributes")
        .unnest("attributes")
        .explode("samples")
        # We use access key ID as the label for good / bad event
        .select(
            [
                # User
                pl.col("userIdentity").struct.field("arn").alias("arn"),
                pl.col("userIdentity").struct.field("accessKeyId").alias("accessKeyId"),
                pl.col("userIdentity"),
                # Alert timestamp
                pl.col("timestamp").alias("alerted_at"),
                # Severity
                pl.col("status").alias("severity"),
                # Event
                pl.col("samples")
                .struct.field("content")
                .struct.field("custom")
                .struct.field("eventTime"),
                pl.col("samples")
                .struct.field("content")
                .struct.field("custom")
                .struct.field("eventName"),
                # Rule ID
                pl.col("workflow")
                .struct.field("rule")
                .struct.field("defaultRuleId")
                .alias("rule_id"),
                # Rule name
                pl.col("workflow")
                .struct.field("rule")
                .struct.field("name")
                .alias("rule_name"),
            ]
        )
        .write_parquet(path)
    )
    return path
