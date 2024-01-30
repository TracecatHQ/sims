import os
from pathlib import Path

import httpx
import polars as pl
from tracecat.config import TRACECAT__RULES_DIR

TRACECAT__RULES_DIR.mkdir(parents=True, exist_ok=True)


def get_datadog_rules(max_pages: int = 15, page_size: int = 100) -> Path:
    """Get log detection rules from Datadog."""
    site = os.environ.get("DD_SITE", "api.datadoghq.com")
    url = f"https://{site}/api/v2/security_monitoring/rules"
    dd_api_key = os.environ["DD_API_KEY"]
    dd_app_key = os.environ["DD_APP_KEY"]
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "DD-API-KEY": dd_api_key,
        "DD-APPLICATION-KEY": dd_app_key,
    }
    rules = []
    for i in range(max_pages):
        with httpx.Client() as client:
            rsp = client.get(
                url,
                headers=headers,
                params={"page[size]": page_size, "page[number]": i},
            )
            rsp.raise_for_status()
            obj = rsp.json()
        # Unpack rules
        listed_rules = obj["data"]
        rules.extend(listed_rules)
        if len(listed_rules) < page_size:
            break

    path = TRACECAT__RULES_DIR / "datadog.parquet"
    tagged_rules = (
        pl.LazyFrame(rules).unique("id").filter(pl.col("type") == "log_detection")
    )
    # Unpack tags
    tags = tagged_rules.select(["id", "tags"]).explode("tags")
    sources = tags.filter(pl.col("tags").str.starts_with("source:")).rename(
        {"tags": "source"}
    )
    tactics = tags.filter(pl.col("tags").str.starts_with("tactic:")).rename(
        {"tags": "tactic"}
    )
    techniques = tags.filter(pl.col("tags").str.starts_with("technique:")).rename(
        {"tags": "technique"}
    )
    # Join it back to detection rules
    detection_rules = (
        tagged_rules.join(sources, on="id", how="left")
        .join(tactics, on="id", how="left")
        .join(techniques, on="id", how="left")
        .drop("tags")
        # Reorder columns
        .select(
            [
                pl.col("id").alias("rule_id"),
                pl.col("name").alias("rule_name"),
                pl.col("source").str.strip_prefix("source:"),
                pl.col("tactic").str.strip_prefix("tactic:"),
                pl.col("technique").str.strip_prefix("technique:"),
                pl.col("queries"),
                pl.col("options"),
                pl.col("cases"),
                pl.col("message"),
                pl.col("isDefault").alias("is_default"),
                pl.col("isEnabled").alias("is_enabled"),
                pl.col("isDeleted").alias("is_deleted"),
            ]
        )
        .sort(["source", "tactic", "technique"])
    )
    detection_rules.sink_parquet(path)
    return path


if __name__ == "__main__":
    print(get_datadog_rules())
