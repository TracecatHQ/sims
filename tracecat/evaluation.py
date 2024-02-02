"""Functions to evaluate fidelity of SIEM alerts."""

from datetime import datetime
from pathlib import Path

import polars as pl
from tracecat.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


def label_malicious_events(events: pl.LazyFrame, malicious_ids: list[str]):
    """Label events (alerts or logs) as malicious or not based on `accessKeyId``."""
    return events.with_columns(is_attack=pl.col("accessKeyId").is_in(malicious_ids))


def correlate_alerts_with_logs(
    alerts_source: Path,
    logs_source: Path,
    malicious_ids: list[str],
) -> pl.DataFrame:
    logger.info("🧲 Correlate alerts with logs")
    correlated_alerts = (
        pl.scan_parquet(logs_source)
        .select(["accessKeyId", "eventTime"])
        .join(
            pl.scan_parquet(alerts_source).select(
                ["accessKeyId", "eventTime", "severity", "rule_id"]
            ),
            on=["accessKeyId", "eventTime"],
            how="left",
        )
        .pipe(label_malicious_events, malicious_ids=malicious_ids)
        .collect()
    )
    return correlated_alerts


def compute_confusion_matrix(correlated_alerts: pl.DataFrame) -> pl.DataFrame:
    # Joins alerts to logs by nearest key
    logger.info("🎯 Score detection rules")
    confusion_matrix = (
        correlated_alerts.lazy()
        .with_columns(has_alert=pl.col("rule_id").is_not_null())
        .select(
            true_positive=(pl.col("is_attack") & pl.col("has_alert")).sum(),
            false_positive=(~pl.col("is_attack") & pl.col("has_alert")).sum(),
            true_negative=(~pl.col("is_attack") & ~pl.col("has_alert")).sum(),
            false_negative=(pl.col("is_attack") & ~pl.col("has_alert")).sum(),
        )
        .collect(streaming=True)
    )
    logger.info("🎯 Final detection rule scores: %s", confusion_matrix)
    return confusion_matrix


if __name__ == "__main__":
    pass
