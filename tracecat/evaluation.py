"""Functions to evaluate fidelity of SIEM alerts."""

from pathlib import Path

import polars as pl


def label_malicious_events(events: pl.LazyFrame, malicious_ids: list[str]):
    """Label events (alerts or logs) as malicious or not based on `accessKeyId``."""
    return events.with_columns(is_attack=pl.col("accessKeyId").is_in(malicious_ids))


def correlate_alerts_with_logs(
    alerts_source: Path,
    logs_source: Path,
    malicious_ids: list[str],
) -> pl.DataFrame:
    correlated_alerts = (
        pl.scan_parquet(logs_source)
        .select(["accessKeyId", "eventTime"])
        .join(
            pl.scan_parquet(alerts_source).select(
                ["accessKeyId", "eventTime", "severity", "rule_id", "rule_name"]
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
    confusion_matrix = (
        correlated_alerts.lazy()
        .with_columns(has_alert=pl.col("rule_id").is_not_null())
        .groupby(["rule_id", "rule_name"])
        .agg(
            true_positive=(pl.col("is_attack") & pl.col("has_alert")).sum(),
            false_positive=(~pl.col("is_attack") & pl.col("has_alert")).sum(),
            true_negative=(~pl.col("is_attack") & ~pl.col("has_alert")).sum(),
            false_negative=(pl.col("is_attack") & ~pl.col("has_alert")).sum(),
        )
        .collect(streaming=True)
    )
    return confusion_matrix


def compute_event_counts(logs_source: Path, eager: bool = False) -> pl.DataFrame | pl.LazyFrame:
    counts = (
        pl.scan_parquet(logs_source)
        .select(pl.col("eventName").value_counts())
        .unnest("eventName")
    )
    if eager:
        counts = counts.collect()
    return counts


def compute_event_percentage_counts(
    logs_source: Path,
    include_absolute: bool = False
) -> pl.DataFrame:
    counts = (
        compute_event_counts(logs_source=logs_source)
        .with_columns(percentage_count=pl.col("count") / pl.col("count").sum())
    )
    if not include_absolute:
        counts = counts.drop("count")
    counts = counts.collect()
    return counts
