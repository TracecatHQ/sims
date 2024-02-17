import gzip
import io
from datetime import datetime, timedelta
from functools import partial
from itertools import chain
from pathlib import Path
from uuid import uuid4

import boto3
import orjson
import polars as pl
from tqdm.contrib.concurrent import thread_map

from tracecat.config import (
    LOGS_FILE_TIMESTAMP_FORMAT,
    TRACECAT__LOGS_DIR,
)
from tracecat.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


AWS_CLOUDTRAIL__LOGS_DIR = TRACECAT__LOGS_DIR / "aws_cloudtrail"
AWS_CLOUDTRAIL__LOGS_DIR.mkdir(parents=True, exist_ok=True)

AWS_CLOUDTRAIL__EVENT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

AWS_CLOUDTRAIL__SELECTED_FIELDS = [
    # Normalized fields
    pl.col("userIdentity").str.json_path_match("$.arn").alias("arn"),
    pl.col("userIdentity").str.json_path_match("$.accessKeyId").alias("accessKeyId"),
    # Original fields
    "userIdentity",
    "userAgent",
    "sourceIPAddress",
    "eventTime",
    "eventName",
    "eventSource",
    "awsRegion",
    "requestParameters",
    "responseElements",
]
AWS_CLOUDTRAIL__NESTED_FIELDS = [
    "userIdentity",
    "requestParameters",
    "responseElements",
]


def _list_objects_under_prefix(prefix: str, bucket_name: str) -> list[str]:
    client = boto3.client("s3")
    paginator = client.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
    object_names = []
    try:
        object_names = [
            content["Key"]
            for content in chain.from_iterable(p["Contents"] for p in pages)
        ]
    except KeyError as err:
        if "Contents" not in str(err):
            raise err
    return object_names


def _list_all_objects_under_prefix(
    account_id: str,
    bucket_name: str,
    date_range: pl.Series,
    regions: list[str],
) -> list[str]:
    prefix_format = (
        "AWSLogs/{account_id}/CloudTrail/{region}/{year}/{month:02d}/{day:02d}/"
    )
    nested_object_names = []
    for region in regions:
        # List all relevant prefixes given dates in date range
        prefixes = iter(
            prefix_format.format(
                account_id=account_id,
                region=region,
                year=dt.year,
                month=dt.month,
                day=dt.day,
            )
            for dt in date_range
        )
        # List all object names that start with prefixes
        start = min(date_range)
        end = max(date_range)
        region_object_names = thread_map(
            partial(_list_objects_under_prefix, bucket_name=bucket_name),
            prefixes,
            desc=f"📂 Enumerate AWS CloudTrail logs between [{start}, {end}]",
        )
        nested_object_names.extend(region_object_names)
    object_names = list(chain.from_iterable(nested_object_names))
    n_objects = len(object_names)
    if n_objects > 1:
        logger.info("Found %s log files", n_objects)
    else:
        raise ValueError(f"⚠️ No logs found between [{start}, {end}]")
    return object_names


def _record_to_json(record: dict, json_fields: list[str]) -> dict:
    normalized_record = {}
    for k, v in record.items():
        if k in json_fields:
            normalized_record[k] = orjson.dumps(v).decode()
        else:
            normalized_record[k] = v
    return orjson.dumps(normalized_record)


def _load_cloudtrail_gzip(
    object_name: str, bucket_name: str, triage_source: Path
) -> Path:
    # Download using boto3
    buffer = io.BytesIO()
    client = boto3.client("s3")
    client.download_fileobj(bucket_name, object_name, buffer)
    # Unzip and save as ndjson
    buffer.seek(0)
    with gzip.GzipFile(fileobj=buffer, mode="rb") as f:
        records = orjson.loads(f.read().decode("utf-8"))["Records"]
    # NOTE: We force nested JSONs to be strings
    ndjson_file_path = (triage_source / uuid4().hex).with_suffix(".ndjson")
    with open(ndjson_file_path, "w") as f:
        # Stream each record into an ndjson file
        for record in records:
            log_bytes = _record_to_json(
                record=record, json_fields=AWS_CLOUDTRAIL__NESTED_FIELDS
            )
            f.write(log_bytes.decode("utf-8") + "\n")
    return ndjson_file_path


def _load_cloudtrail_ndjson(
    ndjson_file_paths: list[Path],
    start: datetime,
    end: datetime,
    malicious_ids: list[str],
    normal_ids: list[str],
) -> Path:
    logger.info("📂 Convert triaged AWS CloudTrail logs into parquet")
    # NOTE: To save space we only keep the minimum number of fields
    timestamp = datetime.utcnow().strftime(LOGS_FILE_TIMESTAMP_FORMAT)
    logs_file_path = (AWS_CLOUDTRAIL__LOGS_DIR / timestamp).with_suffix(".parquet")
    raw_logs = pl.scan_ndjson(ndjson_file_paths, infer_schema_length=None)
    logger.info("🗂️ Filter for events between [%s, %s]", start, end)
    logger.info("🗂️ Filter for malicious IDs: %s", malicious_ids)
    logger.info("🗂️ Filter for normal IDs: %s", normal_ids)
    logs = (
        # NOTE: This might cause memory to blow up
        raw_logs.select(AWS_CLOUDTRAIL__SELECTED_FIELDS)
        .filter(
            pl.col("eventTime")
            .str.strptime(format=AWS_CLOUDTRAIL__EVENT_TIME_FORMAT, dtype=pl.Datetime)
            .is_between(start, end)
        )
        .filter(pl.col("accessKeyId").is_in(malicious_ids + normal_ids))
        # Defensive to avoid concats with mismatched struct column schemas
        .select(pl.all().cast(pl.Utf8))
        .collect(streaming=True)
    )
    logger.info("💾 Write AWS CloudTrail logs to: %s", logs_file_path)
    logs.write_parquet(logs_file_path)
    return logs_file_path


def load_cloudtrail_logs(
    triage_source: Path,
    account_id: str,
    bucket_name: str,
    regions: list[str],
    start: datetime,
    end: datetime,
    malicious_ids: list[str],
    normal_ids: list[str],
) -> Path:
    logger.info(
        "📂 Download AWS CloudTrail logs from: account_id=%s, regions=%s",
        account_id,
        regions,
    )
    # NOTE: We add a 1 day buffer as a defensive
    # measure to deal with possible date spillovers
    # Not the best performance, but it's safer.
    date_range = pl.date_range(
        start=start.date() - timedelta(days=1),  # Defensive
        end=end.date() + timedelta(days=1),  # Defensive
        interval=timedelta(days=1),
        eager=True,
    )
    object_names = _list_all_objects_under_prefix(
        account_id=account_id,
        bucket_name=bucket_name,
        date_range=date_range,
        regions=regions,
    )
    ndjson_file_paths = thread_map(
        partial(
            _load_cloudtrail_gzip, bucket_name=bucket_name, triage_source=triage_source
        ),
        object_names,
        desc="📂 Download AWS CloudTrail logs",
    )
    logs_file_path = _load_cloudtrail_ndjson(
        ndjson_file_paths,
        start=start,
        end=end,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
    )
    return logs_file_path


def load_triaged_cloudtrail_logs(
    triage_source: Path,
    start: datetime,
    end: datetime,
    malicious_ids: list[str],
    normal_ids: list[str],
) -> Path:
    ndjson_file_paths = triage_source.glob("*")
    logs_file_path = _load_cloudtrail_ndjson(
        ndjson_file_paths,
        start=start,
        end=end,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
    )
    return logs_file_path
