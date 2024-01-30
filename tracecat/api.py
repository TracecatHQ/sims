from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Optional

import polars as pl
from dotenv import find_dotenv, load_dotenv
from datetime import timedelta
from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from tracecat.agents import TRACECAT__LAB_ACTIONS_LOGS_PATH
from tracecat.config import TRACECAT__API_DIR
from tracecat.lab import (
    LabInformation,
    check_lab,
    clean_up_lab,
    run_lab,
)
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


API_CALL_STATISTICS_FILE_PATH = TRACECAT__API_DIR / "api_calls.json"
ACTION_STATISTICS_FILE_PATH = TRACECAT__API_DIR / "action_statistics.json"
STATISTICS_FILE_PATH = TRACECAT__API_DIR / "statistics.json"


API_CALL_STATISTICS_FILE_PATH.touch(exist_ok=True)
ACTION_STATISTICS_FILE_PATH.touch(exist_ok=True)
STATISTICS_FILE_PATH.touch(exist_ok=True)


API_CALL_STATISTICS_FILE_LOCK = asyncio.Lock()
ACTION_STATISTICS_FILE_LOCK = asyncio.Lock()
TRACECAT__LOG_QUEUES: dict[str, asyncio.Queue] = {}

for q in ["statistics", "activity"]:
    TRACECAT__LOG_QUEUES[q] = asyncio.Queue()


async def tail_file_handler():
    async for line in tail_file(TRACECAT__LAB_ACTIONS_LOGS_PATH):
        line = line.strip()
        for _, q in TRACECAT__LOG_QUEUES.items():
            await q.put(line)


async def update_stats_handler():

    while True:
        item = await TRACECAT__LOG_QUEUES["statistics"].get()
        item = json.loads(item)

        async with API_CALL_STATISTICS_FILE_LOCK:
            data = safe_json_load(API_CALL_STATISTICS_FILE_PATH)

            # update api call frequency
            action = item["action"]
            data[action] = data.get(action, 0) + 1
            with API_CALL_STATISTICS_FILE_PATH.open("w") as f:
                json.dump(data, f)

        async with ACTION_STATISTICS_FILE_LOCK:
            # Update total api calls per user
            # If user bad update bad user count
            data = safe_json_load(ACTION_STATISTICS_FILE_PATH)

            # update bad api call frequency
            data["bad_api_calls_count"] = data.get("bad_api_calls_count", 0) + 1
            action = item["action"]
            data[action] = data.get(action, 0) + 1
            with ACTION_STATISTICS_FILE_PATH.open("w") as f:
                json.dump(data, f)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Context manager to run the API for its lifespan."""
    logger.info("Starting API")
    asyncio.create_task(tail_file_handler())
    asyncio.create_task(update_stats_handler())
    yield


app = FastAPI(debug=True, default_response_class=ORJSONResponse, lifespan=lifespan)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://localhost:3001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ENABLED_OPTIONAL_FEATURES = {}


def safe_json_load(path: Path) -> dict:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        return {}
    elif path.stat().st_size == 0:
        return {}
    with path.open("r") as f:
        return json.load(f)


@app.get("/")
def root():
    return {"status": "ok"}


# Core API


@app.get("lab", response_model=LabInformation)
def get_lab():
    """Get lab information."""
    check_lab()


@app.post("lab")
async def create_lab(
    scenario_id: str,
    background_tasks: BackgroundTasks,
    timeout: int | None = None,
    delayed_seconds: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
    bucket_name: str | None = None,
    regions: list[str] | None = None,
    account_id: str = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    task_retries: int | None = None,
    buffer_time: timedelta | None = None,
    triage: bool = False,
):
    """Run detections lab."""
    background_tasks.add_task(
        run_lab,
        scenario_id=scenario_id,
        timeout=timeout,
        delayed_seconds=delayed_seconds,
        max_tasks=max_tasks,
        max_actions=max_actions,
        bucket_name=bucket_name,
        regions=regions,
        account_id=account_id,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
        task_retries=task_retries,
        buffer_time=buffer_time,
        triage=triage
    )
    return {"message": "Lab created"}


@app.delete("lab")
def delete_lab():
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """
    clean_up_lab()


# Live Agent Feeds


@app.get("/feed/activity", response_class=EventSourceResponse)
async def stream_activity():
    async def log_stream():
        while True:
            item = await TRACECAT__LOG_QUEUES["activity"].get()
            yield item

    return EventSourceResponse(log_stream())


class StatsFeedUpdate(BaseModel):
    """
    Represents a stats feed update.

    Attributes:
        time (datetime): The time of the update.
        data (dict[str, Any]): The data of the update.
    """

    id: str
    title: str
    value: Any
    description: str
    units: Optional[str] = None
    data: Optional[dict[str, Any]] = None


# Polling statistics
def validate_statistics_id(id: str):
    if not len(id) == 9 or not id.startswith("STAT-"):
        raise HTTPException(status_code=400, detail="Invalid stat ID")
    return id


@app.get("/feed/statistics/{id}")
async def stream_statistics(id: Annotated[str, Depends(validate_statistics_id)]):
    if id == "STAT-0005":
        data = safe_json_load(API_CALL_STATISTICS_FILE_PATH)

        return {
            "id": "STAT-0005",
            "title": "Total actions taken",
            "value": sum(data.values()),
            "description": "",
        }
    elif id == "STAT-0006":
        data = safe_json_load(ACTION_STATISTICS_FILE_PATH)

        denom = sum(data.values())
        value = 0 if denom == 0 else data.get("bad_api_calls_count", 0) / denom * 100
        return {
            "id": "STAT-0006",
            "title": "% of actions used by adversaries",
            "value": value,
            "units": "%",
            "description": "",
        }
    stats = safe_json_load(STATISTICS_FILE_PATH)
    for item in stats:
        if item["id"] == id:
            return item
    raise HTTPException(status_code=404, detail="Stat ID not found")


def validate_events_id(id: str):
    if not len(id) == 10 or not id.startswith("GRAPH-"):
        raise HTTPException(status_code=400, detail="Invalid stat ID")
    return id


@app.get("/feed/events/{id}")
async def stream_events_distribution(id: Annotated[str, Depends(validate_events_id)]):
    """Returns events distribution feed."""
    path = TRACECAT__API_DIR / "api_calls.json"
    calls = safe_json_load(path)
    return calls


@app.get("/autotune/banner")
def get_autotune_banner():
    return [
        {"key": "fixed-detections", "value": "11", "subtitleValue": "159"},
        {"key": "hours-saved", "value": "52 Hours", "subtitleValue": "457"},
        {"key": "money-saveable", "value": "$19283", "subtitleValue": "268901"},
    ]


@app.get("/autotune/rules/")
def get_all_rules():
    import numpy as np

    df = (
        pl.scan_parquet(".data/datadog.parquet")
        .drop_nulls()
        .select(
            [
                "rule_id",
                "rule_name",
                "source",
                "tactic",
                "technique",
                "queries",
                "cases",
                "message",
            ]
        )
        .collect(streaming=True)
    )
    return (
        df.lazy()
        .with_columns(
            score=np.random.randint(0, 100, df.height),
            status=pl.lit("active"),
            timeSaved=np.random.randint(30, 100, df.height),
            severity=np.random.choice(["low", "medium", "high"], df.height),
        )
        .rename({"rule_id": "id", "rule_name": "ruleName", "tactic": "ttp"})
        .collect(streaming=True)
        .to_dicts()
    )


new_query = [
    {
        "query": "source:(apache OR nginx) (@http.referrer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http.user_agent:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*))",
        "groupByFields": [],
        "hasOptionalGroupByFields": False,
        "distinctFields": [],
        "metric": None,
        "metrics": None,
        "aggregation": "count",
        "name": "standard_attributes",
    },
    {
        "query": "source:(apache OR nginx) (@http_referer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http_referrer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http_user_agent:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*))",
        "groupByFields": [],
        "hasOptionalGroupByFields": False,
        "distinctFields": [],
        "metric": None,
        "metrics": None,
        "aggregation": "count",
        "name": "non_standard_attributes",
    },
]
new_cases = [
    {
        "name": "standard attribute query triggered",
        "status": "medium",
        "notifications": [],
        "condition": "standard_attributes > 0",
    },
    {
        "name": "non standard attribute query triggered",
        "status": "medium",
        "notifications": [],
        "condition": "non_standard_attributes > 0",
    },
]


@app.get("/autotune/rules/{id}")
def get_rule(id: str):
    return (
        pl.scan_parquet(".data/datadog.parquet")
        .filter(pl.col.id == id)
        .collect(streaming=True)
        .to_dicts()[0]
    )
