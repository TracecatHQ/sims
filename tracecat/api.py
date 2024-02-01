from __future__ import annotations

import asyncio
from datetime import datetime
import json
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Optional

import numpy as np
import polars as pl
from dotenv import find_dotenv, load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from tracecat.agents import TRACECAT__LAB_ACTIONS_LOGS_PATH
from tracecat.config import TRACECAT__API_DIR
from tracecat.lab import (
    LabResults,
    evaluate_lab,
    clean_up_lab,
    run_lab,
)
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


TRACECAT__API_DIR.mkdir(parents=True, exist_ok=True)
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


@app.get("/lab", response_model=LabResults)
def get_lab(
    scenario_id: str,
    bucket_name: str | None = None,
    regions: list[str] | None = None,
    account_id: str = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    buffer_time: int | None = None,
    triage: bool = False,
):
    """Get lab results.
    
    Assumes lab simulation succesfully finished.
    """
    # NOTE: Very crude approximation...will need a place
    # to store state of start and time detonation times.
    # NOTE: The more buffer the safer: at least 6 hours.
    # It's easier to deal with duplicate events downstream
    # than no events at all...
    logger.info("🔬 Evaluate lab simulation")
    buffer_time = buffer_time or 21_600
    buffer_delta = timedelta(seconds=buffer_time)
    now = datetime.now().replace(second=0, microsecond=0)
    results = evaluate_lab(
        scenario_id=scenario_id,
        start=now - buffer_delta,
        end=now + buffer_delta,
        account_id=account_id,
        bucket_name=bucket_name,
        regions=regions,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
        triage=triage
    )
    return results


@app.post("/lab")
async def create_lab(
    scenario_id: str,
    background_tasks: BackgroundTasks,
    skip_simulation: bool = False,
    timeout: int | None = None,
    delayed_seconds: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
    task_retries: int | None = None,
):
    """Run detections lab."""
    background_tasks.add_task(
        run_lab,
        scenario_id=scenario_id,
        skip_simulation=skip_simulation,
        timeout=timeout,
        delayed_seconds=delayed_seconds,
        max_tasks=max_tasks,
        max_actions=max_actions,
        task_retries=task_retries,
    )
    return {"message": "Lab created"}


@app.delete("/lab")
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


# TODO: Change this out for a real implementation
TEMPORARY_AUTOTUNE_DB_PATH = Path(".data/datadog.parquet").expanduser()


@app.get("/autotune/banner")
def get_autotune_banner():
    return [
        {"key": "fixed-detections", "value": "11", "subtitleValue": "159"},
        {"key": "hours-saved", "value": "52 Hours", "subtitleValue": "457"},
        {"key": "money-saveable", "value": "$19283", "subtitleValue": "268901"},
    ]


@app.get("/autotune/rules/")
def get_all_rules():
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
    df = (
        pl.scan_parquet(TEMPORARY_AUTOTUNE_DB_PATH)
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
        .rename({"rule_id": "id", "rule_name": "ruleName", "tactic": "ttp"})
        .with_columns(
            score=np.random.randint(0, 100, df.height),
            status=pl.lit("active"),
            timeSavable=np.random.randint(30, 100, df.height),
            severity=np.random.choice(["low", "medium", "high"], df.height),
            newQueries=pl.lit(new_query),
            newCases=pl.lit(new_cases),
        )
        .collect(streaming=True)
        .to_dicts()
    )


@app.get("/autotune/rules/{id}")
def get_rule(id: str):
    return (
        pl.scan_parquet(TEMPORARY_AUTOTUNE_DB_PATH)
        .filter(pl.col.id == id)
        .with_columns(
            score=pl.lit(np.randint(0, 100)),
            status=pl.lit("active"),
            timeSavable=pl.lit(np.randint(0, 100)),
            severity=np.random.choice(["low", "medium", "high"]),
        )
        .collect(streaming=True)
        .to_dicts()[0]
    )
