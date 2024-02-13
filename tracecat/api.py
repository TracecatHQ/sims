from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
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

from tracecat.agents import TRACECAT__LAB__ACTIONS_LOGS_PATH
from tracecat.attack.stratus import clean_up_stratus, ddos
from tracecat.autotuner import optimizer
from tracecat.config import TRACECAT__API_DIR, TRACECAT__AUTOTUNER_DIR
from tracecat.lab import (
    LabResults,
    clean_up_lab,
    evaluate_lab,
)
from tracecat.logger import standard_logger, tail_file
from tracecat.schemas.datadog import RuleUpdateRequest

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
TRACECAT__JOB_QUEUES: dict[str, asyncio.Queue] = {}

for q in ["statistics", "activity"]:
    TRACECAT__LOG_QUEUES[q] = asyncio.Queue()

for q in ["lab", "optimizer"]:
    TRACECAT__JOB_QUEUES[q] = asyncio.Queue()


async def tail_file_handler():
    async for line in tail_file(TRACECAT__LAB__ACTIONS_LOGS_PATH):
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


async def optimizer_job_consumer():
    queue = TRACECAT__JOB_QUEUES["optimizer"]
    while True:
        task = await queue.get()
        logger.info(
            f"Running optimizer job for rule: {task['id']}. There are {queue.qsize()} jobs left."
        )
        coro = task["coro"]
        try:
            await coro
            logger.info(f"Finished running optimizer job for rule: {task['id']}")
        except Exception as e:
            logger.error(f"Error running optimizer job for rule: {task['id']}. {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Context manager to run the API for its lifespan."""
    logger.info("Starting API")
    asyncio.create_task(tail_file_handler())
    asyncio.create_task(update_stats_handler())
    asyncio.create_task(optimizer_job_consumer())
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
        start=now - buffer_delta,
        end=now + buffer_delta,
        account_id=account_id,
        bucket_name=bucket_name,
        regions=regions,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
        triage=triage,
    )
    return results


@app.post("/ddos")
async def create_ddos_lab(
    background_tasks: BackgroundTasks,
    # Temporary default to speedup development
    scenario_id: str = "ec2-brute-force",
    timeout: int | None = None,
    delay: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):
    background_tasks.add_task(
        ddos,
        scenario_id=scenario_id,
        timeout=timeout,
        delay=delay,
        max_tasks=max_tasks,
        max_actions=max_actions,
    )
    return {"message": "Lab created"}


@app.delete("/lab")
def delete_lab(force: bool = False):
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """
    clean_up_lab(force=force)
    clean_up_stratus(include_all=True)
    if force:
        logger.info("✅ Lab cleanup complete. What will you break next?")
    else:
        logger.info(
            "✅🛎️ Infrastructure cleanup complete."
            " Rerun clean up with `force=True` to destroy remaining artifacts."
        )


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
PY_TO_TS_SCHEMA = {"rule_id": "id", "rule_name": "ruleName", "tactic": "ttp"}


@app.get("/autotune/banner")
def get_autotune_banner():
    return [
        {"key": "fixed-detections", "value": "11", "subtitleValue": "159"},
        {"key": "hours-saved", "value": "52 Hours", "subtitleValue": "457"},
        {"key": "money-saveable", "value": "$19283", "subtitleValue": "268901"},
    ]


@app.get("/autotune/rules/")
def get_all_rules():
    """Get all rules.

    The assumption is all rules have already been evaluated ahead of time.
    This endpoint should return all rules with evaluation metrics done.
    The user should only then commit the new rules.

    Here we set the actual number of alerts.
    Whatever is shown on the UI should be inflated by a random number.
    """
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
        .filter(pl.col.source == "cloudtrail")
        .collect(streaming=True)
    )
    return (
        df.lazy()
        .rename(PY_TO_TS_SCHEMA)
        .with_columns(
            score=np.random.randint(0, 65, df.height),
            status=pl.lit("todo"),
            alerts=np.random.randint(4, 15, df.height),
            severity=np.random.choice(["low", "medium", "high"], df.height),
            truePositives=np.random.randint(1, 3, df.height),
            falsePositives=np.random.randint(4, 15, df.height),
            relatedAttacks=np.random.randint(4, 15, df.height),
            timeSavable=pl.lit(None),
            tunedScore=pl.lit(None),
            tunedAlerts=pl.lit(None),
        )
        .collect(streaming=True)
        .to_dicts()
    )


@app.get("/autotune/rules/{id}")
def get_rule(id: str):
    df = (
        pl.scan_parquet(TEMPORARY_AUTOTUNE_DB_PATH)
        .filter(pl.col.rule_id == id)
        .collect(streaming=True)
    )
    if df.is_empty():
        raise HTTPException(status_code=404, detail="Rule not found")

    res = (
        df.lazy()
        .with_columns(
            score=pl.lit(np.random.randint(0, 100)),
            status=pl.lit("active"),
            timeSavable=pl.lit(np.random.randint(0, 100)),
            severity=pl.lit(np.random.choice(["low", "medium", "high"])),
        )
        .rename(PY_TO_TS_SCHEMA)
        .collect(streaming=True)
    ).to_dicts()[0]
    return res


def get_results_dir(rule_id: str, variant: str = "datadog"):
    path = TRACECAT__AUTOTUNER_DIR / "results" / f"{variant}_{rule_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


async def run_optimizer_single(rule_id: str):
    rule_data = get_rule(rule_id)
    rule = RuleUpdateRequest.model_validate(rule_data)

    opt_results = await optimizer.optimize_rule(
        rule_id, rule, variant="datadog", strategy="user_select"
    )
    with get_results_dir(rule_id).joinpath("results.json").open("w") as f:
        data = [res.model_dump() for res in opt_results]
        json.dump(data, f, indent=2)
        logger.info(f"Successfully wrote {len(data)} options to disk")
    logger.info(f"Finished running optimizer for rule {rule_id}")


@app.post("/autotune/optimizer/run")
async def run_optimizer(rule_ids: list[str]):
    """Run the optimizer for the given rule and return the recommendation results.

    This should trigger a background job.

    Additionally saves the recommendation results to a directory.

    For each rule, run the optimizer
    Optimizer Steps (This is repeated in parallel 10x):
    1. LLM Suggests a new rule using few show prompting with input/output examples
      - Optional data enrichment step (RAG, threat intel)
    2. We now have N new rules. Run these against the datdog API and return the results.

    """

    queue = TRACECAT__JOB_QUEUES["optimizer"]

    # NOTE(perf): We should probably batch these 'gather' steps for performance in prod
    logger.info("Queueing jobs for optimizer evaluation step")
    for rule_id in rule_ids:
        queue.put_nowait({"id": rule_id, "coro": run_optimizer_single(rule_id)})

    return {"status": "ok", "message": f"{len(rule_ids)} optimizer jobs completed"}


@app.get(
    "/autotune/optimizer/results/{rule_id}",
    response_model=list[optimizer.OptimizerResult],
)
async def get_optimizer_results(rule_id: str):
    """Return the results for the given rule."""
    path = get_results_dir(rule_id) / "results.json"
    with path.open("r") as f:
        data = json.load(f)
    results = [optimizer.OptimizerResult.model_validate(r) for r in data]
    return results


@app.get(
    "/autotune/optimizer/results/{rule_id}/{index}",
    response_model=optimizer.OptimizerResult,
)
async def get_optimizer_result_by_index(rule_id: str, index: int):
    """Return the index-th result for the given rule."""
    path = get_results_dir(rule_id) / "results.json"
    with path.open("r") as f:
        data = json.load(f)
    if index >= len(data):
        raise HTTPException(status_code=404, detail="Index not found")
    result = optimizer.OptimizerResult.model_validate(data[index])
    return result
