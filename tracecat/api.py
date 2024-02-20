from __future__ import annotations

import asyncio
import json
import ssl
from pathlib import Path

import polars as pl
from dotenv import find_dotenv, load_dotenv
from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sse_starlette.sse import EventSourceResponse

from tracecat.agents import get_path_to_user_logs
from tracecat.attack.stratus import ddos
from tracecat.config import path_to_pkg
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


TRACECAT__LOG_QUEUES: dict[str, asyncio.Queue] = {}
BG_TASKS: dict[str, asyncio.Task] = {}

app = FastAPI(debug=True, default_response_class=ORJSONResponse)

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


@app.post("/ddos")
async def create_ddos_lab(
    uuid: str,
    background_tasks: BackgroundTasks,
    technique_ids: list[str],
    # Temporary default to speedup development
    timeout: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):
    BG_TASKS[uuid] = asyncio.create_task(
        ddos(
            uuid=uuid,
            technique_ids=technique_ids,
            timeout=timeout,
            max_tasks=max_tasks,
            max_actions=max_actions,
        )
    )
    return {"message": f"Created lab {uuid}"}


# Live stream


async def tail_file_handler(uuid: str, queue: asyncio.Queue):
    file_path = get_path_to_user_logs(uuid=uuid)
    try:
        async for line in tail_file(file_path=file_path):
            line = line.strip()
            await queue.put(line)
    except asyncio.CancelledError:
        logger.info(f"Cancelled tail file handler for {uuid}")
        return


@app.get("/feed/logs/{uuid}", response_class=EventSourceResponse)
async def stream_agent_logs(uuid: str):
    queue = TRACECAT__LOG_QUEUES.get("uuid", asyncio.Queue())
    asyncio.create_task(tail_file_handler(uuid=uuid, queue=queue))
    logger.info(f"Started log stream for {uuid}")

    async def log_stream():
        while True:
            item = await queue.get()
            yield item

    return EventSourceResponse(log_stream())


@app.get("/feed/logs/{uuid}/cancel")
async def cancel_stream_agent_logs(uuid: str):
    task = BG_TASKS.get(uuid)
    if not task:
        return {"message": f"Job {uuid} not found"}

    try:
        task.cancel()
        await task
    except (asyncio.CancelledError, ssl.SSLError):
        logger.info(f"Task {uuid} has been cancelled")
    except Exception as e:
        logger.error(f"An Exception occurred: {e}")
        raise e
    except BaseException as e:
        logger.error(f"A BaseException occurred: {e}")
    finally:
        del BG_TASKS[uuid]
        logger.info(f"Cancelled log stream for {uuid}")
    return {"message": f"Stopped lab {uuid}"}


@app.get("/primitives-catalog")
def get_primitives_catalog():
    path = path_to_pkg() / "tracecat" / "catalog" / "primitives.parquet"
    df = pl.read_parquet(path)
    return {"primitives": df.to_dicts()}
