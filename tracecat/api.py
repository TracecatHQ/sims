from __future__ import annotations

import asyncio
import json
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sse_starlette.sse import EventSourceResponse

from tracecat.agents import get_path_to_user_logs
from tracecat.attack.stratus import ddos
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


TRACECAT__LOG_QUEUES: dict[str, asyncio.Queue] = {}


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
    # Temporary default to speedup development
    scenario_id: str = "ec2-brute-force",
    timeout: int | None = None,
    delay: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):
    background_tasks.add_task(
        ddos,
        uuid=uuid,
        scenario_id=scenario_id,
        timeout=timeout,
        max_tasks=max_tasks,
        max_actions=max_actions,
    )
    return {"message": "Lab created"}


# Live stream


async def tail_file_handler(uuid: str, queue: asyncio.Queue):
    file_path = get_path_to_user_logs(uuid=uuid)
    async for line in tail_file(file_path=file_path):
        line = line.strip()
        await queue.put(line)


@app.get("/feed/logs/{uuid}", response_class=EventSourceResponse)
async def stream_agent_logs(uuid: str):
    queue = TRACECAT__LOG_QUEUES.get("uuid", asyncio.Queue())
    asyncio.create_task(tail_file_handler(uuid=uuid, queue=queue))

    async def log_stream():
        while True:
            item = await queue.get()
            yield item

    return EventSourceResponse(log_stream())
