from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from tracecat.agents import TRACECAT__LAB__ACTIONS_LOGS_PATH
from tracecat.attack.stratus import ddos
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


TRACECAT__LOG_QUEUES: dict[str, asyncio.Queue] = {}

for q in ["statistics", "activity"]:
    TRACECAT__LOG_QUEUES[q] = asyncio.Queue()


async def tail_file_handler():
    async for line in tail_file(TRACECAT__LAB__ACTIONS_LOGS_PATH):
        line = line.strip()
        for _, q in TRACECAT__LOG_QUEUES.items():
            await q.put(line)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Context manager to run the API for its lifespan."""
    logger.info("Starting API")
    asyncio.create_task(tail_file_handler())
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
