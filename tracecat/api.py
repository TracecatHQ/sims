from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from dotenv import find_dotenv, load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from tracecat.config import TRACECAT__API_DIR
from tracecat.logger import standard_logger, tail_file

load_dotenv(find_dotenv())
logger = standard_logger(__name__)


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


#################
### ENDPOINTS ###
#################


@app.get("/")
def root():
    return {"status": "ok"}


queues: dict[str, asyncio.Queue] = {}
for q in ["stats", "activity"]:
    queues[q] = asyncio.Queue()


JobStatus = Literal["success", "error"]


async def tail_file_handler():
    log_file = TRACECAT__API_DIR / "logs/test.log"

    async for line in tail_file(log_file):
        line = line.strip()
        for _, q in queues.items():
            await q.put(line)


api_call_stats_file_lock = asyncio.Lock()
action_stats_file_lock = asyncio.Lock()

bad_usernames = {"root", "admin", "test", "user"}


async def update_stats_handler():
    api_call_stats_file = TRACECAT__API_DIR / "api_calls.json"
    action_stats_file = TRACECAT__API_DIR / "action_stats.json"

    api_call_stats_file.touch(exist_ok=True)
    action_stats_file.touch(exist_ok=True)
    while True:
        item = await queues["stats"].get()
        item = json.loads(item)
        async with api_call_stats_file_lock:
            data = safe_json_load(api_call_stats_file)

            # update api call frequency
            action = item["action"]
            data[action] = data.get(action, 0) + 1
            with api_call_stats_file.open("w") as f:
                json.dump(data, f)

        if item["user"] not in bad_usernames:
            continue
        async with action_stats_file_lock:
            # Update total api calls per user
            # If user bad update bad user count
            data = safe_json_load(action_stats_file)

            # update bad api call frequency
            data["bad_api_calls_count"] = data.get("bad_api_calls_count", 0) + 1
            action = item["action"]
            data[action] = data.get(action, 0) + 1
            with api_call_stats_file.open("w") as f:
                json.dump(data, f)


@app.get("/activity-stream", response_class=EventSourceResponse)
async def stream_logs():
    async def log_stream():
        while True:
            item = await queues["activity"].get()
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


# Polling stats
def validate_stat_id(id: str):
    if not len(id) == 9 or not id.startswith("STAT-"):
        raise HTTPException(status_code=400, detail="Invalid stat ID")
    return id


@app.get("/stats-feed/{id}")
async def get_stats(id: Annotated[str, Depends(validate_stat_id)]):
    stats_path = TRACECAT__API_DIR / "stats.json"
    if id == "STAT-0005":
        data = safe_json_load(TRACECAT__API_DIR / "api_calls.json")

        return {
            "id": "STAT-0005",
            "title": "Total actions taken",
            "value": sum(data.values()),
            "description": "",
        }
    elif id == "STAT-0006":
        data = safe_json_load(TRACECAT__API_DIR / "action_stats.json")

        denom = sum(data.values())
        value = 0 if denom == 0 else data.get("bad_api_calls_count", 0) / denom * 100
        return {
            "id": "STAT-0006",
            "title": "% of actions used by adversaries",
            "value": value,
            "units": "%",
            "description": "",
        }
    stats = safe_json_load(stats_path)
    for item in stats:
        if item["id"] == id:
            return item
    raise HTTPException(status_code=404, detail="Stat ID not found")


def validate_graph_id(id: str):
    if not len(id) == 10 or not id.startswith("GRAPH-"):
        raise HTTPException(status_code=400, detail="Invalid stat ID")
    return id


@app.get("/graph-feed/{id}")
async def get_graph_feed(id: Annotated[str, Depends(validate_graph_id)]):
    """Returns a graph feed update."""
    path = TRACECAT__API_DIR / "api_calls.json"
    calls = safe_json_load(path)
    return calls
