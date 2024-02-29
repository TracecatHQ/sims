from __future__ import annotations

import asyncio
import os

from dotenv import find_dotenv, load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, WebSocketException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from websockets.exceptions import ConnectionClosed

from sims.api.models import WebsocketData
from sims.logger import standard_logger

load_dotenv(find_dotenv(".env.local", raise_error_if_not_found=True))

from sims.attack.stratus import ddos  # noqa: E402

app = FastAPI(
    debug=os.environ.get("TRACECAT__ENV", "dev") == "dev",
    title="Tracecat Simulation API",
    default_response_class=ORJSONResponse,
)

SIGNAL: dict[str, str] = {}

logger = standard_logger(__name__)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok"}


@app.websocket("/labs/ws")
async def stream_lab_logs(websocket: WebSocket):
    await websocket.accept()
    logger.info("Accepted websocket connection")
    try:
        while True:
            logger.info("Waiting for lab data")
            raw_data = await websocket.receive_json()
            data = WebsocketData.model_validate(raw_data)

            logger.info(f"Started log stream for {data.uuid}. Data: {data!r}")
            _queue = asyncio.Queue()
            SIGNAL[data.uuid] = "running"

            ddos_task = asyncio.create_task(
                ddos(
                    uuid=data.uuid,
                    technique_ids=data.technique_ids,
                    scenario_id=data.scenario_id,
                    timeout=data.timeout,
                    max_tasks=data.max_tasks,
                    max_actions=data.max_actions,
                    enqueue=_queue.put_nowait,
                )
            )
            try:
                while True:
                    logger.info(f"{data.uuid}: In queue")
                    signal = SIGNAL.get(data.uuid)
                    if signal == "cancel":
                        logger.info(f"{data.uuid}: Cancel lab")
                        break
                    item = await _queue.get()
                    logger.info(f"{data.uuid}: Dequeued item: {item}")
                    await websocket.send_json(item)
            except (WebSocketException, WebSocketDisconnect) as e:
                logger.info(f"{e.__class__.__qualname__} occurred inside")
                raise e
            except ConnectionClosed as e:
                logger.info(f"Connection closed inside: {e.reason}")
                raise e
            except Exception as e:
                logger.info(f"An Exception occurred inside: {e}")
                raise e
            finally:
                ddos_task.cancel()
                logger.info(f"Cancelled log stream for {data.uuid}")
                SIGNAL.pop(data.uuid)
    except (WebSocketException, WebSocketDisconnect):
        logger.info("Websocket error")
    except ConnectionClosed as e:
        logger.info(f"Connection closed: {e.reason}")
    except Exception as e:
        logger.info(f"An Exception occurred: {e}")


@app.delete("/labs/{uuid}")
async def cancel_stream_agent_logs(uuid: str):
    SIGNAL[uuid] = "cancel"
    return {"message": f"Stopping lab {uuid}"}
