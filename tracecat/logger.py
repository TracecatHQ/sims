import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

LOG_FORMAT = (
    "%(asctime)s - [%(levelname)s] - %(name)s::%(funcName)s(%(lineno)d) - %(message)s"
)


def log_id_gen():
    i = 0
    while True:
        yield f"LOG-{i:04d}"
        i += 1


class Log(BaseModel):
    id: str
    title: str
    user: str
    action: str
    description: str | None = None


class JsonFormatter(logging.Formatter):
    """Custom formatter to output logs in JSON format."""

    _date_format = "%Y-%m-%dT%H:%M:%SZ"

    def _get_json_msg(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            return json.dumps(record.msg)
        if isinstance(record.msg, BaseModel):
            return record.msg.model_dump_json()
        raise ValueError("Log message must be JSON serializable.")

    def format(self, record: logging.LogRecord):
        model_dict = self._get_json_msg(record)
        model_dict["time"] = self.formatTime(record, self._date_format)
        return json.dumps(model_dict)


LOG_FORMATTER_FACTORY = {
    "json": JsonFormatter,
    "log": logging.Formatter,
}


def file_logger(
    name: str,
    file_path: str,
    level: int | str | None = None,
    format: Literal["json", "log"] | None = None,
) -> logging.Logger:
    """Sets up a logger that logs messages to a file."""
    logger = logging.getLogger(name)
    format = format or "log"
    formatter = LOG_FORMATTER_FACTORY[format]

    # Set logger level
    resolved_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(resolved_level)

    # Create file handler
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.touch(exist_ok=True)

    file_handler = logging.FileHandler(file_path)
    file_handler.setFormatter(formatter())

    # Add the handler to the logger
    logger.addHandler(file_handler)

    return logger


def standard_logger(
    name: str,
    level: int | str | None = None,
    format: Literal["json", "log"] | None = None,
) -> logging.Logger:
    """Sets up a logger that logs messages to the console."""
    logger = logging.getLogger(name)
    format = format or "log"
    formatter = LOG_FORMATTER_FACTORY[format]

    # Set logger level
    resolved_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(resolved_level)

    # Create stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter())

    # Add the handler to the logger
    logger.addHandler(stream_handler)

    return logger


def composite_logger(
    name: str,
    level: int | str | None = None,
    file_paths: list[str | Path] | None = None,
    format: Literal["json", "log"] | None = None,
) -> logging.Logger:
    """Log to stdout and file(s)"""
    logger = logging.getLogger(name)
    logger.setLevel(level or os.getenv("LOG_LEVEL", "INFO"))
    format = format or "log"
    formatter = LOG_FORMATTER_FACTORY[format]

    # Files
    if file_paths is not None:
        for file in file_paths:
            file = Path(file)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.touch(exist_ok=True)
            logger.addHandler(logging.FileHandler(str(file)))

    # Stderr
    logger.addHandler(logging.StreamHandler())
    for handler in logger.handlers:
        handler.setFormatter(formatter())
    return logger


async def tail_file(file_path: Path):
    """Tail an NDJSON file and put new lines into a queue."""
    with open(file_path, "r") as file:
        file.seek(0, 2)  # Go to the end of the file
        while True:
            line = file.readline()
            if not line:
                await asyncio.sleep(0.1)  # Wait briefly
                continue
            yield line
