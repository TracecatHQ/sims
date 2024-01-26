import logging
import os
from pathlib import Path

from helloworldkitty.config import HWK__HOME_DIR

LOG_FILE = HWK__HOME_DIR / "hwk.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
LOG_FILE.touch(exist_ok=True)

LOG_FORMAT = (
    "%(asctime)s - [%(levelname)s] - %(name)s::%(funcName)s(%(lineno)d) - %(message)s"
)


def file_logger(name: str, level: int | str | None = None) -> logging.Logger:
    """Sets up a logger that logs messages to a file."""
    logger = logging.getLogger(name)

    # Set logger level
    resolved_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(resolved_level)

    # Create file handler
    file_handler = logging.FileHandler(str(LOG_FILE))
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # Add the handler to the logger
    logger.addHandler(file_handler)

    return logger


def standard_logger(name: str, level: int | str | None = None) -> logging.Logger:
    """Sets up a logger that logs messages to the console."""
    logger = logging.getLogger(name)

    # Set logger level
    resolved_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(resolved_level)

    # Create stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # Add the handler to the logger
    logger.addHandler(stream_handler)

    return logger


class TqdmToFile:
    def __init__(self, file_path: Path):
        self.file_path = file_path

    def write(self, s):
        with self.file_path.open("a") as f:
            f.write(s)

    def flush(self):
        pass  # This is a no-op since we are immediately writing to the file


TQDM_FILE_HANDLER = TqdmToFile(LOG_FILE)
