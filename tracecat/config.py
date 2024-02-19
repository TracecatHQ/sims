import os
from importlib import resources
from pathlib import Path

LOGS_FILE_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
STRATUS__HOME_DIR = (
    Path(os.environ.get("STRATUS__HOME_DIR", "~/.stratus-red-team"))
    .expanduser()
    .resolve()
)
TRACECAT__HOME_DIR = (
    Path(os.environ.get("TRACECAT__HOME_DIR", "~/.tracecat")).expanduser().resolve()
)
TRACECAT__LAB_DIR = TRACECAT__HOME_DIR / "lab"


def path_to_pkg() -> Path:
    import tracecat

    return resources.files(tracecat).parent
