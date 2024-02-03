import os
from importlib import resources
from pathlib import Path

LOGS_FILE_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
STRATUS__HOME_DIR = (
    Path(os.environ.get("STRATUS__HOME_DIR", "~/.stratus-red-team")).expanduser().resolve()
)
TRACECAT__HOME_DIR = (
    Path(os.environ.get("TRACECAT__HOME_DIR", "~/.tracecat")).expanduser().resolve()
)
TRACECAT__LAB_DIR = TRACECAT__HOME_DIR / "lab"
TRACECAT__API_DIR = TRACECAT__HOME_DIR / "api"
TRACECAT__RULES_DIR = TRACECAT__HOME_DIR / "rules"
TRACECAT__ALERTS_DIR = TRACECAT__HOME_DIR / "alerts"
TRACECAT__TRIAGE_DIR = TRACECAT__HOME_DIR / "triage"
TRACECAT__LOGS_DIR = TRACECAT__HOME_DIR / "logs"  # Nice clean normalized logs
TRACECAT__DOCKER_COMPOSE_NAME = "tracecat-lab"
TRACECAT__DOCKER_WORKDIR = "/home/terraform/lab"

TRACECAT__TRIAGE_DIR.mkdir(parents=True, exist_ok=True)
TRACECAT__LOGS_DIR.mkdir(parents=True, exist_ok=True)


def path_to_pkg() -> Path:
    import tracecat

    return resources.files(tracecat).parent
