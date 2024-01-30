import os
from pathlib import Path

LOGS_FILE_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
HWK__HOME_DIR = (
    Path(os.environ.get("HWK__HOME_DIR", "~/.helloworldkitty")).expanduser().resolve()
)
HWK__LAB_DIR = HWK__HOME_DIR / "lab"
HWK__RULES_DIR = HWK__HOME_DIR / "rules"
HWK__ALERTS_DIR = HWK__HOME_DIR / "alerts"
HWK__TRIAGE_DIR = HWK__HOME_DIR / "triage"
HWK__LOGS_DIR = HWK__HOME_DIR / "logs"  # Nice clean normalized logs
HWK__DOCKER_COMPOSE_NAME = "hwk-lab"
HWK__DOCKER_WORKDIR = "/home/terraform/lab"
