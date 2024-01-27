import os
from pathlib import Path

HWK__HOME_DIR = (
    Path(os.environ.get("HWK__HOME_DIR", "~/.helloworldkitty")).expanduser().resolve()
)
HWK__LAB_DIR = HWK__HOME_DIR / "lab"
HWK__DOCKER_COMPOSE_NAME = "hwk-lab"
HWK__DOCKER_WORKDIR = "/home/terraform/lab"
