import os
import subprocess
from pathlib import Path

from sims.config import path_to_pkg
from sims.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


class TerraformRunError(Exception):
    pass


def run_terraform(cmds: list[str], chdir: str | None = None):
    base_cmds = ["docker", "compose", "run", "--rm", "terraform"]
    if chdir:
        base_cmds.append(f"-chdir={chdir}")
    process = subprocess.run(
        [*base_cmds, *cmds],
        cwd=path_to_pkg(),  # For docker-compose.yaml
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # Ensure the output is returned as a string
    )
    print(process.stdout)
    print(process.stderr)
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)


def show_terraform_state(path: Path):
    # Assumes Terraform installed
    cmds = ["terraform", "show"]
    process = subprocess.run(
        cmds,
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # Ensure the output is returned as a string
    )
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)
    state = process.stdout
    return state
