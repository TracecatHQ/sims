import os
import subprocess
from pathlib import Path
from tracecat.config import path_to_pkg


class TerraformRunError(Exception):
    pass


def scenario_to_infra_path(scenario_id: str) -> Path:
    path = path_to_pkg() / "tracecat/scenarios" / scenario_id / "infra"
    return path


def run_terraform(cmds: list[str], cwd: Path | None = None, chdir: str | None = None):
    cwd = cwd or path_to_pkg()
    base_cmds = ["docker", "compose", "run", "--rm", "terraform"]
    if chdir:
        base_cmds.append(f"-chdir={chdir}")
    process = subprocess.run(
        [*base_cmds, *cmds],
        cwd=cwd,
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # Ensure the output is returned as a string
    )
    print(process.stdout)
    print(process.stderr)
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)
    

def show_terraform_state(cwd: Path, chdir: str | None = None):
    cwd = cwd or path_to_pkg()
    base_cmds = ["docker", "compose", "run", "--rm", "terraform"]
    if chdir:
        base_cmds.append(f"-chdir={chdir}")
    process = subprocess.run(
        [*base_cmds, "show"],
        cwd=cwd,
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # Ensure the output is returned as a string
    )
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)
    state = process.stdout
    return state
