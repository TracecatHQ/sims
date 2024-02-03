import os
import subprocess
from pathlib import Path
from tracecat.config import path_to_pkg


class TerraformRunError(Exception):
    pass


def scenario_to_infra_path(scenario_id: str) -> Path:
    path = path_to_pkg() / "tracecat/scenarios" / scenario_id / "infra"
    return path


def run_terraform(cmds: list[str], cwd: Path | None = None):
    cwd = cwd or path_to_pkg()
    process = subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "-chdir=terraform", *cmds],
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
