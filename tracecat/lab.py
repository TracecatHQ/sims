import asyncio
import os
import shutil
import subprocess
from contextlib import contextmanager
from tenacity import retry, stop_after_attempt
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from tracecat.config import TRACECAT__LAB_DIR, TRACECAT__TRIAGE_DIR, path_to_pkg
from tracecat.defense.siem_alerts import get_datadog_alerts
from tracecat.evaluation import (
    compute_confusion_matrix,
    correlate_alerts_with_logs,
)
from tracecat.ingestion.aws_cloudtrail import (
    load_cloudtrail_logs,
    load_triaged_cloudtrail_logs,
)
from tracecat.logger import standard_logger
from tracecat.scenarios import SCENARIO_ID_TO_SIMULATION
from tracecat.setup import create_compromised_ssh_keys, create_ip_whitelist
from tracecat.credentials import get_normal_ids, get_malicious_ids


logger = standard_logger(__name__, level="INFO")


class TerraformRunError(Exception):
    pass


def _run_terraform(cmds: list[str]):
    process = subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "-chdir=terraform", *cmds],
        cwd=path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # Ensure the output is returned as a string
    )
    print(process.stdout)
    print(process.stderr)
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)


def _scenario_to_infra_path(scenario_id: str) -> Path:
    path = path_to_pkg() / "tracecat/scenarios" / scenario_id / "infra"
    return path


class LabStatus(StrEnum):
    cold = "cold"  # No lab
    warm = "warm"  # Lab with infrastructure
    running = "running"  # Ongoing simulation
    complete = "completed"  # Simutation complete
    failed = "failed"  # Simutation complete


class LabInformation(BaseModel):
    status: LabStatus
    results: dict | None = None
    error: str | None = None


def check_lab():
    # Cold: Missing or empty directory
    # Warm:
    # 1. Non-empty directory
    # 2. `terraform plan` no changes
    # 3. But no Action logs
    # Running:
    # Warm 1 + 2 and Action logs, but no timeout
    # Completed: TimeoutError
    # Failed: Any other exception
    pass


def _deploy_lab() -> Path:
    """Deploy lab infrastructure ready for attacks.

    Assumes lab project files already configured and Terraform in Docker is available.
    """
    # Terraform plan (safety)
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform plan")
    _run_terraform(["plan", "-out=plan.tfplan"])

    # Terraform deploy
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform apply")
    _run_terraform(["apply", "-auto-approve", "plan.tfplan"])


def initialize_lab(scenario_id: str):
    """Create lab directory and spin-up Terraform in Docker.

    Parameters
    ----------
    scenario_id : str
    """
    logger.info("🐱 Create new lab directory")
    TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)

    # Shared configs
    create_ip_whitelist()
    create_compromised_ssh_keys()

    # Create Terraform on Docker
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Create Terraform in Docker container")
    subprocess.run(
        ["docker", "compose", "-f", path_to_pkg() / "docker-compose.yaml", "up", "-d"],
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )

    # Copy Terraform project into labs
    logger.info("🚧 Copy Terraform project into lab")
    project_path = _scenario_to_infra_path(scenario_id=scenario_id)
    shutil.copytree(project_path, TRACECAT__LAB_DIR, dirs_exist_ok=True)

    logger.info("🚧 Initialize Terraform project")
    _run_terraform(["init"])

    logger.info("🚧 Deploy Terraform project")
    _deploy_lab()


async def simulate_lab(
    scenario_id: str,
    timeout: int | None = None,
    delayed_seconds: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):
    """Asynchronously run organization to simuluate normal behavior and detonate attack."""
    timeout = timeout or 300
    delayed_seconds = delayed_seconds or 60

    try:
        simulate = SCENARIO_ID_TO_SIMULATION[scenario_id]
    except KeyError as err:
        raise KeyError("Scenario ID not found: %s", scenario_id) from err

    try:
        await asyncio.wait_for(
            simulate(
                delay_seconds=delayed_seconds,
                max_tasks=max_tasks,
                max_actions=max_actions,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.info("✅ Lab timed out successfully after %s seconds", timeout)


def evaluate_lab(
    start: datetime,
    end: datetime,
    bucket_name: str | None = None,
    regions: list[str] | None = None,
    account_id: str = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    triage: bool = False,
):
    normal_ids = get_normal_ids()
    malicious_ids = get_malicious_ids()
    if triage:
        logs_source = load_triaged_cloudtrail_logs(
            malicious_ids=malicious_ids,
            normal_ids=normal_ids,
        )
    else:
        bucket_name = bucket_name or os.environ["AWS_CLOUDTRAIL__BUCKET_NAME"]
        logs_source = load_cloudtrail_logs(
            bucket_name=bucket_name,
            start=start,
            end=end,
            malicious_ids=malicious_ids,
            normal_ids=normal_ids,
            regions=regions,
            account_id=account_id,
        )
    alerts_source = get_datadog_alerts(start=start, end=end)
    correlated_alerts = correlate_alerts_with_logs(
        alerts_source=alerts_source,
        logs_source=logs_source,
        start=start,
        end=end,
        malicious_ids=malicious_ids,
    )
    compute_confusion_matrix(correlated_alerts)


async def run_lab(
    scenario_id: str,
    skip_simulation: bool = False,
    timeout: int | None = None,
    delayed_seconds: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
    bucket_name: str | None = None,
    regions: list[str] | None = None,
    account_id: str = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    task_retries: int | None = None,
    buffer_time: timedelta | None = None,
    triage: bool = False,
) -> Path:
    """Run lab and return path to lab results.

    Parameters
    ----------
    skip_run : bool
        Defaults to False. If True, assumes simulation is complete
        and skips straight to evaluation.
    """
    timeout = timeout or 300
    if not skip_simulation:
        logger.info("🎲 Run lab simulation")
        task_retries = task_retries or 2
        _retry = retry(stop=stop_after_attempt(task_retries))
        task_queue = [
            (initialize_lab, {"scenario_id": scenario_id}),
            (simulate_lab, {
                "scenario_id": scenario_id,
                "timeout": timeout,
                "delayed_seconds": delayed_seconds,
                "max_tasks": max_tasks,
                "max_actions": max_actions}
            ),
        ]
        for task, params in task_queue:
            if asyncio.iscoroutinefunction(task):
                await _retry(task)(**params)
            else:
                _retry(task)(**params)

    # NOTE: Very crude approximation...will need a place
    # to store state of start and time detonation times.
    logger.info("🔬 Evaluate lab simulation")
    buffer_time = buffer_time or timedelta(seconds=timeout + 3600)
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    evaluate_lab(
        start=now - buffer_time,
        end=now + buffer_time,
        bucket_name=bucket_name,
        regions=regions,
        account_id=account_id,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
        triage=triage
    )


class FailedTerraformDestroy(Exception):
    pass


def clean_up_lab(force: bool = False):
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """
    # Terraform destroy
    logger.info("🧹 Destroy lab infrastructure")
    _run_terraform(["destroy"])

    # NOTE: ONLY SPIN DOWN DOCKER AND
    # DELETE LAB FILES (which includes tfstate)
    # IF TERRAFORM DESTORY IS SUCCESSFUL
    if force:
        logger.info("🧹 Spin down Terraform in Docker")
        subprocess.run(
            ["docker", "compose", "down"],
            cwd=path_to_pkg(),
            env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
        )

        # Remove triaged logs
        logger.info("🧹 Delete triaged logs")
        shutil.rmtree(TRACECAT__TRIAGE_DIR)

        logger.info("🧹 Delete lab directory")
        try:
            shutil.rmtree(TRACECAT__LAB_DIR)
        except FileNotFoundError:
            logger.info("❗ No lab directory found")
        logger.info("✅ Lab cleanup complete. What will you break next?")
    else:
        logger.info(
            "✅🛎️ Infrastructure cleanup complete."
            " Rerun clean up with `force=True` to destroy remaining artifacts."
        )
