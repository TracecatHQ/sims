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
from tracecat.scenarios import SCENARIO_ID_TO_RUN
from tracecat.setup import create_compromised_ssh_keys, create_ip_whitelist
from tracecat.credentials import load_lab_credentials


logger = standard_logger(__name__, level="INFO")


def _run_terraform(cmds: list[str]):
    subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "-chdir=terraform", *cmds],
        cwd=path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )


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
    _run_terraform(["plan"])

    # Terraform deploy
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform apply")
    _run_terraform(["apply"])


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


async def detonate_lab(
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
        run = SCENARIO_ID_TO_RUN[scenario_id]
    except KeyError as err:
        raise KeyError("Scenario ID not found: %s", scenario_id) from err

    try:
        await asyncio.wait_for(
            run(
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
    normal_ids = [
        creds["aws_access_key_id"] for creds in
        load_lab_credentials(is_compromised=False).values()
    ]
    malicious_ids = [
        creds["aws_access_key_id"] for creds in
        load_lab_credentials(is_compromised=True).values()
    ]
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


@contextmanager
def track_time():
    class Timer:
        def __init__(self):
            self.start_time = datetime.now()
            self.end_time = None
            self.elapsed = None

        def stop(self):
            self.end_time = datetime.now()
            self.elapsed = self.end_time - self.start_time

    timer = Timer()
    yield timer
    timer.stop()


def run_lab(
    scenario_id: str,
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

    Lab results contain th
    """
    task_retries = task_retries or 3
    _retry = retry(stop=stop_after_attempt(task_retries))
    task_queue = [
        (initialize_lab, {"scenario_id": scenario_id}),
        (detonate_lab, {"timeout": timeout, "delayed_seconds": delayed_seconds, "max_tasks": max_tasks, "max_actions": max_actions}),
    ]
    with track_time() as timer:
        for task, params in task_queue:
            result = _retry(task)(**params)

    buffer_time = buffer_time or timedelta(hours=1)
    evaluate_lab(
        start=timer.start_time - buffer_time,
        end=timer.end_time + buffer_time,
        bucket_name=bucket_name,
        regions=regions,
        account_id=account_id,
        malicious_ids=malicious_ids,
        normal_ids=normal_ids,
        triage=triage
    )

    return result


class FailedTerraformDestroy(Exception):
    pass


def clean_up_lab():
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """
    # Terraform destroy
    logger.info("🧹 Destroy lab infrastructure")
    _run_terraform(["destroy"])

    # Delete labs directory
    logger.info("🧹 Delete lab directory")
    try:
        shutil.rmtree(TRACECAT__LAB_DIR)
    except FileNotFoundError:
        logger.info("❗ No lab directory found")

    # Delete docker containers
    logger.info("🧹 Spin down Terraform in Docker")
    subprocess.run(
        ["docker", "compose", "down"],
        cwd=path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )
    # Remove triaged logs
    shutil.rmtree(TRACECAT__TRIAGE_DIR)

    logger.info("✅ Lab cleanup complete. What will you break next?")
