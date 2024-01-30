import os
import shutil
from datetime import datetime

from tracecat.attack.ddos import ddos
from tracecat.config import TRACECAT__TRIAGE_DIR
from tracecat.defense.siem_alerts import get_datadog_alerts
from tracecat.evaluation import (
    compute_confusion_matrix,
    correlate_alerts_with_logs,
)
from tracecat.ingestion.aws_cloudtrail import (
    load_cloudtrail_logs,
    load_triaged_cloudtrail_logs,
)
import subprocess
from importlib import resources
from pathlib import Path

from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.logger import standard_logger

from tracecat.setup import create_ip_whitelist, create_compromised_ssh_keys


logger = standard_logger(__name__, level="INFO")


def _run_terraform(cmds: list[str]):
    subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "-chdir=terraform", *cmds],
        cwd=path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )


def _scenario_to_infra_path(scenario_id: str) -> Path:
    path = path_to_pkg() / "terraform" / scenario_id / "infra"
    return path


def _initialize_lab(scenario_id: str):
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


def warmup_lab(scenario_id: str):
    """Create lab ready for attacks."""
    _initialize_lab(scenario_id=scenario_id)
    _deploy_lab()


def ddos_lab(n_attacks: int = 10, delay: int = 1):
    ddos(n_attacks=n_attacks, delay=delay)


def diagnose_lab(
    start: datetime,
    end: datetime,
    bucket_name: str | None = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    regions: list[str] | None = None,
    account_id: str = None,
    triage: bool = False,
):
    malicious_ids = malicious_ids or []
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


class FailedTerraformDestroy(Exception):
    pass


def cleanup_lab():
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
