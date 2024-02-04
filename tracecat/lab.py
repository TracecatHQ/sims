import boto3
import os
import shutil
import polars as pl
import subprocess
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from tracecat.credentials import load_lab_credentials
from tracecat.config import TRACECAT__LAB_DIR, TRACECAT__TRIAGE_DIR, path_to_pkg
from tracecat.defense.siem_alerts import get_datadog_alerts
from tracecat.evaluation import (
    compute_confusion_matrix,
    correlate_alerts_with_logs,
    compute_event_percentage_counts
)
from tracecat.ingestion.aws_cloudtrail import (
    load_cloudtrail_logs,
    load_triaged_cloudtrail_logs,
)
from tracecat.logger import standard_logger
from tracecat.infrastructure import run_terraform
from tracecat.credentials import get_normal_ids, get_malicious_ids


logger = standard_logger(__name__, level="INFO")


def deploy_lab() -> Path:
    """Deploy lab infrastructure ready for attacks.

    Assumes lab project files already configured and Terraform in Docker is available.
    """

    chdir = "terraform"

    logger.info("🚧 Initialize Terraform project")
    run_terraform(["init"], chdir=chdir)

    # Terraform plan (safety)
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform plan")
    run_terraform(["plan", "-out=plan.tfplan"], chdir=chdir)

    # Terraform deploy
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform apply")
    run_terraform(["apply", "-auto-approve", "plan.tfplan"], chdir=chdir)


def get_lab_users() -> pl.DataFrame:
    creds = load_lab_credentials(load_all=True)
    compromised_users = creds["compromised"].keys()
    lab_users = (
        pl.DataFrame({"name": creds["normal"].keys()})
        .with_columns(is_compromised=pl.col("name").is_in(compromised_users))
    )
    return lab_users


class LabResults(BaseModel):
    start: datetime
    end: datetime
    account_id: str
    bucket_name: str
    regions: list[str]
    rule_scores: list[dict]  # Confusion matrix
    event_counts: list[dict]  # Event frequencies
    users: list[dict]  # Fields: name, is_compromised, policy, persona


def evaluate_lab(
    start: datetime,
    end: datetime,
    account_id: str = None,
    bucket_name: str | None = None,
    regions: list[str] | None = None,
    malicious_ids: list[str] | None = None,
    normal_ids: list[str] | None = None,
    triage: bool = False,
):
    normal_ids = get_normal_ids()
    malicious_ids = get_malicious_ids()
    sts_client = boto3.client("sts")
    account_id = account_id or sts_client.get_caller_identity()["Account"]
    bucket_name = bucket_name or os.environ["AWS_CLOUDTRAIL__BUCKET_NAME"]
    regions = regions or [os.environ["AWS_DEFAULT_REGION"]]
    if triage:
        logs_source = load_triaged_cloudtrail_logs(
            start=start,
            end=end,
            malicious_ids=malicious_ids,
            normal_ids=normal_ids,
        )
    else:
        logs_source = load_cloudtrail_logs(
            account_id=account_id,
            bucket_name=bucket_name,
            regions=regions,
            start=start,
            end=end,
            malicious_ids=malicious_ids,
            normal_ids=normal_ids,
        )
    alerts_source = get_datadog_alerts(start=start, end=end)
    logger.info("🧲 Correlate alerts with logs")
    correlated_alerts = correlate_alerts_with_logs(
        alerts_source=alerts_source,
        logs_source=logs_source,
        malicious_ids=malicious_ids,
    )

    logger.info("🎯 Score detection rules")
    confusion_matrix = compute_confusion_matrix(correlated_alerts=correlated_alerts)
    logger.info("🎯 Final detection rule scores: %s", confusion_matrix)

    logger.info("🔢 Compute event counts")
    event_counts = compute_event_percentage_counts(
        logs_source=logs_source,
        include_absolute=True
    )
    logger.info("🔢 Final event counts: %s", confusion_matrix)

    logger.info("🧬 Gather lab users info")
    users = get_lab_users()
    logger.info("🧬 All lab users info: %s", users)

    results = LabResults(
        start=start,
        end=end,
        account_id=account_id,
        bucket_name=bucket_name,
        regions=regions,
        rule_scores=confusion_matrix.to_dicts(),
        event_counts=event_counts.to_dicts(),
        users=users.to_dicts(),
    )
    return results


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
    run_terraform(["destroy", "-auto-approve"], chdir="terraform")

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
