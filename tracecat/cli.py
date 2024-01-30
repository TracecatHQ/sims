import os
import shutil
from datetime import datetime

import typer
from typing_extensions import Annotated

from tracecat.attack.ddos import ddos as signal_ddos
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
from tracecat.setup import cleanup_lab, deploy_lab, initialize_lab

app = typer.Typer()
cleanup_app = typer.Typer(help="Cleanup lab, logs, and resources.")
app.add_typer(cleanup_app, name="cleanup")


@app.command()
def warmup(
    project_path: Annotated[str, typer.Argument(help="Path to Terraform project")],
):
    """Create lab ready for attacks."""
    initialize_lab(project_path=project_path)
    deploy_lab(project_path=project_path)


@app.command(help="Denotate attacks.")
def ddos(n_attacks: int = 10, delay: int = 1):
    signal_ddos(n_attacks=n_attacks, delay=delay)


@app.command(help="Diagnose your SIEM.")
def diagnose(
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


@cleanup_app.command(help="Destroy lab.")
def lab():
    delete = typer.confirm(
        "Are you sure you want to destroy all resources and scripts in your lab?"
    )
    if not delete:
        print("Cleanup aborted")
        raise typer.Abort()
    print("🧹 Run lab cleanup")
    cleanup_lab()


@cleanup_app.command(help="Delete triaged logs")
def logs():
    delete = typer.confirm("Are you sure you want to delete all triaged logs?")
    if not delete:
        print("Logs deletion aborted")
        raise typer.Abort()
    print("🧹 Run logs deletion")
    shutil.rmtree(TRACECAT__TRIAGE_DIR)


if __name__ == "__main__":
    app()
