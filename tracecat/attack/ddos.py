"""Module with functions to DDoS your AWS environment with possible attacks. Chaos engineering style.

This is a pentesting tool that assumes full visibility into your AWS inventory.
"""

from datetime import datetime, timedelta
import asyncio
import boto3
import gzip
import io
import orjson
import os
import random
import secrets
import shutil
import subprocess
import string

from tracecat.ingestion.aws_cloudtrail import (
    AWS_CLOUDTRAIL__EVENT_TIME_FORMAT
)
from tracecat.attack.detonation import DelayedDetonator
from tracecat.attack.noise import NoisyStratusUser
from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.credentials import load_lab_credentials
from tracecat.logger import standard_logger
from tracecat.lab import deploy_lab
from tracecat.infrastructure import TerraformRunError


logger = standard_logger(__name__, level="INFO")


AWS_ATTACK_TECHNIQUES = [
    "aws.credential-access.ec2-get-password-data",
    "aws.credential-access.ec2-steal-instance-credentials",
    "aws.credential-access.secretsmanager-batch-retrieve-secrets",
    "aws.credential-access.secretsmanager-retrieve-secrets",
    "aws.credential-access.ssm-retrieve-securestring-parameters",
    "aws.defense-evasion.cloudtrail-delete",
    "aws.defense-evasion.cloudtrail-event-selectors",
    "aws.defense-evasion.cloudtrail-lifecycle-rule",
    "aws.defense-evasion.cloudtrail-stop",
    "aws.defense-evasion.organizations-leave",
    "aws.defense-evasion.vpc-remove-flow-logs",
    "aws.discovery.ec2-enumerate-from-instance",
    "aws.discovery.ec2-download-user-data",
    "aws.execution.ec2-launch-unusual-instances",
    "aws.execution.ec2-user-data",
    "aws.exfiltration.ec2-security-group-open-port-22-ingress",
    "aws.exfiltration.ec2-share-ami",
    "aws.exfiltration.ec2-share-ebs-snapshot",
    # "aws.exfiltration.rds-share-snapshot",  # Too slow
    "aws.exfiltration.s3-backdoor-bucket-policy",
    "aws.impact.s3-ransomware-batch-deletion",
    "aws.impact.s3-ransomware-client-side-encryption",
    "aws.impact.s3-ransomware-individual-deletion",
    # "aws.initial-access.console-login-without-mfa",  # Creates new user
    "aws.persistence.iam-backdoor-role",
    # "aws.persistence.iam-backdoor-user",  # Creates new user
    "aws.persistence.iam-create-admin-user",
    # "aws.persistence.iam-create-user-login-profile",  # Creates new user
    "aws.persistence.lambda-backdoor-function",
    "aws.persistence.lambda-layer-extension",
    "aws.persistence.lambda-overwrite-code",
    "aws.persistence.rolesanywhere-create-trust-anchor",
]


def initialize_stratus_lab():
    # Create temporary admin user with Terraform
    # Two set of IAM keys are stored in labs/terraform/credentials.json
    
    logger.info("🐱 Create new lab directory")
    TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)

    # Create Terraform on Docker
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Create Terraform in Docker container")
    subprocess.run(
        ["docker", "compose", "-f", path_to_pkg() / "docker-compose.yaml", "up", "-d"],
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )

    # Copy Terraform project into labs
    logger.info("🚧 Copy Terraform script into lab")
    script_src = path_to_pkg() / "tracecat/attack/attacker.tf"
    script_dst = TRACECAT__LAB_DIR / "terraform"
    script_dst.mkdir(parents=True, exist_ok=True)
    shutil.copy(script_src, script_dst)

    # Create Terraform infra
    deploy_lab()


def _run_stratus_cmd(
    cmds: list[str],
    aws_access_key_id: str,
    aws_secret_access_key: str,
):
    aws_default_region = os.environ["AWS_DEFAULT_REGION"]
    cmd = ["stratus", *cmds]
    process = subprocess.run(
        cmd,
        env={
            **os.environ.copy(),
            "AWS_ACCESS_KEY_ID": aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": aws_secret_access_key,
            "AWS_DEFAULT_REGION": aws_default_region
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # Ensure the output is returned as a string
    )
    print(process.stdout)
    print(process.stderr)
    if "Error" in process.stdout or "Error" in process.stderr:
        raise TerraformRunError(process.stdout)


def warm_up_stratus(technique_id: str):
    # NOTE: We create infra using server admin
    # to avoid this being logged into scored alerts
    _run_stratus_cmd(
        cmds=["warmup", technique_id],
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"]
    )


def detonate_stratus(technique_id: str):

    # Get creds for compromised user
    creds = load_lab_credentials(is_compromised=True)
    aws_access_key_id = creds["redpanda"]["aws_access_key_id"]
    aws_secret_access_key = creds["redpanda"]["aws_secret_access_key"]

    # Create infra
    _run_stratus_cmd(
        cmds=["warmup", technique_id],
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )


async def simulate_stratus(
    technique_id: str,
    delay: int,
    max_tasks: int,
    max_actions: int,
    timeout: int
):
    user = NoisyStratusUser(
        name="redpanda",
        technique_id=technique_id,
        max_tasks=max_tasks,
        max_actions=max_actions
    )
    denotator = DelayedDetonator(
        delay=delay,
        detonate=detonate_stratus,
        technique_id=technique_id
    )
    tasks = [user, denotator]
    await asyncio.wait_for(
        asyncio.gather(*[task.run() for task in tasks]),
        timeout=timeout,
    )


def clean_up_stratus(technique_id: str | None = None, include_all: bool = False):
    # NOTE: We clean up infra using server admin
    # to avoid this being logged into scored alerts
    if include_all:
        _run_stratus_cmd(
            ["cleanup", "--all"],
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"]
        )
    else:
        _run_stratus_cmd(
            ["cleanup", technique_id],
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"]
        )


def upload_lab_logs():
    """Upload generated fake lab logs into S3 bucket for AWS CloudTrail.
    """
    
    # Get S3 location
    aws_account_id = os.environ["AWS_ACCOUNT_ID"]
    aws_default_region = os.environ["AWS_DEFAULT_REGION"]
    bucket_name = os.environ["AWS_CLOUDTRAIL__BUCKET_NAME"]

    # Create S3 Key
    now = datetime.utcnow()
    date_text = now.strftime("%Y/%m/%d")
    ts = (now - timedelta(minutes=now.minute % 5)).replace(second=0, microsecond=0)
    ts_text = ts.strftime("%Y%m%dT%H%M%Z")
    prefix = "tracecat"
    alphabet = string.ascii_letters + string.digits
    uuid = prefix + "".join(secrets.choice(alphabet) for _ in range(16 - len(prefix)))
    file_name = f"{aws_account_id}_CloudTrail_{aws_default_region}_{ts_text}_{uuid.upper()}.json.gz"
    key = f"AWSLogs/{aws_account_id}/CloudTrail/{aws_default_region}/{date_text}/{file_name}"

    # Load ndjson file into list of dict
    njson_logs_path = TRACECAT__LAB_DIR / "aws_cloudtrail.ndjson"
    records = []
    with open(njson_logs_path, "r") as f:
        for line in f:
            # Parse the JSON line and append the resulting dictionary to the list
            records.append(orjson.loads(line))

    gzipped_records = io.BytesIO()
    with gzip.GzipFile(fileobj=gzipped_records, mode="w") as gz_file:
        gz_file.write(orjson.dumps(records))
    gzipped_records.seek(0)

    # Upload gzipped json
    s3_client = boto3.client("s3")
    s3_client.put_object(
        Body=gzipped_records,
        Bucket=bucket_name,
        Key=key,
        ContentEncoding="gzip",
        ContentType="application/json"
    )

    # Delete old logs
    os.remove(njson_logs_path)


async def ddos(
    n_attacks: int = 10,
    timeout: int | None = None,
    delay: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):

    timeout = timeout or 300
    delay = delay or 30

    # Create lab admin credentials
    initialize_stratus_lab()

    # Run simulation
    for _ in range(n_attacks):
        technique_id = random.choice(AWS_ATTACK_TECHNIQUES)

        logger.info("🚧 Warm up infrastructure %r", technique_id)
        warm_up_stratus(technique_id=technique_id)
        
        try:
            logger.info("🎲 Run simulation %r", technique_id)
            await simulate_stratus(
                technique_id=technique_id,
                delay=delay,
                max_tasks=max_tasks,
                max_actions=max_actions,
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.info("✅ Simulation %r timed out successfully after %s seconds", technique_id, timeout)
        finally:
            logger.info("🗂️ Upload logs to S3 %r", technique_id)
            upload_lab_logs()

    # Final clean up
    clean_up_stratus(include_all=True)
