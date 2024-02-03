"""Module with functions to DDoS your AWS environment with possible attacks. Chaos engineering style.

This is a pentesting tool that assumes full visibility into your AWS inventory.
"""

import asyncio
import datetime
import os
import random
import subprocess
import shutil
from pathlib import Path

from tracecat.attack.detonation import DelayedDetonator
from tracecat.attack.noise import NoisyStratusUser
from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.credentials import assume_aws_role, load_lab_credentials
from tracecat.logger import standard_logger
from tracecat.lab import _deploy_lab


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
    "aws.exfiltration.rds-share-snapshot",
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
    logger.info("🚧 Copy Terraform project into lab")
    project_path = path_to_pkg() / "tracecat/attack"
    shutil.copytree(project_path, TRACECAT__LAB_DIR, dirs_exist_ok=True)

    # Create Terraform infra
    _deploy_lab()


def _run_stratus_cmd(
    cmds: list[str],
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str | None = None,
    aws_default_region: str | None = None
):
    aws_default_region = aws_default_region or os.environ["AWS_DEFAULT_REGION"]
    stratus_dir_path = Path(os.path.expanduser("~")) / ".stratus-red-team"
    os.makedirs(stratus_dir_path, exist_ok=True)
    parent_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{stratus_dir_path}:/root/.stratus-red-team",
        "-e",
        f"AWS_ACCESS_KEY_ID={aws_access_key_id}",
        "-e",
        f"AWS_SECRET_ACCESS_KEY={aws_secret_access_key}",
        "-e",
        f"AWS_DEFAULT_REGION={aws_default_region}"
    ]
    if aws_session_token:
        cmd = parent_cmd + [
            "-e",
            f"AWS_SESSION_TOKEN={os.environ['AWS_SESSION_TOKEN']}",
            "ghcr.io/datadog/stratus-red-team",
            *cmds
        ]
    else:
        cmd = parent_cmd + ["ghcr.io/datadog/stratus-red-team", *cmds]
    subprocess.run(cmd)


def warm_up_stratus(technique_id: str):
    # NOTE: We create infra using server admin
    # to avoid this being logged into scored alerts
    _run_stratus_cmd(
        cmds=["warmup", technique_id],
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_EY"]
    )


def detonate_stratus(technique_id: str):

    # Get creds for compromised user
    creds = load_lab_credentials(is_compromised=True)
    aws_access_key_id = creds["redpanda"]["aws_access_key_id"]
    aws_secret_access_key = creds["redpanda"]["aws_secret_access_key"]

    # Assume role and get session token
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    session_token = assume_aws_role(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_role_name="tracecat-lab-admin-attacker-role",
        aws_role_session_name=f"tracecat-lab-stratus-{technique_id}-{ts}",
    )

    # Create infra
    _run_stratus_cmd(
        cmds=["warmup", technique_id],
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=session_token
    )


async def simulate_stratus(technique_id: str, delay: int):
    normal_user = NoisyStratusUser(
        name="redpanda",
        technique_id=technique_id
    )
    normal_user.set_background()
    denotator = DelayedDetonator(
        delay=delay,
        detonate=detonate_stratus,
        technique_id=technique_id
    )
    tasks = [normal_user, denotator]
    await asyncio.gather(*[task.run() for task in tasks])


def clean_up_stratus(technique_id: str):
    # NOTE: We clean up infra using server admin
    # to avoid this being logged into scored alerts
    _run_stratus_cmd(
        ["cleanup", technique_id],
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_EY"]
    )


async def ddos(
    n_attacks: int = 10,
    timeout: int | None = None,
    delay: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):

    timeout = timeout or 100
    delay = delay or 50

    # Create lab admin credentials
    initialize_stratus_lab()

    # Run simulation
    for _ in range(n_attacks):
        technique_id = random.choice(AWS_ATTACK_TECHNIQUES)

        logger.info("🎲 Run simulation %r", technique_id)
        warm_up_stratus(technique_id=technique_id)
        try:
            await asyncio.wait_for(
                simulate_stratus(
                    technique_id=technique_id,
                    delay=delay,
                    max_tasks=max_tasks,
                    max_actions=max_actions,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.info("✅ Simulation %r timed out successfully after %s seconds", technique_id, timeout)

        simulate_stratus(technique_id=technique_id)
        clean_up_stratus(technique_id=technique_id)

    # Final clean up
    _run_stratus_cmd(["cleanup", "--all"])
