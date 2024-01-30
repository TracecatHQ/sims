"""Module with functions to DDoS your AWS environment with possible attacks. Chaos engineering style.

This is a pentesting tool that assumes full visibility into your AWS inventory.
"""

import os
import random
import subprocess
import time
from pathlib import Path

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
    "aws.initial-access.console-login-without-mfa",
    "aws.persistence.iam-backdoor-role",
    "aws.persistence.iam-backdoor-user",
    "aws.persistence.iam-create-admin-user",
    "aws.persistence.iam-create-user-login-profile",
    "aws.persistence.lambda-backdoor-function",
    "aws.persistence.lambda-layer-extension",
    "aws.persistence.lambda-overwrite-code",
    "aws.persistence.rolesanywhere-create-trust-anchor",
]


def _run_stratus(cmds: list[str]):
    stratus_dir_path = Path(os.path.expanduser("~")) / ".stratus-red-team"
    os.makedirs(stratus_dir_path, exist_ok=True)
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{stratus_dir_path}:/root/.stratus-red-team",
        "-e",
        f"AWS_ACCESS_KEY_ID={os.environ['AWS_ACCESS_KEY_ID']}",
        "-e",
        f"AWS_SECRET_ACCESS_KEY={os.environ['AWS_SECRET_ACCESS_KEY']}",
        "-e",
        f"AWS_DEFAULT_REGION={os.environ['AWS_DEFAULT_REGION']}",
        "ghcr.io/datadog/stratus-red-team",
        *cmds,
    ]
    subprocess.run(cmd)


def ddos(n_attacks: int = 10, delay: int = 1):
    for _ in range(n_attacks):
        technique_id = random.choice(AWS_ATTACK_TECHNIQUES)
        _run_stratus(["detonate", technique_id])
        time.sleep(delay)
    _run_stratus("cleanup", "--all")
