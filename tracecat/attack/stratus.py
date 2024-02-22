"""Module with functions to DDoS your AWS environment with possible attacks. Chaos engineering style.

This is a pentesting tool that assumes full visibility into your AWS inventory.
"""

import asyncio
import ssl

from tracecat.agents import AWSUser
from tracecat.attack.attacker import MaliciousStratusUser
from tracecat.attack.noise import NoisyStratusUser
from tracecat.logger import standard_logger

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
    "aws.defense-evasion.dns-delete-logs",
    "aws.defense-evasion.organizations-leave",
    "aws.defense-evasion.vpc-remove-flow-logs",
    "aws.discovery.ec2-enumerate-from-instance",
    "aws.discovery.ec2-download-user-data",
    "aws.execution.ec2-launch-unusual-instances",
    "aws.execution.ec2-user-data",
    "aws.execution.ssm-send-command",
    "aws.execution.ssm-start-session",
    "aws.exfiltration.ec2-security-group-open-port-22-ingress",
    "aws.exfiltration.ec2-share-ami",
    "aws.exfiltration.ec2-share-ebs-snapshot",
    "aws.exfiltration.rds-share-snapshot",  # Too slow
    "aws.exfiltration.s3-backdoor-bucket-policy",
    "aws.impact.s3-ransomware-batch-deletion",
    "aws.impact.s3-ransomware-client-side-encryption",
    "aws.impact.s3-ransomware-individual-deletion",
    "aws.initial-access.console-login-without-mfa",  # Creates new user
    "aws.lateral-movement.ec2-instance-connect",
    "aws.persistence.iam-backdoor-role",
    "aws.persistence.iam-backdoor-user",  # Creates new user
    "aws.persistence.iam-create-admin-user",
    "aws.persistence.iam-create-backdoor-role",
    "aws.persistence.iam-create-user-login-profile",  # Creates new user
    "aws.persistence.lambda-backdoor-function",
    "aws.persistence.lambda-layer-extension",
    "aws.persistence.lambda-overwrite-code",
    "aws.persistence.rolesanywhere-create-trust-anchor",
]

# NOTE: We piece together independent attacks in
# temporal order as a proxy for a multistage attack
# These attacks don't actually chain together by identities (human and non-human)

AWS_ATTACK_SCENARIOS = {
    "ec2-brute-force": [
        "aws.execution.ssm-start-session",  # Execution
        "aws.credential-access.ec2-get-password-data",  # Credential Access
        "aws.discovery.ec2-enumerate-from-instance",  # Discovery
        "aws.exfiltration.ec2-share-ami",  # Exfiltration
    ]
}


IAM_SCENARIOS = [
    "codebuild_secrets",
    "detection_evasion",
    "ec2_ssrf",
    "ecs_efs_attack",
    "iam_prvesec_by_attachment",
]


async def simulate_stratus(
    technique_id: str,
    scenario_id: str,
    uuid: str,
    user_name: str,
    max_tasks: int,
    max_actions: int,
    timeout: int,
):
    user = NoisyStratusUser(
        uuid=uuid,
        name=user_name,
        technique_id=technique_id,
        scenario_id=scenario_id,
        max_tasks=max_tasks,
        max_actions=max_actions,
    )
    denotator = MaliciousStratusUser(
        uuid=uuid,
        name=user_name,
        technique_id=technique_id,
        scenario_id=scenario_id,
        # Assume very carefully executed attack
        max_tasks=scenario_id,
        max_actions=max_actions,
    )

    tasks: list[AWSUser] = [user, denotator]
    try:
        logger.info(f"🚀 Launching job {uuid} with {technique_id}")
        await asyncio.gather(
            *[asyncio.wait_for(task.run(), timeout=timeout) for task in tasks]
        )
    except asyncio.TimeoutError:
        logger.info(f"✅ Timed out job {uuid} with {technique_id}")
    except (asyncio.CancelledError, ssl.SSLError) as e:
        logger.info(f"✅ Stopped job {uuid} with {technique_id}")
        raise e


async def ddos(
    uuid: str,
    technique_ids: list[str] | None = None,
    scenario_id: str | None = None,
    user_name: str | None = None,
    timeout: int | None = None,
    max_tasks: int | None = None,
    max_actions: int | None = None,
):
    user_name = "tracecat-user"
    timeout = timeout or 300
    technique_ids = technique_ids or AWS_ATTACK_SCENARIOS["ec2-brute-force"]
    scenario_id = scenario_id or "codebuild_secrets"

    # Run simulation
    kill_chain_length = len(technique_ids)
    try:
        for i, technique_id in enumerate(technique_ids):
            technique_desc = f"☢️ Execute campaign [Technique {i + 1} of {kill_chain_length} | {technique_id} | %s]"
            # Execute attack
            try:
                logger.info(technique_desc, "🎲 Run simulation")
                await simulate_stratus(
                    technique_id=technique_id,
                    scenario_id=scenario_id,
                    uuid=uuid,
                    user_name=user_name,
                    max_tasks=max_tasks,
                    max_actions=max_actions,
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.info(technique_desc, "✅ Timed out successfully")
            except (asyncio.CancelledError, ssl.SSLError) as e:
                raise e
    except (asyncio.CancelledError, ssl.SSLError):
        logger.info(f"✅ Successfully cancelled job {uuid}")
