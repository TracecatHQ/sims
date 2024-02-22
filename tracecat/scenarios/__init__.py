from tracecat.scenarios.codebuild_secrets import (
    tf_script as codebuild_secrets_tf_script,
)
from tracecat.scenarios.detection_evasion import (
    tf_script as detection_evasion_tf_script,
)
from tracecat.scenarios.ec2_ssrf import tf_script as ec2_ssrf_tf_script
from tracecat.scenarios.ecs_efs_attack import tf_script as ecs_efs_attack_tf_script
from tracecat.scenarios.iam_privesec_by_attachment import (
    tf_script as iam_privesec_by_attachment_tf_script,
)

SCENARIOS_MAPPING = {
    "codebuild_secrets": codebuild_secrets_tf_script,
    "ecs_efs_attack": ecs_efs_attack_tf_script,
    "detection_evasion": detection_evasion_tf_script,
    "ec2_ssrf": ec2_ssrf_tf_script,
    "iam_privesec_by_attachment": iam_privesec_by_attachment_tf_script,
}
