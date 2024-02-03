import json
import textwrap
import subprocess
from tracecat.llm import openai_call, async_openai_call
from tracecat.agents import Objective, model_as_text, dynamic_action_factory, Task, AWSUser


MOST_COMMON_AWS_API_CALLS = [
    # S3 actions
    "s3:CreateBucket",
    "s3:ListBucket",
    "s3:PutObject",
    "s3:GetObject",
    "s3:DeleteBucket",
    "s3:DeleteObject",
    # EC2 actions
    "ec2:RunInstances",
    "ec2:DescribeInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    # Lambda actions
    "lambda:ListFunctions",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "lambda:DeleteFunction",
    # DynamoDB actions
    "dynamodb:CreateTable",
    "dynamodb:PutItem",
    "dynamodb:GetItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:Scan",
    "dynamodb:Query",
    # SQS actions
    "sqs:CreateQueue",
    "sqs:GetQueueUrl",
    "sqs:ListQueues",
    "sqs:SendMessage",
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
    # IAM actions
    "iam:CreateUser",
    "iam:ListUsers",
    "iam:DeleteUser",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    # SNS actions
    "sns:CreateTopic",
    "sns:ListTopics",
    "sns:Publish",
    "sns:Subscribe",
    "sns:Unsubscribe",
    # General AWS Management & Governance
    "ec2:DescribeRegions",
    "ec2:DescribeAvailabilityZones",
]


class NoisyStratusUser(AWSUser):
    """The expert false positives generator."""

    def __init__(
        self,
        name: str,
        technique_id: str,
        max_tasks: int | None = None,
        max_actions: int | None = None,
        mock_actions: bool = False
    ):
        self.name = name
        self.technique_id = technique_id
        self.max_tasks = max_tasks
        self.max_actions = max_actions
        self.mock_actions = mock_actions
        self.objectives: list[str] = []

    def set_background(self) -> str:
        stratus_show_output = subprocess.run([
            "docker",
            "run",
            "--rm",
            "ghcr.io/datadog/stratus-red-team",
            "show",
            self.technique_id
        ], capture_output=True, text=True)
        attack_description = stratus_show_output.stdout
        system_context = (
            "You are an expert in reverse engineering Cloud cyber attacks."
            "You are an expert in Cloud activities that produce false positives in a SIEM."
            "You are an expert in spoofing in the Cloud."
        )
        prompt = (
            f"Your task is to rewrite this attack description:\n```{attack_description}```\n"
            "Into a description of a software engineer or DevOps engineer"
            " using the same tools and techniques as described in the attack"
            " but in a completely non-malicious way."
            " The software engineer or DevOps engineer might not follow security best practices,"
            " but they do not intend to harm their company in any way."
        )
        result = openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="text",
        )
        self.background = result

    async def get_objective(self) -> Objective:
        system_context = (
            "You are an expert in predicting what users in an organization might do."
            "You are also an expert at breaking down objectives into smaller tasks."
            "You are creative and like to think outside the box."
        )
        api_calls_list = "\n".join(f"- {item}" for item in MOST_COMMON_AWS_API_CALLS)
        prompt = textwrap.dedent(
            f"""
            Your task is to predict what a user with the following background might realistically do:

            Background:
            {self.background}

            The user has completed the following objectives:
            {self.objectives!s}

            You must either select from the following list of AWS API calls:
            ```
            {api_calls_list}
            ```
            or any AWS API call explicitly mentioned in the "Background".

            Please describe an Objective with its constituent Tasks and Actions according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {dynamic_action_factory(MOST_COMMON_AWS_API_CALLS)}
            ```

            You are to generate a structured JSON response.
            Each objective should have no more than {self.max_tasks} tasks.
            Each task should have no more than {self.max_actions} actions.
            Please be realistic and detailed when describing the objective and tasks.
            """
        )
        # self.logger.info(f"### Get objective prompt\n\n{prom`pt}")
        result = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info(f"New objective:\n```\n{json.dumps(result, indent=2)}\n```")
        obj = Objective(**result)
        return obj
