"""LLM Driven Users.

Architecture
------------

How it works
- Use GPT3.5 (chespest + fastest) to make decisions about:
    - What to do (select an action)
    - When to do it (how long to sleep)
    - How to do it  (additional context)

User's event loop (agent):
1. Define an objective, dictated by the background/persona of the user. e.g. if the user is a dev, then they might want to write and test code.
2. Define a task
3. Select a sequence of actions (from the permitted actions list) that will complete the task
4. Perform the actions with random delays between them
5. Repeat 3-4 until the task is complete
6. Repeat 2-6 until the objective is complete
7. Start again from 1

Simpler kflow (less api calls):
1. When there is no current objective, get an objective (from some mediator) (get_objective)
2. (LLM) Given an objective, break it down into tasks based on the user's background (get_tasks)
3. (LLM) Given a task, break it down into actions based on whatever actions are available (get_actions)
4. For each task and action, execute it with random noise and delay in between to simulate a workflow (do_action)
5. Repeat from step 1
"""
from __future__ import annotations

import asyncio
import inspect
import json
import ssl
import textwrap
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Literal, TypeVar
from uuid import uuid4

from pydantic import BaseModel

from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.infrastructure import show_terraform_state
from tracecat.llm import async_openai_call
from tracecat.logger import JsonFormatter, ThoughtLog, composite_logger, standard_logger
from tracecat.scenarios import SCENARIOS_MAPPING

TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)
AWS_CLOUDTRAIL__EVENT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


T = TypeVar("T", bound=BaseModel)


def model_as_text(model: type[T]) -> str:
    return inspect.getsource(model)


__REPLACE_WITH_ACTIONS_LIST__ = str


class Background(BaseModel):
    """User background.

    Parameters
    ----------
    job_title: str
        The user's job title.
    description: str
        The user's background.
    """

    job_title: str
    description: str


class AWSAPICallAction(BaseModel):
    """An action that a user can perform.

    Parameters
    ----------
    name: str
        The name of the AWS service and API call (e.g. `s3:ListBucket`).
        This must be explicitly mentioned in the "Background" or "Objectives".
    description: str
        The intent of the action. Please be detailed and verbose when describing the intent.
    duration: int
        Time in seconds to complete this action.
    """

    name: __REPLACE_WITH_ACTIONS_LIST__
    description: str
    duration: int


def dynamic_action_factory(actions: list[str]) -> str:
    src = inspect.getsource(AWSAPICallAction)
    actions_list_type = (
        "Literal[" + ",".join((f"{action!r}" for action in actions)) + "]"
    )
    src = src.replace("__REPLACE_WITH_ACTIONS_LIST__", actions_list_type)
    return src


class Task(BaseModel):
    """A task is a collection of actions.

    The task is complete when all actions are complete.

    Parammeters
    -----------
    name: str
        The name of the task.
    description: str
        The intent of the task. Please be detailed and verbose when describing the intent.
    actions: list[str]
        A list of AWS API calls that must be completed to complete the task.
    """

    name: str
    description: str
    actions: list[AWSAPICallAction]


class Objective(BaseModel):
    """An objective is a collection of tasks.

    The objective is complete when all tasks are complete.

    Parammeters
    -----------
    name: str
        The name of the objective.
    description: str
        A description of the objective. Please be detailed and verbose when describing the objective.
    tasks: list[Task]
        An ordered sequence of tasks that must be completed to complete the objective.
    """

    name: str
    description: str
    tasks: list[Task]


def get_path_to_user_logs(uuid: str) -> Path:
    file_path = TRACECAT__LAB_DIR / "thoughts" / f"{uuid}.ndjson"
    return file_path


class User(ABC):
    def __init__(
        self,
        uuid: str,
        name: str,
        scenario_id: str,
        terraform_path: Path,
        is_compromised: bool,
        policy: dict[str, Any] | None = None,
        terraform_script_path: Path | None = None,
        max_tasks: int | None = None,
        max_actions: int | None = None,
        enqueue: Callable | None = None,
    ):
        self.uuid = uuid
        self.name = name
        self.scenario_id = scenario_id
        self.terraform_path = terraform_path
        # Backup in case Terraform state is not available
        self.terraform_script_path = terraform_script_path
        self.is_compromised = is_compromised
        self.policy = policy
        self.max_tasks = max_tasks or 10
        self.max_actions = max_actions or 10
        self.objectives: list[str] = []
        self.background = None  # Only set at .run
        self.objective = None  # Latest objective
        # For lab diagnostics
        self._user_uuid = str(uuid4())
        self.logger = standard_logger(self.uuid, level="INFO", log_format="log")
        # For thoughts
        logs_file_path = get_path_to_user_logs(uuid=self.uuid)

        self._use_enqueue = enqueue is not None
        if self._use_enqueue:
            self.enqueue = enqueue
        else:
            self.thoughts_logger = composite_logger(
                f"{self.uuid}__{self.name}__thoughts__{self._user_uuid}",
                file_path=logs_file_path,
                log_format="json",
            )

    @property
    def terraform_state(self) -> str | None:
        try:
            state = show_terraform_state(self.terraform_path)
            if isinstance(state, str) and "no state" in state.lower():
                raise FileNotFoundError
        except FileNotFoundError:
            state = None
            self.logger.warning("⚠️ Terraform state not found. Ignore state in prompt.")
        else:
            self.logger.info("🚧 Got Terraform state:\n%s", state)
        return state

    @abstractmethod
    async def _get_background(self) -> str:
        pass

    @abstractmethod
    async def _get_objective(self) -> str:
        pass

    def log_thought(self, thought_log: ThoughtLog):
        if self._use_enqueue:
            log = thought_log.model_dump()
            log["time"] = datetime.now().strftime(JsonFormatter._date_format)
            self.enqueue(log)
        else:
            self.thoughts_logger.info(thought_log)

    async def get_background(self) -> str:
        self.logger.info("🔍 Getting user background...")
        background = await self._get_background()
        self.background = background
        return background

    async def get_objective(self) -> Objective:
        objective = await self._get_objective()
        if "Objectives" in objective.keys():
            objective = objective["Objectives"]

        elif "objectives" in objective.keys():
            objective = objective["objectives"]

        if "Objective" in objective.keys():
            objective = objective["Objective"]

        elif "objective" in objective.keys():
            objective = objective["objective"]

        objective = Objective(
            name=objective["name"],
            description=objective["description"],
            tasks=objective["tasks"],
        )
        return objective

    @abstractmethod
    async def _make_api_call(self, action: AWSAPICallAction) -> list[dict]:
        pass

    async def perform_action(self, action: AWSAPICallAction):
        try:
            logs = await self._make_api_call(action=action)
        except (asyncio.CancelledError, ssl.SSLError) as e:
            self.logger.info("🛑 User action cancelled.")
            raise e
        except Exception as e:
            self.logger.warning(
                "⚠️ Error performing action: %s. Skipping...", action, exc_info=e
            )
        return logs

    async def run(self):
        """Run the user's script on the event loop."""
        self.logger.info("🚀 Starting user script...")
        try:
            background = await self.get_background()
            # Log background
            background_log = ThoughtLog(
                uuid=self.uuid,
                user_name=self.name,
                thought=background,
                tag="background",
                is_compromised=self.is_compromised,
            )
            self.log_thought(background_log)
            while True:
                objective = await self.get_objective()
                self.objective = objective
                # Log Objective, Tasks, and Actions
                objective_log = ThoughtLog(
                    uuid=self.uuid,
                    user_name=self.name,
                    thought=objective.model_dump(),
                    tag="objective",
                    is_compromised=self.is_compromised,
                )
                self.log_thought(objective_log)
                for task in objective.tasks:
                    for action in task.actions:
                        audit_logs = await self.perform_action(action=action)
                        for audit_log in audit_logs:
                            # Log audit trail
                            audit_log = ThoughtLog(
                                uuid=self.uuid,
                                user_name=self.name,
                                thought=audit_log,
                                tag="log",
                                is_compromised=self.is_compromised,
                            )
                            self.log_thought(audit_log)
                self.objectives.append(f"{objective.name}: {objective.description}")
        except (asyncio.CancelledError, ssl.SSLError):
            self.logger.info("🛑 User script cancelled.")


def load_aws_cloudtrail_docs() -> list[dict]:
    path = path_to_pkg() / "tracecat/log_references/aws_cloudtrail.html"
    with open(path, "r") as f:
        return f.read()


class AWSAPIServiceMethod(BaseModel):
    """AWS API Service and Method

    Parameters
    ----------
    aws_service: str
        The AWS service to call. For s3:ListBuckets, this would be "s3".
    aws_method: str
        The AWS service method name. For s3:ListBuckets, this would be "ListBuckets".
    user_agent: str
        The user agent used to call the AWS API.
        Can choose from `Boto3`, `aws-cli`, or a browser.
    iam_identity: Literal["user", "role"]
        The IAM identity that will call the AWS service.
        An IAM identity can represent a human and non-human identity.
    iam_role_usage: str | None
        If `iam_identity` is 'role', this represents the use-case
        for using IAM roles with temporary policies.
    """

    aws_service: str
    aws_method: str
    user_agent: Literal["Boto3", "aws-cli", "Mozilla", "Chrome", "Safari"]
    iam_identity: Literal["user", "role"]
    iam_role_usage: Literal[
        "federated_user_access",
        "temporary_iam_user_permissions",
        "cross_account_access",
        "cross_service_access__principal_permissions",
        "cross_service_access__service_role",
        "cross_service_access__service_linked_role",
    ]


class AWSCallerIdentity(BaseModel):
    """Represents the realistic identity for a real AWS principal interacting with a real app.
    Make up a story.


    Parameters
    ----------
    account: str
        The AWS account ID number of the account that owns or contains the calling entity.
    user_id: str
        Depends on the principal that is initiating the request.

    arn: str
        The AWS ARN associated with the calling entity. This can be the ARN of an AWS user, role, or assumed role.
        The ARN naming must be description of it's intended use.
        If it's malicious user, DO NOT use a suspicious sounding ARN.
    """

    account: str
    user_id: str
    arn: str


class AWSUser(User):
    def _get_iam(self):
        self.logger.info("🪪 Loading IAM...")

        return SCENARIOS_MAPPING[self.scenario_id]

    async def _simulate_caller_identity(
        self,
        background: dict,
        objective: Objective,
        action: AWSAPICallAction,
        permissions: str,
    ) -> dict:
        system_context = "You are an expert at AWS identity access management."
        prompt = textwrap.dedent(
            f"""
            Your objective is to create a AWS caller identity given:
            - Background: {background}
            - Objective: {objective.description}
            - Action: {action}
            - AWS IAM permissions:
            ```hcl
            {permissions}
            ```

            You must select an AWS identity defined in the AWS IAM Terraform script.

            Create a `AWSCallerIdentity` according to the following pydantic model:
            ```
            {model_as_text(AWSCallerIdentity)}
            ```
            """
        )
        identity = await async_openai_call(
            prompt,
            system_context=system_context,
            response_format="json_object",
        )
        return identity

    async def _make_api_call(self, action: AWSAPICallAction) -> list[dict]:
        """Make AWS API call."""

        # Define Action
        system_context = "You are an expert at performing AWS API calls."
        api_call_prompt = textwrap.dedent(
            f"""
            Your objective is to perform the following AWS API call with the objective:
            Action: {action.name}
            Objective: {action.description}

            Describe a `AWSAPIServiceMethod` according to the following pydantic model.
            ```
            {model_as_text(AWSAPIServiceMethod)}
            ```
            """
        )
        aws_action = await async_openai_call(
            api_call_prompt,
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info("🎲 Selected action:\n%s", json.dumps(aws_action, indent=2))
        if "AWSAPIServiceMethod" in aws_action.keys():
            aws_action = aws_action["AWSAPIServiceMethod"]

        try:
            aws_service = aws_action["aws_service"]
            aws_method = aws_action["aws_method"]
            user_agent = aws_action["user_agent"]
        except KeyError as e:
            raise KeyError(
                f"Expected {AWSAPIServiceMethod!s}. Got {aws_action}."
            ) from e

        # Get AWS user credentials
        permissions = self._get_iam()
        aws_caller_identity = await self._simulate_caller_identity(
            background=self.background,
            objective=self.objective,
            action=action,
            permissions=permissions,
        )

        # Get temporal scope
        start_ts = datetime.now()
        end_ts = start_ts + timedelta(seconds=action.duration)
        start_ts_text = start_ts.strftime(AWS_CLOUDTRAIL__EVENT_TIME_FORMAT)
        end_ts_text = end_ts.strftime(AWS_CLOUDTRAIL__EVENT_TIME_FORMAT)

        # Generate CloudTrail log
        cloudtrail_prompt = textwrap.dedent(
            f"""
            Your objective is to create realistic AWS CloudTrail JSON records with `eventTime` set between {start_ts_text} and {end_ts_text}.

            Task: Generate log records with a realistic `userAgent` according to the following nested JSON format:
            ```json
            {{"Records": list of dicts}}
            ```

            Each record must conform with the following metadata:
            ---
            Action: {action.name}
            Objective: {action.description}
            AWS Caller Identity: {aws_caller_identity}
            AWS Service: {aws_service}
            AWS Method: {aws_method}
            AWS User Agent: {user_agent}
            AWS IAM Permissions: {permissions}
            ---
            """
        )
        self.logger.info(
            "🤖 Generate CloudTrail log given AWS Caller Identity:\n%s",
            json.dumps(aws_caller_identity, indent=2),
        )
        output = await async_openai_call(
            cloudtrail_prompt,
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info(
            "✅ Generated CloudTrail records:\n%s", json.dumps(output, indent=2)
        )

        # We only want individual records
        if isinstance(output, dict):
            if "Records" in output.keys():
                records = output["Records"]
            else:
                records = [output]

        return records
