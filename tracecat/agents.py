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
import random
from pathlib import Path
from abc import abstractmethod, ABC
from datetime import datetime
import boto3
import inspect
import textwrap
import json
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, TypeVar
from typing import Literal

import boto3
from pydantic import BaseModel

from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.credentials import assume_aws_role
from tracecat.llm import async_openai_call
from tracecat.logger import ActionLog, composite_logger, file_logger
from tracecat.credentials import load_lab_credentials
from tracecat.llm import async_openai_call
from tracecat.infrastructure import show_terraform_state
from tracecat.ingestion.aws_cloudtrail import AWS_CLOUDTRAIL__EVENT_TIME_FORMAT


TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)
TRACECAT__LAB_DEBUG_LOGS_PATH = TRACECAT__LAB_DIR / "debug.log"
TRACECAT__LAB_ACTIONS_LOGS_PATH = TRACECAT__LAB_DIR / "actions.log"
TRACECAT__LAB_DEBUG_LOGS_PATH.touch()
TRACECAT__LAB_ACTIONS_LOGS_PATH.touch()


T = TypeVar("T", bound=BaseModel)


def model_as_text(model: type[T]) -> str:
    return inspect.getsource(model)


__REPLACE_WITH_ACTIONS_LIST__ = str


def load_all_policies(scenario_id: str):
    """Returns mapping of every user policy in a scenario."""
    dir_path = path_to_pkg() / "tracecat/scenarios" / scenario_id / "policies"
    policies = {}
    for file_path in dir_path.glob("*.json"):
        if file_path.is_file():
            user_name = file_path.stem
            with file_path.open() as f:
                policies[user_name] = json.load(f)

    if not len(policies) > 0:
        raise FileNotFoundError(f"No policies found in {dir_path}")

    return policies


def load_all_personas(scenario_id: str):
    """Returns mapping of every user persona in a scenario."""
    dir_path = path_to_pkg() / "tracecat/scenarios" / scenario_id / "personas"
    personas = {}
    for file_path in dir_path.glob("*.txt"):
        if file_path.is_file():
            user_name = file_path.stem
            with file_path.open() as f:
                personas[user_name] = f.read()

    if not len(personas) > 0:
        raise FileNotFoundError(f"No personas found in {dir_path}")

    return personas

class AWSAPICallAction(BaseModel):
    """An action that a user can perform.

    Parameters
    -----------
    name: str
        The name of the AWS service and API call (e.g. `s3:ListBucket`).
        This must be explicitly mentioned in the "Background" or "Objectives".
    description: str
        The intent of the action. Please be detailed and verbose when describing the intent.
    duration: float
        Time in seconds between 5-15 seconds to complete this action.
    """

    name: __REPLACE_WITH_ACTIONS_LIST__
    description: str
    duration: float


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


class User(ABC):
    def __init__(
        self,
        name: str,
        terraform_path: Path,
        policy: dict[str, Any] | None = None,
        background: str | None = None,
        max_tasks: int | None = None,
        max_actions: int | None = None,
        mock_actions: bool = False
    ):
        self.name = name
        self.terraform_path = terraform_path
        self.policy = policy
        self.background = background
        self.max_tasks = max_tasks or 10
        self.max_actions = max_actions or 10
        self.tasks = deque()
        self.objectives: list[str] = []
        self.mock_actions = mock_actions
        # Set terraform state on init
        self.terraform_state = show_terraform_state(terraform_path)
        # For lab diagnostics
        self.logger = composite_logger(
            f"diagnostics__{self.name}",
            file_path=TRACECAT__LAB_DEBUG_LOGS_PATH,
            log_format="log",
        )
        # For actions
        self.action_logger = file_logger(
            f"actions__{self.name}",
            file_path=TRACECAT__LAB_ACTIONS_LOGS_PATH,
            log_format="json"
        )

    @abstractmethod
    async def get_objective(self) -> Objective:
        pass

    async def perform_task(self, task: Task):
        for action in task.actions:
            await self.perform_action(action)

    def _perform_action(self, action: AWSAPICallAction):
        return (self._mock_action if self.mock_actions else self._make_api_call)(action)

    async def _mock_action(self, action: AWSAPICallAction):
        """Mock an action by logging it to a file."""
        self.logger.info(f"Mocking action: {action.name}...")
        await asyncio.sleep(1)

    @abstractmethod
    async def _make_api_call(self, action: AWSAPICallAction, max_retries: int = 3) -> Objective:
        pass

    async def perform_action(self, action: AWSAPICallAction):
        # Add random noise to action.duration
        action.duration = min(action.duration, 3)

        offset = int(0.3 * action.duration)
        action.duration += random.randint(-offset, offset)
        self.logger.info(f"Begin action: {action}...")
        duration = action.duration
        start_delay = random.random() * duration
        await asyncio.sleep(start_delay)

        # Do action AKA API call
        self.logger.info(f"Making API call: {action.name}...")
        if action.name is None:
            title = "No API call made"
            action_name = "None"
        else:
            title = f"Performed API call {action.name}"
            action_name = action.name
            await self._perform_action(action)

        # Log action
        log = ActionLog(
            title=title,
            user=self.name,
            action=action_name,
            description=action.description,
        )
        self.action_logger.info(log)

        # End delay
        await asyncio.sleep(duration - start_delay)
        self.logger.info(f"End action: {action.name}")


    async def run(self):
        """Run the user's script on the event loop."""
        while True:
            objective = await self.get_objective()
            for task in objective.tasks:
                await self.perform_task(task)
            self.objectives.append(f"{objective.name}: {objective.description}")


def load_aws_cloudtrail_samples() -> list[dict]:
    dir_path = path_to_pkg() / "tracecat/log_samples/aws_cloudtrail"
    json_paths = dir_path.glob("*.json")
    log_samples = []
    for path in json_paths:
        with open(path, "r", encoding="utf-8") as f:
            log_samples.append(json.load(f))
    return log_samples


def load_aws_cloudtrail_docs() -> list[dict]:
    path = path_to_pkg() / "tracecat/log_references/aws_cloudtrail.html"
    with open(path, "r") as f:
        return f.read()


class AWSAPIServiceMethod(BaseModel):
    """Python Boto3 Service and Method

    Params
    ------
    aws_service: str
        The AWS service to call. For s3:ListBuckets, this would be "s3".
    aws_method: str
        The AWS service method name. For s3:ListBuckets, this would be "ListBuckets".
    user_agent: str
        The user agent used to call the AWS API.
        Can choose from `Boto3`, `aws-cli`, or a browser.
    """

    aws_service: str
    aws_method: str
    user_agent: Literal["Boto3", "aws-cli", "Mozilla", "Chrome", "Safari"]


class AWSUser(User):

    def get_aws_credentials(self):
        creds = load_lab_credentials(is_compromised=False)
        aws_access_key_id = creds[self.name]["aws_access_key_id"]
        aws_secret_access_key = creds[self.name]["aws_secret_access_key"]
        # Assume role and get session token
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        session_creds = assume_aws_role(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_role_name="tracecat-lab-admin-role",
            aws_role_session_name=f"tracecat-lab-normal-{ts}",
        )
        return session_creds

    async def _make_api_call(self, action: AWSAPICallAction, max_retries: int = 3):
        """Make AWS API call."""

        # Define Action
        system_context = "You are an expert at performing AWS API calls."
        api_call_prompt = textwrap.dedent(
            f"""
            Your objective is to perform the following AWS API call with the objective:
            Action: {action.name}
            Objective: {action.description}

            Please describe a AWSAPIServiceMethod according to the following pydantic model.
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
        aws_service = aws_action["aws_service"]
        aws_method = aws_action["aws_method"]
        user_agent = aws_action["user_agent"]
        terraform_state = self.terraform_state

        # Get AWS user credentials
        session_creds = self.get_aws_credentials()
        aws_account_id = session_creds.get("aws_account_id")
        aws_access_key_id = session_creds.get("aws_access_key_id")

        # Generate CloudTrail log
        ts = datetime.now().strftime(AWS_CLOUDTRAIL__EVENT_TIME_FORMAT)
        cloudtrail_docs = load_aws_cloudtrail_docs()
        sample_logs = "\n".join(json.dumps(d) for d in load_aws_cloudtrail_samples())
        cloudtrail_prompt = textwrap.dedent(
            f"""
            You objective is to create a realistic AWS CloudTrail log JSON with `eventTime` set to {ts}.

            The JSON log must conform with the following metadata:
            ```
            Action: {action.name}
            Objective: {action.description}
            AWS Account ID: {aws_account_id}
            AWS Access Key ID: {aws_access_key_id}
            AWS Service: {aws_service}
            AWS Method: {aws_method}
            User Agent: {user_agent}
            Terraform state:\n{terraform_state}
            ```

            The JSON log must conform with the AWS CloudTrail JSON schema.
            Please predict a realistic `userAgent` in the JSON log.
            If applicable, please include realistic `requestParameters` and `responseElements` in the JSON log.

            You must use the following AWS CloudTrail documentation in HTML as a guide:
            ```html
            {cloudtrail_docs}
            ```

            You can use the following eexample AWS CloudTrail JSON logs as a guide:
            ```ndjson
            {sample_logs}
            ```
            """
        )
        cloudtrail_log = await async_openai_call(
            cloudtrail_prompt,
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info("🤖 Generated CloudTrail log:\n%s", json.dumps(cloudtrail_log, indent=2))


class NormalAWSUser(AWSUser):

    async def get_objective(self) -> Objective:
        """Get an objective, dictated by the background/persona of the user."""
        system_context = (
            "You are an expert in predicting what users in an organization might do."
            "You are also an expert at breaking down objectives into smaller tasks."
            "You are creative and like to think outside the box."
        )
        prompt = textwrap.dedent(
            f"""
            Your task is to predict what a user with the following background might realistically do:

            Background:
            {self.background}

            The user has completed the following objectives:
            {self.objectives!s}

            You must select from a list of actions that the user can perform, given their IAM policy:
            ```
            {json.dumps(self.policy, indent=2)}
            ```

            Please describe an Objective with its constituent Tasks and Actions according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {dynamic_action_factory(self.policy["Statement"][0]["Action"])}
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
