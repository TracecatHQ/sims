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
from datetime import datetime, timedelta
import inspect
import textwrap
import json
import orjson
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, TypeVar, Literal

from pydantic import BaseModel

from tracecat.config import TRACECAT__LAB_DIR, path_to_pkg
from tracecat.llm import async_openai_call
from tracecat.logger import ActionLog, composite_logger, file_logger
from tracecat.credentials import load_lab_credentials, get_caller_identity
from tracecat.llm import async_openai_call
from tracecat.infrastructure import show_terraform_state
from tracecat.ingestion.aws_cloudtrail import AWS_CLOUDTRAIL__EVENT_TIME_FORMAT


TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)
TRACECAT__LAB__DEBUG_LOGS_PATH = TRACECAT__LAB_DIR / "debug.log"
TRACECAT__LAB__ACTIONS_LOGS_PATH = TRACECAT__LAB_DIR / "actions.log"
TRACECAT__LAB__AWS_CLOUDTRAIL_PATH = TRACECAT__LAB_DIR / "aws_cloudtrail.ndjson"

TRACECAT__LAB__DEBUG_LOGS_PATH.touch()
TRACECAT__LAB__ACTIONS_LOGS_PATH.touch()


T = TypeVar("T", bound=BaseModel)


def model_as_text(model: type[T]) -> str:
    return inspect.getsource(model)


__REPLACE_WITH_ACTIONS_LIST__ = str


class AWSAPICallAction(BaseModel):
    """An action that a user can perform.

    Parameters
    -----------
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
        # For lab diagnostics
        self.logger = composite_logger(
            f"diagnostics__{self.name}",
            file_path=TRACECAT__LAB__DEBUG_LOGS_PATH,
            log_format="log",
        )
        # For actions
        self.action_logger = file_logger(
            f"actions__{self.name}",
            file_path=TRACECAT__LAB__ACTIONS_LOGS_PATH,
            log_format="json"
        )

    @property
    def terraform_state(self):
        return show_terraform_state(self.terraform_path)

    @abstractmethod
    async def get_objective(self) -> Objective:
        pass

    async def perform_task(self, task: Task):
        for action in task.actions:
            await self.perform_action(action)

    def _perform_action(self, action: AWSAPICallAction):
        return (self._mock_action if self.mock_actions else self._make_api_call)(action=action)

    async def _mock_action(self, action: AWSAPICallAction):
        """Mock an action by logging it to a file."""
        self.logger.info(f"Mocking action: {action.name}...")
        await asyncio.sleep(1)

    @abstractmethod
    async def _make_api_call(self, action: AWSAPICallAction) -> Objective:
        pass

    async def perform_action(self, action: AWSAPICallAction):
        # Add random noise to action.duration
        action.duration = min(action.duration, 3)

        offset = int(0.3 * action.duration)
        action.duration += random.randint(-offset, offset)
        duration = action.duration
        start_delay = random.random() * duration
        await asyncio.sleep(start_delay)

        # Do action AKA API call
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
        return {"aws_access_key_id": aws_access_key_id, "aws_secret_access_key": aws_secret_access_key}

    async def _make_api_call(self, action: AWSAPICallAction):
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
            model="gpt-3.5-turbo-1106"
        )
        self.logger("🎲 Selected action:\n%s", json.dumps(aws_action, indent=2))
        aws_service = aws_action["aws_service"]
        aws_method = aws_action["aws_method"]
        user_agent = aws_action["user_agent"]
        terraform_state = self.terraform_state

        # Get AWS user credentials
        creds = self.get_aws_credentials()
        aws_caller_identity = get_caller_identity(
            aws_access_key_id=creds["aws_access_key_id"],
            aws_secret_access_key=creds["aws_secret_access_key"] 
        )

        # Generate CloudTrail log
        start_ts = datetime.now().strftime(AWS_CLOUDTRAIL__EVENT_TIME_FORMAT)
        end_ts = start_ts + timedelta(seconds=action.duration)
        cloudtrail_docs = load_aws_cloudtrail_docs()
        cloudtrail_prompt = textwrap.dedent(
            f"""
            You objective is to create realistic AWS CloudTrail JSON log records with `eventTime` set between {start_ts} and {end_ts}.
            Use this format:
            ```json
            {{"Records": list of dictionaries}}
            ```

            Each record must conform with the following metadata:
            ```
            Action: {action.name}
            Objective: {action.description}
            AWS Caller Identity: {aws_caller_identity}
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
            """
        )
        self.logger.info(
            "🤖 Generate CloudTrail log given AWS Caller Identity:\n%s",
            json.dumps(aws_caller_identity, indent=2)
        )
        cloudtrail_log = await async_openai_call(
            cloudtrail_prompt,
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info("✅ Generated CloudTrail log:\n%s", json.dumps(cloudtrail_log, indent=2))
        
        # Write log to ndjson
        TRACECAT__LAB__AWS_CLOUDTRAIL_PATH.touch()
        record = orjson.dumps(cloudtrail_log)
        with TRACECAT__LAB__AWS_CLOUDTRAIL_PATH.open("ab") as f:
            f.write(record + b"\n")
