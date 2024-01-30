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
from abc import abstractmethod, ABC
import boto3
import inspect
import textwrap
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, TypeVar

import boto3
from pydantic import BaseModel

from tracecat.config import TRACECAT__LAB_DIR
from tracecat.llm import async_openai_call
from tracecat.logger import ActionLog, composite_logger, file_logger
from tracecat.credentials import load_lab_credentials
from tracecat.llm import async_openai_call


TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)
TRACECAT__LAB_DEBUG_LOGS_PATH = TRACECAT__LAB_DIR / "debug.log"
TRACECAT__LAB_ACTIONS_LOGS_PATH = TRACECAT__LAB_DIR / "actions.log"
TRACECAT__LAB_DEBUG_LOGS_PATH.touch()
TRACECAT__LAB_ACTIONS_LOGS_PATH.touch()


T = TypeVar("T", bound=BaseModel)


def model_as_text(model: type[T]) -> str:
    return inspect.getsource(model)


__REPLACE_WITH_ACTIONS_LIST__ = str


class Action(BaseModel):
    """An action that a user can perform.

    Parammeters
    -----------
    name: str | None = None
        The name of the action. This may be an API call within the permitted actions list, or a custom non-API call action.
        Use "None" if the action is a custom action.
    description: str
        The intent of the action. Please be detailed and verbose when describing the intent.
    duration: float
        A reasonable estimate of the time in seconds to complete this action.
    """

    name: __REPLACE_WITH_ACTIONS_LIST__ | None = None
    description: str
    duration: float


def dynamic_action_factory(actions: list[str]) -> str:
    src = inspect.getsource(Action)
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
        A list of actions that must be completed to complete the task.
    """

    name: str
    description: str
    actions: list[Action]


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
        policy: dict[str, Any],
        background: str,
        max_tasks: int | None = None,
        max_actions: int | None = None,
    ):
        self.name = name
        self.policy = policy
        self.background = background
        self.max_tasks = max_tasks or 10
        self.max_actions = max_actions or 10
        self.tasks = deque()
        self.objectives: list[str] = []
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

    async def perform_action(self, action: Action):
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


class PythonBoto3APICall(BaseModel):
    """Python Boto3 API Call

    Params
    ------
    service: str
        The AWS service to call. For s3:ListBuckets, this would be "s3".
    method: str
        The service method to call. For s3:ListBuckets, this would be "list_buckets".
        I should be able to use `getattr(boto3.client(service), method)` to get the method.
    kwargs: dict[str, Any]
        The kwargs to pass to the action.

    """

    service: str
    method: str  # Lower snake case AWS client methods
    kwargs: dict[str, Any]


class AWSUser(User):

    async def _make_aws_api_call(self, action: Action, max_retries: int = 3):
        error = None
        for _ in range(max_retries):
            system_context = "You are an expert at performing AWS API calls."
            error_msg = (
                (
                    f"\bThere was an error in the previous API call:"
                    f"\n```\n{error}\n```"
                    f"\nPlease amend your API call and try again.\n"
                )
                if error is not None
                else ""
            )
            prompt = textwrap.dedent(
                f"""
                Your objective is to perform the following AWS API call using the python3 boto3 client with the objective:
                Action: {action.name}
                Objective: {action.description}
                {error_msg}
                Please describe a PythonBoto3APICall according to the following pydantic model.
                ```
                {model_as_text(PythonBoto3APICall)}
                ```
                """
            )
            args = await async_openai_call(
                prompt, system_context=system_context, response_format="json_object"
            )
            try:
                service = args.pop("service")
                method = args.pop("method")
                kwargs = args.pop("kwargs")
                # TODO: Use context manager to switch compromised / not
                creds = load_lab_credentials(is_compromised=False)
                client = boto3.client(
                    service,
                    aws_access_key_id=creds[self.name]["aws_access_key_id"],
                    aws_secret_access_key=creds[self.name]["aws_secret_access_key"],
                )
                fn = getattr(client, method)
                result = fn(**kwargs)
                return result
            except Exception as e:
                self.logger.error(f"Error in boto3 api call: {e}")
                error = e
