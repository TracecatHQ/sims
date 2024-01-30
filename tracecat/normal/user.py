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
import os
import random
import textwrap
from collections import deque
from pathlib import Path
from typing import Any, TypeVar

import boto3
from pydantic import BaseModel

from tracecat.config import TRACECAT__HOME_DIR
from tracecat.llm import async_openai_call
from tracecat.logging import standard_logger

T = TypeVar("T", bound=BaseModel)


def model_as_text(model: type[T]) -> str:
    return inspect.getsource(model)


__REPLACE_WITH_ACTIONS_LIST__ = str

MAX_TASKS = 10
MAX_ACTIONS = 10


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


class User:
    def __init__(self, name: str, policy: dict[str, Any], background: str):
        self.name = name
        self.policy = policy
        self.background = background
        self.tasks = deque()
        self.objectives: list[str] = []
        self.logger = standard_logger(self.name)

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

            Please describe an Objective with its constutuent Tasks and Actions according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {dynamic_action_factory(self.policy["Statement"][0]["Action"])}
            ```

            You are to generate a structured JSON response.
            Each objective should have no more than {MAX_TASKS} tasks.
            Each task should have no more than {MAX_ACTIONS} actions.
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
        self.logger.info(f"### Get objective result\n\n{result}")
        obj = Objective(**result)
        return obj

    async def perform_task(self, task: Task):
        for action in task.actions:
            await self.perform_action(action)

    async def perform_action(self, action: Action):
        # Add random noise to action.duration
        action.duration = min(action.duration, 20)

        offset = int(0.3 * action.duration)
        action.duration += random.randint(-offset, offset)
        self.logger.info(f"Begin action: {action}")
        duration = action.duration
        # Wait random  T = duration - random.randint(0, duration)
        start_delay = random.random() * duration
        await asyncio.sleep(start_delay)
        # Do action

        if action.name is not None:
            # Do API call
            self.logger.info(f"Call API: {action.name}...")
            creds_path = TRACECAT__HOME_DIR / f"{self.name}_user_credentials.json"
            with creds_path.open("r") as f:
                creds = json.load(f)["AccessKey"]
            await self._make_aws_api_call(action, creds)
            self.logger.info(f"End API call: {action.name}")
        else:
            # Do custom action
            self.logger.info("Performing custom action")
        # End delay
        await asyncio.sleep(duration - start_delay)
        self.logger.info(f"End action: {action.name}")

    async def _make_aws_api_call(self, action: Action, creds: dict):
        error = None
        for _ in range(3):
            system_context = "You are an expert at performing AWS API calls."
            prompt = textwrap.dedent(
                f"""
                Your objective is to perform the following AWS API call using the python3 boto3 client with the objective:
                Action: {action.name}
                Objective: {action.description}

                Please describe a PythonBoto3APICall according to the following pydantic model.
                ```
                {model_as_text(PythonBoto3APICall)}
                ```
                {f'Error in previous call: {error}' if error is not None else ''}
                """
            )
            args = await async_openai_call(
                prompt, system_context=system_context, response_format="json_object"
            )
            try:
                service = args.pop("service")
                method = args.pop("method")
                kwargs = args.pop("kwargs")
                client = _get_boto3_client(creds=creds, service=service)
                fn = getattr(client, method)
                result = fn(**kwargs)
                return result
            except Exception as e:
                self.logger.error(f"Error in boto3 api call: {e}")
                error = e

    async def run(self):
        """Run the user's script on the event loop."""
        while True:
            objective = await self.get_objective()
            for task in objective.tasks:
                await self.perform_task(task)
            self.objectives.append(f"{objective.name}: {objective.description}")


async def run_org(users: list[User]):
    await asyncio.gather(*[user.run() for user in users])


def _get_boto3_client(creds: dict, service: str):
    client = boto3.client(
        service,
        aws_access_key_id=creds.get("AccessKeyId"),
        aws_secret_access_key=creds.get("SecretAccessKey"),
        aws_session_token=creds.get("SessionToken"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"),
        endpoint_url=os.environ.get("TRACECAT__AWS_ENDPOINT_URL"),
        verify=os.environ.get("TRACECAT__AWS_VERIFY", True),
    )
    return client


if __name__ == "__main__":
    with Path("policies/solo.json").open() as f:
        solo_policy = json.load(f)

    with Path("personas/solo.txt").open() as f:
        solo_background = f.read()
    solo = User("solo", solo_policy, solo_background)

    with Path("policies/calrissian.json").open() as f:
        cal_policy = json.load(f)
    with Path("personas/calrissian.txt").open() as f:
        cal_bg = f.read()
    calrissian = User("calrissian", cal_policy, cal_bg)

    users: list[User] = [solo, calrissian]
    asyncio.run(run_org(users))
