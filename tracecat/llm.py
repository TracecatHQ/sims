from __future__ import annotations

from typing import Literal

import orjson
from dotenv import find_dotenv, load_dotenv
from openai import AsyncOpenAI, OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from tracecat.logger import standard_logger

load_dotenv(find_dotenv())

logger = standard_logger(__name__)

client = OpenAI()

MODEL_T = Literal["gpt-4-0125-preview", "gpt-4-vision-preview", "gpt-3.5-turbo-1106"]
MAX_RETRIES = 3
DEFAULT_SYSTEM_CONTEXT = "You are an expert threat intelligence researcher, detection and response engineer, and threat hunter."


@retry(
    stop=stop_after_attempt(MAX_RETRIES),
    wait=wait_exponential(multiplier=1, min=4, max=10),
)
def openai_call(
    prompt: str,
    model: MODEL_T = "gpt-4-0125-preview",
    temperature: float = 0.2,
    system_context: str = DEFAULT_SYSTEM_CONTEXT,
    response_format: Literal["json_object", "text"] = "text",
    stream: bool = False,
    parse_json: bool = True,
    **kwargs,
):
    """Call the OpenAI API with the given prompt and return the response.

    Returns
    -------
    dict[str, Any]
        The message object from the OpenAI ChatCompletion API.
    """
    if response_format == "json_object":
        system_context += " Please only output valid JSON."

    messages = [
        {"role": "system", "content": system_context},
        {"role": "user", "content": prompt},
    ]

    logger.info("Calling OpenAI API...")
    response = client.chat.completions.create(
        model=model,
        response_format={"type": response_format},
        messages=messages,
        temperature=temperature,
        stream=stream,
        **kwargs,
    )
    if stream:
        return response
    res = response.choices[0].message.content.strip()

    if parse_json and response_format == "json_object":
        return orjson.loads(res)
    return res


async_client = AsyncOpenAI()


@retry(
    stop=stop_after_attempt(MAX_RETRIES),
    wait=wait_exponential(multiplier=1, min=4, max=10),
)
async def async_openai_call(
    prompt: str,
    model: MODEL_T = "gpt-4-0125-preview",
    temperature: float = 0.2,
    system_context: str = DEFAULT_SYSTEM_CONTEXT,
    response_format: Literal["json_object", "text"] = "text",
    stream: bool = False,
    parse_json: bool = True,
    **kwargs,
):
    """Call the OpenAI API with the given prompt and return the response.

    Returns
    -------
    dict[str, Any]
        The message object from the OpenAI ChatCompletion API.
    """
    if response_format == "json_object":
        system_context += " Please only output valid JSON."

    messages = [
        {"role": "system", "content": system_context},
        {"role": "user", "content": prompt},
    ]

    logger.info("Calling OpenAI API...")
    response = await async_client.chat.completions.create(
        model=model,
        response_format={"type": response_format},
        messages=messages,
        temperature=temperature,
        stream=stream,
        **kwargs,
    )
    if stream:
        return response
    res = response.choices[0].message.content.strip()

    if parse_json and response_format == "json_object":
        return orjson.loads(res)
    return res
