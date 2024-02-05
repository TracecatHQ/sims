from __future__ import annotations

import asyncio
import json
import os
import textwrap
from datetime import datetime, timedelta
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Literal,
    Self,
    TypeVar,
    get_args,
    get_origin,
)
from uuid import uuid4

import httpx
import orjson
import polars as pl
from pydantic import BaseModel, Field, field_serializer

from tracecat.agents import model_as_text
from tracecat.autotuner.types import RuleType
from tracecat.config import TRACECAT__AUTOTUNER_DIR, path_to_pkg
from tracecat.cspm import search_many
from tracecat.cspm.prowler import get_latest_report_df
from tracecat.llm import async_openai_call
from tracecat.logger import standard_logger
from tracecat.schemas.datadog import RuleUpdateRequest

logger = standard_logger(__name__)

Rule = TypeVar("Rule", bound=RuleUpdateRequest)
Q = TypeVar("Q", bound=BaseModel)


def _is_pydantic_model(cls: type) -> bool:
    return isinstance(cls, type) and issubclass(cls, BaseModel)


def _find_model_dependencies(model: type[BaseModel]) -> set[type[BaseModel]]:
    """Find all the dependencies of a Pydantic model."""

    dependencies = set()
    for field_type in model.__annotations__.values():
        # If it's a generic type (e.g., List, Union)
        if get_origin(field_type) is not None:
            args = get_args(field_type)
            # Get all next level types, included nested
            next_args: list[type] = []
            for arg in args:
                if get_origin(arg) is not None:  # List or Union
                    next_args.extend(get_args(arg))
                else:
                    next_args.append(arg)
            # Check if any of the arguments is a subclass of BaseModel
            for arg in next_args:
                if _is_pydantic_model(arg):
                    dependencies.add(arg)
                    dependencies |= _find_model_dependencies(arg)
        elif _is_pydantic_model(field_type):
            dependencies.add(field_type)
    return dependencies


def _get_model_dependencies_string(model: type[BaseModel]) -> str:
    """Find all the dependencies of a Pydantic model and return a string representation."""
    dependencies = _find_model_dependencies(model)

    return "\n\n".join([model_as_text(dep) for dep in [*dependencies, model]])


#####################
## STEP 0: Augment ##
#####################
__PLACEHOLDER_TABLES__ = str


class InvestigationQuery(BaseModel):
    """A list of queries that will help determine whether the alert is a true or false positive.

    Parameters
    ----------
    table_name: str
        The table in the vector database to be serached.

    query: str
        The natural language query to be run against the vector database table.
    """

    table_name: __PLACEHOLDER_TABLES__
    query: str


async def get_retrieval_queries(
    rule_id: str, rule: Rule, sources: list[str]
) -> list[InvestigationQuery]:
    logger.info(f"Generating retrieval queries for rule {rule_id}...")
    system_context = (
        "You are an expert security content educator."
        " You are an expert at writing queries for information retrieval in a security context."
        " You always break down security content into concise questions that will guide an investigation."
    )

    prompt = textwrap.dedent(
        f"""
        You have been given an alert with the following description:
        ```
        {rule.message}
        ```
        Your task is to generate a list of 5-8 queries that will help determine whether the alert is a true or false positive.

        Construct your query under the assumption that it will be used to retrieve information about a rule, through a vector database.
        The available tables in the vector database are: {sources!r}.

        Please return describe a `InvestigationQueries` according to the following pydantic model.
        ```
        InvestigationQueries = list[InvestigationQuery]

        {model_as_text(InvestigationQuery).replace("__PLACEHOLDER_TABLES__", "Literal" + repr(sources))}
        ```
        """
    )

    response = await async_openai_call(
        prompt,
        system_context=system_context,
        response_format="json_object",
        temperature=0.5,
    )
    if isinstance(response, dict) and "InvestigationQueries" in response:
        response = response["InvestigationQueries"]
    queries = [InvestigationQuery.model_validate(r) for r in response]
    return queries


async def get_relevant_vdb_documents(
    rule_id: str, rule: Rule, variant: str, table_name: str
) -> list[tuple[str, str]]:
    # What is the rule?

    # Why did the LLM make the suggestion?

    # Back this up with facts from dynamic sources
    # 1. Construct IR queries
    # 2. Run search for each query
    queries = await get_retrieval_queries(rule_id, rule, sources=[table_name])

    search_results = search_many([q.query for q in queries], table_name=table_name)

    # Correlate the search results with the report
    report_lf = get_latest_report_df().lazy()
    uuid_col = "FindingUniqueId"
    lfs = []
    # Construct list of lazyframes
    for res in search_results:
        lf = (
            # Take only top 3
            res.data.head(3)
            .select(pl.col.embed_text, uuid_col)
            .explode(uuid_col)
            .lazy()
            .join(report_lf, on=uuid_col, how="left")
            .select(
                [
                    "ResourceArn",
                    "ServiceName",
                    "ResourceType",
                    "CheckTitle",
                    "Status",
                    "StatusExtended",
                    "Severity",
                    "Description",
                    "Risk",
                    pl.col.Remediation.struct.field("Recommendation").struct.field(
                        "Text"
                    ),
                    pl.col.Remediation.struct.field("Recommendation").struct.field(
                        "Url"
                    ),
                ]
            )
        )
        lfs.append(lf)

    dfs = pl.collect_all(lfs)
    return [
        (q.query, df.write_csv(include_header=True))
        for q, df in zip(queries, dfs, strict=True)
    ]


async def get_recommendations(
    rule_id: str, rule: Rule, variant: str, n_choices: int = 3
) -> list[RuleUpdateRec]:
    """Get recommendations for a rule.

    Steps
    -----
    Get supporting documents
    -------------------------
    - Operate under the assumption that all required data is available and preprocessed.
    - The objective is to bring together all the data that is relevant to the rule.
    - Perform a RAG step to consolidate relevant documents from:
        1. Prowler CSPM
        2. Attack path
        3.
    2. Suggest new rules

    """
    cspm_prowler_docs = await get_relevant_vdb_documents(
        rule_id, rule, variant, "cspm_prowler"
    )

    cspm_prowler_full = "\n".join(
        f"### {query}\n{result}" for query, result in cspm_prowler_docs
    )
    additional_context = {"CSPM Findings": cspm_prowler_full}

    recs = await recommend_new_rule(
        rule_id,
        rule,
        additional_context=additional_context,
        variant=variant,
        n_choices=n_choices,
    )
    return recs


#####################
## STEP 1: Suggest ##
#####################


class RuleUpdateRec(BaseModel):
    """A recommendation for a new rule.

    Attributes
    -----------
    rule: Rule
        The suggested rule.

    explanation: str
        An explanation of why the rule was suggested. Please be detailed and specific.

    changes: str
        A description of what was changed in the rule. Please be detailed and specific.

    """

    id: str = Field(default_factory=lambda _: f"rec-{uuid4()}")
    rule_id: str
    rule: RuleUpdateRequest
    explanation: str
    changes: str


async def recommend_new_rule(
    rule_id: str,
    rule: Rule,
    *,
    additional_context: dict[str, Any],
    variant: RuleType,
    n_choices: int = 3,
) -> list[RuleUpdateRec]:
    """Suggests an optimized rule based on the input rule.

    Takes a rule and suggests N optimized rules based on the input rule.
    """
    system_context = (
        "You are a principal security engineer working for a large enterprise."
        "Your KPIs for this quarter are to reduce the false positive rate of your SIEM."
        " You are an expert at writing and amending SIEM detection rules in order to "
        "improve the SIEM's false positive rate."
    )
    additional_context = "# Additional Context\n" + "\n\n".join(
        f"## {k}\n{v}" for k, v in additional_context.items()
    )
    rule_improvement = "lower false positive rate"
    # Read markdown file
    path = path_to_pkg() / "tracecat/schemas/datadog_log_search_syntax.md"
    with path.open("r") as f:
        rule_syntax = f.read()
    prompt = textwrap.dedent(
        f"""
        Your objective is to suggest an improved {variant.capitalize()} SIEM rule.

        Given the following original rule:
        ```
        {rule.model_dump_json()}
        ```
        with id: {rule_id}

        And the following information about the rule:
        {additional_context}

        Your goal is to suggest a new {variant.capitalize()} SIEM rule that has a {rule_improvement} than the original rule.
        The new rule that you suggest will be sent to the {variant.capitalize()} SIEM to run in production.

        You MUST only amend the `queries`, `filters`, and `casees` fields of the rule.

        The rule syntax is documented below:
        {rule_syntax}

        Please describe a `{RuleUpdateRec.__name__}` according to the following pydantic model.
        ```
        {_get_model_dependencies_string(RuleUpdateRequest)}

        {model_as_text(RuleUpdateRec)}
        ```
        """
    )

    logger.info("################")
    logger.info(prompt)
    logger.info("################")

    response = await async_openai_call(
        prompt,
        system_context=system_context,
        response_format="json_object",
        temperature=1,
        n=n_choices,
    )

    return [RuleUpdateRec.model_validate(r) for r in response]


#######################
## STEP 2: Translate ##
#######################


# NOTE: We don't need the translate step ATM. Going to use LLM to generate datadog query directly, and run the query on the logs search API.


class PythonPolarsQuery(BaseModel):
    query: str


async def translate_rules(
    rules: list[RuleUpdateRec], *, variant: RuleType
) -> list[PythonPolarsQuery]:
    """Translates a list of rules from its original to a list of python-polars queries."""
    translator = RULE_TRANSLATOR_FACTORY[variant]

    # Schedule all tasks to run in parallel by creating a task for each coroutine
    tasks = [translator(suggestion.rule) for suggestion in rules]

    return await asyncio.gather(*tasks)


async def translate_datadog_rule(rule: RuleUpdateRequest) -> PythonPolarsQuery:
    """Translate a Datadog rule to a python-polars query."""
    system_context = (
        "You are a principal security data engineer."
        " You are an expert at translating Datadog JSON rules into their equivalent python-Polars queries."
        " You always write correct and functional python-Polars queries/expressions."
    )

    # TODO: Few shot prompting
    examples: list[str] = []
    examples_string = "\n".join(examples)

    prompt = textwrap.dedent(
        f"""

        Your task is to translate the following Datadog rule into a python-polars query.

        Given the following Datadog JSON rule:
        ```
        {rule.model_dump_json()}
        ```

        Here are some exmaples of inputs and outputs for this task:
        ```
        {examples_string}
        ```

        Please translate the rule into a python-polars query.

        You must write your code such that I can pass it into `subprocess.run(["python", "-c", "<YOUR CODE>"])` to execute.
        You must not include any comments in your code.

        Please describe a `PythonPolarsQuery` according to the following pydantic model.
        ```
        {model_as_text(PythonPolarsQuery)}
        ```
        """
    )
    response = await async_openai_call(
        prompt,
        system_context=system_context,
        response_format="json_object",
        temperature=0.3,
    )
    return PythonPolarsQuery(**response)


#####################
## STEP 3: Execute ##
#####################

# NOTE: We don't need to build a custom execute step ATM.
# Going to use LLM to generate datadog query directly, and run the query on the logs search API.


async def handle_rate_limiting(response: httpx.Response, rule_id: str):
    """Handles waiting based on Datadog's rate limiting response headers."""
    if "X-RateLimit-Reset".lower() in response.headers:
        wait_time = int(response.headers["X-RateLimit-Reset".lower()])
        logger.info(f"{rule_id}: Rate limited. Waiting for {wait_time} seconds...")
        await asyncio.sleep(wait_time)


# @retry(
#     wait=wait_random_exponential(multiplier=1, max=60),
#     stop=stop_after_attempt(5),  # Stop after 5 tries
#     retry=retry_if_exception_type(httpx.HTTPStatusError),  # Retry on HTTPStatusError
#     before=before_log(logger, logging.INFO),
# )
async def _make_request(url: str, headers: dict, body: dict, tags: dict | None = None):
    tags = tags or {}
    rule_id = tags.get("id")
    max_retries = 10
    async with httpx.AsyncClient(http2=True) as client:
        for i in range(max_retries):
            try:
                logger.info(f"{rule_id}: Request {i}/{max_retries}...")
                response = await client.post(
                    url, headers=headers, data=orjson.dumps(body)
                )

                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
                    await handle_rate_limiting(response, rule_id)
                    continue
                logger.exception(f"{rule_id}: Failed to make request. {response.text}")
                raise e


async def _get_paginated_endpoint(url: str, headers: dict, body: dict):
    all_events = []
    while True:
        response = await _make_request(url, headers, body)
        response_json = response.json()

        events = response_json["data"]
        if not events:
            break
        all_events.extend(events)
        cursor = response_json.get("meta", {}).get("page", {}).get("after")
        if cursor is None:
            break  # No more pages
        body["page"] = {"cursor": cursor}
        await asyncio.sleep(1)
    return all_events


async def _get_endpoint(url: str, headers: dict, body: dict, tags: dict | None = None):
    response = await _make_request(url, headers, body, tags)
    response_json = response.json()
    events = response_json["data"]
    return events


def get_queries_dir() -> Path:
    path = TRACECAT__AUTOTUNER_DIR / "queries"
    path.mkdir(parents=True, exist_ok=True)
    return path


async def run_datadog_query_on_logs(
    start: datetime,
    end: datetime,
    rule_id: str,
    rule: Rule,
    limit: int = 1000,
) -> tuple[Path | None, int | None]:
    """Run Datadog query on a range of logs.

    Only CloudTrail alerts are downloaded.
    """
    url = "https://api.us5.datadoghq.com/api/v2/logs/events/search"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "DD-API-KEY": os.environ["DD_API_KEY"],
        "DD-APPLICATION-KEY": os.environ["DD_APP_KEY"],
    }
    filters: list[str] = []
    if rule.filters:
        for f in rule.filters:
            query = f"-{f.query}" if f.action == "suppress" else f.query
            if query:
                filters.append(query)
    queries = rule.queries or []
    filter_string = " ".join(filters)
    query_string = " ".join(q.query for q in queries if hasattr(q, "query") and q.query)
    full_filter_query = f"{filter_string} {query_string}"

    body = {
        "filter": {
            "query": full_filter_query,
            "from": start.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "to": end.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        },
        "page": {"limit": limit},
    }
    logger.info(f"🐶 Filter query: {full_filter_query}")
    logger.info("🐶 Querying Datadog logs between [%s, %s]", start, end)

    events = await _get_endpoint(url, headers, body, tags={"id": rule_id})

    if not events:
        logger.info(f"{rule_id}: No events found for the query.")
        return None, None

    df = pl.from_dicts(events).unnest("attributes")
    logger.info(f"{rule_id}: Found %d events for the query.", df.height)
    file_path = (
        get_queries_dir() / f"{rule.name}__{datetime.utcnow().isoformat()}.parquet"
    )
    df.write_parquet(file_path)
    return file_path, df.height


class QueryResult(BaseModel):
    rule_id: str
    path: Path | None = None
    n_alerts: int | None = None

    @field_serializer("path")
    def serialize_path(self, path: Path | None):
        return str(path.expanduser().resolve()) if path else None


class OptimizerResult(BaseModel):
    rule_id: str
    rule_rec: RuleUpdateRec
    query_path: Path | None = None
    n_alerts: int | None = None

    @field_serializer("query_path")
    def serialize_query_path(self, path: Path | None):
        return str(path.expanduser().resolve()) if path else None

    @classmethod
    def list_from_query_results(
        cls, query_results: list[QueryResult], rule_rec: list[RuleUpdateRec]
    ) -> list[Self]:
        return [
            cls(
                rule_id=qr.rule_id,
                rule_rec=rec,
                query_path=qr.path,
                n_alerts=qr.n_alerts,
            )
            for qr, rec in zip(query_results, rule_rec, strict=True)
        ]


async def execute_query(
    start: datetime, end: datetime, rule_rec: RuleUpdateRec
) -> QueryResult:
    """Execute the query and add the number of alerts."""
    path, n_alerts = await run_datadog_query_on_logs(
        start, end, rule_rec.rule_id, rule_rec.rule
    )
    return QueryResult(rule_id=rule_rec.rule_id, path=path, n_alerts=n_alerts)


async def execute_queries(
    start: datetime, end: datetime, rule_recs: list[RuleUpdateRec]
) -> list[QueryResult]:
    """Executes a list of queries and returns the paths of the results."""
    # NOTE: This is likely IO bound because we're hitting DD api

    tasks = [execute_query(start, end, rule_rec) for rule_rec in rule_recs]
    logger.info("Executing %d queries...", len(tasks))
    return await asyncio.gather(*tasks)


####################
## STEP 4: Select ##
####################

# NOTE: No need to select - user will manually select the best rule from the suggestions.


def count_false_positives(alert: dict) -> int:
    """Counts the number of false positives for a given rule."""
    return NotImplemented


def pick_best_rule(rules: list[Rule]) -> Rule:
    """Picks the best rule from a list of rules.

    Strategy
    --------
    The best rule is the one that has the lowest number of false positives.
    """

    return NotImplemented


########################
## STEP 5: Strategies ##
########################


def get_recs_dir() -> Path:
    path = TRACECAT__AUTOTUNER_DIR / "recommendations"
    path.mkdir(parents=True, exist_ok=True)
    return path


async def cherry_pick_strategy(
    rule_id: str, rule: Rule, variant: RuleType
) -> list[OptimizerResult]:
    """Returns a cherry picked rule based on the input rule."""
    # We first generate a list of options, then cherry pick the best one.
    # This returns a list of rule suggestions
    # TODO: Stream them in a generator

    logger.info(f"Generating options for rule {rule.name}...")
    checkpoint_path = TRACECAT__AUTOTUNER_DIR / "checkpoints"
    checkpoint_path.mkdir(parents=True, exist_ok=True)

    filename = f"{variant}__{rule_id}.json"
    recs_path = checkpoint_path / filename
    if not recs_path.exists():
        recs = await recommend_new_rule(rule_id, rule, variant=variant, n_choices=3)
        with recs_path.open("w") as f:
            json.dump([r.model_dump() for r in recs], f, indent=4)
    else:
        logger.info(f"Loading recommendations from {recs_path!s}...")
        with recs_path.open("r") as f:
            obj = json.load(f)
        recs = [RuleUpdateRec.model_validate(r) for r in obj]

    # Execute all queries and get the results
    logger.info(f"Executing queries for rule {rule.name}...")
    end = datetime.utcnow() + timedelta(days=1)
    start = end - timedelta(days=3)
    query_results = await execute_queries(start, end, recs)
    return OptimizerResult.list_from_query_results(query_results, recs)


async def user_select_strategy(
    rule_id: str, rule: Rule, variant: RuleType
) -> list[OptimizerResult]:
    """Returns list of rule recommendations for the user to select."""

    logger.info(f"Generating recommendations for rule {rule_id}...")

    filename = f"{variant}__{rule_id}.json"
    recs_path = get_recs_dir() / filename

    # TODO(perf): Improve this caching strategy
    if not recs_path.exists():
        recs = await get_recommendations(rule_id, rule, variant=variant, n_choices=3)
        with recs_path.open("w") as f:
            json.dump([r.model_dump() for r in recs], f, indent=4)
    else:
        logger.info(f"Loading recommendations from {recs_path!s}...")
        with recs_path.open("r") as f:
            obj = json.load(f)
        recs = [RuleUpdateRec.model_validate(r) for r in obj]

    # Execute all queries and get the results
    logger.info(f"Executing queries for rule {rule_id}...")
    end = datetime.utcnow() + timedelta(days=1)
    start = end - timedelta(days=3)
    query_results = await execute_queries(start, end, recs)
    logger.info(f"Finished executing queries for rule {rule_id}...")
    return OptimizerResult.list_from_query_results(query_results, recs)


OptimizerStrategy = Literal["cherry_pick", "user_select"]


async def optimize_rule(
    rule_id: str,
    rule: Rule,
    *,
    variant: RuleType,
    strategy: OptimizerStrategy = "user_select",
) -> list[OptimizerResult]:
    """Optimizes a rule based on the input rule."""
    optimizer = RULE_OPTIMIZER_FACTORY[strategy]
    return await optimizer(rule_id, rule, variant=variant)


RULE_OPTIMIZER_FACTORY: dict[
    OptimizerStrategy, Callable[..., Awaitable[list[OptimizerResult]]]
] = {
    "cherry_pick": cherry_pick_strategy,
    "user_select": user_select_strategy,
}

RULE_TRANSLATOR_FACTORY = {
    "datadog": translate_datadog_rule,
}
