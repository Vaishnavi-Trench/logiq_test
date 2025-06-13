"""Splunk Utils for SIEM Agent Tools"""

from langchain_core.prompts import PromptTemplate

from app.services.siem.splunk import utils
from app.services.siem.splunk import models as splunk_models
from pltfrm import Logger2 as Logger
from pltfrm import AIManager
from pltfrm import RedisManager, PromptManager, PropX
import hashlib


async def splunk_choose_index(
    intcid: str, aid: str, requirement: str, alert: str
) -> dict:
    """
    First tool to run while triaging a requirement.
    Fetches the correct index for the requirement.
    """
    Logger.info("Entering Splunk Choose Index tool to run while triaging a requirement")
    customer_index_details = utils.get_indices_with_metadata(intcid)
    requirement_hash = hashlib.sha256(requirement.strip().encode()).hexdigest()
    redis_key = f"K:SI:{intcid}:splunk:{requirement_hash}"
    cached_index = RedisManager.get_key(redis_key)
    Logger.info(f"Cached index: {cached_index}")
    if cached_index is not None:  # Ensure it's not None before decoding
        decoded_index = cached_index.decode("utf-8")
        index_data = decoded_index.split("|")
        index_name = index_data[0]
        sourcetype = index_data[1]
        Logger.debug(
            f"Cache hit: Returning cached index for requirement {requirement}: {decoded_index}"
        )
        return {"index_name": index_name, "sourcetype": sourcetype}

    index_name = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="SPLUNK_INDEX_SELECTION_PROMPT",
        prompt_params={
            "requirement": requirement,
            "alert": alert,
            "customer_index_details": customer_index_details,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=splunk_models.IndexName,
        history_params={
            "aid": aid,
            "subtype": "index_name",
        },
        type="triage",
        system_prompt="You are an expert in understanding Splunk SIEM Alerts. Your task is to determine index_name to query from given input.",
    )

    index_name = index_name["index_name"]
    Logger.debug(f"Index name: {index_name}")
    RedisManager.set_key(redis_key, index_name, expiry=3600)
    Logger.debug(f"Index chosen: {index_name}")
    index_data = index_name.split("|")
    index_name = index_data[0]
    sourcetype = index_data[1]
    return {"index_name": index_name, "sourcetype": sourcetype}


async def _generate_splunk_query_with_steps(
    intcid: str,
    aid: str,
    requirement: str,
    alert: str,
    index_and_sourcetype: dict,
    field_name_list: list,
) -> str:
    """Helper function to generate a Splunk query through all steps."""
    # Step 1: Generate query template
    splunk_query_template = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="SPLUNK_QUERY_TEMPLATE_PROMPT",
        prompt_params={
            "requirement": requirement,
            "alert": alert,
            "index_and_sourcetype": index_and_sourcetype,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=splunk_models.SplunkQueryTemplate,
        history_params={
            "aid": aid,
            "subtype": "query_template",
        },
        type="triage",
        system_prompt="You are an expert in understanding Splunk SIEM Alerts. Your task is to determine query template with placeholders for querying SPLUNK for given input.",
    )

    splunk_query_template = splunk_query_template["query_template"]
    Logger.info(f"Generated Splunk query template: {splunk_query_template}")

    # Step 2: Field replacement
    splunk_query = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="SPLUNK_FIELD_REPLACEMENT_PROMPT",
        prompt_params={
            "query_template": splunk_query_template,
            "field_mapping": field_name_list,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=splunk_models.SplunkQuery,
        history_params={
            "aid": aid,
            "subtype": "query_template",
        },
        type="triage",
        system_prompt="You are an expert in understanding Splunk SIEM Alerts. Your task is to replace fields in the given query template.",
    )

    splunk_query = splunk_query["query"]
    Logger.debug(f"Fields replaced: {splunk_query}")

    # Step 3: Query sanitization
    splunk_query = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="SPLUNK_QUERY_SANITIZER_PROMPT",
        prompt_params={
            "splunk_query": splunk_query,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=splunk_models.SplunkQuery,
        history_params={
            "aid": aid,
            "subtype": "query_template",
        },
        type="triage",
        system_prompt="You are an expert in understanding Splunk SIEM Alerts. Your task is to determine sanitize the given query.",
    )

    splunk_query = splunk_query["query"]
    Logger.info(f"Query sanitized: {splunk_query}")
    if not splunk_query.strip().lower().startswith("search"):
        splunk_query = f"search {splunk_query}"
    return splunk_query_template, splunk_query


async def generate_splunk_query(
    intcid: str,
    aid: str,
    index_name: str,
    sourcetype: str,
    requirement: str,
    alert: str,
) -> dict:
    """Second tool to run while triaging a requirement."""
    Logger.debug(
        f"tool:generate_splunk_query: {intcid}, {index_name}:{sourcetype}, {requirement}, {alert}"
    )
    field_name_list = utils.get_fields_with_metadata(
        intcid, f"{index_name}|{sourcetype}"
    )

    index_and_sourcetype = {"index": index_name, "sourcetype": sourcetype}

    # Generate initial query
    splunk_query_template, splunk_query = await _generate_splunk_query_with_steps(
        intcid=intcid,
        aid=aid,
        requirement=requirement,
        alert=alert,
        index_and_sourcetype=index_and_sourcetype,
        field_name_list=field_name_list,
    )

    # Try validation and regeneration if needed
    for attempt in range(3):  # Allow up to 3 retries
        if utils.validate_splunk_query(splunk_query, intcid):
            Logger.debug(f"Final Query: {splunk_query}")
            requirement_hash = hashlib.sha256(requirement.strip().encode()).hexdigest()
            redis_key = f"K:QC:{intcid}:splunk:{requirement_hash}"
            utils.push_template_data_to_mongo(
                requirement, intcid, "splunk", splunk_query_template, splunk_query
            )
            RedisManager.set_key(redis_key, splunk_query_template, expiry=3600)
            return {"query": splunk_query}

        Logger.info(
            f"Validation failed (Attempt {attempt+1}). Regenerating query from scratch..."
        )
        splunk_query = await _generate_splunk_query_with_steps(
            intcid=intcid,
            aid=aid,
            requirement=requirement,
            alert=alert,
            index_and_sourcetype=index_and_sourcetype,
            field_name_list=field_name_list,
        )

    # If we get here, all attempts failed
    Logger.info("Failed to generate a valid Splunk query after 3 attempts")
    # splunk_query = f"search index={index_and_sourcetype['index']} sourcetype={index_and_sourcetype['sourcetype']}"
    return {"query": splunk_query}


async def run_splunk_query(intcid: str, query: str) -> dict:
    """
    Third tool to run while triaging a requirement.
    Runs a Splunk query in the customer's Splunk instance and returns the result.
    """

    Logger.debug(f"tool: run_splunk_query: {query} for {intcid}")
    response = utils.execute_splunk_query(query, intcid)
    Logger.debug(f"Response after Executing the query: {response}")
    return response
