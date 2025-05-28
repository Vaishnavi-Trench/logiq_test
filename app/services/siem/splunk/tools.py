"""Splunk Utils for SIEM Agent Tools"""

from langchain_core.prompts import PromptTemplate

from app.services.siem.splunk import utils
from pltfrm import Logger2 as Logger
from pltfrm import AIManager
from pltfrm import RedisManager, PromptManager, PropX
import hashlib


async def splunk_choose_index(intcid: str, requirement: str, alert: str) -> dict:
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

    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "SPLUNK_INDEX_SELECTION_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)

    formatted_prompt = prompt_template.invoke(
        {
            "requirement": requirement,
            "alert": alert,
            "customer_index_details": customer_index_details,
        }
    ).text

    index_name = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.debug(f"Index name: {index_name}")
    RedisManager.set_key(redis_key, index_name, expiry=3600)
    Logger.debug(f"Index chosen: {index_name}")
    index_data = index_name.split("|")
    index_name = index_data[0]
    sourcetype = index_data[1]
    return {"index_name": index_name, "sourcetype": sourcetype}


async def _generate_splunk_query_with_steps(
    intcid: str,
    requirement: str,
    alert: str,
    index_and_sourcetype: dict,
    field_name_list: list,
) -> str:
    """Helper function to generate a Splunk query through all steps."""
    # Step 1: Generate query template
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "SPLUNK_QUERY_TEMPLATE_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "requirement": requirement,
            "alert": alert,
            "index_and_sourcetype": index_and_sourcetype,
        }
    ).text
    splunk_query_template = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.debug(f"Template generated: {splunk_query_template}")

    # Step 2: Field replacement
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "SPLUNK_FIELD_REPLACEMENT_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {"query_template": splunk_query_template, "field_mapping": field_name_list}
    ).text
    splunk_query = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.debug(f"Fields replaced: {splunk_query}")

    # Step 3: Query sanitization
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "SPLUNK_QUERY_SANITIZER_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "splunk_query": splunk_query,
        }
    ).text
    splunk_query = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"Query sanitized: {splunk_query}")
    if not splunk_query.strip().lower().startswith("search"):
        splunk_query = f"search {splunk_query}"
    return splunk_query_template, splunk_query


async def generate_splunk_query(
    intcid: str, index_name: str, sourcetype: str, requirement: str, alert: str
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
