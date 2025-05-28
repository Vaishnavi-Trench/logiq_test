from langchain_core.prompts import PromptTemplate
import json

from app.services.siem.wazuh import utils
from pltfrm import Logger2 as Logger
from pltfrm import AIManager
from pltfrm import RedisManager, PromptManager, PropX


async def wazuh_get_alert_context(intcid: str, task: str, alert: str) -> dict:
    """Retrieves context for a given Wazuh alert.

    Uses AI to determine the relevant index and environment, fetches field metadata
    and matching records, then generates and runs a query to extract context
    relevant to the specified task and alert.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed from the alert context.
        alert: The Wazuh alert content (as a string or dict).

    Returns:
        A dictionary containing the extracted alert context under the key
        'alert_context', including the environment ('env'). Returns an error
        dictionary if context extraction fails.
    """
    Logger.info(f"tool:wazuh_get_source_ip_for_alert: {intcid}, {task}")

    customer_index_details = utils.get_indices_with_metadata(intcid)
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_INDEX_NAME_AND_ENVIRONMENT_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "alert": alert,
            "customer_index_details": customer_index_details,
        }
    ).text
    response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    response = json.loads(response)
    Logger.debug(f"Response: {response}")

    index_name = response["index_name"]
    env = response["env"]

    field_data_string = utils.get_fields_with_metadata(intcid, f"{index_name}")
    matching_records = utils.get_matching_records(
        intcid, index_name, '{"query":{"bool":{"must":[{"match_all":{}}]}}}'
    )
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "ALERT_CONTEXT_EXTRACTION_QUERY_BUILDER"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "requirement": task,
            "alert": alert,
            "index_name": index_name,
            "customer_index_details": field_data_string,
            "env": env,
            "matching_records": matching_records,
        }
    ).text

    alert_context_response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"Query source_ip_details: {alert_context_response}")

    # Parse the sanitized_response as a JSON object if it's a string
    if isinstance(alert_context_response, str):
        alert_contex_json = json.loads(alert_context_response)
    else:
        alert_contex_json = alert_context_response
    if not alert_contex_json:
        Logger.error(f"Error in fetch_srcip_of_event: {intcid}")
        return {"error": alert_contex_json}

    alert_contex_json["env"] = env
    return {"alert_context": alert_contex_json}


async def wazuh_get_all_index_names(intcid: str, task: str) -> dict:
    """Fetches all available Wazuh index names for a customer.

    Args:
        intcid: The customer integration ID.
        task: A description of the task requesting the index names (used for logging).

    Returns:
        A dictionary containing a list of index names under the key 'index_names'.
        Returns an error dictionary if fetching fails.
    """
    Logger.info(f"tool:wazuh_get_all_index_names: {intcid}, {task}")

    status, customer_index_details = utils.get_all_indices(intcid)
    if not status:
        Logger.error(f"Error fetching index names for {intcid}")
        return {"error": customer_index_details}

    return {"index_names": customer_index_details}


async def wazuh_get_available_fields_of_index(
    intcid: str, task: str, index_name: str
) -> dict:
    """Retrieves the available fields for a specific Wazuh index.

    Args:
        intcid: The customer integration ID.
        task: A description of the task requesting the fields (used for logging).
        index_name: The name of the Wazuh index.

    Returns:
        A dictionary containing the index name and a list of its available fields
        under the key 'available_fields'. Returns an error dictionary if fetching fails.
    """
    Logger.info(
        f"tool:wazuh_get_available_fields_of_index: {intcid}, {task}, {index_name}"
    )

    status, available_fields = utils.get_available_fields(intcid, index_name)
    if not status:
        Logger.error(f"Error fetching index names for {intcid}")
        return {"error": available_fields}

    return {"index_name": index_name, "available_fields": available_fields}


async def wazuh_get_single_matching_record(
    intcid: str, task: str, index_name: str, query: str
) -> dict:
    """Fetches a single record matching a query from a specific Wazuh index.

    Args:
        intcid: The customer integration ID.
        task: A description of the task requesting the record (used for logging).
        index_name: The name of the Wazuh index to query.
        query: The Elasticsearch query string to execute.

    Returns:
        A dictionary containing the index name, query, and the matching record
        under the key 'result'. Returns an error dictionary if fetching fails or
        no record is found.
    """
    Logger.info(
        f"tool:wazuh_get_available_fields_of_index: {intcid}, {task}, {index_name}"
    )

    matching_record = utils.get_single_matching_record(intcid, index_name, query)
    if not matching_record:
        Logger.error(f"Error in wazuh_get_single_matching_record: {intcid}")
        return {"error": matching_record}

    return {
        "index_name": index_name,
        "qeury": query,
        "result": matching_record,
    }


async def wazuh_choose_index(
    intcid: str, tid: str, question_id: str, triage_question: str, alert: str
) -> dict:
    """Selects the appropriate Wazuh index for a given triage requirement and alert.

    Checks cache first. If not cached, uses AI to determine the relevant environment
    and select the best index based on the triage question, alert content, and
    available index metadata. Caches the result and stores it in MongoDB.

    Args:
        intcid: The customer integration ID.
        tid: The triage ID.
        question_id: The specific question ID within the triage process.
        triage_question: The text of the triage question being addressed.
        alert: The Wazuh alert content (as a string or dict).

    Returns:
        A dictionary containing the chosen 'index_name' and the determined 'env'.
    """
    Logger.info(
        f"tool:choose_index: {intcid}, {tid}, {question_id}, {triage_question}, {alert}"
    )

    customer_index_details = utils.get_indices_with_metadata(intcid)
    redis_key = f"K:IN:{intcid}:wazuh:{tid}:{question_id}"
    index_name = RedisManager.get_key(redis_key)
    Logger.info(f"Cached index: {index_name}")

    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_ENVIRONMENT_SELECTION_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "alert": alert,
        }
    ).text
    response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    response = json.loads(response)
    Logger.debug(f"Response: {response}")
    env = response["env"]

    if index_name is not None:  # Ensure it's not None before decoding
        Logger.debug(
            f"Cache hit: Returning cached index for requirement {triage_question}: {index_name}"
        )
        utils.push_index_name_to_mongo(
            intcid, "wazuh", env, tid, question_id, triage_question, index_name
        )
        return {"index_name": index_name, "env": env}

    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_INDEX_SELECTION_PROMPT"
    )

    prompt_template = PromptTemplate.from_template(_template)

    formatted_prompt = prompt_template.invoke(
        {
            "requirement": triage_question,
            "alert": alert,
            "customer_index_details": customer_index_details,
        }
    ).text

    response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    response = json.loads(response)
    Logger.debug(f"Response: {response}")
    index_name = response["index_name"]

    RedisManager.set_key(redis_key, index_name)
    utils.push_index_name_to_mongo(
        intcid, "wazuh", env, tid, question_id, triage_question, index_name
    )

    Logger.debug(f"Index chosen: {index_name}")
    return {"index_name": index_name, "env": env}


async def _generate_wazuh_query_template(
    intcid: str,
    requirement: str,
    alert: str,
    index_name: str,
    field_name_list: list,
    env: str,
):
    """Generates a Wazuh query template using AI.

    Takes requirement, alert details, index info, fields, and environment to
    prompt an AI model to generate a query template. Includes sanitization and
    up to 3 rounds of reflection for refinement.

    Args:
        intcid: Customer integration ID.
        requirement: The specific task or information needed.
        alert: The Wazuh alert content.
        index_name: The target Wazuh index name.
        field_name_list: String containing field names and metadata for the index.
        env: The environment associated with the index/alert.

    Returns:
        The generated and refined Wazuh query template string.
    """
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_QUERY_TEMPLATE_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "requirement": requirement,
            "alert": alert,
            "index_name": index_name,
            "field_mapping": field_name_list,
            "env": env,
        }
    ).text

    query_generaton_response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"response generated: {query_generaton_response}")

    # Step 3: Query sanitization
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_QUERY_SANITIZER_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "text_json": query_generaton_response,
        }
    ).text
    sanitized_response = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"Query sanitized: {sanitized_response}")

    # Parse the sanitized_response as a JSON object if it's a string
    if isinstance(sanitized_response, str):
        sanitized_response = json.loads(sanitized_response)

    query_template = sanitized_response["query_template"]
    Logger.info(f"Final query template before reflection: {query_template}")

    # Reflection rounds now
    for attempt in range(3):
        Logger.info(f"Reflection round: {attempt}, query_template: {query_template}")
        _template, _version = PromptManager.get_prompt_template(
            intcid, "logiq", "WAZUH_QUERY_TEMPLATE_REFLECTION_PROMPT"
        )
        prompt_template = PromptTemplate.from_template(_template)
        formatted_prompt = prompt_template.invoke(
            {
                "requirement": requirement,
                "alert": alert,
                "index_name": index_name,
                "field_mapping": field_name_list,
                "query_template": query_template,
            }
        ).text

        query_generaton_response = AIManager.run_prompt(
            PropX.get_property("module.llm.model"), formatted_prompt
        )
        Logger.info(f"response generated: {query_generaton_response}")

        # Step 3: Query sanitization
        _template, _version = PromptManager.get_prompt_template(
            intcid, "logiq", "WAZUH_QUERY_SANITIZER_PROMPT"
        )
        prompt_template = PromptTemplate.from_template(_template)
        formatted_prompt = prompt_template.invoke(
            {
                "text_json": query_generaton_response,
            }
        ).text
        sanitized_response = AIManager.run_prompt(
            PropX.get_property("module.llm.model"), formatted_prompt
        )
        Logger.info(f"Query sanitized: {sanitized_response}")

        # Parse the sanitized_response as a JSON object if it's a string
        if isinstance(sanitized_response, str):
            sanitized_response = json.loads(sanitized_response)

        query_template = sanitized_response["query_template"]

    Logger.info(f"Final query template after reflection: {query_template}")
    return query_template


async def _replace_timerange_as_per_requirement(
    intcid: str, requirement: str, wazuh_query_template: str, alert: str
) -> str:
    """Replaces time range placeholders in a Wazuh query template.

    Uses an AI prompt to analyze the requirement and alert, then replaces
    generic time range placeholders (like '{{start_time}}', '{{end_time}}')
    in the provided query template with specific time values derived from
    the alert or requirement context.

    Args:
        intcid: Customer integration ID.
        requirement: The specific task or information needed, potentially containing time context.
        wazuh_query_template: The query template string with placeholders.
        alert: The Wazuh alert content, potentially containing time context.

    Returns:
        The Wazuh query string with time range placeholders replaced.
    """

    Logger.info(
        f"_replace_timerange_as_per_requirement: Recevied template: {wazuh_query_template}"
    )
    # Generate actual query
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_TIMERANGE_REPLACEMENT_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "requirement": requirement,
            "query_template": wazuh_query_template,
            "alert": alert,
        }
    ).text
    wazuh_query = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"Final actualy query: {wazuh_query}")

    return wazuh_query


async def _generate_wazuh_query_using_template(
    intcid: str, requirement: str, wazuh_query_template: str, alert: str
) -> str:
    """Generates a final Wazuh query by replacing field value placeholders.

    Uses an AI prompt to analyze the requirement and alert context, then replaces
    generic field value placeholders (like '{{field_value}}') in the provided
    query template with specific values derived from the alert or requirement.

    Args:
        intcid: Customer integration ID.
        requirement: The specific task or information needed.
        wazuh_query_template: The query template string, potentially with time ranges already replaced.
        alert: The Wazuh alert content containing field values.

    Returns:
        The final, executable Wazuh query string.
    """

    Logger.info(
        f"_generate_wazuh_query_using_template: Recevied template: {wazuh_query_template}"
    )
    # Generate actual query
    _template, _version = PromptManager.get_prompt_template(
        intcid, "logiq", "WAZUH_FIELD_VALUE_REPLACEMENT_PROMPT"
    )
    prompt_template = PromptTemplate.from_template(_template)
    formatted_prompt = prompt_template.invoke(
        {
            "requirement": requirement,
            "query_template": wazuh_query_template,
            "alert": alert,
        }
    ).text
    wazuh_query = AIManager.run_prompt(
        PropX.get_property("module.llm.model"), formatted_prompt
    )
    Logger.info(f"Final actualy query: {wazuh_query}")

    return wazuh_query


async def wazuh_generate_query(
    intcid: str,
    task: str,
    index_name: str,
    tid: str,
    question_id: str,
    triage_question: str,
    alert: str,
    env: str,
) -> dict:
    """Generates a Wazuh query for a specific triage requirement.

    Checks cache for an existing query template. If not found or invalid, it
    generates a new query template using AI based on the task, alert, index,
    fields, and environment. It then replaces time range placeholders and field
    values based on the alert context. The generated query is validated, and
    regeneration is attempted up to 3 times if validation fails. The final
    template and query are cached and stored in MongoDB.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed.
        index_name: The name of the target Wazuh index.
        tid: The triage ID.
        question_id: The specific question ID within the triage process.
        triage_question: The text of the triage question being addressed.
        alert: The Wazuh alert content (as a string or dict).
        env: The environment associated with the index/alert.

    Returns:
        A dictionary containing the generated Wazuh query under the key 'query'.
    """
    Logger.debug(
        f"tool:generate_wazuh_query: {intcid}, {index_name}, {tid}, {question_id}, {triage_question}, {task}, {alert}, {env}"
    )
    field_data_string = utils.get_fields_with_metadata(intcid, f"{index_name}")

    query_template = None
    redis_key = f"K:QT:{intcid}:wazuh:{tid}:{question_id}:{env}"
    str_query_template = RedisManager.get_key(redis_key)

    if str_query_template is not None:
        Logger.debug(f"Cached response: {str_query_template}")

        # Parse the cached response as a JSON object if it's a string
        if isinstance(str_query_template, str):
            query_template = json.loads(str_query_template)

    # Try validation and regeneration if needed
    for attempt in range(3):  # Allow up to 3 retries
        if query_template is None:
            # Generate query template
            query_template = await _generate_wazuh_query_template(
                intcid=intcid,
                requirement=task,
                alert=alert,
                index_name=index_name,
                field_name_list=field_data_string,
                env=env,
            )

        Logger.info(f"Response after Generating the query template: {query_template}")

        wazuh_query_template_time_replaced = (
            await _replace_timerange_as_per_requirement(
                intcid,
                task,
                query_template,
                alert,
            )
        )
        Logger.info(
            f"Query after replacing timerange: {wazuh_query_template_time_replaced}"
        )

        wazuh_query = await _generate_wazuh_query_using_template(
            intcid,
            task,
            wazuh_query_template_time_replaced,
            alert,
        )
        Logger.info(f"Query after replacing field values: {wazuh_query}")

        # If validation fails repeat generation and validation
        if not utils.validate_wazuh_query(index_name, wazuh_query, intcid):
            Logger.info(
                f"Validation failed (Attempt {attempt+1}). Regenerating query from scratch..."
            )

            if attempt < 2:
                # set to none so we generate a fresh template
                query_template = None
                continue

        if attempt < 2:
            Logger.debug(f"Validation succeeded. Final Query: {wazuh_query}")
        else:
            Logger.info(
                f"Validation failed after 3 attempts. Proceeding anyway with Query: {wazuh_query}"
            )

        utils.push_template_data_to_mongo(
            intcid,
            "wazuh",
            env,
            tid,
            question_id,
            triage_question,
            task,
            index_name,
            query_template,
            wazuh_query,
        )
        # write the sanitized_response dict into json format string in redis
        RedisManager.set_key(redis_key, json.dumps(query_template))  # 7 days

        # If we get here, all attempts failed
        Logger.info("Successfully generated a query after 3 attempts")
        return {"query": wazuh_query}


async def wazuh_run_query(intcid: str, index_name: str, query: str) -> dict:
    """Executes a given Wazuh query against a specified index.

    Args:
        intcid: The customer integration ID.
        index_name: The name of the Wazuh index to query.
        query: The Wazuh (Elasticsearch) query string to execute.

    Returns:
        A dictionary containing the results of the query execution.
    """

    Logger.debug(
        f"tool: wazuh_run_query: index: {index_name}, query:{query} for {intcid}"
    )
    response = utils.execute_wazuh_query(intcid, index_name, query)
    Logger.debug(f"Response after Executing the query: {response}")
    return response
