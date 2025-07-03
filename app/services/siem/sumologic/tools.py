import requests
import json
import traceback
import asyncio
from langchain_core.prompts import PromptTemplate
from typing import Optional  # Only import Optional, remove unused imports
import time
from datetime import datetime, timedelta, timezone  # Add timezone here
import fnmatch
import re

DEFAULT_QUERY_TIME_RANGE = "1h"

# Import platform components
from pltfrm import PropX, AIManager, Logger2 as Logger, MongoDBManager

from app.services.siem.sumologic.utils import SumoLogicUtils

from app.services.siem.sumologic import models as sumologic_models


def is_ignored_index(intcid: str, index_name: str) -> bool:
    """
    Check if an index should be ignored based on the ignorance list (regex patterns) from MongoDB.
    """
    ignorance_list_doc = MongoDBManager.get_record_by_multiple_fields(
        PropX.get_property("module.integration.config.db"),
        PropX.get_property("module.integration.config.collection"),
        {
            "intcid": intcid,
            "type": "integration",
            "subtype": "ignore_index_list",
        },
    )
    ignorance_list = ignorance_list_doc.get("ignorance_list", [])
    return any(re.match(pattern, index_name) for pattern in ignorance_list)


async def get_available_indices(intcid: str, task: str) -> dict:
    """
    Get all available indices in SumoLogic using the Partitions API.
    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging

    Returns:
        List of index names
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info("Fetching available indices using the Partitions API")

    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    access_id = sumo_logic_utils.get_access_id()
    access_key = sumo_logic_utils.get_access_key()

    auth = (access_id, access_key)
    partition_url = sumo_logic_utils.partition_url
    collectors_url = sumo_logic_utils.collectors_url

    try:
        # response = requests.get(partition_url, auth=auth)
        response = requests.get(collectors_url, auth=auth)
        response.raise_for_status()  # Raise an error for bad responses
        Logger.info(f"Response: {response}")
        # partitions_data = response.json()
        collectors_data = response.json()
        indices = []
        # for partition in partitions_data.get("data", []):
        #     name = partition.get("name")
        for collector in collectors_data.get("collectors", []):
            name = collector.get("name")
            isAlive = collector.get("alive", False)
            if name and isAlive:
                indices.append(name)  # Collect only the collector names

        # Filter indices using the ignorance list
        filtered_indices = [i for i in indices if not is_ignored_index(intcid, i)]

        Logger.info(f"Found {len(filtered_indices)} indices")
        Logger.info(f"Available indices: {filtered_indices}")

        return {"indices": filtered_indices}
    except requests.exceptions.RequestException as e:
        Logger.error(f"Error fetching indices: {e}")
        Logger.error(traceback.format_exc())
        return {"error": "indices_fetch_error", "message": str(e)}


async def get_available_fields(intcid: str, task: str, index_name: str) -> dict:
    """
    Get all available fields in SumoLogic using the Fields API.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging

    Returns:
        dict: List of field names and a sample record
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info("Fetching available fields using the Fields API")

    # query = f"_index={index_name} | limit 1"
    query = f'_collector="{index_name}" | limit 1'  # Use collector name for query
    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    try:
        response = await sumologic_run_sql_query(
            intcid=intcid,
            task=task,
            query=query,
            from_time=None,  # Use default time range
            to_time=None,  # Use default time range
            query_timezone="UTC",
            wait_time=5,
            max_wait_iterations=60,
        )

        if not response or "query_results" not in response:
            Logger.error("No results returned from SumoLogic query")
            return {"error": "no_results", "message": "No fields found"}

        results = response.get("query_results", [])
        if not results:
            Logger.error("Query results are empty")
            return {"error": "no_results", "message": "No fields found"}

        sample_record = results[0]
        fields = sumo_logic_utils.extract_field_names(sample_record)

        Logger.info(f"Found {len(fields)} fields in index {index_name}")
        return {"fields": list(fields), "sample_record": sample_record}
    except Exception as e:
        Logger.error(f"Error fetching fields: {str(e)}")
        Logger.error(traceback.format_exc())
        return {"error": "fields_fetch_error", "message": str(e)}


async def sumologic_run_sql_query(
    intcid: str,
    task: str,
    query: str,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    query_timezone: str = "UTC",
    wait_time: int = 5,
    max_wait_iterations: int = 60,
) -> Optional[dict]:
    """
    Run a query against the SumoLogic API and return the complete job status.
    It automatically detects whether to fetch from the /messages or /records endpoint.

    Args:
        intcid (str): Integration ID
        query (str): The SumoLogic query to execute
        from_time (str, optional): Start time in ISO-8601 format (default: 7 days ago)
        to_time (str, optional): End time in ISO-8601 format (default: now)
        query_timezone (str, optional): Timezone for the query (default: UTC)
        wait_time (int, optional): Seconds to wait between job status checks
        max_wait_iterations (int, optional): Maximum number of status checks before timing out

    Returns:
        dict: A dictionary containing the list of results or None if the query failed.
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Running query: {query}")
    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    access_id = sumo_logic_utils.get_access_id()
    access_key = sumo_logic_utils.get_access_key()
    api_endpoint = sumo_logic_utils.api_endpoint

    current_time = datetime.now(timezone.utc)
    if not from_time:
        from_time = (current_time - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not to_time:
        to_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    Logger.info(f"Query time range: {from_time} to {to_time}")
    auth = (access_id, access_key)
    Logger.info(f"API Endpoint: {api_endpoint}")

    try:
        session = requests.Session()
        session.auth = auth
        search_job_url = f"{api_endpoint}/search/jobs"
        payload = {
            "query": query,
            "from": from_time,
            "to": to_time,
            "timeZone": query_timezone,
            "autoParsingMode": "AutoParse"
        }
        Logger.info(f"Submitting SumoLogic search job: {payload}")
        response = session.post(search_job_url, json=payload)
        response.raise_for_status()
        job_id = response.json().get("id")

        if not job_id:
            Logger.error("Failed to get job ID from SumoLogic response")
            return None
        Logger.info(f"Search job created with ID: {job_id}")

        status_url = f"{api_endpoint}/search/jobs/{job_id}"
        iterations = 0
        while iterations < max_wait_iterations:
            await asyncio.sleep(wait_time)  # Use asyncio.sleep in an async function
            iterations += 1
            try:
                status_response = session.get(status_url)
                Logger.info(f"Raw job status response: {status_response.text}")

                if status_response.status_code == 404:
                    Logger.warn(f"Job {job_id} not found (404). Retrying...")
                    continue

                status_response.raise_for_status()
                job_status = status_response.json()
                state = job_status.get("state", "")
                Logger.info(
                    f"Job status: {state} (check {iterations}/{max_wait_iterations})"
                )

                if state == "DONE GATHERING RESULTS":

                    record_count = job_status.get("recordCount", 0)
                    message_count = job_status.get("messageCount", 0)

                    if record_count > 0:
                        Logger.info(
                            f"Query is an aggregate. Fetching {record_count} records."
                        )
                        results_url = f"{api_endpoint}/search/jobs/{job_id}/records"
                        results_data = session.get(
                            results_url, params={"offset": 0, "limit": record_count}
                        ).json()
                        # Extract the 'map' from each record
                        parsed_results = [
                            r.get("map") for r in results_data.get("records", [])
                        ]
                        return {"query_results": parsed_results}

                    elif message_count > 0:
                        Logger.info(
                            f"Query is for raw logs. Fetching {message_count} messages."
                        )
                        # This is your original, unchanged logic for fetching messages
                        all_parsed_results = []
                        limit = 1000
                        results_url = f"{api_endpoint}/search/jobs/{job_id}/messages"
                        for offset in range(0, message_count, limit):
                            params = {"offset": offset, "limit": limit}
                            results_response = session.get(results_url, params=params)
                            results_response.raise_for_status()
                            results_data = results_response.json().get("messages", [])
                            for message in results_data:
                                raw_log_string = message.get("map", {}).get("_raw")
                                if raw_log_string:
                                    try:
                                        all_parsed_results.append(
                                            json.loads(raw_log_string)
                                        )
                                    except json.JSONDecodeError:
                                        all_parsed_results.append(
                                            {"_raw": raw_log_string}
                                        )
                        return {"query_results": all_parsed_results}

                    else:
                        Logger.info("Query returned no results.")
                        return {"query_results": []}

                elif state in ["CANCELLED", "FORCE CANCELLED", "FAILED"]:
                    messages = job_status.get("messages", [])
                    Logger.error(f"Job failed or was cancelled: {messages}")
                    return None

            except requests.exceptions.RequestException as e:
                Logger.error(f"Error during polling loop: {str(e)}")
                if iterations > 5:
                    return {"error": str(e)}

        Logger.error(f"Job timed out after {iterations} status checks")
        Logger.info(f"Cancelling job {job_id} due to timeout.")
        session.delete(status_url)
        return {"error": "job_timed_out"}

    except requests.exceptions.RequestException as e:
        Logger.error(f"Request failed: {str(e)}")
        if hasattr(e, "response") and e.response:
            Logger.error(f"Response status: {e.response.status_code}")
            Logger.error(f"Response body: {e.response.text}")
        return None
    except Exception as e:
        Logger.error(f"Unexpected error running query: {str(e)}")
        return None


async def fetch_security_alerts(
    intcid: str, task: str, start_time: str = None, end_time: str = None
) -> dict:
    """
    Fetch system alerts from SumoLogic using a specific query.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        start_time (str, optional): Start time in ISO-8601 format
        end_time (str, optional): End time in ISO-8601 format

    Returns:
        dict: {"alerts_created": [...]}
    """
    # Set default time range to 1 month if not provided
    now = datetime.utcnow()
    if not end_time:
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not start_time:
        start_time = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = '_index=sumologic_system_events AND _sourcename = "AlertSystemInfo"'
    results = await sumologic_run_sql_query(
        intcid=intcid, task=task, query=query, from_time=start_time, to_time=end_time
    )
    alerts = results.get("query_results", []) if results else []

    alerts_created = [
        a for a in alerts if a.get("details", {}).get("name") == "AlertCreated"
    ]

    return {"security_alerts_data": alerts_created}


async def fetch_security_alerts_with_query(
    intcid: str,
    task: str,
    query: str,
    time_field: str,
    start_time: str = None,
    end_time: str = None,
) -> dict:
    Logger.info(f"tool:fetch_security_alerts_with_query: Starting for {intcid} {task}")

    now = datetime.utcnow()
    if not end_time:
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not start_time:
        start_time = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    Logger.debug(f"KQL Query: {query}")
    results = await sumologic_run_sql_query(
        intcid=intcid, task=task, query=query, from_time=start_time, to_time=end_time
    )
    Logger.debug(f"Query results: {results}")
    alerts = results.get("query_results", []) if results else []

    return {"alert_query_results": alerts}


async def sumologic_get_alert_context(intcid: str, task: str, aid: str, alert: dict):
    """
    Get context for a specific alert by its ID.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        aid (str): Alert ID
        alert (dict): Alert data

    Returns:
        dict: Context information for the alert
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Fetching context for alert ID: {aid}")

    if isinstance(alert, str):
            try:
                alert = json.loads(alert)
            except json.JSONDecodeError:
                Logger.error(f"Failed to decode alert_context string into a dict: {alert}")
                return {"error": "alert_context_decode_error", "message": "Failed to decode alert_context from string."}

    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    alert_source = alert.get("source", "").lower()  # Get the alert source in lowercase

    if alert_source:
        prompt_name = sumo_logic_utils.get_prompt_name(alert_source, "alert_context")
        Logger.info(f"Using prompt template: {prompt_name} for alert source: {alert_source}")
    else:
        prompt_name = "SUMOLOGIC_ALERT_CONTEXT_EXTRACTION_PROMPT"

    try:
        env = "unknown"
        alert_context = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name=prompt_name,
            prompt_params={
                "alert": json.dumps(
                    alert
                ),  # This now contains either the original alert/incident or the list of fetched alerts
                "env": env,
                "requirement": task,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sumologic_models.AlertContextResponse,
            history_params={
                "aid": aid,
                "subtype": "alert_context",
            },
            type="triage",
            system_prompt="You are an expert in understanding Sumologic Alerts. Your task is to extract context parameters from given input which included received alert.",
        )

        
        Logger.info(f"AI response for context extraction: {alert_context}")
        sumo_logic_utils = SumoLogicUtils(intcid=intcid)
        alert_context = sumo_logic_utils.transform_alert_context(
            input_data=alert_context
        )
        alert_context["env"] = env  # Ensure env is included
        return alert_context

    except Exception as e:
        Logger.error(f"Error fetching alert context: {str(e)}")
        Logger.error(traceback.format_exc())
        return {"error": "alert_context_fetch_error", "message": str(e)}


async def sumologic_choose_table(
    intcid: str,
    task: str,
    aid: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: any,
) -> dict:

    sumologic_utils = SumoLogicUtils(intcid=intcid)
    model_name = PropX.get_property("module.llm.model")
    env = alert_context.get("env", "unknown").lower()

    query = {"intcid": intcid, "vendor": "sumologic", "subtype": "index_list"}
    index_list = sumologic_utils.fetch_index_list(query=query)

    if not index_list:
        Logger.warn(f"No indices found for query: {query}")
        return {"error": "no_indices_found"}

    Logger.info(f"Found {len(index_list)} indices for integration {intcid}")

    ## Commented temporarily to avoid MongoDB dependency
    # try:
    #     table_name = sumologic_utils.get_table_name_from_mongo(
    #         intcid, "sumologic", env, tid, question_id, step_id
    #     )
    #     reason = "Table name found in MongoDB template."
    # except Exception as mongo_e:
    #     Logger.warn(f"Failed to push AI-selected table name to MongoDB: {mongo_e}")

    table_name = None

    if not table_name:
        try:
            tables_list = sumologic_utils.get_top_matching_tables(intcid, tid)
            Logger.info(
                f"Top matching tables for {intcid} and TID {tid}: {tables_list}"
            )
            table_name_to_desc = {entry["index"]: entry["desc"] for entry in index_list}
            tables_name_and_description_list = [
                {"index": table, "desc": table_name_to_desc.get(table, "")}
                for table in tables_list
            ]

            if not tables_name_and_description_list:
                Logger.warn(
                    f"No matching tables found for intcid: {intcid}, tid: {tid}. Using all available indices."
                )
                tables_name_and_description_list = [
                    {"index": entry["index"], "desc": entry["desc"]}
                    for entry in index_list
                ]

            tables_name_and_description = sumologic_utils.parse_indices(
                tables_name_and_description_list
            )

            response_data = AIManager.run_prompt_with_structured_output(
                intcid=intcid,
                prompt_template_name="SUMOLOGIC_QUERY_TABLE_SELECTION_PROMPT",
                prompt_params={
                    "requirement": task,
                    "triage_question": triage_question,
                    "alert_context": alert_context,
                    "tables_list": tables_name_and_description,
                },
                model_name=model_name,
                model_class=sumologic_models.TableName,
                history_params={
                    "aid": aid,
                    "tid": tid,
                    "qid": question_id,
                    "step_id": step_id,
                    "subtype": "table_selection",
                },
                type="triage",
                system_prompt="You are an expert in Sumologic and sumologic query language. Your task is to select the most appropriate table for the given requirement based on the available tables and their schemas. Provide only the table name in your response.",
            )

            Logger.debug(f"AI response for table selection: {response_data}")
            if response_data is None:
                Logger.error("Failed to parse AI response during table selection.")
                return {"error": "Failed to parse AI response during table selection."}

            table_name = response_data.get("table_name")
            Logger.debug(
                f"AI selected table name: {table_name}, available tables: {index_list}"
            )
            if not table_name:
                Logger.error(
                    f"AI selected an invalid or unavailable table: '{table_name}'. Response: {response_data}"
                )
                return {
                    "error": f"AI failed to select a valid table. Selection: '{table_name}'"
                }

            # Temporarily commented out MongoDB push to avoid dependency issues
            # try:
            #     sumologic_utils.push_table_name_to_mongo(
            #         intcid,
            #         "sumologic",
            #         env,
            #         tid,
            #         question_id,
            #         step_id,
            #         triage_question,
            #         table_name,
            #     )
            # except Exception as mongo_e:
            #     Logger.warn(
            #         f"Failed to push AI-selected table name to MongoDB: {mongo_e}"
            #     )

            Logger.info(f"Sumologic table chosen by AI: {table_name}")
            reason = "Table name selected by AI based on context and available tables."

            table_status = sumologic_utils.check_table(intcid, table_name)
            if table_status:
                Logger.info(f"Table {table_name} is available in Sumologic.")
                return {"table_name": table_name, "env": env}
            else:
                Logger.error(
                    f"Table {table_name} is not available in Sumologic. Please check the table name."
                )
                return {"error": f"{reason} failed"}

        except Exception as e:
            Logger.error(
                f"Error during Sumologic table selection: {e}\n{traceback.format_exc()}"
            )
            return {
                "error": f"An unexpected error occurred during table name selection: {e}"
            }


async def sumologic_generate_query(
    intcid: str,
    task: str,
    aid: str,
    table_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: dict,
) -> dict:
    """
    Generate a query for the specified table based on the alert context and triage question.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        aid (str): Alert ID
        table_name (str): Name of the table to query
        tid (str): Task ID
        question_id (str): Question ID
        step_id (str): Step ID
        triage_question (str): The question to be answered by the query
        alert_context (dict): Context information for the alert

    Returns:
        dict: Generated query or error message
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Generating query for table: {table_name}")

    max_retries = 5
    last_error_msg = ""

    query_template = None
    final_query = None
    attempt = 0
    env = alert_context.get("env", "UNKNOWN").lower()
    try:
        for attempt in range(max_retries):
            query_template_resp = await sumologic_generate_query_template(
                intcid=intcid,
                aid=aid,
                tid=tid,
                question_id=question_id,
                step_id=step_id,
                task=task,
                table=table_name,
                alert_context=alert_context,
                triage_question=triage_question,
            )
            if "error" in query_template_resp:
                last_error_msg = query_template_resp["error"]
                Logger.warn(
                    f"Attempt {attempt+1}: Failed to generate query template: {last_error_msg}"
                )
                continue
            query_template = query_template_resp.get("query_template")

            final_sumo_query_resp = await sumologic_prepare_query(
                intcid=intcid,
                task=task,
                aid=aid,
                table_name=table_name,
                tid=tid,
                question_id=question_id,
                step_id=step_id,
                triage_question=triage_question,
                alert_context=alert_context,
                query_template=query_template,
            )
            final_query = final_sumo_query_resp.get("query")

            # Check for unresolved placeholders like <<Alert.key.value>>
            if final_query and not re.search(r"<<[^>]+>>", final_query):
                Logger.info(f"Query template successfully resolved: {query_template}")
                return {
                    "query_template": query_template,
                    "query": final_query,
                    "from_time": query_template_resp.get("from_time"),
                    "to_time": query_template_resp.get("to_time"),
                }
            else:
                Logger.warn(
                    f"Attempt {attempt+1}: Final query still contains placeholders: {final_query}"
                )

        # If we reach here, all attempts failed
        Logger.error(f"Failed to generate a valid query after {max_retries} attempts.")
        return {
            "error": "query_generation_failed",
            "query": final_query,
            "from_time": query_template_resp.get("from_time"),
            "to_time": query_template_resp.get("to_time"),
        }
    except Exception as e:
        Logger.error(f"Error during query generation: {str(e)}")
    Logger.error(traceback.format_exc())
    return {"error": f"An unexpected error occurred during query generation: {str(e)}"}


async def sumologic_generate_query_template(
    intcid: str,
    aid: str,
    tid: str,
    question_id: str,
    step_id: str,
    task: str,
    table: str,
    alert_context: dict,
    triage_question: str,
) -> dict:

    sumologic_utils = SumoLogicUtils(intcid=intcid)
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Generating query template for table: {table}")

    # try:
    #     _query_template = sumologic_utils.get_sumologic_template_data_from_mongo(
    #         intcid=intcid,
    #         env=alert_context["env"],
    #         tid=tid,
    #         question_id=question_id,
    #         step_id=step_id,
    #     )

    #     if _query_template and _query_template != "":
    #         Logger.info(f"Using cached sumologic query template for {intcid}, table: {tables}")
    #         return {"query_templates": [_query_template]}
    # except Exception as e:
    #     Logger.error(f"Error getting sumologic query template from MongoDB: {e}")
    #     pass

    # for table in tables:
    Logger.info(f"Processing table: {table}")
    sample_records = sumologic_utils.get_sample_records(intcid, table)

    Logger.info(f"Fetched {len(sample_records)} sample records for {table}")
    Logger.debug(f"Sample Records: {sample_records}")

    response = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="SUMOLOGIC_QUERY_TEMPLATE_PROMPT",
        prompt_params={
            "requirement": task,
            "triage_question": triage_question,
            "alert": alert_context,
            "table_name": table,
            "sample_records": sample_records,
            "env": alert_context.get("env", "unknown").lower(),
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=sumologic_models.QueryTemplate,
        history_params={
            "aid": aid,
            "tid": tid,
            "qid": question_id,
            "step_id": step_id,
            "subtype": "query",
        },
        type="triage",
        system_prompt="You are an expert in Sumologic and sumologic query generation. Your task is to generate a sumologic query template based on the provided requirement, alert context, table name, and schema. The output should be a valid sumologic query template that can be used to fetch relevant data from the specified table.",
    )

    query_template = response.get("query_template")
    from_time = response.get("from_time", None)
    to_time = response.get("to_time", None)
    Logger.info(f"Query Template: {query_template}")

    return {
        "query_template": query_template,
        "from_time": from_time,
        "to_time": to_time,
    }


async def sumologic_prepare_query(
    intcid: str,
    task: str,
    aid: str,
    table_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: dict,
    query_template: str,
) -> dict:
    """
    Prepare the final query for execution in SumoLogic.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        aid (str): Alert ID
        table_name (str): Name of the table to query
        tid (str): Task ID
        question_id (str): Question ID
        step_id (str): Step ID
        triage_question (str): The question to be answered by the query
        alert_context (dict): Context information for the alert
        query_templates (list): List of query templates to use

    Returns:
        dict: Final sumologic query query or error message
    """

    Logger.info(f"Task: {task} - Integration ID: {intcid}")

    try:
        query = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="SUMOLOGIC_FIELD_VALUE_REPLACEMENT_PROMPT",
            prompt_params={
                "requirement": task,
                "query_template": query_template,
                "alert": alert_context,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sumologic_models.FinalQuery,
            history_params={
                "aid": aid,
                "tid": tid,
                "qid": question_id,
                "step_id": step_id,
                "subtype": "prepare_query",
            },
            type="triage",
            system_prompt="You are an expert in Microsoft Sumologic and sumologic query. Your task is to replace field placeholders in the provided sumologic query query template with actual values based on the alert context. The output should be a valid sumologic query query that can be executed against the specified table.",
        )
        query = query.get("final_query")
        return {"query": query}

    except Exception as e:
        Logger.error(f"Error preparing final sumologic query query: {str(e)}")
        return {
            "error": f"An unexpected error occurred while preparing the sumologic query query: {str(e)}"
        }
