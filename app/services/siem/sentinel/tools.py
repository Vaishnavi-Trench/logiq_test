import requests
import json
import traceback
from langchain_core.prompts import PromptTemplate

# Import platform components
from pltfrm import (
    Logger2 as Logger,
    PromptManager,
    AIManager,
    PropX,
    MongoDBManager,
)

from app.services.siem.sentinel import models as sentinel_models

# Import Sentinel specific utils and functions
from app.services.siem.sentinel.utils import (
    SentinelUtils,
    DEFAULT_QUERY_TIME_RANGE,
    MAX_KQL_GENERATION_ATTEMPTS,
)


async def sentinel_choose_table(
    intcid: str,
    task: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: any,
) -> dict:
    """Selects the appropriate Sentinel table using AI based on triage context and alert.

    Fetches available tables with schemas, checks cache, uses AI for selection
    if needed, caches the result, and stores it in MongoDB.

    Args:
        intcid: The customer integration ID.
        tid: The triage ID.
        question_id: The specific question ID within the triage process.
        triage_question: The text of the triage question being addressed.
        alert: The relevant alert/event content (dict or JSON string).

    Returns:
        A dictionary containing the chosen 'table_name' and 'env'.
        Returns an error dictionary if table fetching or selection fails.
        Example success: {'table_name': 'SecurityEvent', 'env': 'Production'}
        Example error: {'error': 'No suitable Sentinel tables found.'}
    """
    Logger.info(
        f"tool:sentinel_choose_table: Starting for {intcid}, TID: {tid}, QID: {question_id}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)
    model_name = PropX.get_property("module.llm.model")

    if not model_name:
        Logger.error("Model name not found in configuration.")
        return {"error": "Model name not found in configuration."}

    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    alert_str = (
        json.dumps(alert_context)
        if isinstance(alert_context, dict)
        else str(alert_context)
    )

    # --- Determine Environment ---
    env = None
    try:
        env_prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_ENVIRONMENT_SELECTION_PROMPT"
            )
        )
        env_formatted_prompt = env_prompt_template.invoke({"alert": alert_str}).text

        env_response = AIManager.run_prompt_with_structured_output(
            model_name, env_formatted_prompt, sentinel_models.Environment
        )

        if env_response is None:
            return {"error": "Failed to parse AI response for environment selection."}

        Logger.debug(f"AI response for environment selection: {env_response}")

        env_response = env_response.model_dump()
        env = env_response.get("env", "unknown").lower()

        if not env:
            Logger.warn(f"Could not determine environment from AI response: {env}")
            return {"error": "Failed to determine environment."}
        Logger.info(f"Determined environment: {env}")
    except Exception as e:
        Logger.error(f"Error determining environment: {e}\n{traceback.format_exc()}")
        return {"error": f"Failed to determine environment: {e}"}

    # --- Get Available Tables ---

    query = {"intcid": intcid, "vendor": "sentinel", "subtype": "index_list"}

    table_metadata = MongoDBManager.get_record_by_multiple_fields(
        sentinel_utils.main_db, sentinel_utils.toolsmetadata_db, query
    )
    if table_metadata is not None:
        customer_tables_with_schema = table_metadata.get("indices")
    else:
        # table_schema = await get_sentinel_tables_with_schema(intcid, task=triage_question)
        # if "error" in table_schema:
        #     Logger.error(
        #         f"Failed to get Sentinel tables for {intcid}: {table_schema['error']}"
        #     )
        #     return {
        #         "error": f"Failed to retrieve Sentinel tables: {table_schema['error']}"
        #     }
        # else:
        #     customer_tables_with_schema = table_schema.get("tables_with_schema")
        return {"error": "Failed to retrieve Sentinel tables. No metadata found."}

    try:
        table_name = sentinel_utils.get_table_name_from_mongo(
            intcid, "sentinel", env, tid, question_id, step_id
        )
    except Exception as mongo_e:
        Logger.warn(f"Failed to push AI-selected table name to MongoDB: {mongo_e}")

    if not table_name:
        try:
            table_prompt_template = PromptTemplate.from_template(
                PromptManager.get_prompt_template(
                    intcid, "logiq", "SENTINEL_TABLE_SELECTION_PROMPT"
                )
            )
            formatted_tables_schema = json.dumps(customer_tables_with_schema, indent=2)
            table_formatted_prompt = table_prompt_template.invoke(
                {
                    "requirement": triage_question,
                    "available_table_details": formatted_tables_schema,
                    "alert": alert_str,
                }
            ).text
            Logger.debug(
                f"Formatted prompt for Sentinel table selection: {table_formatted_prompt}"
            )

            response_str = AIManager.run_prompt_with_structured_output(
                model_name, table_formatted_prompt, sentinel_models.TableName
            )
            Logger.debug(f"AI response for table selection: {response_str}")

            response_data = response_str.model_dump()

            if response_data is None:
                Logger.error("Failed to parse AI response during table selection.")
                return {"error": "Failed to parse AI response during table selection."}

            table_name = response_data.get("table_name", None)

            Logger.debug(
                f"AI selected table name: {table_name}, available tables: {customer_tables_with_schema}"
            )
            if not table_name:
                Logger.error(
                    f"AI selected an invalid or unavailable table: '{table_name}'. Response: {response_str}"
                )
                return {
                    "error": f"AI failed to select a valid table. Selection: '{table_name}'"
                }

            try:
                sentinel_utils.push_table_name_to_mongo(
                    intcid,
                    "sentinel",
                    env,
                    tid,
                    question_id,
                    step_id,
                    triage_question,
                    table_name,
                )
            except Exception as mongo_e:
                Logger.warn(
                    f"Failed to push AI-selected table name to MongoDB: {mongo_e}"
                )

            Logger.info(f"Sentinel table chosen by AI: {table_name}")
        except Exception as e:
            Logger.error(
                f"Error during Sentinel table selection: {e}\n{traceback.format_exc()}"
            )
            return {
                "error": f"An unexpected error occurred during table name selection: {e}"
            }

    return {"table_name": table_name, "env": env}


async def get_sentinel_tables_with_schema(intcid: str, task: str) -> dict:
    """Fetches Sentinel Log Management tables that contain data, along with their schemas.

    Authenticates using SentinelUtils, retrieves the workspace ID, and lists all
    tables via the Azure Management API. It checks if tables contain *any* data
    by querying its count. If a table has data (count > 0), its schema
    (column names) is fetched and added to the result.

    Args:
        intcid: Integration/Customer ID (used for configuration and logging).
        task: Description of the task requesting the tables (used for logging).

    Returns:
        A dictionary with table names containing data as keys and lists of their
        column names (schema) as values, under the key 'tables_with_schema'.
        Example: {'tables_with_schema': {'Syslog': ['TimeGenerated', ...], ...}}
        Returns an error dictionary on failure.
        Example: {'error': 'Authentication failed.'}
    """
    Logger.info(f"tool:get_sentinel_tables_with_schema: Starting for {intcid} {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    all_tables_with_schema = sentinel_utils.list_all_tables_with_columns()
    if not all_tables_with_schema:
        Logger.error("Failed to list tables from Azure Management API.")
        return {
            "status": False,
            "all_tables": all_tables_with_schema,
            "error": "Failed to list tables.",
        }

    return {"status": True, "tables_with_schema": all_tables_with_schema}


async def get_sentinel_table_row_count(intcid: str, task: str, table_name: str) -> dict:
    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    status, count, error = sentinel_utils.get_table_row_count(table_name)
    return {"status": status, "count": count, "error": str(error)}


async def get_sentinel_table_schema(intcid: str, task: str, table_name: str) -> dict:
    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    success, response = sentinel_utils.get_table_schema(table_name)
    if success:
        return {"status": success, "columns": response}
    else:
        return {
            "status": success,
            "error": response,
        }


async def fetch_security_alerts_with_query(
    intcid: str,
    task: str,
    query: str,
    time_field: str,
    start_time: str = None,
    end_time: str = None,
) -> dict:
    """Fetches recent security alerts from the Sentinel SecurityAlert table.

    Authenticates, retrieves workspace ID, and queries the SecurityAlert table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security alert records under the key
        'security_alerts_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_alerts_data': [{'tableName': 'SecurityAlert', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_alerts_with_query: Starting for {intcid} {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        time_filter = f"| where {time_field} between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where {time_field} > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    kql_query = f"{query} {time_filter}"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found for query '{kql_query}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for query:'{kql_query}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for query: '{kql_query}'.")
        return {"security_alerts_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Error querying data for query '{kql_query}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_alerts_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for query '{kql_query}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {kql_query}."}

    Logger.info(
        f"Finished querying:{kql_query} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"alert_query_results": all_records}


async def fetch_security_alerts(
    intcid: str, task: str, start_time: str = None, end_time: str = None
) -> dict:
    """Fetches recent security alerts from the Sentinel SecurityAlert table.

    Authenticates, retrieves workspace ID, and queries the SecurityAlert table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security alert records under the key
        'security_alerts_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_alerts_data': [{'tableName': 'SecurityAlert', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_alerts: Starting for {intcid} {task}")
    table_name = "SecurityAlert"

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        time_filter = f"| where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where TimeGenerated > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    Logger.info(f"Querying {table_name}. {time_filter_log_message}")

    kql_query = f"{table_name} {time_filter}"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records in '{table_name}'.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    record_dict["tableName"] = table_name
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found in '{table_name}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for '{table_name}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for table '{table_name}'.")
        return {"security_alerts_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Could not query data for table '{table_name}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_alerts_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for table '{table_name}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {table_name}."}

    Logger.info(
        f"Finished querying {table_name} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"security_alerts_data": all_records}


async def fetch_security_incidents(
    intcid: str, task: str, start_time: str = None, end_time: str = None
) -> dict:
    """Fetches recent security incidents from the Sentinel SecurityIncident table.

    Authenticates, retrieves workspace ID, and queries the SecurityIncident table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security incident records under the key
        'security_incidents_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_incidents_data': [{'tableName': 'SecurityIncident', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_incidents: Starting for {intcid} {task}")
    table_name = "SecurityIncident"

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        # Assuming TimeGenerated exists; adjust if CreatedTime or LastModifiedTime is needed
        time_filter = f"| where CreatedTime between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where CreatedTime > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    Logger.info(f"Querying {table_name}. {time_filter_log_message}")

    kql_query = f"{table_name} {time_filter}| where Status == 'New'"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records in '{table_name}'.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    record_dict["tableName"] = table_name
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found in '{table_name}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for '{table_name}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for table '{table_name}'.")
        return {"security_incidents_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Could not query data for table '{table_name}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_incidents_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for table '{table_name}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {table_name}."}

    Logger.info(
        f"Finished querying {table_name} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"security_incidents_data": all_records}


async def _generate_sentinel_kql_template(
    intcid: str,
    tid: str,
    question_id: str,
    step_id: str,
    requirement: str,
    alert: str,
    table_name: str,
    table_schema: list,
    env: str = None,
) -> str | None:
    """Generates a Sentinel KQL query template using AI.

    Internal helper function for sentinel_generate_kql_query.

    Args:
        intcid: Customer Integration ID.
        requirement: The task or information needed.
        alert: Relevant context data (e.g., alert details as JSON string).
        table_name: Target Sentinel table name.
        table_schema: Schema (list of column names) of the target table.
        env: Optional environment identifier.

    Returns:
        The generated KQL query template string, or None on failure.
    """
    Logger.info(
        f"_generate_sentinel_kql_template: Generating KQL template for {intcid}, table: {table_name}"
    )
    sentinel_utils = SentinelUtils(intcid=intcid)
    try:
        _query_template_record = sentinel_utils.get_kql_template_data_from_mongo(
            intcid=intcid, env=env, tid=tid, question_id=question_id, step_id=step_id
        )

        if _query_template_record:
            Logger.info(
                f"Found KQL template in MongoDB for {intcid}, table: {table_name}"
            )
            _query_template = _query_template_record.get("query_template", None)
            if _query_template and _query_template != "":
                Logger.info(
                    f"Using cached KQL template for {intcid}, table: {table_name}"
                )
                return _query_template
    except Exception as persist_e:
        Logger.warn(f"Failed to persist KQL template/query: {persist_e}")

    model_name = PropX.get_property("module.llm.model")
    if not model_name:
        Logger.error("Model name not found in configuration.")
        return {"error": "Model name not found in configuration."}

    try:
        prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_QUERY_TEMPLATE_PROMPT"
            )
        )
        formatted_prompt = prompt_template.invoke(
            {
                "requirement": requirement,
                "alert": alert,
                "table_name": table_name,
                "columns": json.dumps(table_schema),
                "env": env,
            }
        ).text
        Logger.debug(
            f"Formatted prompt for KQL template generation: {formatted_prompt}"
        )

        query_generation_response = AIManager.run_prompt_with_structured_output(
            model_name, formatted_prompt, sentinel_models.QueryTemplate
        )
        Logger.debug(
            f"AI response for KQL template generation: {query_generation_response}"
        )

        query_template_response = query_generation_response.model_dump()

        if query_template_response is None:
            Logger.error("Failed to sanitize KQL template response.")
            return {"error": "Failed to sanitize KQL template response."}

        query_template = query_template_response.get("query_template")

        if not query_template:
            Logger.error(
                f"Sanitized response missing 'query_template': {query_template_response}"
            )
            return {"error": "KQL template generation failed."}

        Logger.info(f"Final KQL template: {query_template}")
        return query_template

    except Exception as e:
        Logger.error(
            f"Error in _generate_sentinel_kql_template: {e}\n{traceback.format_exc()}"
        )
        return {"error": f"KQL template generation failed: {e}"}


async def _replace_kql_timerange(
    intcid: str, requirement: str, kql_template: str, alert: str
) -> str | None:
    """Replaces time range placeholders in a KQL query template using AI.

    Internal helper function for sentinel_generate_kql_query.

    Args:
        intcid: Customer Integration ID.
        requirement: The task or information needed.
        kql_template: The KQL template with time placeholders.
        alert: Relevant context data (e.g., alert details as JSON string).

    Returns:
        The KQL query string with time ranges replaced, or None on failure.
    """
    Logger.info(
        f"_replace_kql_timerange: Replacing time range in template: {kql_template}"
    )

    model_name = PropX.get_property("module.llm.model")
    try:
        prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_TIMERANGE_REPLACEMENT_PROMPT"
            )
        )
        formatted_prompt = prompt_template.invoke(
            {
                "requirement": requirement,
                "query_template": kql_template,
                "alert": alert,
            }
        ).text

        kql_query_time_replaced = AIManager.run_prompt_with_structured_output(
            model_name, formatted_prompt, sentinel_models.TimeRangeReplacement
        )
        kql_query_time_replaced = kql_query_time_replaced.model_dump()
        kql_query_time_replaced = kql_query_time_replaced.get("replaced_query", None)
        if kql_query_time_replaced is None:
            Logger.error("Failed to parse AI response for time range replacement.")
            return {"error": "Failed to parse AI response for time range replacement."}
        Logger.info(
            f"KQL query after time range replacement: {kql_query_time_replaced}"
        )
        return kql_query_time_replaced
    except Exception as e:
        Logger.error(f"Error in _replace_kql_timerange: {e}\n{traceback.format_exc()}")
        return None


async def _generate_sentinel_kql_from_template(
    intcid: str,
    requirement: str,
    kql_template_time_replaced: str,
    alert: str,
    alert_context: any,
) -> str | None:
    """Generates the final KQL query by replacing field value placeholders using AI.

    Internal helper function for sentinel_generate_kql_query. Also includes a
    final validation/cleanup step via AI.

    Args:
        intcid: Customer Integration ID.
        requirement: The task or information needed.
        kql_template_time_replaced: KQL template with time ranges replaced.
        alert: Relevant context data (e.g., alert details as JSON string).

    Returns:
        The final, validated KQL query string, or None on failure.
    """
    Logger.info(
        f"_generate_sentinel_kql_from_template: Generating final KQL from: {kql_template_time_replaced}"
    )
    # No sanitizer needed here as the expected output is a string, not JSON
    try:
        model_name = PropX.get_property("module.llm.model")
        if not model_name:
            Logger.error("Model name not found in configuration.")
            return {"error": "Model name not found in configuration."}

        # --- Field Value Replacement ---
        replacement_prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_FIELD_VALUE_REPLACEMENT_PROMPT"
            )
        )
        replacement_formatted_prompt = replacement_prompt_template.invoke(
            {
                "requirement": requirement,
                "query_template": kql_template_time_replaced,
                "alert": alert,
            }
        ).text

        final_kql_query = AIManager.run_prompt_with_structured_output(
            model_name, replacement_formatted_prompt, sentinel_models.FinalQuery
        )

        final_kql_query = final_kql_query.model_dump()
        if final_kql_query is None:
            Logger.error("Failed to parse AI response for final KQL query.")
            return {"error": "Failed to parse AI response for final KQL query."}

        final_kql_query = final_kql_query.get("final_query", None)
        if final_kql_query is None:
            Logger.error(
                f"Final KQL query generation failed. Response: {final_kql_query}"
            )
            return {"error": "Final KQL query generation failed."}

        validation_prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_QUERY_VALIDATION_PROMPT"
            )
        )
        validation_formatted_prompt = validation_prompt_template.invoke(
            {
                "alert": alert,
                "alert_context": alert_context,
                "kql_query": final_kql_query,
            }
        ).text

        final_kql_query_validation_result = AIManager.run_prompt_with_structured_output(
            model_name, validation_formatted_prompt, sentinel_models.FinalQuery
        )
        final_kql_query_dict = final_kql_query_validation_result.model_dump()

        # Check if the validation itself returned an error structure (adjust key if needed)
        if "error" in final_kql_query_dict:
            Logger.error(
                f"[FinalQueryValidation] Final KQL query validation failed. Response: {final_kql_query_dict}"
            )
            # Consider returning the specific error if available:
            # return {"error": f"Final KQL query validation failed: {final_kql_query_dict.get('error')}"}
            return {"error": "Final KQL query validation failed."}

        # Attempt to extract the final query string after validation
        final_kql_query = final_kql_query_dict.get("final_query", None)

        if final_kql_query is None:
            Logger.error(
                f"[FinalQueryExtraction] Final KQL query extraction failed after validation. Response dict: {final_kql_query_dict}"
            )
            return {"error": "Final KQL query extraction failed after validation."}

        # If successful, final_kql_query now holds the validated query string
        Logger.info(
            f"[FinalQueryExtraction] Successfully extracted validated KQL query."
        )
        # ... rest of the function using the validated final_kql_query string ...
        return final_kql_query

    except Exception as e:
        Logger.error(
            f"Error in _generate_sentinel_kql_from_template: {e}\n{traceback.format_exc()}"
        )
        return {"error": "Final KQL query generation failed."}


async def sentinel_generate_kql_query(
    intcid: str,
    task: str,
    table_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: any,  # Accept dict or string
    env: str,
) -> dict:
    """Generates a Sentinel KQL query for a specific task and context using AI.

    Handles template generation, placeholder replacement (time, fields),
    validation, and retries.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed (requirement).
        table_name: The name of the target Sentinel table.
        tid: Triage ID for caching/persistence.
        question_id: Question ID for caching/persistence.
        triage_question: Original question text for persistence.
        alert: Relevant data (like an alert or event details) as dict or JSON string.
        env: Environment identifier.

    Returns:
        A dictionary containing the generated KQL query under the key 'query'.
        Returns an error dictionary if generation fails after retries.
        Example success: {'query': 'SecurityEvent | where ...'}
        Example error: {'error': 'Failed to generate valid KQL...'}
    """
    Logger.info(
        f"tool:sentinel_generate_kql_query: Starting for {intcid}, Table: {table_name}, Task: {task}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    schema = sentinel_utils.get_table_metadata(intcid, table_name)

    if not schema or len(schema) < 0:
        Logger.error(
            f"Could not retrieve schema for table '{table_name}'. Cannot generate query."
        )
        return {"error": f"Failed to get schema for table {table_name}."}

    query_template = None
    final_kql_query = None
    is_valid = False
    alert_str = (
        json.dumps(alert_context)
        if isinstance(alert_context, dict)
        else str(alert_context)
    )
    msg = ""  # Initialize msg
    env = env.lower()
    for attempt in range(MAX_KQL_GENERATION_ATTEMPTS):
        Logger.info(
            f"KQL Generation Attempt {attempt + 1}/{MAX_KQL_GENERATION_ATTEMPTS} for task: {task}"
        )
        try:
            if query_template is None:
                query_template = await _generate_sentinel_kql_template(
                    intcid=intcid,
                    tid=tid,
                    question_id=question_id,
                    step_id=step_id,
                    requirement=task,
                    alert=alert_str,
                    table_name=table_name,
                    table_schema=schema,
                    env=env,
                )
                if "error" in query_template:
                    Logger.warn(
                        f"Attempt {attempt + 1}: Failed to generate KQL template."
                    )
                    continue

            kql_template_time_replaced = await _replace_kql_timerange(
                intcid=intcid,
                requirement=task,
                kql_template=query_template,
                alert=alert_str,
            )
            if "error" in kql_template_time_replaced:
                Logger.warn(f"Attempt {attempt + 1}: Failed to replace time range.")
                query_template = None  # Force regeneration
                continue

            final_kql_query = await _generate_sentinel_kql_from_template(
                intcid=intcid,
                requirement=task,
                kql_template_time_replaced=kql_template_time_replaced,
                alert=alert_str,
                alert_context=alert_context,
            )
            if "error" in final_kql_query:
                Logger.warn(
                    f"Attempt {attempt + 1}: Failed to generate final KQL query."
                )
                query_template = None  # Force regeneration
                continue

            is_valid, msg = sentinel_utils.validate_sentinel_kql(
                final_kql_query, intcid
            )
            if not is_valid:
                Logger.warn(
                    f"Attempt {attempt + 1}: Generated KQL failed validation: {final_kql_query} - Reason: {msg}"
                )
                query_template = None  # Force regeneration
            else:
                Logger.info(f"Attempt {attempt + 1}: Generated KQL passed validation.")
                break  # Exit loop successfully

        except Exception as e:
            Logger.error(
                f"Attempt {attempt + 1}: Error during KQL generation/validation: {e}\n{traceback.format_exc()}"
            )
            query_template = None  # Force regeneration

    if not is_valid or final_kql_query is None:
        Logger.error(
            f"Failed to generate a valid KQL query after {MAX_KQL_GENERATION_ATTEMPTS} attempts for task: {task}"
        )
        return {
            "error": f"Failed to generate valid KQL after {MAX_KQL_GENERATION_ATTEMPTS} attempts. Last error: {msg}"
        }

    # --- Persistence Hook ---
    if query_template and final_kql_query and is_valid:
        try:
            sentinel_utils.push_kql_template_data_to_mongo(
                intcid=intcid,
                siem_type="sentinel",
                env=env,
                tid=tid,
                question_id=question_id,
                step_id=step_id,
                triage_question=triage_question,
                requirement=task,
                table_name=table_name,
                query_template=query_template,
                final_query=final_kql_query,
            )
        except Exception as persist_e:
            Logger.warn(f"Failed to persist KQL template/query: {persist_e}")

    Logger.info(f"Successfully generated and validated KQL query for task: {task}")
    Logger.debug(f"Final KQL query: {final_kql_query}")
    return {"query": final_kql_query}


async def sentinel_run_kql_query(intcid: str, task: str, kql_query: str) -> dict:
    """Executes a given KQL query against the Sentinel Log Analytics workspace.

    Authenticates, gets workspace ID, and runs the query using the Log Analytics API.

    Args:
        intcid: Integration/Customer ID.
        task: Description of the task executing the query.
        kql_query: The KQL query string to execute.

    Returns:
        A dictionary containing the query results under the key 'query_results'.
        Each result is a dictionary representing a row. Returns an empty list
        if no data is found. Returns an error dictionary on failure.
        Example success: {'query_results': [{'TimeGenerated': '...', ...}]}
        Example error: {'error': 'Authentication failed.'}
    """
    Logger.info(f"tool:sentinel_run_kql_query: Starting for {intcid}, Task: {task}")
    Logger.debug(f"Executing KQL: {kql_query}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }
    query_payload = json.dumps({"query": kql_query})

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=60
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        Logger.debug(f"Query response: {query_result}")
        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            primary_table = query_result["tables"][0]
            columns = [col["name"] for col in primary_table.get("columns", [])]
            rows = primary_table.get("rows", [])
            if rows:
                Logger.info(f"Query returned {len(rows)} records.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    all_records.append(record_dict)
            else:
                Logger.info("Query executed successfully but returned no records.")
        else:
            Logger.info(
                "Query executed successfully but the response structure had no primary table data."
            )

    except requests.exceptions.Timeout:
        Logger.warn(
            f"Timeout occurred while executing KQL query for task '{task}'. Query: {kql_query}"
        )
        return {"error": "Query execution timed out."}
    except requests.exceptions.HTTPError as http_err:
        Logger.error(
            f"HTTP error occurred while executing KQL query {kql_query}: {http_err}"
        )
        error_details = ""
        try:
            error_content = http_err.response.json()
            error_details = error_content.get("error", {}).get(
                "message", http_err.response.text
            )
            Logger.error(f"Query Error Details: {error_content}")
        except ValueError:
            error_details = http_err.response.text
            Logger.error(f"Query Error Details (non-JSON): {error_details}")
        return {
            "error": f"Query execution failed with HTTP status {http_err.response.status_code}. Details: {error_details}"
        }
    except requests.exceptions.RequestException as req_err:
        Logger.error(f"Request error occurred while executing KQL query: {req_err}")
        return {"error": f"Network or request error during query execution: {req_err}"}
    except Exception as e:
        Logger.error(
            f"An unexpected error occurred executing KQL query: {e}\n{traceback.format_exc()}"
        )
        return {"error": f"An unexpected error occurred during query execution: {e}"}

    Logger.info(
        f"Finished executing KQL query for task: {task}. Found {len(all_records)} records."
    )
    return {"query_results": all_records}


async def sentinel_get_single_matching_record(
    intcid: str, task: str, table_name: str, kql_query: str
) -> dict:
    """Fetches a single record matching a specific KQL query from a Sentinel table.

    Uses the `get_single_matching_record` method from `SentinelUtils`, which
    handles authentication and query execution, ensuring only one record is fetched.

    Args:
        intcid: The customer integration ID.
        task: A description of the task requesting the record (for logging).
        table_name: The name of the Sentinel table targeted by the query.
        kql_query: The KQL query string expected to return a single record.

    Returns:
        A dictionary containing the table name, query, and the matching record
        under the key 'result'. Returns an error dictionary if fetching fails or
        no record is found by the query.
        Example success: {'table_name': 'SecurityEvent', 'kql_query': '...', 'result': {...}}
    """
    Logger.info(
        f"tool:sentinel_get_single_matching_record: Starting for {intcid}, Task: {task}, Table: {table_name}"
    )
    Logger.debug(f"Executing KQL to get single record: {kql_query}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    execution_result = sentinel_utils.get_single_matching_record(
        intcid, table_name, kql_query
    )

    if "error" in execution_result:
        Logger.error(
            f"Error executing KQL for single record: {execution_result['error']}"
        )
        # Propagate the specific error from the utility function
        return {"error": execution_result}

    # The utility function returns {"matching_record": {}} if no record is found
    matching_record = execution_result.get("matching_record", {})

    if not matching_record:
        Logger.warn(
            f"Query for single record executed successfully but returned no results. Query: {kql_query}"
        )
    else:
        Logger.info(f"Successfully fetched single matching record from {table_name}.")

    return {
        "table_name": table_name,
        "query": kql_query,
        "result": matching_record,
    }


async def sentinel_get_alert_context(intcid: str, task: str, alert: any) -> dict:
    """Retrieves context for a given Sentinel alert/event using AI.

    If the input is a SecurityIncident, it attempts to fetch the underlying
    SecurityAlerts. It then determines the relevant environment, fetches sample
    matching records and table schema for the relevant table (Incident or Alert),
    and uses AI to extract context relevant to the specified task and alert/event data.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed from the alert context.
        alert: The Sentinel alert/event content (dict or JSON string).

    Returns:
        A dictionary containing the extracted alert context under the key
        'alert_context', including the environment ('env'). Returns an error
        dictionary if context extraction fails.
        Example success: {'alert_context': {'field1': 'val1', 'env': 'Prod'}}
        Example error: {'error': 'Failed to determine environment.'}
    """
    Logger.info(f"tool:sentinel_get_alert_context: Starting for {intcid}, Task: {task}")

    try:
        alert_dict = json.loads(alert) if isinstance(alert, str) else alert
        if not isinstance(alert_dict, dict):
            raise ValueError("Parsed alert is not a dictionary.")
    except (json.JSONDecodeError, ValueError) as e:
        Logger.error(f"Failed to parse input alert: {e}. Alert data: {alert}")
        return {"error": "Invalid alert format provided."}

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    # Initialize context data and target table name
    context_data = alert_dict
    target_table_name = alert_dict.get("tableName") or alert_dict.get("Type")
    original_alert_type = target_table_name
    Logger.debug(f"Initial context type: {original_alert_type}")

    # --- Check if it's a SecurityIncident and fetch related alerts ---
    if original_alert_type == "SecurityIncident":
        Logger.info("Input is a SecurityIncident. Attempting to fetch related alerts.")
        alert_ids_str = alert_dict.get("AlertIds", "[]")
        try:
            alert_id_list = json.loads(alert_ids_str)
            if isinstance(alert_id_list, list) and alert_id_list:
                # Construct KQL query for SecurityAlert
                alert_id_filter = ",".join([f"'{id}'" for id in alert_id_list])
                kql_query = (
                    f"SecurityAlert | where SystemAlertId in ({alert_id_filter})"
                )
                Logger.debug(f"Fetching related alerts with KQL: {kql_query}")

                # Use sentinel_run_kql_query to fetch alerts
                fetched_alerts_result = await sentinel_run_kql_query(
                    intcid,
                    f"fetch related alerts for incident {alert_dict.get('IncidentNumber', '')}",
                    kql_query,
                )

                if "error" in fetched_alerts_result:
                    Logger.warn(
                        f"Failed to fetch related SecurityAlerts: {fetched_alerts_result['error']}. Proceeding with Incident data."
                    )
                elif fetched_alerts_result.get("query_results"):
                    context_data = fetched_alerts_result["query_results"]
                    target_table_name = "SecurityAlert"  # Update target table
                    Logger.info(
                        f"Successfully fetched {len(context_data)} related SecurityAlerts. Using alerts as context."
                    )
                else:
                    Logger.warn(
                        "Fetching related SecurityAlerts returned no results. Proceeding with Incident data."
                    )
            else:
                Logger.warn(
                    "No AlertIds found or invalid format in SecurityIncident. Proceeding with Incident data."
                )
        except json.JSONDecodeError:
            Logger.warn(
                "Failed to parse AlertIds JSON string. Proceeding with Incident data."
            )
        except Exception as e:
            Logger.warn(
                f"Error fetching related alerts: {e}. Proceeding with Incident data."
            )

    # Prepare alert string from the final context_data (could be incident or list of alerts)
    alert_str = json.dumps(context_data)

    # --- Step 1: Determine Environment ---
    env = None
    try:
        env_prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_ENVIRONMENT_SELECTION_PROMPT"
            )
        )
        # Use the potentially updated alert_str for environment selection
        env_formatted_prompt = env_prompt_template.invoke({"alert": alert_str}).text
        env_response_str = AIManager.run_prompt(
            PropX.get_property("module.llm.model"), env_formatted_prompt
        )

        env_response = sentinel_utils.sanitize_json_response(
            env_response_str, context="Context extraction - Environment selection"
        )
        Logger.debug(f"Response for environment selection: {env_response_str}")
        if env_response is None:
            return {
                "error": "Failed to parse AI response for environment selection (context extraction)."
            }

        env = env_response.get("env").lower()
        if not env:
            Logger.warn(
                f"Could not determine environment from AI response: {env_response_str}"
            )
            # Allow proceeding without env, context extraction might still work
            env = "unknown"
        Logger.info(f"Determined environment: {env}")
    except Exception as e:
        Logger.error(f"Error determining environment: {e}\n{traceback.format_exc()}")
        # Allow proceeding without env
        env = "unknown"
        Logger.warn(f"Failed to determine environment: {e}. Setting to 'Unknown'.")

    # --- Step 2: Get Schema for the target table ---
    schema = None
    schema_str = "{}"
    if target_table_name:
        schema = sentinel_utils.get_table_schema(target_table_name)
        if not schema:
            Logger.warn(
                f"Could not retrieve schema for determined table '{target_table_name}'."
            )
        else:
            schema_str = json.dumps(schema)
            Logger.info(f"Successfully retrieved schema for table: {target_table_name}")
    else:
        Logger.warn("Target table name could not be determined. Cannot fetch schema.")

    # --- Step 3: Get Sample Matching Records ---
    # Note: Fetching samples might be less relevant if context_data is already a list of alerts.
    # We fetch from the target_table_name determined earlier.
    # matching_records = []
    # matching_records_str = "[]"
    # if target_table_name:
    #     # Basic query for sample records from the target table
    #     sample_kql_query = f"{target_table_name} | take 5" # Limit sample size
    #     Logger.info(
    #         f"Fetching sample records from '{target_table_name}' using query: {sample_kql_query}"
    #     )
    #     matching_records_result = sentinel_utils.get_matching_records(
    #         intcid, target_table_name, sample_kql_query
    #     )

    #     if "error" in matching_records_result:
    #         Logger.warn(
    #             f"Failed to get sample matching records for '{target_table_name}': {matching_records_result['error']}"
    #         )
    #     else:
    #         matching_records = matching_records_result.get("matching_records", [])
    #         if not matching_records:
    #             Logger.info(f"No sample matching records found for '{target_table_name}'.")
    #         else:
    #             Logger.info(f"Found {len(matching_records)} sample matching records for '{target_table_name}'.")
    #             matching_records_str = json.dumps(matching_records)
    # else:
    #     Logger.warn("Target table name unknown. Cannot fetch sample records.")

    # --- Step 4: AI Call for Context Extraction ---
    try:
        context_prompt_template = PromptTemplate.from_template(
            PromptManager.get_prompt_template(
                intcid, "logiq", "SENTINEL_ALERT_CONTEXT_EXTRACTION_PROMPT"
            )
        )
        context_formatted_prompt = context_prompt_template.invoke(
            {
                "alert": alert_str,  # This now contains either the original alert/incident or the list of fetched alerts
                "env": env,
                "requirement": task,
                "table_name": target_table_name
                or "Unknown",  # Pass the determined table name
                "table_schema_details": schema_str,
            }
        ).text
        Logger.debug(
            f"Formatted prompt for Sentinel context extraction: {context_formatted_prompt}"
        )

        context_response = AIManager.run_prompt_with_structured_output(
            PropX.get_property("module.llm.model"),
            context_formatted_prompt,
            sentinel_models.AlertContextResponse,
        )
        Logger.info(f"AI response for context extraction: {context_response}")

        alert_context = context_response.model_dump()
        alert_context = transform_alert_context(alert_context)
        alert_context["env"] = env  # Ensure env is included
        alert_context["alert_type"] = original_alert_type
        Logger.info(f"Successfully extracted alert context for task: {task}")
        return alert_context

    except Exception as e:
        Logger.error(
            f"Error during Sentinel context extraction: {e}\n{traceback.format_exc()}"
        )
        return {"error": f"An unexpected error occurred during context extraction: {e}"}


def transform_alert_context(input_data: dict) -> dict:
    """Transforms the alert context structure.

    Converts the 'extracted_fields' list into a dictionary keyed by the 'id'
    of each field, removing the 'id' key from the nested dictionaries.

    Args:
        input_data: The dictionary containing the alert context, potentially
                    nested under the 'alert_context' key.

    Returns:
        The transformed dictionary.
    """
    if "alert_context" not in input_data:
        Logger.warn("transform_alert_context: 'alert_context' key not found in input.")
        return input_data  # Return original if structure is unexpected

    alert_context_data = input_data["alert_context"]

    if "extracted_fields" not in alert_context_data or not isinstance(
        alert_context_data["extracted_fields"], list
    ):
        Logger.warn(
            "transform_alert_context: 'extracted_fields' is not a list or not found."
        )
        # Return the structure as is if extracted_fields is missing or not a list
        return input_data

    original_fields = alert_context_data.get("extracted_fields", [])
    transformed_fields = {}

    for field in original_fields:
        if isinstance(field, dict) and "id" in field:
            field_id = field.get("id")
            if field_id:  # Ensure id is not empty or None
                field_copy = field.copy()
                del field_copy["id"]  # Remove the id key
                transformed_fields[field_id] = field_copy
            else:
                Logger.warn(
                    f"transform_alert_context: Found field with missing/empty id: {field}"
                )
        else:
            Logger.warn(
                f"transform_alert_context: Skipping invalid field format: {field}"
            )

    # Replace the list with the new dictionary structure within the nested alert_context
    alert_context_data["extracted_fields"] = transformed_fields

    # Return the modified top-level structure
    return input_data["alert_context"]


async def fetch_sample_records(intcid: str, table_name: str, limit: int = 3) -> dict:
    """
    Fetches sample records from the specified table using SentinelUtils.

    Args:
        intcid (str): The integration/customer ID.
        table_name (str): The name of the table to fetch records from.
        limit (int): The number of sample records to fetch (default is 3).

    Returns:
        dict: A dictionary containing the sample records or an error message.
    """
    Logger.info(
        f"Fetching {limit} sample records from table: {table_name} for intcid: {intcid}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)

    # Authenticate with Sentinel
    if not sentinel_utils.authenticate():
        Logger.error("Failed to authenticate with Sentinel.")
        return {"error": "Authentication failed. Check configuration and credentials."}

    # Fetch sample records using the utility function
    kql_query = f"{table_name} | take {limit}"
    result = sentinel_utils.get_matching_records(intcid, table_name, kql_query, limit)

    if "error" in result:
        Logger.error(f"Error fetching sample records: {result['error']}")
        return {"error": result["error"]}

    Logger.info(f"Successfully fetched sample records from table: {table_name}")
    return {"sample_records": result.get("matching_records", [])}
