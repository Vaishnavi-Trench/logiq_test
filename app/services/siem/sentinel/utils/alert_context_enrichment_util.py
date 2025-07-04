"""
This module aggregates results from KQL queries executed against a SIEM.
"""

from typing import Any, Dict, List
from pltfrm import Logger2 as Logger
"""
Alert Labels Processing for Table Context Enrichment.

This module provides functionality to process alert labels selected from the 
fetch_facet_templates node and enriches them with descriptions, then retrieves 
matching tables using Elasticsearch vector search.
"""

from datetime import datetime, timedelta

from pltfrm import AIManager, ElasticsearchManager
from pltfrm import  PropX
from app.services.siem.sentinel.models import AlertContextEnrichmentQueryList


def get_matching_tables_for_username(intcid):
    Logger.info("Step 2: Getting matching tables for Username with index filter")
    username_context = "Good to have parameters: | Username"
    username_embedding = AIManager.get_vector_embedding(
        PropX.get_property("module.embedding.model"),
        username_context
    )
    try:
        username_filters = [{"intcid": intcid}, {"type": "index_fields"}]
        username_matching_tables = ElasticsearchManager.get_multiple_best_match_with_params(
            "rag_integration",
            username_filters,
            username_embedding,
            threshold=0.65,
            max_results=100
        )
    except Exception as e:
        Logger.error(f"Error in username search: {e}")
        username_matching_tables = []
    Logger.info(f"Found {len(username_matching_tables)} matching tables for Username")
    return username_matching_tables


def get_matching_tables_for_ip(intcid):
    Logger.info("Step 3: Getting matching tables for IP Address with index filter")
    ip_context = "Good to have parameters: | Source IP Address | Destination IP Address"
    ip_embedding = AIManager.get_vector_embedding(
        PropX.get_property("module.embedding.model"),
        ip_context
    )
    try:
        ip_filters = [{"intcid": intcid}, {"type": "index_fields"}]
        ip_matching_tables = ElasticsearchManager.get_multiple_best_match_with_params(
            "rag_integration",
            ip_filters,
            ip_embedding,
            threshold=0.65,
            max_results=100,
        )
    except Exception as e:
        Logger.error(f"Error in IP address search: {e}")
        ip_matching_tables = []
    Logger.info(f"Found {len(ip_matching_tables)} matching tables for IP Address")
    return ip_matching_tables


def group_tables(username_matching_tables, ip_matching_tables):
    username_grouped_by_index = {}
    for table in username_matching_tables:
        index_name = table.get("index_name", "unknown_index")
        if index_name not in username_grouped_by_index:
            username_grouped_by_index[index_name] = []
        username_grouped_by_index[index_name].append(table)
    ip_grouped_by_index = {}
    for table in ip_matching_tables:
        index_name = table.get("index_name", "unknown_index")
        if index_name not in ip_grouped_by_index:
            ip_grouped_by_index[index_name] = []
        ip_grouped_by_index[index_name].append(table)
    username_indices = set(username_grouped_by_index.keys())
    ip_indices = set(ip_grouped_by_index.keys())
    common_indices = username_indices.intersection(ip_indices)
    Logger.info(f"Username search found {len(username_indices)} indices: {list(username_indices)}")
    Logger.info(f"IP search found {len(ip_indices)} indices: {list(ip_indices)}")
    Logger.info(f"Common indices found in both searches: {len(common_indices)} - {list(common_indices)}")
    all_matching_tables = []
    grouped_by_index = {}
    for index_name in common_indices:
        combined_tables = username_grouped_by_index[index_name] + ip_grouped_by_index[index_name]
        grouped_by_index[index_name] = combined_tables
        all_matching_tables.extend(combined_tables)
    Logger.info(f"Combined total for common indices: {len(all_matching_tables)} tables")
    Logger.info(f"Grouped results by common index_name:")
    for index_name, tables in grouped_by_index.items():
        Logger.info(f"  Index '{index_name}': {len(tables)} tables")
    return username_grouped_by_index, ip_grouped_by_index, common_indices, grouped_by_index


def build_final_ans_dict(common_indices, username_grouped_by_index, ip_grouped_by_index):
    final_ans_dict = {}
    for index_name in common_indices:
        username_fields = []
        ip_fields = []
        for table in username_grouped_by_index[index_name]:
            field_name = table.get("field_name") or table.get("name") or table.get("table_name")
            if field_name and field_name not in username_fields:
                username_fields.append(field_name)
        for table in ip_grouped_by_index[index_name]:
            field_name = table.get("field_name") or table.get("name") or table.get("table_name")
            if field_name and field_name not in ip_fields:
                ip_fields.append(field_name)
        final_ans_dict[index_name] = {
            "username_fields": username_fields,
            "ip_fields": ip_fields
        }
        Logger.debug(f"Index '{index_name}': {len(username_fields)} username fields - {username_fields}")
        Logger.debug(f"Index '{index_name}': {len(ip_fields)} IP fields - {ip_fields}")
    Logger.info(f"Final answer dict contains {len(final_ans_dict)} common indices {final_ans_dict}")
    return final_ans_dict


def build_kql_queries_for_usernames(table_name, username_fields, ip_fields, alert_context=None):
    start_time, end_time = (None, None)
    if alert_context:
        start_time, end_time = get_time_window_from_alert_context(alert_context)
    if start_time and end_time:
        time_filter = f"| where TimeGenerated between (datetime('{start_time}') .. datetime('{end_time}'))\n"
    else:
        time_filter = "| where TimeGenerated between (datetime(<start_time>) .. datetime(<end_time>))\n"
    kql = (
        f"{table_name}\n" +
        time_filter +
        f"| where (\n    " +
        " or\n    ".join([
            f"{uf} in (<username>,<email> taken from alert context)" for uf in username_fields
        ]) +
        "\n)"
    )
    kql += "\n| limit 1"
    if ip_fields:
        kql += "\n| project " + ', '.join(list(set(username_fields + ip_fields)))
    else:
        kql += "\n| project " + ', '.join(list(set(username_fields)))
    return {
        'index_name': table_name,
        'query': kql,
        'description': f"KQL query for {table_name} with usernames.",
        'reason': f"Auto-generated for context enrichment."
    }


def build_kql_queries_for_ip_address(table_name, username_fields, ip_fields, alert_context=None):
    start_time, end_time = (None, None)
    if alert_context:
        start_time, end_time = get_time_window_from_alert_context(alert_context)
    if start_time and end_time:
        time_filter = f"| where TimeGenerated between (datetime('{start_time}') .. datetime('{end_time}'))\n"
    else:
        time_filter = "| where TimeGenerated between (datetime(<start_time>) .. datetime(<end_time>))\n"
    kql = (
        f"{table_name}\n" +
        time_filter +
        f"| where (\n    " +
        " or\n    ".join([
            f"{ipf} in (<ip_addresses> taken from alert context)" for ipf in ip_fields
        ]) +
        "\n)"
    )
    kql += "\n| limit 1"
    if username_fields:
        kql += "\n| project " + ', '.join(list(set(username_fields + ip_fields)))
    else:
        kql += "\n| project " + ', '.join(list(set(username_fields)))    
    return {
        'index_name': table_name,
        'query': kql,
        'description': f"KQL query for {table_name} with IP addresses.",
        'reason': f"Auto-generated for context enrichment."
    }


async def process_user_kql_queries(final_ans_dict, group_dict, alert, alert_context_from_state, intcid, aid, discovered_ip_addresses, tables_with_discoveries, all_kql_queries, all_query_results):
    user_kql_queries = []
    for table_name, fields in group_dict.items():
        username_fields = fields.get('username_fields', [])
        ip_fields = fields.get('ip_fields', [])
        if username_fields:
            user_kql = build_kql_queries_for_usernames(table_name, username_fields, ip_fields, alert_context=alert_context_from_state)
            user_kql_queries.append(user_kql)
    if user_kql_queries:
        substituted_user_kql_results = generate_kql_queries(
            alert=alert,
            alert_context=alert_context_from_state,
            final_dict=user_kql_queries,
            intcid=intcid,
            aid=aid
        )
        final_user_kql_queries = [q["query"] for q in user_kql_queries if "query" in q]
        user_query_results = await aggregate_query_results(substituted_user_kql_results, intcid, aid)
        all_kql_queries.extend(final_user_kql_queries)
        all_query_results.extend(user_query_results)
        qr_list = user_query_results.get('query_results', []) if isinstance(user_query_results, dict) else user_query_results
        for qr in qr_list:
            results = qr.get('result', {}).get('query_results', []) if isinstance(qr, dict) else []
            table_name = qr.get('index_name')
            if results:
                for row in results:
                    ip_fields = final_ans_dict.get(table_name, {}).get('ip_fields', [])
                    for ip_field in ip_fields:
                        if ip_field in row and row[ip_field]:
                            if row[ip_field] not in discovered_ip_addresses:
                                discovered_ip_addresses.append(row[ip_field])
                if table_name and table_name not in tables_with_discoveries:
                    tables_with_discoveries.append(table_name)


async def process_ip_kql_queries(
    final_ans_dict,
    group_dict,
    alert,
    alert_context,
    intcid,
    aid,
    discovered_usernames,
    tables_with_discoveries,
    all_kql_queries,
    all_query_results
):
    ip_kql_queries = []
    for table_name, fields in group_dict.items():
        username_fields = fields.get('username_fields', [])
        ip_fields = fields.get('ip_fields', [])        
        if ip_fields:
            ip_kql = build_kql_queries_for_ip_address(table_name, username_fields, ip_fields, alert_context=alert_context)
            ip_kql_queries.append(ip_kql)
    if ip_kql_queries:
        substituted_ip_kql_results = generate_kql_queries(
            alert=alert,
            alert_context=alert_context,
            final_dict=ip_kql_queries,
            intcid=intcid,
            aid=aid
        )
        final_ip_kql_queries = [q["query"] for q in ip_kql_queries if "query" in q]
        ip_query_results = await aggregate_query_results(substituted_ip_kql_results, intcid, aid)
        all_kql_queries.extend(final_ip_kql_queries)
        all_query_results.extend(ip_query_results)
        qr_list = ip_query_results.get('query_results', []) if isinstance(ip_query_results, dict) else ip_query_results
        for qr in qr_list:
            results = qr.get('result', {}).get('query_results', []) if isinstance(qr, dict) else []
            table_name = qr.get('index_name')
            if results:
                for row in results:
                    username_fields = final_ans_dict.get(table_name, {}).get('username_fields', [])
                    for username_field in username_fields:
                        if username_field in row and row[username_field]:
                            if row[username_field] not in discovered_usernames:
                                discovered_usernames.append(row[username_field])
                if table_name and table_name not in tables_with_discoveries:
                    tables_with_discoveries.append(table_name)
    # No return, discovered_usernames is updated in-place


def get_time_window_from_alert_context(alert_context):
    """
    Extracts and returns the time window (start, end) for KQL queries from alert context.
    Subtracts 1 hour from activity_start_time and adds 1 hour to activity_end_time.
    Returns (start_time_str, end_time_str) in ISO8601 format.
    """
    import re
    start_time = None
    end_time = None
    # Defensive: alert_context may be dict or str
    if isinstance(alert_context, dict):
        start_str = alert_context.get('extracted_fields',{}).get('activity_start_time', {}).get('value')
        end_str = alert_context.get('extracted_fields',{}).get('activity_end_time', {}).get('value')
        def parse_iso8601(ts):
            if not ts:
                return None
            try:
                # Regex to match ISO8601 with optional fractional seconds and 'Z'
                m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.(\d+))?(Z|[+-]\d{2}:\d{2})?", ts)
                if not m:
                    Logger.error(f"Timestamp '{ts}' does not match expected ISO8601 format.")
                    return None
                base = m.group(1)
                frac = m.group(3) or ''
                tz = m.group(4) or ''
                if frac:
                    frac = frac[:6]  # Only up to 6 digits for microseconds
                    ts_clean = f"{base}.{frac}"
                else:
                    ts_clean = base
                if tz == 'Z':
                    tz = '+00:00'
                ts_clean += tz
                return datetime.fromisoformat(ts_clean)
            except Exception as e:
                Logger.error(f"Error parsing ISO8601 timestamp '{ts}': {e}")
                return None
        if start_str:
            start_time = parse_iso8601(start_str)
            if start_time:
                start_time = start_time - timedelta(hours=1)
        if end_str:
            end_time = parse_iso8601(end_str)
            if end_time:
                end_time = end_time + timedelta(hours=1)
    # Fallback: if not found, return None
    Logger.info(f"Extracted time window from alert context: start_time={start_time}, end_time={end_time}")
    return (
        start_time.isoformat() if start_time else None,
        end_time.isoformat() if end_time else None
    )


async def run_kql_and_collect(final_ans_dict, grouped_by_index, alert, aid, alert_context, intcid, use_user_kql=True):
    all_kql_queries = []
    all_query_results = []


    discovered_usernames = []
    discovered_ip_addresses = []
    tables_with_discoveries = []
    index_scores = {}
    for index_name in final_ans_dict:
        username_scores = [t.get("score", 0) for t in grouped_by_index.get(index_name, [])]
        ip_scores = [t.get("score", 0) for t in grouped_by_index.get(index_name, [])]
        best_score = max(username_scores + ip_scores) if (username_scores or ip_scores) else 0
        index_scores[index_name] = best_score
    sorted_indices = sorted(final_ans_dict.keys(), key=lambda idx: index_scores[idx], reverse=True)
    groups = [sorted_indices[i:i+5] for i in range(0, len(sorted_indices), 5)]
    Logger.info(f"Split {len(sorted_indices)} indices into {len(groups)} groups of up to 5 by RAG match score.")
    for group_num, group_indices in enumerate(groups, 1):
        group_dict = {idx: final_ans_dict[idx] for idx in group_indices}
        Logger.info(f"Generating KQL queries for group {group_num} with indices: {list(group_dict.keys())}")
        try:
            if use_user_kql:
                await process_user_kql_queries(final_ans_dict, group_dict, alert, alert_context, intcid, aid, discovered_ip_addresses, tables_with_discoveries, all_kql_queries, all_query_results)
            else:
                await process_ip_kql_queries(final_ans_dict, group_dict, alert, alert_context, intcid, aid, discovered_usernames, tables_with_discoveries, all_kql_queries, all_query_results)
        except Exception as e:
            Logger.error(f"Error in group {group_num} KQL/query aggregation: {e}")
            continue
    Logger.info(f"Discovered usernames (global): {discovered_usernames}")
    Logger.info(f"Discovered IP addresses (global): {discovered_ip_addresses}")
    Logger.info(f"Tables with discoveries: {tables_with_discoveries}")
    # Save tables_with_discoveries in state and alert_context
    alert_context["extracted_fields"]["tables_with_discoveries"] = tables_with_discoveries
    if isinstance(alert_context, dict):
        # Place discovered usernames under a new field at alert_context level, grouped by user_name
        if discovered_usernames:
            if alert_context["extracted_fields"]["user_name"]:
                # Check if 'value' exists and convert string to list if needed
                if "value" in alert_context["extracted_fields"]["user_name"]:
                    current_value = alert_context["extracted_fields"]["user_name"]["value"]
                    if isinstance(current_value, str):
                        alert_context["extracted_fields"]["user_name"]["value"] = [current_value]
                    elif not isinstance(current_value, list):
                        alert_context["extracted_fields"]["user_name"]["value"] = []
                    # Add discovered usernames to the list
                    alert_context["extracted_fields"]["user_name"]["value"].extend(discovered_usernames)
                else:
                    alert_context["extracted_fields"]["user_name"]["discovered_usernames"] = discovered_usernames
        # Place discovered IPs under a new field at alert_context level, grouped by source_ip and target_ip
        if discovered_ip_addresses:
            # Ensure 'source_ip' exists and is a dict before assignment
            if "source_ip" not in alert_context["extracted_fields"] or not isinstance(alert_context["extracted_fields"]["source_ip"], dict):
                alert_context["extracted_fields"]["source_ip"] = {}
            # Check if 'value' exists and convert string to list if needed
            if "value" in alert_context["extracted_fields"]["source_ip"]:
                current_value = alert_context["extracted_fields"]["source_ip"]["value"]
                if isinstance(current_value, str):
                    alert_context["extracted_fields"]["source_ip"]["value"] = [current_value]
                elif not isinstance(current_value, list):
                    alert_context["extracted_fields"]["source_ip"]["value"] = []
                # Add discovered IP addresses to the list
                alert_context["extracted_fields"]["source_ip"]["value"].extend(discovered_ip_addresses)
            else:
                alert_context["extracted_fields"]["source_ip"]["discovered_ip_addresses"] = discovered_ip_addresses
            

    return alert_context



def generate_kql_queries(alert, alert_context, final_dict, intcid, aid):
    """
    Generate KQL queries using AIManager's structured output.
    
    Args:
        alert: Alert information
        alert_context: Alert context dictionary
        final_dict: Dictionary containing index names with username and IP fields
        intcid: Interaction customer ID
        aid: Alert ID
    
    Returns:
        List[dict]: List of KQL queries with descriptions and index names
    """
    Logger.info("[QueryGenerator] Generating KQL queries using AIManager structured output")
    
    try:
        # Use AIManager's structured output to generate KQL queries
        kql_response = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="KQL_ALERT_CONTEXT_ENRICHMENT_PROMPT",
            prompt_params={
                "alert": alert,
                "alert_context": alert_context,
                "final_dict": final_dict
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=AlertContextEnrichmentQueryList,
            history_params={
                "aid": aid,
                "subtype": "kql_query_generation",
            },
        )
        
        Logger.info(f"[QueryGenerator] KQL response: {kql_response.get('queries', [])}")
        # Return the list of queries
        return kql_response.get('queries', [])
        
    except Exception as e:
        Logger.error(f"[QueryGenerator] Error generating KQL queries: {e}")
        return []



async def aggregate_query_results(kql_queries: List[Dict[str, Any]], intcid: str, aid: str) -> Dict[str, Any]:
    """
    Executes KQL queries and aggregates the results.

    This function retrieves KQL queries from the state, executes them via a REST API call,
    and stores the results back into the state.

    Args:
        kql_queries (List[Dict[str, Any]]): A list of KQL queries to execute.
        intcid (str): The interaction customer ID.
        aid (str): The alert ID.

    Returns:
        Dict[str, Any]: An updated state dictionary with query results.
    """
    Logger.info("[NODE] Executing node: aggregate_query_results")
    
    if not kql_queries:
        Logger.warn("No KQL queries found. Skipping execution.")
        return {"query_results": []}
        
    if not intcid:
        Logger.error("Missing 'intcid'. Cannot execute queries.")
        return {"query_results": []}

    # Lazy import to avoid circular dependency
    from app.services.siem.sentinel.tools import sentinel_run_kql_query
    
    query_results = []
    
    for query_details in kql_queries:
        kql_query = query_details.get("query")
        index_name = query_details.get("index_name")
        
        if not kql_query:
            Logger.warn(f"Skipping a query for index '{index_name}' because it is empty.")
            continue

        response = await sentinel_run_kql_query(
            intcid=intcid,
            task="Run the Alert Context Enrichment KQL query",
            kql_query=kql_query
        )

        try:
            Logger.info(f"Executing KQL query for index: {index_name}")
            Logger.debug(f"Query: {kql_query}")            
            Logger.info(f"Successfully executed query for index: {index_name}")
            Logger.debug(f"Response: {response}")
            query_results.append({
                "index_name": index_name,
                "query": kql_query,
                "result": response,
                "status": "success"
            })
        

        except Exception as e:
            Logger.error(f"An exception occurred while executing query for index {index_name}: {e}")
            query_results.append({
                "index_name": index_name,
                "query": kql_query,
                "error": str(e),
                "status": "failure"
            })
            
    Logger.info(f"Finished executing all queries. Total results: {query_results}")
    return {"query_results": query_results}
















