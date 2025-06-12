"""OpenSearch Utils"""

from azure.identity import ClientSecretCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
import requests
import json
import traceback
import re  # Import regex for checking limit patterns
from datetime import datetime, timezone
import collections
from pltfrm import PropX, Logger2 as Logger, MongoDBManager
from typing import List, Dict, Any

# Removed global property assignments

# Define the list of Log Management tables you are interested in


# --- Time Range for Queries ---
DEFAULT_QUERY_TIME_RANGE = "1h"  # e.g., "5m", "1h", "1d"
# --- KQL Generation Attempts ---
MAX_KQL_GENERATION_ATTEMPTS = 3


class SentinelUtils:
    """Utility class for interacting with Azure Sentinel/Log Analytics."""

    def __init__(self, intcid: str):
        """Initializes the SentinelUtils class."""
        self.intcid = intcid
        self.main_db = PropX.get_property("module.integration.config.db")
        self.integration_db = PropX.get_property("module.integration.config.collection")
        self.toolsmetadata_db = PropX.get_property(
            "module.integration.metadata.collection"
        )
        self.trenchrecords_db = PropX.get_property(
            "module.trenchrun.collection"
        )
        self.templates_db = PropX.get_property("module.templates.collection")
        config = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration_db,
            {
                "intcid": self.intcid,
                "type": "siem",
                "vendor": "sentinel",
                "recordType": "investigation",
            },
        )

        tables = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.templates_db,
            {"type": "tables", "subtype": "sentinel-tables"},
        )
        self.tenant_id = None
        self.client_id = None
        self.client_secret = None
        self.subscription_id = None
        self.resource_group_name = None
        self.workspace_name = None
        self.workspace_id_from_config = (
            None  # Store workspace_id from config separately if needed
        )
        self.mgmt_api_version = "2022-10-01"

        if config:
            self.tenant_id = config.get("tenant_id")
            self.client_id = config.get("client_id")
            self.client_secret = config.get("client_secret")
            self.subscription_id = config.get("subscription_id")
            self.resource_group_name = config.get(
                "resource_grp_name"
            )  # Note the key name difference
            self.workspace_name = config.get("workspace_name")
            self.workspace_id_from_config = config.get(
                "workspace_id"
            )  # Store the one from config
            Logger.debug(f"Loaded Sentinel configuration for tenant: {self.tenant_id}")
        else:
            Logger.error("Failed to load Sentinel configuration from MongoDB.")
            # Handle the case where config is not found - perhaps raise an exception or set a failure state
        if tables:
            self.log_tables = tables.get("log_tables")
            Logger.debug(f"Loaded Sentinel log tables: {self.log_tables}")
        # Initialize tokens to None
        self.mgmt_access_token = None
        self.la_access_token = None
        self.workspace_id = self.workspace_id_from_config
        Logger.debug("SentinelUtils initialized.")

    def authenticate(self):
        """Authenticates using Client Secret and stores tokens."""
        try:
            # Use instance variables fetched during __init__
            if not all([self.tenant_id, self.client_id, self.client_secret]):
                Logger.error(
                    "Missing one or more authentication properties (tenant_id, client_id, client_secret) from configuration."
                )
                return False

            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            self.mgmt_access_token = credential.get_token(
                "https://management.azure.com/.default"
            )
            self.la_access_token = credential.get_token(
                "https://api.loganalytics.io/.default"
            )
            Logger.debug("Successfully obtained and stored Azure access tokens.")
            return True
        except ClientAuthenticationError as e:
            Logger.error(f"Error during authentication: {e}")
            self.mgmt_access_token = None
            self.la_access_token = None
            return False
        except Exception as e:
            Logger.error(f"An unexpected error occurred during authentication: {e}")
            self.mgmt_access_token = None
            self.la_access_token = None
            return False

    def get_workspace_id(self):
        """Retrieves and stores the Log Analytics Workspace ID (customerId)."""
        if self.workspace_id:  # Return cached value if already fetched
            return self.workspace_id
        if not self.mgmt_access_token:
            Logger.error(
                "Authentication required before getting workspace ID. Call authenticate() first."
            )
            return None

        # Use instance variables
        if not all(
            [
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                self.mgmt_api_version,
            ]
        ):
            Logger.error(
                "Missing one or more workspace properties (subscription_id, resource_group_name, workspace_name, mgmt_api_version) from configuration."
            )
            return None

        workspace_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}?api-version={self.mgmt_api_version}"
        )
        mgmt_headers = {
            "Authorization": f"Bearer {self.mgmt_access_token.token}",
            "Content-Type": "application/json",
        }
        Logger.debug(f"Getting Workspace ID from: {workspace_url}")
        try:
            response = requests.get(workspace_url, headers=mgmt_headers, timeout=20)
            response.raise_for_status()
            workspace_data = response.json()
            self.workspace_id = workspace_data.get("properties", {}).get("customerId")
            if not self.workspace_id:
                Logger.error("Could not retrieve Workspace ID (customerId) via API.")
                return None
            Logger.debug(f"Found and stored Workspace ID via API: {self.workspace_id}")
            # Compare with config value if desired
            if (
                self.workspace_id_from_config
                and self.workspace_id != self.workspace_id_from_config
            ):
                Logger.warn(
                    f"API Workspace ID ({self.workspace_id}) differs from config Workspace ID ({self.workspace_id_from_config}). Using API value."
                )
            return self.workspace_id
        except requests.exceptions.RequestException as e:
            Logger.error(f"HTTP error getting workspace details: {e}")
            if hasattr(e, "response") and e.response is not None:
                Logger.error(f"Response Status Code: {e.response.status_code}")
                try:
                    Logger.error(f"Response Body: {e.response.json()}")
                except ValueError:
                    Logger.error(f"Response Body: {e.response.text}")
            self.workspace_id = None
            return None
        except Exception as e:
            Logger.error(f"Unexpected error getting workspace details: {e}")
            self.workspace_id = None
            return None

    def list_all_rules(self):
        if not self.mgmt_access_token:
            Logger.error(
                "Authentication required before listing tables. Call authenticate() first."
            )
            return False, "Authentication error: no access token available."

        # Use instance variables
        if not all(
            [
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                self.mgmt_api_version,
            ]
        ):
            Logger.error(
                "Missing one or more workspace properties (subscription_id, resource_group_name, workspace_name, mgmt_api_version) from configuration."
            )
            return False, "Configuration error: missing workspace properties."

        # Use a supported API version specifically for alert rules
        alert_rules_api_version = (
            "2023-11-01"  # Using one of the supported versions from the error message
        )

        alert_rules_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights"
            f"/alertRules?api-version={alert_rules_api_version}"
        )
        mgmt_headers = {
            "Authorization": f"Bearer {self.mgmt_access_token.token}",
            "Content-Type": "application/json",
        }
        Logger.debug(f"Calling REST API URL to list rules: {alert_rules_url}")
        try:
            response = requests.get(alert_rules_url, headers=mgmt_headers)
            response.raise_for_status()
            rules_data = response.json()
            all_rules = rules_data.get("value", [])

            final_rule_list = []
            for rule in all_rules:
                try:
                    rule_name = rule.get("name")
                    rule_id = rule.get("id")
                    rule_type = rule.get("type")
                    rule_kind = rule.get(
                        "kind", "unknown"
                    )  # Default to Scheduled if not present
                    rule_properties = rule.get("properties", {})
                    display_name = rule_properties.get("displayName", "Unknown Rule")
                    description = rule_properties.get(
                        "description", "No description provided"
                    )
                    severity = rule_properties.get("severity", "Unknown")
                    tactics = rule_properties.get("tactics", [])
                    techniques = rule_properties.get("techniques", [])
                    enabled = rule_properties.get("enabled", False)
                    last_modified_time = rule_properties.get(
                        "lastModifiedUtc", "Unknown"
                    )

                    rule_record = {
                        "rule_name": rule_name,
                        "rule_id": rule_id,
                        "rule_type": rule_type,
                        "display_name": display_name,
                        "description": description,
                        "severity": severity,
                        "tactics": tactics,
                        "techniques": techniques,
                        "enabled": enabled,
                        "last_modified_time": last_modified_time,
                        "kind": rule_kind,
                    }

                    if rule_kind == "Scheduled":
                        # For Scheduled rules, we can extract the query
                        query = rule_properties.get("query", "")
                        query_frequency = rule_properties.get(
                            "queryFrequency", "Unknown"
                        )
                        query_period = rule_properties.get("queryPeriod", "Unknown")

                        rule_record.update(
                            {
                                "query": query,
                                "query_frequency": query_frequency,
                                "query_period": query_period,
                            }
                        )

                    final_rule_list.append(rule_record)
                except Exception as e:
                    Logger.error(
                        f"Error processing rule {rule.get('name', 'Unknown')}: {e}"
                    )
                    Logger.debug(traceback.format_exc())

            Logger.debug(f"Successfully listed {len(final_rule_list)} rules.")
            return True, final_rule_list
        except requests.exceptions.RequestException as e:
            Logger.error(f"HTTP error listing tables: {e}")
            if hasattr(e, "response") and e.response is not None:
                Logger.error(f"Response Status Code: {e.response.status_code}")
                try:
                    Logger.error(f"Response Body: {e.response.json()}")
                except ValueError:
                    Logger.error(f"Response Body: {e.response.text}")
            return False, "Request exception occurred while listing rules."
        except Exception as e:
            Logger.error(f"Unexpected error listing tables: {e}")
            return False, "Unexpected error occurred while listing rules."

    def list_all_tables(self):
        """Lists all tables in the workspace via the Management API."""
        if not self.mgmt_access_token:
            Logger.error(
                "Authentication required before listing tables. Call authenticate() first."
            )
            return None

        # Use instance variables
        if not all(
            [
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                self.mgmt_api_version,
            ]
        ):
            Logger.error(
                "Missing one or more workspace properties (subscription_id, resource_group_name, workspace_name, mgmt_api_version) from configuration."
            )
            return None

        list_tables_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}/tables?api-version={self.mgmt_api_version}"
        )
        mgmt_headers = {
            "Authorization": f"Bearer {self.mgmt_access_token.token}",
            "Content-Type": "application/json",
        }
        Logger.debug(f"Calling REST API URL to list tables: {list_tables_url}")
        try:
            response = requests.get(list_tables_url, headers=mgmt_headers)
            response.raise_for_status()
            response_data = response.json()
            all_tables_raw = response_data.get("value", [])
            Logger.debug(f"Successfully listed {len(all_tables_raw)} raw tables.")
            return all_tables_raw
        except requests.exceptions.RequestException as e:
            Logger.error(f"HTTP error listing tables: {e}")
            if hasattr(e, "response") and e.response is not None:
                Logger.error(f"Response Status Code: {e.response.status_code}")
                try:
                    Logger.error(f"Response Body: {e.response.json()}")
                except ValueError:
                    Logger.error(f"Response Body: {e.response.text}")
            return None
        except Exception as e:
            Logger.error(f"Unexpected error listing tables: {e}")
            return None

    def get_table_row_count(self, table_name):
        query_api_version = "v1"
        query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{self.workspace_id}/query"
        la_headers = {
            "Authorization": f"Bearer {self.la_access_token.token}",
            "Content-Type": "application/json",
        }

        try:
            kql_query = f"{table_name} | count"
            query_payload = json.dumps({"query": kql_query})
            query_response = requests.post(
                query_url, headers=la_headers, data=query_payload, timeout=20
            )
            query_response.raise_for_status()
            query_result = query_response.json()

            count = 0
            if (
                query_result.get("tables")
                and len(query_result["tables"]) > 0
                and query_result["tables"][0].get("rows")
                and len(query_result["tables"][0]["rows"]) > 0
                and len(query_result["tables"][0]["rows"][0]) > 0
            ):
                count = query_result["tables"][0]["rows"][0][0]
                return True, count, ""
        except requests.exceptions.Timeout:
            Logger.warn(
                f"Timeout occurred while querying count for table '{table_name}'."
            )
            return False, 0, "Timeout occurred."
        except requests.exceptions.RequestException as qe:
            Logger.warn(f"Could not query count for table '{table_name}'. Error: {qe}")
            if hasattr(qe, "response") and qe.response is not None:
                try:
                    Logger.warn(f"Query Error Details: {qe.response.json()}")
                except ValueError:
                    Logger.warn(f"Query Error Details: {qe.response.text}")
            return False, 0, str(qe)
        except (json.JSONDecodeError, KeyError, TypeError, IndexError) as qe_other:
            Logger.warn(
                f"Unexpected error processing count result for table '{table_name}': {qe_other}"
            )
            return False, 0, str(qe_other)

    def list_all_tables_with_columns(self):
        """Lists all tables in the workspace via the Management API."""
        if not self.mgmt_access_token:
            Logger.error(
                "Authentication required before listing tables. Call authenticate() first."
            )
            return None

        # Use instance variables
        if not all(
            [
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                self.mgmt_api_version,
            ]
        ):
            Logger.error(
                "Missing one or more workspace properties (subscription_id, resource_group_name, workspace_name, mgmt_api_version) from configuration."
            )
            return None

        list_tables_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}/tables?api-version={self.mgmt_api_version}"
        )
        mgmt_headers = {
            "Authorization": f"Bearer {self.mgmt_access_token.token}",
            "Content-Type": "application/json",
        }
        Logger.debug(f"Calling REST API URL to list tables: {list_tables_url}")
        try:
            response = requests.get(list_tables_url, headers=mgmt_headers)
            response.raise_for_status()
            response_data = response.json()
            all_tables_raw = response_data.get("value", [])
            Logger.debug(f"Successfully listed {len(all_tables_raw)} raw tables.")

            response_data = []
            for table_raw in all_tables_raw:
                table_name = table_raw.get("name")
                solutions = table_raw.get("properties", {}).get("solutions", [])
                response_table = {
                    "table_name": table_name,
                    "solutions": solutions,
                    "columns": [],
                }
                columns = []
                schema_info = table_raw.get("properties", {}).get("schema", {})
                if schema_info:
                    # Handle potential variations in schema structure
                    column_list = schema_info.get("columns", []) or schema_info.get(
                        "standardColumns", []
                    )
                    for col in column_list:
                        col_name = col.get("name")
                        if col_name:
                            columns.append(col_name)

                    response_table["columns"] = sorted(columns)
                    Logger.debug(f"Successfully fetched schema for '{table_name}'.")
                    response_data.append(response_table)
            return response_data
        except requests.exceptions.RequestException as e:
            Logger.error(f"HTTP error listing tables: {e}")
            if hasattr(e, "response") and e.response is not None:
                Logger.error(f"Response Status Code: {e.response.status_code}")
                try:
                    Logger.error(f"Response Body: {e.response.json()}")
                except ValueError:
                    Logger.error(f"Response Body: {e.response.text}")
            return None
        except Exception as e:
            Logger.error(f"Unexpected error listing tables: {e}")
            return None

    def get_table_schema(self, table_name):
        """Fetches the schema for a specific table."""
        if not self.mgmt_access_token:
            Logger.error(
                "Authentication required before getting table schema. Call authenticate() first."
            )
            return False, "<Authentication error>"

        # Use instance variables
        if not all(
            [
                self.subscription_id,
                self.resource_group_name,
                self.workspace_name,
                self.mgmt_api_version,
            ]
        ):
            Logger.error(
                "Missing one or more workspace properties (subscription_id, resource_group_name, workspace_name, mgmt_api_version) from configuration."
            )
            return False, "<Schema retrieval configuration error>"

        schema_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}/tables/{table_name}?api-version={self.mgmt_api_version}"
        )
        mgmt_headers = {
            "Authorization": f"Bearer {self.mgmt_access_token.token}",
            "Content-Type": "application/json",
        }
        try:
            schema_response = requests.get(schema_url, headers=mgmt_headers)
            schema_response.raise_for_status()
            schema_data = schema_response.json()
            columns = []
            schema_info = schema_data.get("properties", {}).get("schema", {})
            if schema_info:
                # Handle potential variations in schema structure
                column_list = schema_info.get("columns", []) or schema_info.get(
                    "standardColumns", []
                )
                for col in column_list:
                    col_name = col.get("name")
                    if col_name:
                        columns.append(col_name)
            if columns:
                Logger.debug(f"Successfully fetched schema for '{table_name}'.")
                return True, sorted(columns)
            else:
                Logger.warn(
                    f"Could not extract column names for table '{table_name}' from schema response."
                )
                return False, "<Schema retrieval failed>"
        except requests.exceptions.RequestException as se:
            Logger.warn(
                f"HTTP error fetching schema for table '{table_name}'. Error: {se}"
            )
            # Optionally log response details
            if hasattr(se, "response") and se.response is not None:
                Logger.warn(f"Response Status Code: {se.response.status_code}")
                try:
                    Logger.warn(f"Response Body: {se.response.json()}")
                except ValueError:
                    Logger.warn(f"Response Body: {se.response.text}")
            return False, "<Schema retrieval HTTP error>"
        except Exception as se_other:
            Logger.warn(
                f"Unexpected error fetching schema for table '{table_name}'. Error: {se_other}"
            )
            return False, "<Schema retrieval unexpected error>"

    def get_table_metadata(self, intcid, table_name):

        Logger.debug(f"get_table_metadata for intcid: {intcid}, table: {table_name}")
        query = {
            "intcid": intcid,
            "type": "siem",
            "vendor": "sentinel",
            "subtype": "field_list",
            "index_name": table_name,
        }

        table_metadata_collection = MongoDBManager.get_record_by_multiple_fields(
            self.main_db, self.toolsmetadata_db, query
        )
        if table_metadata_collection:
            # Check if the collection has the expected structure
            if "fields" in table_metadata_collection:
                Logger.debug(f"Found table metadata for '{table_name}' in MongoDB.")
                fields = table_metadata_collection["fields"]
                return fields
            else:
                Logger.warn(
                    f"Table metadata for '{table_name}' does not contain 'fields' key. Returning empty list."
                )
                return []

    def get_table_list(self, intcid):
        query = {
            "intcid": intcid,
            "type": "siem",
            "vendor": "sentinel",
            "subtype": "index_list",
        }
        table_list_collection = MongoDBManager.get_record_by_multiple_fields(
            self.main_db, self.toolsmetadata_db, query
        )
        if table_list_collection:
            return table_list_collection["indices"]
        else:
            return []

    def validate_sentinel_kql(
        self, kql_query: str, intcid: str
    ) -> tuple[bool, str | None]:
        """Validates the syntax of a KQL query using the Log Analytics API.

        Args:
            kql_query: The KQL query string to validate.
            intcid: Integration/Customer ID (for logging).

        Returns:
            A tuple: (True, None) if the query syntax appears valid (API returns 200).
                     (False, error_message) otherwise, where error_message provides details.
        """
        if not self.la_access_token or not self.workspace_id:
            msg = f"{intcid}: Cannot validate KQL, not authenticated or workspace ID missing."
            Logger.error(msg)
            return False, msg

        # Optional: Modify query to minimize execution impact, e.g., append "| take 0"
        # This forces parsing without returning data. Be careful if the original query
        # already has operators like count, summarize etc. A simple check might be needed.
        # validation_query = kql_query.strip()
        # if not validation_query.endswith(("take 0", "count")): # Basic check
        #     validation_query += " | take 0"
        # For simplicity here, we run the original query, relying on API errors for syntax.

        validation_query = kql_query  # Use original query for now

        query_api_version = "v1"  # Or fetch from config
        query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{self.workspace_id}/query"
        headers = {
            "Authorization": f"Bearer {self.la_access_token.token}",
            "Content-Type": "application/json",
            # Add a short timeout preference if desired, though timeout usually indicates service issues, not syntax.
            # "Prefer": "wait=10"
        }
        payload = json.dumps({"query": validation_query})

        Logger.debug(f"{intcid}: Attempting to validate KQL syntax: {validation_query}")

        try:
            # Use a short timeout for validation
            response = requests.post(
                query_url, headers=headers, data=payload, timeout=15
            )

            # Check status code
            if response.status_code == 200:
                Logger.info(
                    f"{intcid}: KQL syntax appears valid (API returned 200 OK)."
                )
                return True, "Valid syntax"
            elif response.status_code == 400:
                # Bad Request likely indicates a syntax error
                error_details = "Unknown syntax error"
                try:
                    error_content = response.json()
                    # Extract the specific error message if available
                    error_details = error_content.get("error", {}).get(
                        "message", response.text
                    )
                    # More specific inner error might be present
                    inner_error = (
                        error_content.get("error", {})
                        .get("innererror", {})
                        .get("message")
                    )
                    if inner_error:
                        error_details = f"{error_details} (Inner Error: {inner_error})"
                except ValueError:
                    error_details = response.text
                Logger.warn(
                    f"{intcid}: KQL syntax validation failed (API returned 400 Bad Request). Query: {kql_query}. Error: {error_details}"
                )
                return False, f"Syntax Error: {error_details}"
            else:
                # Other errors (401, 403, 5xx) indicate other problems (auth, permissions, server issue)
                msg = f"KQL validation check encountered an unexpected HTTP status {response.status_code}. Response: {response.text}"
                Logger.warn(f"{intcid}: {msg}. Query: {kql_query}")
                return False, msg  # Treat other errors as validation failure for safety

        except requests.exceptions.Timeout:
            msg = f"Timeout occurred during KQL syntax validation."
            Logger.warn(f"{intcid}: {msg} Query: {kql_query}")
            return (
                False,
                msg,
            )  # Timeout doesn't strictly mean invalid syntax, but treat as failure
        except requests.exceptions.RequestException as e:
            msg = f"Network or request error during KQL validation: {e}."
            Logger.error(f"{intcid}: {msg} Query: {kql_query}")
            return False, msg
        except Exception as e:
            msg = f"Unexpected error during KQL validation: {e}."
            Logger.error(f"{intcid}: {msg} Query: {kql_query}")
            return False, msg

    def push_kql_template_data_to_mongo(
        self,
        intcid: str,
        siem_type: str,
        env: str,
        tid: str,
        question_id: str,
        step_id: str,
        triage_question: str,  # Original question text from tools.py call
        requirement: str,  # The 'task' or requirement driving the query from tools.py call
        table_name: str,
        query_template: str,
        final_query: str,
    ):
        """
        Saves or updates the generated KQL query template and final query
        along with metadata to MongoDB, following the Wazuh utils pattern.

        Args:
            intcid: Integration/Customer ID.
            siem_type: Type of SIEM ("sentinel").
            env: Environment identifier.
            tid: Triage ID.
            question_id: Question ID within the triage.
            triage_question: The original text of the triage question.
            requirement: The specific requirement or task for the query from tools.py call
            table_name: The target Sentinel table name.
            query_template: The generated KQL template (before value replacement).
            final_query: The final, executable KQL query.
        """
        if not all(
            [
                intcid,
                tid,
                question_id,
                step_id,
                table_name,
                requirement,
                query_template,
                final_query,
            ]
        ):
            Logger.warn(
                "Missing required fields for persisting KQL template data. Skipping."
            )
            return

        try:
            # Define filter similar to Wazuh, mapping Sentinel concepts
            # Note: Wazuh filter used 'questions_id', using 'question_id' for consistency.
            # Added table_name and requirement to filter for better uniqueness than Wazuh example.
            filter_doc = {
                "type": "query_template",
                "intcid": intcid,
                "vendor": siem_type,  # Use siem_type as vendor
                "tid": tid,
                "question_id": question_id,  # Corrected key name
                "step_id": step_id,  # Added for context
                "env": env,
                "table_name": table_name,  # Added for Sentinel context uniqueness
                "requirement": requirement,  # Added for Sentinel context uniqueness
            }

            # Define the document structure similar to Wazuh
            document = {
                "type": "query_template",
                "triage_question": triage_question,  # Use the passed triage_question
                "task": requirement,  # Map requirement to 'task' field like Wazuh
                "intcid": intcid,
                "vendor": siem_type,  # Map siem_type to 'vendor' field
                "tid": tid,
                "question_id": question_id,
                "step_id": step_id,  # Added for context
                "index_name": table_name,  # Map table_name to 'index_name' field
                "env": env,
                "query_template": query_template,  # Map KQL template
                "query": final_query,  # Map final KQL query
                # Add timestamp (optional, but good practice)
                "updated_at": datetime.now(timezone.utc),
                # MongoDBManager.upsert_record might handle created_at via $setOnInsert
            }

            # Get DB and Collection names from PropX configuration
            # Ensure these property keys exist in your configuration
            main_db = PropX.get_property("module.integration.config.db")
            query_template_collection = PropX.get_property(
                "module.query.template.cache.collection"
            )

            if not main_db or not query_template_collection:
                Logger.error(
                    "MongoDB database or collection name not configured in PropX (module.integration.config.db / module.query.template.cache.collection). Cannot persist KQL data."
                )
                return

            # Call the upsert method from MongoDBManager
            # Assumes MongoDBManager.upsert_record(db_name, collection_name, filter_dict, update_dict) signature
            MongoDBManager.upsert_record(
                main_db, query_template_collection, filter_doc, document
            )

            # Log success (assuming upsert_record doesn't raise an error on failure)
            Logger.info(
                f"Upserted KQL template data to MongoDB for {intcid}/{tid}/{question_id}/{table_name}."
            )

        except Exception as e:
            Logger.error(
                f"Failed to push KQL template data to MongoDB for {intcid}/{tid}/{question_id}: {e}\n{traceback.format_exc()}"
            )

    def get_kql_template_data_from_mongo(
        self,
        intcid: str,
        env: str,
        tid: str,
        question_id: str,
        step_id: str,
    ):
        """
        Saves or updates the generated KQL query template and final query
        along with metadata to MongoDB, following the Wazuh utils pattern.

        Args:
            intcid: Integration/Customer ID.
            siem_type: Type of SIEM ("sentinel").
            env: Environment identifier.
            tid: Triage ID.
            question_id: Question ID within the triage.
            triage_question: The original text of the triage question.
            requirement: The specific requirement or task for the query.
            table_name: The target Sentinel table name.
            query_template: The generated KQL template (before value replacement).
            final_query: The final, executable KQL query.
        """
        if not all([intcid, tid, question_id, step_id, env]):
            Logger.warn(
                "Missing required fields for persisting KQL template data. Skipping."
            )
            return None

        try:
            # Define filter similar to Wazuh, mapping Sentinel concepts
            # Note: Wazuh filter used 'questions_id', using 'question_id' for consistency.
            # Added table_name and requirement to filter for better uniqueness than Wazuh example.
            filter_doc = {
                "type": "query_template",
                "intcid": intcid,
                "vendor": "sentinel",  # Use siem_type as vendor
                "tid": tid,
                "question_id": question_id,  # Corrected key name
                "step_id": step_id,  # Added for context
                "env": env,
            }

            # Get DB and Collection names from PropX configuration
            # Ensure these property keys exist in your configuration
            main_db = PropX.get_property("module.integration.config.db")
            query_template_collection = PropX.get_property(
                "module.query.template.cache.collection"
            )

            if not main_db or not query_template_collection:
                Logger.error(
                    "MongoDB database or collection name not configured in PropX (module.integration.config.db / module.query.template.cache.collection). Cannot get KQL data."
                )
                return None

            # Call the upsert method from MongoDBManager
            # Assumes MongoDBManager.upsert_record(db_name, collection_name, filter_dict, update_dict) signature
            record = MongoDBManager.get_record_by_multiple_fields(
                main_db, query_template_collection, filter_doc
            )
            if record:
                # Check if the collection has the expected structure
                if "query_template" in record:
                    Logger.debug(
                        f"Found KQL template data for '{intcid}/{tid}/{question_id}' in MongoDB."
                    )
                    return record["query_template"]
                else:
                    Logger.warn(
                        f"KQL template data for '{intcid}/{tid}/{question_id}' does not contain 'query_template' key. Returning None."
                    )
                    return None
        except Exception as e:
            Logger.error(
                f"Failed to push KQL template data to MongoDB for {intcid}/{tid}/{question_id}: {e}\n{traceback.format_exc()}"
            )
            return None

    def push_table_name_to_mongo(
        self, intcid, vendor, env, tid, question_id, step_id, requirement, index_name
    ):
        filter = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "env": env,
        }

        document = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "env": env,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "step_question": requirement,
            "index_name": index_name,
        }
        main_db = self.main_db
        query_template_collection = PropX.get_property(
            "module.query.template.cache.collection"
        )
        MongoDBManager.upsert_record(
            main_db, query_template_collection, filter, document
        )

    def get_table_name_from_mongo(self, intcid, vendor, env, tid, question_id, step_id):
        filter = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "env": env,
        }

        main_db = self.main_db
        query_template_collection = PropX.get_property(
            "module.query.template.cache.collection"
        )
        record = MongoDBManager.get_record_by_multiple_fields(
            main_db, query_template_collection, filter
        )
        if record:
            index_name = record.get("index_name")
            if index_name:
                Logger.debug(
                    f"Found table name '{index_name}' for intcid: {intcid}, vendor: {vendor}, tid: {tid}, question_id: {question_id}, step_id: {step_id}."
                )
                return index_name
            else:
                Logger.warn(
                    f"No index name found in MongoDB record for intcid: {intcid}, vendor: {vendor}, tid: {tid}, question_id: {question_id}, step_id: {step_id}."
                )

        return None

    def get_single_matching_record(
        self, intcid: str, table_name: str, kql_query: str
    ) -> dict:
        """
        Executes a KQL query expected to return one record and fetches it.

        Appends '| take 1' to the query if no obvious limiting operator is found.

        Args:
            intcid: Integration/Customer ID (for logging).
            table_name: The target Sentinel table (primarily for logging context).
            kql_query: The KQL query string.

        Returns:
            A dictionary containing the single matching record under the key 'matching_record'.
            Returns an empty dictionary if no match is found by the query.
            Returns an error dictionary on failure.
            Example success: {"matching_record": {"TimeGenerated": ..., "ColumnA": ...}}
            Example no match: {"matching_record": {}}
            Example error: {"error": "Authentication failed."}
        """
        Logger.info(
            f"get_single_matching_record for intcid: {intcid}, table: {table_name}"
        )
        Logger.debug(f"Input KQL: {kql_query}")

        if not self.la_access_token or not self.workspace_id:
            Logger.error(
                f"{intcid}: Cannot get single record, not authenticated or workspace ID missing."
            )
            return {"error": "Authentication failed or workspace ID missing."}

        # --- Ensure Query Limits to 1 Record ---
        # Append '| take 1' if the query doesn't seem to limit results already.
        # This is a basic check and might need refinement for complex queries.
        modified_kql = kql_query.strip()
        query_lower = modified_kql.lower()
        # Check for common limiting or aggregation patterns
        if (
            not query_lower.endswith("| take 1")
            and not query_lower.endswith("| limit 1")
            and "| count" not in query_lower
            and "| summarize" not in query_lower
        ):
            modified_kql += " | take 1"
            Logger.debug(f"Appended '| take 1' to query. Modified KQL: {modified_kql}")
        else:
            Logger.debug(
                f"Query likely already limits results or is aggregate. Using as-is: {modified_kql}"
            )

        # --- Prepare and Execute API Call ---
        query_api_version = "v1"
        query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{self.workspace_id}/query"
        headers = {
            "Authorization": f"Bearer {self.la_access_token.token}",
            "Content-Type": "application/json",
        }
        payload = json.dumps({"query": modified_kql})

        matching_record = {}
        try:
            response = requests.post(
                query_url, headers=headers, data=payload, timeout=30
            )  # Adjust timeout as needed
            response.raise_for_status()
            query_result = response.json()

            # --- Process Results ---
            if (
                query_result.get("tables")
                and len(query_result["tables"]) > 0
                and query_result["tables"][0].get("rows")
                and len(query_result["tables"][0]["rows"])
                > 0  # Check if rows list is not empty
            ):
                primary_table = query_result["tables"][0]
                columns = [col["name"] for col in primary_table.get("columns", [])]
                # Get the first (and likely only) row
                row = primary_table.get("rows", [])[0]
                matching_record = dict(zip(columns, row))
                Logger.info(f"Successfully fetched single record from '{table_name}'.")
            else:
                Logger.info(
                    f"Query executed successfully but returned no records for single record fetch. Query: {modified_kql}"
                )
                # Return empty dict for matching_record, not an error

        except requests.exceptions.Timeout:
            Logger.warn(
                f"{intcid}: Timeout occurred while fetching single record from '{table_name}'. Query: {modified_kql}"
            )
            return {"error": "Query execution timed out."}
        except requests.exceptions.HTTPError as http_err:
            Logger.error(
                f"{intcid}: HTTP error occurred while fetching single record: {http_err}"
            )
            error_details = ""
            try:
                error_content = http_err.response.json()
                error_details = error_content.get("error", {}).get(
                    "message", http_err.response.text
                )
            except ValueError:
                error_details = http_err.response.text
            return {
                "error": f"Query execution failed with HTTP status {http_err.response.status_code}. Details: {error_details}",
                "failed_query": modified_kql,
            }
        except requests.exceptions.RequestException as req_err:
            Logger.error(
                f"{intcid}: Request error occurred while fetching single record: {req_err}"
            )
            return {
                "error": f"Network or request error during query execution: {req_err}"
            }
        except Exception as e:
            Logger.error(
                f"{intcid}: An unexpected error occurred fetching single record: {e}\n{traceback.format_exc()}"
            )
            return {
                "error": f"An unexpected error occurred during query execution: {e}"
            }

        # --- Return Result ---
        return {"matching_record": matching_record}

    def get_matching_records(
        self, intcid: str, table_name: str, kql_query: str, limit: int = 5
    ) -> dict:
        """
        Executes a KQL query and fetches a limited number of matching records.

        Appends '| take <limit>' to the query if no obvious limiting operator or aggregation is found.

        Args:
            intcid: Integration/Customer ID (for logging).
            table_name: The target Sentinel table (primarily for logging context).
            kql_query: The KQL query string.
            limit: The maximum number of records to return (default: 5).

        Returns:
            A dictionary containing a list of matching records under the key 'matching_records'.
            Returns an empty list if no matches are found.
            Returns an error dictionary on failure.
            Example success: {"matching_records": [{...}, {...}]}
            Example no match: {"matching_records": []}
            Example error: {"error": "Authentication failed."}
        """
        Logger.info(
            f"get_matching_records for intcid: {intcid}, table: {table_name}, limit: {limit}"
        )
        Logger.debug(f"Input KQL: {kql_query}")

        if not self.la_access_token or not self.workspace_id:
            Logger.error(
                f"{intcid}: Cannot get matching records, not authenticated or workspace ID missing."
            )
            return {"error": "Authentication failed or workspace ID missing."}

        # --- Ensure Query Limits Results ---
        modified_kql = kql_query.strip()
        query_lower = modified_kql.lower()
        # Check for common limiting or aggregation patterns using regex
        limit_pattern = r"\|\s*(take|limit)\s+\d+"
        if (
            not re.search(limit_pattern, query_lower)
            and "| count" not in query_lower
            and "| summarize" not in query_lower
        ):
            modified_kql += f" | take {limit}"
            Logger.debug(
                f"Appended '| take {limit}' to query. Modified KQL: {modified_kql}"
            )
        else:
            Logger.debug(
                f"Query likely already limits results or is aggregate. Using as-is: {modified_kql}"
            )

        # --- Prepare and Execute API Call ---
        query_api_version = "v1"
        query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{self.workspace_id}/query"
        headers = {
            "Authorization": f"Bearer {self.la_access_token.token}",
            "Content-Type": "application/json",
        }
        payload = json.dumps({"query": modified_kql})

        all_records = []
        try:
            response = requests.post(
                query_url, headers=headers, data=payload, timeout=60
            )  # Use a reasonable timeout
            response.raise_for_status()
            query_result = response.json()

            # --- Process Results ---
            if (
                query_result.get("tables")
                and len(query_result["tables"]) > 0
                and query_result["tables"][0].get("rows")
            ):
                primary_table = query_result["tables"][0]
                columns = [col["name"] for col in primary_table.get("columns", [])]
                rows = primary_table.get("rows", [])
                if rows:
                    Logger.info(
                        f"Query returned {len(rows)} records (limit was {limit})."
                    )
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
                f"{intcid}: Timeout occurred while fetching matching records from '{table_name}'. Query: {modified_kql}"
            )
            return {"error": "Query execution timed out."}
        except requests.exceptions.HTTPError as http_err:
            Logger.error(
                f"{intcid}: HTTP error occurred while fetching matching records: {http_err}"
            )
            error_details = ""
            try:
                error_content = http_err.response.json()
                error_details = error_content.get("error", {}).get(
                    "message", http_err.response.text
                )
            except ValueError:
                error_details = http_err.response.text
            return {
                "error": f"Query execution failed with HTTP status {http_err.response.status_code}. Details: {error_details}",
                "failed_query": modified_kql,
            }
        except requests.exceptions.RequestException as req_err:
            Logger.error(
                f"{intcid}: Request error occurred while fetching matching records: {req_err}"
            )
            return {
                "error": f"Network or request error during query execution: {req_err}"
            }
        except Exception as e:
            Logger.error(
                f"{intcid}: An unexpected error occurred fetching matching records: {e}\n{traceback.format_exc()}"
            )
            return {
                "error": f"An unexpected error occurred during query execution: {e}"
            }

        # --- Return Result ---
        return {"matching_records": all_records}

    def sanitize_json_response(self, input_string, context=""):
        """
        Extracts and parses the first JSON object found in the input string.

        Args:
            input_string (str): The string containing JSON data.

        Returns:
            dict: The parsed JSON object.

        Raises:
            ValueError: If no valid JSON is found or parsing fails.
        """
        Logger.info(f"Starting extract_and_parse_json : {context} : {input_string}")
        # Find the positions of the first '{' and the last '}'
        start_pos = input_string.find("{")
        end_pos = input_string.rfind("}") + 1  # +1 to include the '}'

        if start_pos == -1 or end_pos == -1:
            Logger.error("No valid JSON found in the string")
            raise ValueError("No valid JSON found in the string")

        # Extract the substring that contains the JSON
        json_string = input_string[start_pos:end_pos]

        try:
            # Parse the JSON string
            json_object = json.loads(json_string)
            Logger.info("Successfully parsed JSON")
            return json_object
        except json.JSONDecodeError as e:
            Logger.error(f"Failed to parse JSON: {e}")
            raise ValueError(f"Failed to parse JSON: {e}")

    def extract_field_placeholders(self, query_template: str) -> list[str]:
        """
        Extracts placeholder keys from <<field.PlaceholderKey>> style placeholders
        in a KQL query template string.

        Args:
            query_template: The KQL query template string.

        Returns:
            A list of extracted placeholder keys (the 'PlaceholderKey' part).
            Returns an empty list if no such placeholders are found.
        """
        # Regex to find <<field.PlaceholderKey>> and capture 'PlaceholderKey'
        # It looks for:
        # - "<<field." literal string (dot is escaped)
        # - Then captures one or more characters that are not ">" (([^>]+)) - this is the PlaceholderKey
        # - Followed by ">>" literal string
        pattern = r"<<field\.([^>]+)>>"

        extracted_keys = re.findall(pattern, query_template)

        return extracted_keys

    def get_sentinel_functions(self):
        
        credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
        )
        log_analytics_client = LogAnalyticsManagementClient(credential, self.subscription_id)
        Logger.info(f"Log_AnalyticsClient: {log_analytics_client}")
        try:
            Logger.info(f"Listing saved searches in Log Analytics workspace: {self.workspace_name}\n")
            saved_searches = log_analytics_client.saved_searches.list_by_workspace(
                resource_group_name=self.resource_group_name,
                workspace_name=self.workspace_name
            )
            Logger.info(f"Saved Searches: {saved_searches}")
            kql_functions = []
            for search in saved_searches.value:
                kql_functions.append({
                    "name": getattr(search, "display_name", None),
                    "alias": getattr(search, "function_alias", None),
                    "category": getattr(search, "category", None),
                    "query": getattr(search, "query", None),
                })
            Logger.info(f"All SavedSearches (with possible KQL functions): {kql_functions}")
            if not kql_functions:
                Logger.info("No KQL functions found based on current criteria.")
        except Exception as e:
            Logger.info(f"An error occurred: {e}")
            return []
        return kql_functions

    #Not in use
    def get_top_matching_tables_using_tags(
        self, intcid: str, tags: list[str]
    ) -> dict:
        """
        Fetches the top matching Sentinel tables based on provided tags.

        Args:
            intcid: Integration/Customer ID (for logging).
            tags: tags dictionary to match against table metadata.
        Returns:
            A dictionary containing a list of matching table names under the key 'matching_tables'.
            Returns an empty list if no matches are found.
            Returns an error dictionary on failure.
            Example success: {"matching_tables": ["Table1", "Table2"]}
            Example no match: {"matching_tables": []}
            Example error: {"error": "Authentication failed."}
        """
        Logger.info(
            f"get_top_matching_tables_using_tags for intcid: {intcid}, tags: {tags}"
        )

        try:
            
            # Defensive: handle MongoDBManager singleton error gracefully
            try:
                tables_list_doc = MongoDBManager.get_record_by_multiple_fields(
                    self.main_db, self.toolsmetadata_db, {"intcid": intcid, "type": "siem", "vendor": "sentinel", "subtype": "index_list"}
                )
            except Exception as e:
                Logger.error(f"Error retrieving matching tables: {e}")
                return {"matching_tables": []}
            tables_list = tables_list_doc.get("indices", []) if tables_list_doc else []
            if not tables_list:
                Logger.info(f"No tables found for intcid: {intcid} with tags: {tags}")
                return {"matching_tables": []}
            Logger.info(f"Fetched tables list for intcid: {intcid}: {tables_list}")

            # --- Begin prioritization logic ---
            tags = tags.get("tags")
            user_log_source = tags.get("log_source")
            user_device_types = set(tags.get("device_type", []))
            user_event_cats = set(tags.get("security_event_category", []))

            first_priority = []
            second_priority = []
            third_priority = []

            for table in tables_list:
                table_log_source = table.get("log_source")
                # Fix: device_type can be a string or a list
                device_type_val = table.get("device_type")
                if isinstance(device_type_val, list):
                    table_device_type = set(device_type_val)
                elif device_type_val:
                    table_device_type = {device_type_val}
                else:
                    table_device_type = set()
                table_tags = set(table.get("tags", []))

                # First priority: all tags match (log_source, any device_type, all event categories)
                matches_log_source = (user_log_source == table_log_source)
                matches_device_type = bool(user_device_types & table_device_type) if user_device_types else True
                matches_event_cats = user_event_cats.issubset(table_tags) if user_event_cats else True
                total_tag_matches = len(user_event_cats & table_tags)

                if matches_log_source and matches_device_type and matches_event_cats:
                    first_priority.append((table, total_tag_matches))
                elif matches_log_source and matches_device_type:
                    second_priority.append((table, total_tag_matches))
                elif matches_log_source:
                    third_priority.append((table, total_tag_matches))

            # Sort each group by number of matching tags (desc), then row_count (desc)
            def sort_key(item):
                table, tag_matches = item
                return (tag_matches, table.get("row_count", 0))

            first_priority_sorted = [t[0] for t in sorted(first_priority, key=sort_key, reverse=True)]
            second_priority_sorted = [t[0] for t in sorted(second_priority, key=sort_key, reverse=True)]
            third_priority_sorted = [t[0] for t in sorted(third_priority, key=sort_key, reverse=True)]

            # Combine results, remove duplicates by index name, and track priority
            seen = set()
            matching_tables = []
            table_priority = {}  # Map index to priority name
            for group, priority_name in zip(
                [first_priority_sorted, second_priority_sorted, third_priority_sorted],
                ["first", "second", "third"]
            ):
                for table in group:
                    idx = table.get("index")
                    if idx and idx not in seen:
                        matching_tables.append(idx)
                        seen.add(idx)
                        table_priority[idx] = priority_name

            # Log priorities along with matching tables
            priority_log = [f"{idx} (priority: {table_priority[idx]})" for idx in matching_tables]
            Logger.info(f"Top matching tables for intcid: {intcid}, tags: {tags}: {priority_log}")
            return {"matching_tables": matching_tables}

        except Exception as e:
            Logger.error(
                f"{intcid}: Error occurred while fetching matching tables using tags: {e}"
            )
            return {"error": f"Error occurred: {str(e)}"}

    def get_relevant_sentinel_tables(self, intcid: str, alert_tags: dict, min_score_threshold: int = 20) -> dict:
        """
        Calculates relevance scores for Sentinel tables based on alert tags using a tiered scoring system
        and returns a sorted dictionary of relevant tables, implementing the new priority.

        Args:
            intcid (str): Integration/Customer ID.
            alert_tags (dict): A dictionary containing 'log_source', 'device_type' (list),
                               and 'security_event_category' (list) from the LLM.
            min_score_threshold (int): Minimum score a table needs to be included in the results.

        Returns:
            dict: A dictionary of relevant tables sorted by score (descending),
                  e.g., {"TableName1": score1, "TableName2": score2}.
                  The returned dict contains a "matching_tables" key with a list of table names.
        """
        table_scores = collections.defaultdict(int)

        # Tiered Scoring Weights - these values define the new strict hierarchy
        TIER_SCORES = {
            "all_three_perfect": 500,        # Highest priority (Log Source + Device Type + Security Event Category)
            "log_source_only_base": 400,     # Second priority (Log Source matched)
            "device_security_only": 300,     # Third priority (Device Type + Security Event Category, without Log Source match)

            # Micro-bonuses for within Log Source only tier, to differentiate
            "log_source_plus_device_type_bonus": 5, # L + D (not S)
            "log_source_plus_security_category_bonus": 10, # L + S (not D)

            # Fallback scores for single matches when no higher tier applies
            "device_type_single_fallback": 20,
            "security_category_single_fallback": 30,
        }

        Logger.info(f"Alert tags for relevance scoring: {alert_tags}")

        # Defensive: Handle nested alert_tags
        parsed_alert_tags = {}
        if isinstance(alert_tags, dict):
            if 'tags' in alert_tags and isinstance(alert_tags['tags'], dict):
                if 'tags' in alert_tags['tags'] and isinstance(alert_tags['tags']['tags'], dict):
                    parsed_alert_tags = alert_tags['tags']['tags']
                else:
                    parsed_alert_tags = alert_tags['tags']
            else:
                parsed_alert_tags = alert_tags
        else:
            Logger.error(f"Expected alert_tags to be dict, got {type(alert_tags)}: {alert_tags}")
            return {"matching_tables": []}

        alert_log_source = parsed_alert_tags.get("log_source", "").lower()
        Logger.debug(f"Alert log source (normalized): {alert_log_source}")
        alert_device_types = [dt.lower() for dt in (parsed_alert_tags.get("device_type", []) if isinstance(parsed_alert_tags.get("device_type", []), list) else [parsed_alert_tags.get("device_type", "")]) if isinstance(dt, str)]
        Logger.debug(f"Alert device types (normalized): {alert_device_types}")
        alert_security_event_categories = [sec.lower() for sec in (parsed_alert_tags.get("security_event_category", []) if isinstance(parsed_alert_tags.get("security_event_category", []), list) else [parsed_alert_tags.get("security_event_category", "")]) if isinstance(sec, str)]
        Logger.debug(f"Alert security event categories (normalized): {alert_security_event_categories}")


        # Fetch table profiles from MongoDB
        try:
            tables_list_doc = MongoDBManager.get_record_by_multiple_fields(
                self.main_db, self.toolsmetadata_db, {"intcid": intcid, "type": "siem", "vendor": "sentinel", "subtype": "index_list"}
            )
        except Exception as e:
            Logger.error(f"Error retrieving table profiles from MongoDB: {e}")
            return {"matching_tables": []}

        tables_list = tables_list_doc.get("indices", []) if tables_list_doc else []

        if not tables_list:
            Logger.warning(f"No Sentinel table profiles found for intcid: {intcid}. Check MongoDB configuration.")
            return {"matching_tables": []}

        for table in tables_list:
            table_name = table.get("index")
            if not table_name:
                continue # Skip if table name is missing

            profile_log_source = table.get("log_source", "")
            if not profile_log_source:
                continue  # Skip tables with empty log_source
            # No .lower() needed, values are already normalized
            Logger.debug(f"Processing table: {table_name}, profile log_source: {profile_log_source}")

            device_type_val = table.get("device_type", [])
            if not device_type_val:
                continue  # Skip tables with empty device_type
            profile_device_types = device_type_val if isinstance(device_type_val, list) else [device_type_val]
            Logger.debug(f"Device types for table {table_name}: {profile_device_types}")

            security_tags_val = table.get("tags", [])
            if not security_tags_val:
                continue  # Skip tables with empty security_event_category/tags
            profile_security_event_categories = security_tags_val if isinstance(security_tags_val, list) else [security_tags_val]
            Logger.debug(f"Security event categories for table {table_name}: {profile_security_event_categories}")

            current_score = 0

            # Determine match conditions using normalized values
            log_source_matched = (alert_log_source and alert_log_source == profile_log_source)
            device_type_overlap = bool(set(alert_device_types) & set(profile_device_types))
            security_category_overlap = bool(set(alert_security_event_categories) & set(profile_security_event_categories))

            # --- Apply new tiered scoring based on the strict priority ---

            # Priority 1: All Three (Log Source + Device Type + Security Event Category)
            if log_source_matched and device_type_overlap and security_category_overlap:
                current_score = TIER_SCORES["all_three_perfect"]
            # Priority 2: Log Source Only (and any additional matches that don't make it Tier 1)
            elif log_source_matched:
                current_score = TIER_SCORES["log_source_only_base"]
                # Add micro-bonuses if device type or security category also overlap
                if device_type_overlap:
                    current_score += TIER_SCORES["log_source_plus_device_type_bonus"]
                if security_category_overlap:
                    current_score += TIER_SCORES["log_source_plus_security_category_bonus"]
            # Priority 3: Device Type AND Security Event Type (without a Log Source match)
            elif device_type_overlap and security_category_overlap:
                current_score = TIER_SCORES["device_security_only"]
            # Fallback: Single matches (only Device Type OR Security Event Type, without Log Source)
            else:
                if device_type_overlap:
                    current_score += TIER_SCORES["device_type_single_fallback"]
                if security_category_overlap:
                    current_score += TIER_SCORES["security_category_single_fallback"]

            table_scores[table_name] = current_score
            Logger.debug(f"  --> Table '{table_name}' final score: {current_score}")


        # Filter and sort
        relevant_tables = {
            table: score for table, score in table_scores.items()
            if score >= min_score_threshold
        }
        
        sorted_relevant_tables = dict(sorted(relevant_tables.items(), key=lambda item: item[1], reverse=True))
        selected_tables = list(sorted_relevant_tables.keys())
        if len(selected_tables) > 15:
            selected_tables = selected_tables[:15]
        Logger.info(f"Top relevant tables for intcid: {intcid}, tags: {parsed_alert_tags}: {sorted_relevant_tables}")

        return {"matching_tables": selected_tables}
    
    
    def get_top_matching_tables(self, intcid: str, tid: str) -> list:
        
        filter = {
            "intcid": intcid,
            "tid": tid,
        }
        try:
            doc = MongoDBManager.get_record_by_multiple_fields(
                self.main_db, self.trenchrecords_db, filter
            )
            if doc and "matching_tables" in doc:
                matching_tables = doc["matching_tables"]
                Logger.info(f"Found matching tables for intcid: {intcid}, tid: {tid}: {matching_tables}")
                return matching_tables
            else:
                Logger.info(f"No matching tables found for intcid: {intcid}, tid: {tid}.")
                return []
        except Exception as e:
            Logger.error(f"Error retrieving matching tables for intcid: {intcid}, tid: {tid}: {e}")
            return []
        
    def parse_indices(self, indices_data: List[Dict[str, Any]]) -> str:
        
        Logger.debug(f"Parsing indices: {indices_data}")
        
        if not indices_data:
            return "No SIEM indices available"
            
        try:
            # Build the formatted string
            output = ["Available SIEM Indices:\n"]
            

            for idx, info in enumerate(indices_data, 1):
                index_name = info.get('index', 'Unknown Index')
                description = info.get('desc', 'No description available')
                
                # Add formatted index information
                output.append(f"{idx}. {index_name}")
                output.append(f"   Description: {description}")
                
            # Join all lines with newlines
            formatted_output = "\n".join(output)
            Logger.debug(f"Formatted indices output: {formatted_output}")
            
            return formatted_output
        except Exception as e:
            Logger.error(f"Error formatting indices: {e}")
            return "Error formatting SIEM indices"
        
    def user_lookup(self, intcid: str, username: str) -> str:
        """
        Looks up user information in the MongoDB collection.

        Args:
            username (str): The username to look up.
            intcid (str): Integration/Customer ID for logging.

        Returns:
            dict: User information if found, otherwise an empty dictionary.
        """
        Logger.info(f"Looking up user '{username}' for intcid: {intcid}")
        filter = {"intcid": intcid, "type": "siem", "subtype": "lookup_table"}
        
        user_lookup_collection = MongoDBManager.get_record_by_multiple_fields(self.main_db, self.toolsmetadata_db, filter)
        if not user_lookup_collection:
            Logger.warn(f"No user lookup collection found for intcid: {intcid}")
            return ""
        user_lookup = user_lookup_collection["user_lookup_table"]
        
        if user_lookup[username]:
            user_info = user_lookup[username]
            Logger.info(f"Found user info for '{username}': {user_info}")
            return user_info
        else:
            return ""
        