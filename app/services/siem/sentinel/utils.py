"""OpenSearch Utils"""

from azure.identity import ClientSecretCredential
from azure.core.exceptions import ClientAuthenticationError
import requests
import json
import traceback
import re  # Import regex for checking limit patterns
from datetime import datetime, timezone

from pltfrm import PropX, Logger2 as Logger, MongoDBManager

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
            return ["<Authentication error>"]

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
            return ["<Schema retrieval configuration error>"]

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
                return sorted(columns)
            else:
                Logger.warn(
                    f"Could not extract column names for table '{table_name}' from schema response."
                )
                return ["<Schema retrieval failed>"]
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
            return ["<Schema retrieval HTTP error>"]
        except Exception as se_other:
            Logger.warn(
                f"Unexpected error fetching schema for table '{table_name}'. Error: {se_other}"
            )
            return ["<Schema retrieval unexpected error>"]

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
                return table_metadata_collection["fields"]
            else:
                Logger.warn(
                    f"Table metadata for '{table_name}' does not contain 'fields' key. Returning empty list."
                )
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
            requirement: The specific requirement or task for the query.
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
            return

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
                return

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
