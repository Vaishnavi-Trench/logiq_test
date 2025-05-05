import time

import requests
import json

from requests.auth import HTTPBasicAuth


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class SplunkManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

    @staticmethod
    def get_instance():
        if SplunkManager.__instance is None:
            SplunkManager.__instance = SplunkManager()

        return SplunkManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    @staticmethod
    def get_all_indices(splunkurl, username, password):
        try:
            response = requests.get(
                f"{splunkurl}/services/data/indexes?output_mode=json",
                auth=(username, password),
                verify=False,
            )
            response.raise_for_status()
            indices = response.json().get("entry", [])
            return indices
        except requests.exceptions.RequestException as e:
            print(f"Error fetching indices: {e}")
            return []

    @staticmethod
    def get_fields_for_index(splunkurl, username, password, index_name):
        print(index_name)
        search_query = f"search index={index_name} | fieldsummary | table field"
        try:
            response = requests.post(
                f"{splunkurl}/services/search/jobs/export",
                auth=(username, password),
                data={"search": search_query, "output_mode": "json"},
                verify=False,
                stream=True,  # Enable streaming
            )
            response.raise_for_status()
            print(response)
            fields = []
            for line in response.iter_lines(decode_unicode=True):
                if line.strip():  # Ignore empty lines
                    try:
                        json_data = json.loads(line)
                        field = json_data.get("result", {}).get("field")
                        if field:
                            fields.append(field)
                    except json.JSONDecodeError:
                        print(f"Invalid JSON: {line}")

            print(f"Fields extracted for index: {index_name}")
            return fields

        except requests.exceptions.RequestException as e:
            print(f"Error extracting fields for index '{index_name}': {e}")
            return []

    @staticmethod
    def create_search_job(search_query, splunk_host, username, password):
        search_url = f"{splunk_host}/services/search/jobs"
        # Step 1: Create a search job with the query
        payload = {
            "search": search_query,  # The Splunk search query
            "output_mode": "json",  # Output mode: json, xml, csv
        }

        # job_id = 1731757053.496
        params = {"output_mode": "json"}
        # Send a POST request to create a search job
        response = requests.post(
            search_url,
            data=payload,
            auth=HTTPBasicAuth(username, password),
            verify=False  # Set to True if using a valid SSL certificate
        )

        # Check if job was successfully created
        if response.status_code == 201:
            job_id = response.json()['sid']  # Search job ID (SID)
            print(f"Search job created successfully! SID: {job_id}")
            return job_id
        else:
            print(f"Error creating search job: {response.status_code}")
            return None

    @staticmethod
    def get_search_job_status(job_id, retries, timeout, splunk_host, username, password):
        job_status_url = f"{splunk_host}/services/search/jobs/{job_id}"
        count = 0
        while True:
            status_response = requests.get(
                job_status_url,
                params={"output_mode": "json"},
                auth=HTTPBasicAuth(username, password),
                verify=False
            )

            job_status = status_response.json()['entry'][0]['content']['dispatchState']
            if job_status == 'DONE':
                print(f"Job {job_id} is done.")
                return "DONE"
            else:
                if count >= retries:
                    break
                print(f"Job {job_id} is {job_status}. Waiting for completion...")
                time.sleep(timeout)  # Wait before checking again

            count += 1

        return None

    @staticmethod
    def get_search_results(job_id, splunk_host, username, password):
        results_url = f"{splunk_host}/services/search/jobs/{job_id}/results"
        results_response = requests.get(
            results_url,
            params={"output_mode": "json"},
            auth=HTTPBasicAuth(username, password),
            verify=False
        )

        # Check if we received the results successfully
        if results_response.status_code == 200:
            results = results_response.json()
            print("Search Results: ", results)
        else:
            print(f"Error fetching results: {results_response.status_code}")