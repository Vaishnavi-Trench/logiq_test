"""Test script for the sentinel_generate_kql_query endpoint."""

import requests
import json
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sentinel_endpoint_test.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def test_sentinel_generate_kql_query(intcid, payload):
    """Send a request to the sentinel_generate_kql_query endpoint and log details."""
    url = (
        f"http://localhost:8000/api/siem/sentinel/sentinel_generate_kql_query/{intcid}"
    )
    headers = {"Content-Type": "application/json"}

    logger.info(f"Sending request to {url}")
    logger.info(f"Request payload: {json.dumps(payload, indent=2)}")

    # Check for potentially missing fields in the payload
    required_fields = [
        "task",
        "aid",
        "tid",
        "question_id",
        "triage_question",
        "table_name",
        "alert_context",
        "additional_info",
        "env",
    ]
    missing_fields = [field for field in required_fields if field not in payload]

    if missing_fields:
        logger.warning(f"Payload is missing the following fields: {missing_fields}")

    try:
        response = requests.post(url, json=payload, headers=headers)
        status_code = response.status_code
        logger.info(f"Response status code: {status_code}")

        if status_code == 200:
            logger.info(f"Response body: {json.dumps(response.json(), indent=2)}")
        elif status_code == 422:
            logger.error(f"Validation error (422): {response.text}")
            # Try to parse the validation error details
            try:
                error_details = response.json()
                logger.error(
                    f"Validation error details: {json.dumps(error_details, indent=2)}"
                )

                # Extract detailed validation errors
                if "detail" in error_details:
                    for error in error_details["detail"]:
                        logger.error(
                            f"Field: {error.get('loc', ['unknown'])[1]}, Error: {error.get('msg', 'unknown error')}"
                        )
            except Exception as parse_error:
                logger.error(
                    f"Could not parse validation error details: {str(parse_error)}"
                )
        else:
            logger.error(f"Unexpected status code: {status_code}")
            logger.error(f"Response body: {response.text}")
    except Exception as e:
        logger.error(f"Exception during request: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_sentinel_endpoint.py <payload_file.json>")
        sys.exit(1)

    payload_file = sys.argv[1]
    with open(payload_file, "r") as f:
        payload = json.load(f)

    intcid = "1008"  # Change this if needed
    test_sentinel_generate_kql_query(intcid, payload)
