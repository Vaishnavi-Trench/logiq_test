"""JSON Extractor"""

import json
from pltfrm import Logger2 as Logger


def extract_and_parse_json(input_string):
    """
    Extracts and parses the first JSON object found in the input string.

    Args:
        input_string (str): The string containing JSON data.

    Returns:
        dict: The parsed JSON object.

    Raises:
        ValueError: If no valid JSON is found or parsing fails.
    """
    Logger.info("Starting extract_and_parse_json")
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


def extract_and_parse_last_json_list(input_string):
    """
    Extracts and parses the last JSON array found in the input string.

    Args:
        input_string (str): The string containing JSON data.

    Returns:
        list: The parsed JSON array.

    Raises:
        ValueError: If no valid JSON array is found or parsing fails.
    """
    Logger.info("Starting extract_and_parse_last_json_list")
    # Find all occurrences of '[' and ']'
    positions = []
    last_json_object = None
    for i, char in enumerate(input_string):
        if char == "[":
            positions.append(i)
        elif char == "]":
            if positions:
                start_pos = positions.pop()
                end_pos = i + 1
                json_string = input_string[start_pos:end_pos]
                try:
                    # Try parsing the JSON string
                    json_object = json.loads(json_string)
                    last_json_object = json_object  # Store the last valid JSON object
                except json.JSONDecodeError:
                    # Continue to the next potential JSON object
                    continue

    if "last_json_object" in locals():
        Logger.info("Successfully parsed last JSON array")
        return last_json_object
    else:
        Logger.error("No valid JSON array found in the string")
        raise ValueError("No valid JSON array found in the string")


def extract_and_parse_last_json(input_string):
    """
    Extracts and parses the last JSON object found in the input string.

    Args:
        input_string (str): The string containing JSON data.

    Returns:
        dict: The parsed JSON object.

    Raises:
        ValueError: If no valid JSON object is found or parsing fails.
    """
    Logger.info("Starting extract_and_parse_last_json")
    # Find all occurrences of '{' and '}'
    positions = []
    last_json_object = None
    for i, char in enumerate(input_string):
        if char == "{":
            positions.append(i)
        elif char == "}":
            if positions:
                start_pos = positions.pop()
                end_pos = i + 1
                json_string = input_string[start_pos:end_pos]
                try:
                    # Try parsing the JSON string
                    json_object = json.loads(json_string)
                    last_json_object = json_object  # Store the last valid JSON object
                except json.JSONDecodeError:
                    # Continue to the next potential JSON object
                    continue

    if "last_json_object" in locals():
        Logger.info("Successfully parsed last JSON object")
        return last_json_object
    else:
        Logger.error("No valid JSON object found in the string")
        raise ValueError("No valid JSON object found in the string")
