"""Implements Orbit table name related API routes."""

from typing import Dict

from pltfrm import Logger2 as Logger
from pltfrm import PropX, MongoDBManager, AIManager

from app.services.orbit.tablename import models


def get_feedbackform(
    intcid: str,
    type: str,
    vendor: str,
    alert_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    selected_table_name: str,
) -> tuple[bool, dict]:
    """
    Generates a feedback form for table name selection feedback.

    Returns:
        A tuple containing (success: bool, response_data: dict)
    """
    Logger.info(
        f"api: /orbit/tablename/get_feedbackform/{intcid}: Retrieving feedbackform for tid {tid}, question_id {question_id}, step_id {step_id}, selected_table_name {selected_table_name}"
    )

    # fetch triage playbook from database using tid
    # fetch specific question from triage playbook using question_id

    # for prompt we need
    # alert title - input
    # triage question - from playbook
    # selected_tablename - from user input
    # selected_table_description - from integration data , type and vendor needed

    # validate
    if not intcid or not type or not vendor or not alert_name or not tid:
        Logger.error(
            "Missing required parameters: intcid, type, vendor, alert_name, or tid"
        )
        return False, {"error": "Missing required parameters"}

    main_db = PropX.get_property("module.config.db")
    # fetch triage record from database
    playbook_collection = PropX.get_property("module.playbook.collection")
    filter_criteria = {
        "intcid": intcid,
        "tid": tid,
    }
    triage_question = ""
    triage_record = MongoDBManager.get_record_by_multiple_fields(
        main_db, playbook_collection, filter_criteria, {"tql": 1, "_id": 0}
    )
    if triage_record:
        # tql is an array of questions, we need to find the question with question_id
        tql = triage_record.get("tql", [])
        for question in tql:
            if question.get("question_id") == question_id:
                triage_question = question.get("triage_question")
                break
    # triage_question is now set

    # table record fetching
    relevance_tags = []
    table_desc = ""
    metadata_collection = PropX.get_property("module.integration.metadata.collection")
    filter_criteria = {
        "intcid": intcid,
        "type": type,
        "subtype": "field_list",
        "vendor": vendor,
        "index_name": selected_table_name,
    }

    table_record = MongoDBManager.get_record_by_multiple_fields(
        main_db,
        metadata_collection,
        filter_criteria,
        {"desc": 1, "triage_scope": 1, "_id": 0},
    )
    if table_record:
        table_desc = table_record.get("desc", "")
        if table_record.get("triage_scope"):
            relevance_tags = table_record.get("triage_scope", {}).get(
                "security_event_category", []
            )

    # table desc we got

    response_data = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="ORBIT_TABLENAME_FEEDBACK_FORM",
        prompt_params={
            "alert": alert_name,
            "triage_question": triage_question,
            "selected_tablename": selected_table_name,
            "selected_table_description": table_desc,
            "table_relevance_tags": relevance_tags,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=models.FeedbackForm,
        history_params={
            "tid": tid,
            "qid": question_id,
            "step_id": step_id,
            "subtype": "tablename_correction",
        },
        type="playbook",
        system_prompt="You are a helpful SOC expert who knows which SIEM index or tables name has which data",
    )

    return True, response_data


def process_feedbackform(
    intcid: str,
    type: str,
    vendor: str,
    alert_name: str,
    tid: str,
    instruction_note_id: str,
) -> tuple[bool, dict]:
    """
    Processes feedback form for table name correction and performs necessary updates.

    Returns:
        A tuple containing (success: bool, response_data: dict)
    """
    Logger.info(
        f"api: /orbit/tablename/get_feedbackform/{intcid}: Retrieving feedbackform for tid {tid}"
    )

    # validate
    if not intcid or not type or not vendor or not alert_name or not tid:
        Logger.error(
            "Missing required parameters: intcid, type, vendor, alert_name, or tid"
        )
        return False, {"error": "Missing required parameters"}

    main_db = PropX.get_property("module.config.db")
    # fetch the instruction note
    # question_id, step_id, corrected_table_name, instruction_note_id, feedbackform fetch from note
    filter_criteria = {
        "intcid": intcid,
        "noteId": instruction_note_id,
        "recordType": "tablename_instruction",
    }
    instruction_note = MongoDBManager.get_record_by_multiple_fields(
        main_db,
        PropX.get_property("module.instruction.note.collection"),
        filter_criteria,
        projection={
            "_id": 0,
            "selectedTableName": 1,
            "correctTableName": 1,
            "questionId": 1,
            "stepId": 1,
            "feedbackForm": 1,
            "feedbackAnswers": 1,
        },
    )
    if not instruction_note:
        Logger.error(
            f"Instruction note with ID {instruction_note_id} not found for intcid {intcid}"
        )
        return False, {"error": "Instruction note not found"}

    question_id = instruction_note.get("questionId")
    step_id = instruction_note.get("stepId")
    selected_table_name = instruction_note.get("selectedTableName")
    corrected_table_name = instruction_note.get("correctTableName")
    feedback_form = instruction_note.get("feedbackForm", {})
    feedback_answers = instruction_note.get("feedbackAnswers", {})

    # Format feedback form and answers for LLM prompt
    success, formatted_feedback = format_feedback_form_for_prompt(
        feedback_form, feedback_answers
    )
    if not success:
        Logger.error(f"Failed to format feedback form: {formatted_feedback}")
        return False, {"error": "error in feedback form formatting"}

    # fetch triage playbook from database using tid
    # fetch specific question from triage playbook using question_id
    triage_question = None
    playbook_collection = PropX.get_property("module.playbook.collection")
    filter_criteria = {
        "intcid": intcid,
        "tid": tid,
    }

    triage_record = MongoDBManager.get_record_by_multiple_fields(
        main_db, playbook_collection, filter_criteria, {"tql": 1, "_id": 0}
    )
    if triage_record:
        # tql is an array of questions, we need to find the question with question_id
        tql = triage_record.get("tql", [])
        for question in tql:
            if question.get("question_id") == question_id:
                triage_question = question.get("triage_question")
                break

    if not triage_question:
        Logger.error(
            f"Triage question with ID {question_id} not found in playbook for tid {tid}"
        )
        return False, {"error": "Triage question not found"}

    # original table record fetching
    selected_table_relevance_tags = []
    selected_table_desc = None
    metadata_collection = PropX.get_property("module.integration.metadata.collection")
    filter_criteria = {
        "intcid": intcid,
        "type": type,
        "subtype": "field_list",
        "vendor": vendor,
        "index_name": selected_table_name,
    }

    table_record = MongoDBManager.get_record_by_multiple_fields(
        main_db,
        metadata_collection,
        filter_criteria,
        {"desc": 1, "triage_scope": 1, "_id": 0},
    )
    if table_record:
        selected_table_desc = table_record.get("desc", "")
        if table_record.get("triage_scope"):
            selected_table_relevance_tags = table_record.get("triage_scope", {}).get(
                "security_event_category", []
            )

    if not selected_table_desc:
        Logger.error(
            f"Table record for selected table {selected_table_name} not found in metadata for intcid {intcid}"
        )
        return False, {"error": "Selected table record not found"}

    corrected_table_relevance_tags = []
    corrected_table_desc = None
    metadata_collection = PropX.get_property("module.integration.metadata.collection")
    filter_criteria = {
        "intcid": intcid,
        "type": type,
        "subtype": "field_list",
        "vendor": vendor,
        "index_name": corrected_table_name,
    }

    table_record = MongoDBManager.get_record_by_multiple_fields(
        main_db,
        metadata_collection,
        filter_criteria,
        {"desc": 1, "triage_scope": 1, "_id": 0},
    )
    if table_record:
        corrected_table_desc = table_record.get("desc", "")
        if table_record.get("triage_scope"):
            corrected_table_relevance_tags = table_record.get("triage_scope", {}).get(
                "security_event_category", []
            )

    if not corrected_table_desc:
        Logger.error(
            f"Table record for corrected table {selected_table_name} not found in metadata for intcid {intcid}"
        )
        return False, {"error": "Corrected table record not found"}

    # for prompt we need
    # alert title - input
    # triage question - from playbook
    # selected_tablename - from user input
    # selected_table_description, tags - from integration data , type and vendor needed
    # corrected_tablename - from user input
    # corrected_table_description, tags - from integration data, type and vendor needed
    # formatted feedback form with users answers - fetch from instruction note

    # operations
    # playbook:
    #  table name should be corrected in the question
    #  table name of tasks in the choose_table and generate_query and run_query if its present should be replaced with new table name
    #  table name should be corrected in the choose_table plan cache

    # integration data:
    #  table desc, tags of source table to be corrected in the integration data
    #  table desc, tags of corrected table to be added in the integration data

    # table record fetching
    response_data = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="ORBIT_TABLENAME_CORRECTION_PROMPT",
        prompt_params={
            "alert": alert_name,
            "triage_question": triage_question,
            "selected_tablename": selected_table_name,
            "selected_table_description": selected_table_desc,
            "selected_table_relevance_tags": selected_table_relevance_tags,
            "correct_tablename": corrected_table_name,
            "correct_table_description": corrected_table_desc,
            "correct_table_relevance_tags": corrected_table_relevance_tags,
            "feedback_form_answers": formatted_feedback,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=models.FeedbackOutput,
        history_params={
            "tid": tid,
            "qid": question_id,
            "step_id": step_id,
            "subtype": "tablename_correction",
        },
        type="playbook",
        system_prompt="You are a helpful SOC expert who knows which SIEM index or tables name has which data",
    )

    return True, response_data


def format_feedback_form_for_prompt(feedback_form: Dict, feedback_answers: Dict) -> str:
    """
    Format feedback form questions and answers into a readable string for LLM prompt.

    Args:
        feedback_form: Dictionary containing the feedback form structure
        feedback_answers: Dictionary containing user's answers mapped by question_id

    Returns:
        Formatted string with questions and answers
    """
    if not feedback_form or not feedback_form.get("questions"):
        return False, "No feedback form data available."

    formatted_feedback = "Feedback Form Questions and Answers:\n\n"

    questions = feedback_form.get("questions", [])

    for question in questions:
        question_id = str(question.get("question_id", ""))
        question_text = question.get("question", "")
        feedback_type = question.get("feedback_type", "")

        # Get the user's answer for this question
        user_answer = feedback_answers.get(question_id, "No answer provided")

        formatted_feedback += f"Q{question_id}: {question_text}\n"
        formatted_feedback += f"Type: {feedback_type}\n"
        formatted_feedback += f"Answer: {user_answer}\n\n"

    return True, formatted_feedback.strip()
