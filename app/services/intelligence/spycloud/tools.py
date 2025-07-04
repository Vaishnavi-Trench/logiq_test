"""Implements Spycloud Tools."""
from pltfrm import Logger2 as Logger
import traceback
from app.services.intelligence.spycloud.utils import extract_alert_context

def get_alert_context(intcid: str, task: str, alert: dict, aid: str) -> dict:
    """
    Get the alert context for a given alert.

    Args:
        intcid: The customer ID.
        alert: The alert data.
        aid: The alert ID.

    Returns:
        A dictionary containing the alert context.
    """
    try:
        return extract_alert_context(intcid, task, alert, aid)
    except Exception as e:
        Logger.error(f"Error getting alert context: {e}")
        Logger.error(traceback.format_exc())
        return {"error": "Failed to retrieve alert context."}
   