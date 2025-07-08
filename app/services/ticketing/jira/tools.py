from app.services.ticketing.jira.utils import JiraUtils
from typing import Any, Optional
from pltfrm import Logger2 as Logger







async def raise_ticket(intcid: str, summary: str, description: str, issuetype: Optional[str] = "Task") -> dict:
    jira_utils = JiraUtils(intcid)
    # Here you would implement the logic to raise a ticket in Jira using the jira_utils instance
    
    try:
        # Example of raising a ticket (this is a placeholder, actual implementation will depend on JiraUtils)
        issue_dict = {
            'project': {'key': intcid},  # Assuming intcid is the project key
            'summary': summary,
            'description': description,
            'issuetype': {'name': issuetype}  # Assuming issuetype is a valid Jira issue type
        }
        result = await jira_utils.create_issue(issue_dict)
        
        if not result:
            return result
        return result
    except Exception as e:
        Logger.error(f"Error creating Jira ticket: {e}")
        return result
    