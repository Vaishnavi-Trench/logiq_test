"""GCP Tools Module"""

from google.cloud import iam_admin_v1, resourcemanager_v3

from pltfrm import Logger2 as Logger


def gcp_iam_role_lookup(intcid: str, project_id: str, target_user: str) -> dict:
    """Checks the IAM roles of a member for a given resource."""
    Logger.debug(
        f"tool:gcp_iam_role_lookup:\nChecking IAM roles for {target_user} in project {project_id} for {intcid}\n"
    )
    client = resourcemanager_v3.ProjectsClient()
    iam_client = iam_admin_v1.IAMClient()

    # Get IAM policy (Fixed resource format)
    policy = client.get_iam_policy(request={"resource": f"projects/{project_id}"})

    user_roles = {}
    result = f"IAM Roles and Permissions for User: {target_user} in Project: {project_id}\n\n"

    # Filter by target_user
    for binding in policy.bindings:
        role = binding.role
        members = binding.members

        for member in members:
            if member == target_user:
                if target_user not in user_roles:
                    user_roles[target_user] = []
                user_roles[target_user].append(role)

    # If the user is found, fetch their roles and permissions
    if target_user in user_roles:
        for role in user_roles[target_user]:
            result += f"Role: {role}\n"
            try:
                # IAM roles are generally in a "projects" context, so we use the full role name
                role_details = iam_client.get_role(request={"name": role})
                # Add the permissions associated with the role (if available)
                for permission in role_details.included_permissions:
                    result += f" - {permission}\n"
            except Exception as e:
                result += f"Error fetching role permissions: {e}\n"
    else:
        result += f"No roles found for {target_user}.\n"

    result += "-" * 50 + "\n"
    return {"roles": result}
