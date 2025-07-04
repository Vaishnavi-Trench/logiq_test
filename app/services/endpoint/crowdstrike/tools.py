from falconpy import Hosts
from app.services.endpoint.crowdstrike.utils import CrowdStrikeUtils
from typing import Any


async def get_host_ids(intcid: str, hostname: str):
    """
    Get host IDs from hostnames using the CrowdStrike Falcon API.
    """
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = []

    if isinstance(hostname, str):
        hostname = [hostname]

    for host in hostname:
        response = await falcon.query_devices_by_filter(filter=f"hostname:'{host}'")
        print(f"Response for hostname '{host}': {response}")
        if response["body"]["resources"]:
            host_ids.append(response["body"]["resources"][0])
        else:
            print(f"Warning: Host ID not found for hostname: {host}")
    return host_ids


async def contain_host(intcid: str, hostname: str):
    """
    Contain hosts using the CrowdStrike Falcon API.
    """
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = await get_host_ids(intcid, hostname)
    if not host_ids:
        print("No host IDs found to contain.")
        return {"error": "No host IDs found"}
    response = await falcon.perform_action(action_name="contain", ids=host_ids)
    print(f"Containment response: {response}")
    if response["status_code"] in [200, 202]:
        return {"status": True}
    else:
        return {"status": False}


async def lift_containment(intcid: str, hostname: str):
    """
    Lift containment for hosts using the CrowdStrike Falcon API.
    """
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = await get_host_ids(intcid, hostname)
    if not host_ids:
        print("No host IDs found to lift containment.")
        return {"error": "No host IDs found"}
    response = await falcon.perform_action(action_name="lift_containment", ids=host_ids)
    print(f"Lift containment response: {response}")
    if response["status_code"] in [200, 202]:
        return {"status": True}
    else:
        return {"status": False}