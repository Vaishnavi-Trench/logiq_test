from falconpy import Hosts
from app.services.endpoint.crowdstrike.utils import CrowdStrikeUtils
from typing import Any
from pltfrm import Logger2 as Logger


async def get_host_ids(intcid: str, hostname: str) -> list[str]:
    """
    Get host IDs from hostnames using the CrowdStrike Falcon API.
    """
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = []

    if isinstance(hostname, str):
        hostname = [hostname]

    for host in hostname:
        response = falcon.query_devices_by_filter(filter=f"hostname:'{host}'")
        Logger.info(f"Response for hostname '{host}': {response}")
        if response["body"]["resources"]:
            host_ids.append(response["body"]["resources"][0])
        else:
            Logger.info(f"Warning: Host ID not found for hostname: {host}")
    return host_ids


async def contain_host(intcid: str, hostname: str) -> dict:
    """
    Contain hosts using the CrowdStrike Falcon API.
    """
    Logger.info(f"Controlling host containment for {hostname} in integration {intcid}")
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = await get_host_ids(intcid, hostname)
    if not host_ids:
        Logger.info("No host IDs found to contain.")
        return {"error": "No host IDs found"}
    response = falcon.perform_action(action_name="contain", ids=host_ids)
    Logger.info(f"Containment response: {response}")
    if response["status_code"] in [200, 202]:
        return {"status": True}
    else:
        return {"status": False}


async def lift_containment(intcid: str, hostname: str) -> dict:
    """
    Lift containment for hosts using the CrowdStrike Falcon API.
    """
    crowdstrike_utils = CrowdStrikeUtils(intcid=intcid)
    falcon = crowdstrike_utils.authenticate()
    host_ids = await get_host_ids(intcid, hostname)
    if not host_ids:
        Logger.info("No host IDs found to lift containment.")
        return {"error": "No host IDs found"}
    response = falcon.perform_action(action_name="lift_containment", ids=host_ids)
    Logger.info(f"Lift containment response: {response}")
    if response["status_code"] in [200, 202]:
        return {"status": True}
    else:
        return {"status": False}