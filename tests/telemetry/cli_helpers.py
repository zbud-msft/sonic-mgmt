import json
import re
import ipaddress
from tests.common.reboot import reboot


def get_json_from_gnmi_output(stdout):
    marker = "The GetResponse is below"
    marker_pos = stdout.find(marker)
    assert marker_pos != -1, "GetResponse marker not found"

    # Support both object and array JSON roots
    obj_pos = stdout.find("{", marker_pos)
    arr_pos = stdout.find("[", marker_pos)

    if obj_pos == -1 and arr_pos == -1:
        raise AssertionError("JSON not found in GetResponse")

    start_pos = obj_pos if arr_pos == -1 else arr_pos if obj_pos == -1 else min(obj_pos, arr_pos)

    decoder = json.JSONDecoder()
    payload = stdout[start_pos:].lstrip()
    obj, _ = decoder.raw_decode(payload)
    return obj


def reboot_device(duthost, localhost):
    reboot(duthost, localhost)


def transform_reboot_cause_output(reboot_cause_dict):
    reboot_cause_str = ""

    reboot_cause = reboot_cause_dict.get("cause", "Unknown")
    reboot_user = reboot_cause_dict.get("user", "N/A")
    reboot_time = reboot_cause_dict.get("time", "N/A")

    if reboot_user != "N/A":
        reboot_cause_str = "User issued '{}' command".format(reboot_cause)
    else:
        reboot_cause_str = reboot_cause

    if reboot_user != "N/A" or reboot_time != "N/A":
        reboot_cause_str += " ["

        if reboot_user != "N/A":
            reboot_cause_str += "User: {}".format(reboot_user)
            if reboot_time != "N/A":
                reboot_cause_str += ", "

        if reboot_time != "N/A":
            reboot_cause_str += "Time: {}".format(reboot_time)

        reboot_cause_str += "]"
    return reboot_cause_str


def check_reboot_cause(duthost, output):
    cmd = "show reboot-cause"
    result = duthost.shell(cmd)["stdout"]

    reboot_cause_str = transform_reboot_cause_output(output)

    failure_message = "{} no match parsed gnmi output {} for SHOW/reboot-cause path".format(result, reboot_cause_str)
    assert result == reboot_cause_str, failure_message


def check_reboot_cause_history(duthost, output):
    cmd = "show reboot-cause history"
    result = duthost.show_and_parse(cmd)

    result_map = {entry["name"]: {k: entry[k] for k in entry if k != "name"} for entry in result}

    failure_message = "show result {} != output {} for SHOW/reboot-cause/history path".format(result_map, output)
    assert result_map == output, failure_message


def get_valid_interface(duthost):
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet\d+$')
    for name, st in interfaces.items():
        if pattern.match(name) and st.get("oper") == "up" and st.get("admin") == "up":
            return [name]
    return None


def get_period_value(duthost):
    return ["5"]


def get_group_value(duthost):
    return ["BAD"]


def get_counter_type_value(duthost):
    return ["PORT_INGRESS_DROPS"]


def get_rif_portchannel(duthost):
    fallback_portchannel = ["PortChannel101"]

    res = duthost.config_facts(host=duthost.hostname, source="running")
    if not res or "ansible_facts" not in res:
        return fallback_portchannel

    facts = res["ansible_facts"]
    if not facts or "PORTCHANNEL_INTERFACE" not in facts:
        return fallback_portchannel

    pc_intf = facts["PORTCHANNEL_INTERFACE"]
    if not isinstance(pc_intf, dict) or not pc_intf:
        return fallback_portchannel

    first_key = next(iter(pc_intf))
    base = first_key.split("|", 1)[0]
    return [base] if base else fallback_portchannel


def get_ipv6_neighbor(duthost):
    bgp_facts = duthost.get_bgp_neighbors()
    for k, v in list(bgp_facts.items()):
        if v['state'] == 'established' and ipaddress.ip_address(k).version == 6:
            return [k]
    return None


def get_ipv6_prefix(duthost):
    return ["::\/0"]


def get_ipv6_bgp_neighbor_arguments(duthost):
    return ["routes", "advertised-routes", "received-routes"]


def get_ipv6_prefix_family(duthost):
    return ["LOCAL_VLAN_IPV6_PREFIX", "PL_LoopbackV6"]


def get_ipv6_bgp_network_arguments(duthost):
    return ["bestpath", "longer-prefixes", "multipath"]


def get_ipv6_route_arguments(duthost):
    return ["bgp", "nexthop-group", "::\/0"]


def get_interface_vlan(duthost):
    vlan_intfs = duthost.get_vlan_intfs()
    if len(vlan_intfs) == 0:
        return None
    return [vlan_intfs[0]]


def get_iface_mode(duthost):
    return ["alias"]
