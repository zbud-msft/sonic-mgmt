import os
import json
import logging
import itertools
import shlex
import pytest

import cli_helpers as helper
from telemetry_utils import generate_client_cli
from show_cli_to_gnmi_path import ShowCliToGnmiPathConverter, OptionException

pytestmark = [pytest.mark.topology('any')]

logger = logging.getLogger(__name__)

METHOD_GET = "get"
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SHOW_CMD_FILE = os.path.join(BASE_DIR, "show_cmd.json")

argumentMap = {
    "INTERFACE_NAME":  helper.get_valid_interface,
    "RIF_PORTCHANNEL": helper.get_rif_portchannel,
}

# Options (lowercase keys) -> (type, cli-name, getter)
# type: "flag" => --name ; "kv" => --name=value
optionMap = {
    "period":       ("kv",   "period",   helper.get_period_value),
    "printall":     ("flag", "printall", None),
    "group":        ("kv",   "group",    helper.get_group_value),
    "counter_type": ("kv", "counter_type", helper.get_counter_type_value),
    "interface":    ("kv", "interface", helper.get_valid_interface),
}

def powerset(iterable):
    items = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(items, r) for r in range(len(items) + 1))


def build_show_cli(base_path, positional_args, options_selected, duthost):
    # build CLI from base path, args, and options
    parts = [base_path]
    for arg_name in positional_args:
        parts.append(str(arg_name))

    # Then options (no sorting)
    for opt_key in options_selected:
        opt_meta = optionMap.get(opt_key)
        if not opt_meta:
            raise ValueError(f"Unknown option key '{opt_key}'")
        opt_type, opt_cli_name, getter = opt_meta
        if opt_type == "flag":
            parts.append(f"--{opt_cli_name}")
        elif opt_type == "kv":
            value = getter(duthost)
            parts.append(f"--{opt_cli_name}={value}")
        else:
            raise ValueError(f"Unsupported option type '{opt_type}' for '{opt_key}'")

    return " ".join(parts)


def convert_show_cli_to_xpath(cli_str):
    tokens = shlex.split(cli_str)
    return ShowCliToGnmiPathConverter(tokens).convert()


def validate_schema(shape, required_keys, required_map_keys, payload):
    """
    payload can be in multiple shapes:

    1) array: [{"interface": "Ethernet0", "alias": "etp0"}]
    2) object(keys): {"fdb_aging_time": "600s"}
    3) object(map): {"Ethernet0": {"alias": "etp0"}}
    """
    if shape == "array":
        if not isinstance(payload, list):
            return False, f"expected array, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None
        for i, elem in enumerate(payload):
            if not isinstance(elem, dict):
                return False, f"array element {i} not an object (got {type(elem).__name__})"
            missing = [k for k in required_keys if k not in elem]
            if missing:
                return False, f"array element {i} missing keys: {missing}"
        return True, None

    # object_keys
    if shape == "object_keys":
        if not isinstance(payload, dict):
            return False, f"expected object, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None
        missing = [k for k in required_keys if k not in payload]
        if missing:
            return False, f"object missing keys: {missing}"
        return True, None

    # object_map
    if shape == "object_map":
        if not isinstance(payload, dict):
            return False, f"expected object, got {type(payload).__name__}"
        if len(payload) == 0:
            return True, None

        missing_top = [k for k in required_map_keys if k not in payload]
        if missing_top:
            return False, f"object_map missing top-level keys: {missing_top}"

        for k, v in payload.items():
            if not isinstance(v, dict):
                return False, f"value at key '{k}' is not an object (got {type(v).__name__})"
            missing = [rk for rk in required_keys if rk not in v]
            if missing:
                return False, f"value at key '{k}' missing keys: {missing}"
        return True, None

    return False, f"unknown shape '{shape}'"

@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_show_cli_schema_and_safeguard(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    ptfhost,
    setup_streaming_telemetry,
    gnxi_path,
    request,
    skip_non_container_test
):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    with open(SHOW_CMD_FILE, "r", encoding="utf-8") as f:
        show_cmds = json.load(f)

    failures = []

    for show_cmd in show_cmds:
        path = show_cmd["path"]
        required_args = show_cmd.get("required_args", [])
        optional_args = show_cmd.get("optional_args", [])
        options = show_cmd.get("options", [])
        schema = show_cmd["schema"]
        shape = schema["shape"]
        required_keys = schema.get("required_keys", [])
        required_map_keys = schema.get("required_map_keys, []")
        should_validate = show_cmd.get("validateSchema", False)

        required_arg_values = []
        if required_args:
            for arg_key in required_args:
                getter = argumentMap.get(arg_key)
                if not getter:
                    failures.append({
                        "cli": path,
                        "xpath": "",
                        "reason": f"unknown required arg '{arg_key}'"
                    })
                    continue
                required_arg_values.append(getter(duthost))

        argument_combinations = []
        if required_args:
            argument_combinations.append(required_arg_values)
        elif optional_args:
            argument_combinations.append([])  # no argument
            vals = []
            missing = None
            for arg_key in optional_args:
                getter = argumentMap.get(arg_key)
                if not getter:
                    missing = arg_key
                    break
                vals.append(getter(duthost))
            if missing:
                failures.append({
                    "cli": path,
                    "xpath": "",
                    "reason": f"unknown optional arg '{missing}'"
                })
            else:
                argument_combinations.append(vals)
        else:
            argument_combinations.append([])

        for argument_combination in argument_combinations:
            for option_combination in powerset(options):
                try:
                    cli = build_show_cli(path, argument_combination, option_combination, duthost)
                except ValueError as ve:
                    failures.append({
                        "cli": path,
                        "xpath": "",
                        "reason": f"{ve}"
                    })
                    continue
                try:
                    xpath = convert_show_cli_to_xpath(cli)
                except (OptionException, ValueError) as e:
                    failures.append({
                        "cli": cli,
                        "xpath": "",
                        "reason": f"{e}"
                    })
                    continue

                logger.info("CLI: %s, XPATH: %s", cli, xpath)

                before_status = duthost.all_critical_process_status()

                cmd = generate_client_cli(
                    duthost=duthost,
                    gnxi_path=gnxi_path,
                    method=METHOD_GET,
                    xpath=xpath,
                    target="SHOW"
                )
                ptf_result = ptfhost.shell(cmd, module_ignore_errors=True)
                rc = ptf_result.get("rc", 1)
                stdout = ptf_result.get("stdout", "")
                stderr = ptf_result.get("stderr", "")

                if rc != 0:
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": f"ptf rc={rc}, stderr={_trim(stderr)}"
                    })
                    continue

                after_status = duthost.all_critical_process_status()
                if before_status != after_status:
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": "Critical process status changed after GET"
                    })

                try:
                    payload = helper.get_json_from_gnmi_output(stdout)
                except (json.JSONDecodeError, TypeError, AssertionError) as e:
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": f"JSON parse error: {e}. Raw: {_trim(stdout)}"
                    })
                    continue

                if not should_validate:
                    continue

                ok, reason = validate_schema(shape, required_keys, required_map_keys, payload)
                if not ok:
                    failures.append({
                        "cli": cli,
                        "xpath": xpath,
                        "reason": reason
                    })

    if failures:
        lines = ["Failures summary ({} total):".format(len(failures))]
        for f in failures:
            lines.append(f"cli='{f['cli']}' xpath='{f['xpath']}' reason={f['reason']}")
        pytest.fail("\n".join(lines))
