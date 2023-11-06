import os
import sys
import tomllib

from typing import Any, Dict, List, Tuple

from classes import Notification, ShareInfo


def load_config(filename: str) -> Tuple[dict[str, Any] | None, None | str]:
    """Parses TOML configuration file into native Python structures.

    Args:
        filename (str): Path of the configuration file.

    Returns:
        Tuple[dict[str, Any] | None, None | str]: Configuration, None on success, and None, error message on failure.
    """
    try:
        with open(filename, "rb") as input:
            try:
                conf_dict = tomllib.load(input)
                return conf_dict, None
            except tomllib.TOMLDecodeError as err:
                return None, err
    except FileNotFoundError as err:
        return None, err.strerror


def probe_config_to_si(settings: Dict[str, str]) -> ShareInfo:
    print("settings: ", settings)
    password: str = settings.get("password")
    if not password:
        password = os.environ.get("SMB_MONITOR_PROBE_PASSWORD")
    else:
        # We can specify the environment variable from which to obtain the
        # password by prefixing the name of the variable with `$ENV_`.
        # If a "password" string with `$ENV_` is found, we will trim off
        # this prefix and search the environment for a variable with that
        # name.
        if password.startswith("$ENV_"):
            password = os.environ.get(password.removeprefix("$ENV_"))
    print("PASSWORD:", password)
    if not password:
        print("environmentL:", os.environ, flush=True)
        raise RuntimeError("password is required for basic functionality")

    return ShareInfo(
                addr=settings.get("address"),
                share=settings.get("share"),
                domain=settings.get("domain"),
                user=settings.get("username"),
                passwd=password,
            )

def config_to_share_info_list(config: Dict[str, Any]) -> List[ShareInfo]:
    si_list = []
    if not config:
        return []

    for key, settings in config.items():
        print("key =", key, "settings =", settings, flush=True)
        if key != "probes":
            continue
        # print("key =", key, "settings =", settings)
        for probe in settings:
            si = probe_config_to_si(probe)
            print("generated si:", si, flush=True)
            si_list.append(si)
        # password: str = settings.get("password")
        # if not password:
        #     password = os.environ.get("SMB_MONITOR_PROBE_PASSWORD", "invalid")
        # else:
        #     # We can specify the environment variable from which to obtain the
        #     # password by prefixing the name of the variable with `$ENV_`.
        #     # If a "password" string with `$ENV_` is found, we will trim off
        #     # this prefix and search the environment for a variable with that
        #     # name.
        #     if password.startswith("$ENV_"):
        #         password = os.environ.get(password.removeprefix("$ENV_"), "invalid")
        # if not password:
        #     raise RuntimeError("password is required for basic functionality")
        # si_list.append(
        #     ShareInfo(
        #         addr=settings.get("address"),
        #         share=settings.get("share"),
        #         domain=settings.get("domain"),
        #         user=settings.get("username"),
        #         passwd=password,
        #     )
        # )
    return si_list


def config_to_notification_list(config: Dict[str, Any]) -> List[Notification] | None:
    """Builds a list of Notification objects with required information for POSTing to these destinations.

    Args:
        config (Dict[str, Any]): Parsed probe configuration.

    Returns:
        List[Notification] | None: All notification destinations.
    """
    notifications = []
    if not config:
        return []

    for section_name, section in config.items():
        if section_name != "notifications":
            continue

        elem: Dict
        for elem in section:
            notifications.append(
                Notification(
                    url=elem.get("url"),
                    integration_key=elem.get("integration_key"),
                    headers=elem.get("headers"),
                    target=elem.get("target"),
                )
            )

    return notifications


def config_to_si_list(config: Dict[str, Any]) -> List[ShareInfo] | None:
    """Builds a list of ShareInfo objects describing testing targets from the given configuration.

    Args:
        config (Dict[str, Any]): Parsed probe configuration.

    Raises:
        RuntimeError: Exception raised if the password is not provided.

    Returns:
        List[ShareInfo]: All destinations which the probe is to regularly test.
    """
    si_list = []
    if not config:
        return []

    # Locate the probes section (list) in the configuration and iterate the
    # list.
    for section_name, section in config.items():
        if section_name != "probes":
            continue
        for probe in section:
            password: str = probe.get("password")
            if not password:
                password = os.environ.get("SMB_MONITOR_PROBE_PASSWORD", "invalid")
            else:
                # We can specify the environment variable from which to obtain the
                # password by prefixing the name of the variable with `$ENV_`.
                # If a "password" string with `$ENV_` is found, we will trim off
                # this prefix and search the environment for a variable with that
                # name.
                if password.startswith("$ENV_"):
                    password = os.environ.get(password.removeprefix("$ENV_"), "invalid")
            if not password:
                raise RuntimeError("password is required for basic functionality")
            si_list.append(
                ShareInfo(
                    addr=probe.get("address"),
                    share=probe.get("share"),
                    domain=probe.get("domain"),
                    user=probe.get("username"),
                    passwd=password,
                )
            )
    return si_list


def display_parsed_config(config: Dict[str, Any], file=sys.stderr):
    """Prints out the configuration with which we are running.

    Args:
        config (Dict[str, Any]): Parsed probe configuration.
    """
    targets_cnt = 0
    dests_cnt = 0
    lines = ""
    for section, section_data in config.items():
        if section == "probes":
            # for target, share_details in section.items():
            lines += f"----------------------\n"
            lines += f"--- PROBES SECTION ---\n"
            lines += f"----------------------\n"
            for target in section_data:
                if targets_cnt > 0:
                    lines += "\n"  # Add an extra line between target specifications
                targets_cnt += 1
                lines += f"probe[{targets_cnt}]\n"
                for key, value in target.items():
                    if key == "name" and value == "":
                        value = "unnamed"
                    if key == "password" and not value.startswith("$ENV_"):
                        value = "***SANITIZED***"
                    lines += f"{key:<20}\t=> {value}\n"
            lines += "\n"  # Add an extra line between sections
        else:  # notifications section
            lines += f"-----------------------------\n"
            lines += f"--- NOTIFICATIONS SECTION ---\n"
            lines += f"-----------------------------\n"
            for dest in section_data:
                if dests_cnt > 0:
                    lines += (
                        "\n"  # Add an extra line between destination specifications
                    )
                dests_cnt += 1
                lines += f"notification[{dests_cnt}]\n"
                for key, value in dest.items():
                    lines += f"{key:<20}\t=> {value}\n"
    print(lines[:-1], file=file, flush=True, end=None)
