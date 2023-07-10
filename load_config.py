import os
import tomllib

from typing import Any, Dict, List, Tuple

from classes import ShareInfo


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


def config_to_share_info_list(config: Dict[str, Any]) -> List[ShareInfo]:
    si_list = []
    if not config:
        return []

    for _, settings in config.items():
        password: str = settings.get("password")
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
                addr=settings.get("address"),
                share=settings.get("share"),
                domain=settings.get("domain"),
                user=settings.get("username"),
                passwd=password,
            )
        )
    return si_list
