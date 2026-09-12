#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import functools
import getpass
import json
import math
import os
import shutil
import subprocess
import sys
import time
from collections import OrderedDict
from collections.abc import Sequence

from utils import argparse_utils
from utils import lock_manager
from utils import log_manager
from utils import path_utils

## Both providers live here on purpose: log_manager.setup_logger(globals()) rebinds
## `logger` in the calling module's globals, so a provider split into its own module
## would silently run with an unconfigured logger.
# pylint: disable=too-many-lines

## TODO:
## * meshnet
## * login and logout not working right
## INFO: A new version of NordVPN is available!
##       Please update the app.
##       Status: Connected
##       Server: United States #5110

_LOG_FILE_PATH, _LOG_CFG_DEFAULT = log_manager.get_default_log_paths(__file__)
logger = log_manager.LogManager()

## NordVPN is deprecated in favour of protonvpn below; kept selectable via
## `--vpn nordvpn` so the old path stays available, but it is not the default.
_NORD_DNS_IPS = ("103.86.96.100", "103.86.99.100")

_NORD_CMDS = {
    ## settings
    "analytics_off": ("nordvpn", "set", "analytics", "0"),
    "autoconnect_on": ("nordvpn", "set", "autoconnect", "1"),
    "notify_on": ("nordvpn", "set", "notify", "1"),
    "firewall_on": ("nordvpn", "set", "firewall", "1"),
    "killswitch_off": ("nordvpn", "set", "killswitch", "0"),
    "killswitch_on": ("nordvpn", "set", "killswitch", "1"),
    "lan_discovery": ("nordvpn", "set", "lan-discovery", "1"),
    "dns": ("nordvpn", "set", "dns", *_NORD_DNS_IPS),
    ## cmds
    "connect": ("nordvpn", "connect"),
    "disconnect": ("nordvpn", "disconnect"),
    "login": ("nordvpn", "login"),
    "logout": ("nordvpn", "logout"),
    "status": ("nordvpn", "status"),
}

_NORD_PRE_LOGIN_SETTINGS = (
    _NORD_CMDS["analytics_off"],
    _NORD_CMDS["notify_on"],
    _NORD_CMDS["lan_discovery"],
    _NORD_CMDS["dns"],
    _NORD_CMDS["firewall_on"],
)
_NORD_PRE_CONNECT_SETTINGS = (*_NORD_PRE_LOGIN_SETTINGS, _NORD_CMDS["autoconnect_on"])

_NORD_POST_CONNECT_SETTINGS = (_NORD_CMDS["killswitch_on"],)

_NORD_FLAG_TO_PRE_RUN_CMDS = {
    "connect": _NORD_PRE_CONNECT_SETTINGS,
    "disconnect": (),
    "reconnect": _NORD_PRE_CONNECT_SETTINGS,  # TODO: is this right, also post for reconnect
    "status": (),
    "login": (),
    "logout": (),
}

_NORD_FLAG_TO_POST_RUN_CMDS = {
    "connect": _NORD_POST_CONNECT_SETTINGS,
    "disconnect": (_NORD_CMDS["killswitch_off"],),
    "reconnect": _NORD_POST_CONNECT_SETTINGS,
    "status": (),
    "login": _NORD_PRE_LOGIN_SETTINGS,
    "logout": (),
}

_NORD_SET_SETTING_NAME_TO_PRINTED = {
    # "Technology": "Technology",
    "Firewall": "firewall",
    # "Firewall Mark": "Firewall Mark",
    # "Routing": "Routing",
    "User Consent": "analytics",  # used to be Analytics
    "Kill Switch": "killswitch",
    # "Threat Protection Lite": "Threat Protection Lite",
    "Notify": "notify",
    "Auto-connect": "autoconnect",
    # "IPv6": "IPv6",
    # "Meshnet": "Meshnet",
    "DNS": "dns",
    "LAN Discovery": "lan-discovery",
}

_NORD_BOOL_STR_TO_ENABLE_STATUS = {
    "0": "disabled",
    "1": "enabled",
}

_NORD_PRINTED_SETTING_NAME_TO_PRINTED_VALUE_FORM_FUNC = {
    # "Technology" :"Technology",
    "firewall": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
    # "Firewall Mark": lambda *args: ,
    # "Routing": lambda *args: ,
    "analytics": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
    "killswitch": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
    # "Threat Protection Lite": lambda *args: ,
    "notify": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
    "autoconnect": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
    # "IPv6": lambda *args: ,
    # "Meshnet": lambda *args: ,
    "dns": lambda *args: ", ".join(args),
    "lan-discovery": lambda *args: _NORD_BOOL_STR_TO_ENABLE_STATUS[args[0]],
}


@functools.total_ordering
class DateTimeUTC:
    def __init__(self, datetime_: datetime.datetime | str | None = None, str_format: str = "%y%m%dT%H%M%SZ"):
        if datetime_ is None:
            self.datetime = datetime.datetime.now(datetime.timezone.utc)
        elif isinstance(datetime_, datetime.datetime):
            self.datetime = datetime_.replace(tzinfo=datetime.timezone.utc)
        elif isinstance(datetime_, str):
            self.datetime = datetime.datetime.strptime(datetime_, str_format).replace(tzinfo=datetime.timezone.utc)
        else:
            raise TypeError
        self.str_format = str_format
        self.str = self.datetime.strftime(self.str_format)

    def __add__(self, other: datetime.timedelta | float | int | str) -> DateTimeUTC:
        if isinstance(other, datetime.timedelta):
            return DateTimeUTC(self.datetime + other)
        if isinstance(other, float):
            return DateTimeUTC(self.datetime + datetime.timedelta(seconds=other))
        if isinstance(other, int):
            return DateTimeUTC(self.datetime + datetime.timedelta(seconds=other))
        if isinstance(other, str):
            return DateTimeUTC(self.datetime + datetime.timedelta(seconds=DateTimeUTC.str_time_duration_to_secs(other)))
        raise TypeError(f"Unexpected type(other)={type(other)}; other={other}")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DateTimeUTC):
            return self.datetime == other.datetime
        if isinstance(other, datetime.datetime):
            return self.datetime == other
        return False

    def __lt__(self, other: DateTimeUTC | datetime.datetime) -> bool:
        if isinstance(other, DateTimeUTC):
            return self.datetime < other.datetime
        if isinstance(other, datetime.datetime):
            return self.datetime < other
        raise TypeError(f"Unexpected type(other)={type(other)}; other={other}")

    def __sub__(
        self,
        other: DateTimeUTC | datetime.datetime | datetime.timedelta | float | int | str,
    ) -> DateTimeUTC | datetime.timedelta:
        if isinstance(other, DateTimeUTC):
            return self.datetime - other.datetime
        if isinstance(other, datetime.datetime):
            return self.datetime - other
        if isinstance(other, datetime.timedelta):
            return DateTimeUTC(self.datetime - other)
        if isinstance(other, float):
            return DateTimeUTC(self.datetime - datetime.timedelta(seconds=other))
        if isinstance(other, int):
            return DateTimeUTC(self.datetime - datetime.timedelta(seconds=other))
        if isinstance(other, str):
            return DateTimeUTC(self.datetime - datetime.timedelta(seconds=DateTimeUTC.str_time_duration_to_secs(other)))
        raise TypeError(f"Unexpected type(other)={type(other)}; other={other}")

    def __str__(self):
        return self.str

    @staticmethod
    def from_utc_time_str(s: str, str_format: str = "%y%m%dT%H%M%SZ") -> DateTimeUTC:
        return DateTimeUTC(datetime.datetime.strptime(s, str_format).replace(tzinfo=datetime.timezone.utc))

    @staticmethod
    def str_time_duration_to_secs(duration_str: str) -> int:
        try:
            if duration_str.endswith("h"):
                hours = float(duration_str[:-1])
                return int(math.ceil(hours * 3600))  # Convert hours to seconds, rounding up
            if duration_str.endswith("m"):
                mins = float(duration_str[:-1])
                return int(math.ceil(mins * 60))  # Convert mins to seconds, rounding up
            if duration_str.endswith("s"):
                return int(duration_str[:-1])
            return int(duration_str)
        except ValueError as e:
            logger.error(f"Invalid value for duration_str={duration_str}")
            raise e


def _delete_if_exists(file_path: str) -> bool:
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False


def _delete_locks_if_timed_out(locks, time_script_start, time_last_lock_str, lock_timeout_duration_rm):
    locks_deleted_log_msgs = []
    if time_last_lock_str is None:
        for lock in locks:
            if _delete_if_exists(lock):
                locks_deleted_log_msgs.append(f"Deleted lock={lock} as time_last_lock=None")
    else:
        time_last_lock = DateTimeUTC(time_last_lock_str)
        if (time_last_lock + lock_timeout_duration_rm) < time_script_start:
            for lock in locks:
                if _delete_if_exists(lock):
                    locks_deleted_log_msgs.append(
                        f"Deleted lock={lock} as time_script_start={time_script_start} > "
                        f"(time_last_lock={time_last_lock} + "
                        f"lock_timeout_duration_rm={lock_timeout_duration_rm})",
                    )
    return locks_deleted_log_msgs


def _log_stream_if_unempty(str_hdl: str, msg: str) -> None:
    if msg != "":
        logger.info(f"  {str_hdl}:\n{msg}")


def _log_cmd_w_output(cmd: Sequence[str], result, is_error: bool = True) -> None:
    if is_error:
        logger.error(f"failed to execute cmd: {' '.join(cmd)}")
    else:
        logger.info(f"executed cmd: {' '.join(cmd)}")
    _log_stream_if_unempty("stdout", _strip_nl_and_hyphens(result.stdout))
    _log_stream_if_unempty("stderr", _strip_nl_and_hyphens(result.stderr))


def subprocess_run_wrapped(
    cmd: Sequence[str],
    timeout: int = 20,
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            # ["/usr/bin/env", "bash", "-c", " ".join(cmd)], # to force interpreter
            capture_output=True,
            check=False,
            input=stdin_text,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.error("failed to execute cmd=%s within timeout=%s", cmd, timeout)
        raise


# TODO: it is not understood why this is necessary, i.e. where the excess chars come from
def _strip_nl_and_hyphens(s: str) -> str:
    out_s = s
    startswith = lambda s, delims: any(s.startswith(d) for d in delims)
    endswith = lambda s, delims: any(s.endswith(d) for d in delims)
    symbols = ("\n", "-", "/", "\\", "|")
    while startswith(out_s, symbols) or endswith(out_s, ("\n", "-")):
        out_s = out_s.strip()
        out_s = out_s.strip("\n")
        out_s = out_s.strip("-")
    return out_s


def _add_spaces_after_nls(s: str, n: int) -> str:
    return s.replace("\n", "\n" + (" " * n))


def _get_dict_from_json_file(json_file: str) -> dict:
    if not os.path.exists(json_file):
        return {}
    with path_utils.open_unix_safely(json_file) as f:
        ## TODO: this was somehow empty when space was maxxed, show error, also no nl maybe at end of file
        return json.load(f)  # type: ignore[no-any-return]


def _exec_cmd_w_error_handling(cmd: Sequence[str], print_on_succ: bool = False) -> bool:
    logger.info(f"executing cmd: {' '.join(cmd)}")
    result = subprocess_run_wrapped(cmd)
    if result.returncode == 0:
        if print_on_succ:
            _log_cmd_w_output(cmd, result, True)
        return True
    _log_cmd_w_output(cmd, result)
    return False


def _exec_nordvpn_set_cmd_w_error_handling(cmd: Sequence[str], settings: dict, print_on_succ: bool = False) -> bool:
    assert cmd[1] == "set", cmd
    assert cmd[2] in settings, (cmd, settings)
    cmd_setting_value_as_would_be_printed = _NORD_PRINTED_SETTING_NAME_TO_PRINTED_VALUE_FORM_FUNC[cmd[2]](*cmd[3:])
    current_setting_value = settings[cmd[2]]
    if cmd_setting_value_as_would_be_printed == current_setting_value:
        logger.info(f"skipping cmd: {cmd}; {cmd[2]}: {current_setting_value}")
        return True

    logger.info(f"executing cmd: {' '.join(cmd)}")
    result = subprocess_run_wrapped(cmd)
    if result.returncode == 0:
        if print_on_succ:
            _log_cmd_w_output(cmd, result, True)
        return True
    _log_cmd_w_output(cmd, result)
    return False


def _exec_cmd_w_exit_on_failure(cmd: Sequence[str], print_on_succ: bool = False) -> None:
    if not _exec_cmd_w_error_handling(cmd, print_on_succ):
        sys.exit(1)


def _exec_nordvpn_set_cmds_w_error_handling(
    cmds: Sequence[Sequence[str]],
    settings: dict,
    print_on_succ: bool = False,
) -> bool:
    for cmd in cmds:
        if not _exec_nordvpn_set_cmd_w_error_handling(cmd, settings, print_on_succ):
            return False
    return True


def connect(is_connected: bool = False) -> bool:
    if is_connected:
        logger.info("skipping connect due to already being connected.")
        return True
    return _exec_cmd_w_error_handling(_NORD_CMDS["connect"])


def get_settings() -> dict:
    cmd = ("nordvpn", "settings")
    result = subprocess_run_wrapped(cmd)
    settings_to_values = OrderedDict()
    if result.returncode == 0:
        setting_lines = _strip_nl_and_hyphens(result.stdout).split("\n")
        settings_w_value = []
        for line in setting_lines:
            ## accumulate multiline settings into single key
            if ": " in line or line.endswith(":"):
                settings_w_value.append(line)
            elif line in (
                "A new version of NordVPN is available!",
                "Please update the application.",
                "Please update the app.",
            ):
                logger.warning(line)
            else:
                if len(settings_w_value) == 0:
                    logger.error(f"unexpected line: settings_w_value={settings_w_value}; line={line}")
                    sys.exit(1)
                settings_w_value[-1] += f"\n{line}"
        for setting_w_value in settings_w_value:
            setting_w_value_colon_split = [e.strip() for e in setting_w_value.split(":")]
            assert len(setting_w_value_colon_split) == 2, (setting_w_value, setting_w_value_colon_split)
            if setting_w_value_colon_split[0] in _NORD_SET_SETTING_NAME_TO_PRINTED:
                settings_to_values[_NORD_SET_SETTING_NAME_TO_PRINTED[setting_w_value_colon_split[0]]] = (
                    setting_w_value_colon_split[1]
                )
        return settings_to_values
    _log_cmd_w_output(cmd, result)
    sys.exit(1)


def get_status() -> bool:
    cmd = _NORD_CMDS["status"]
    result = subprocess_run_wrapped(cmd)
    if result.returncode == 0:
        logger.info(_add_spaces_after_nls(_strip_nl_and_hyphens(result.stdout), 6))
    else:
        _log_cmd_w_output(cmd, result)
        sys.exit(1)

    if "Status: Connected" in result.stdout:
        return True
    if "Status: Disconnected" in result.stdout:
        return False
    if "Status: Connecting" in result.stdout:
        return False

    logger.fatal(f"unexpected stdout:\n{result.stdout}")
    assert False, result.stdout


def login(is_connected: bool = False) -> None:
    if is_connected:
        logger.info("skipping login due to already being connected.")
    else:
        if not _exec_cmd_w_error_handling(_NORD_CMDS["login"]):
            sys.exit(1)


def write_dict_to_file_as_json(json_dict: dict, filename: str) -> None:
    with path_utils.open_unix_safely(filename, "w") as f:
        json.dump(json_dict, f)


def _track_connect_result(
    connect_success: bool | None,
    vpn_status: dict,
    duration_fail_connect_until_notification: str,
    time_now: DateTimeUTC,
) -> bool:
    """Exit non zero (so cron notifies) once connecting has failed for long enough."""
    if connect_success is False:
        vpn_status["earliest_fail_connect"] = (
            time_now.str
            if vpn_status.get("earliest_fail_connect", None) is None
            else vpn_status["earliest_fail_connect"]
        )
        earliest_fail_connect = DateTimeUTC.from_utc_time_str(vpn_status["earliest_fail_connect"])
        if (time_now - earliest_fail_connect).total_seconds() > DateTimeUTC.str_time_duration_to_secs(
            duration_fail_connect_until_notification,
        ):
            msg = f"vpn disconnected for time > duration_fail_connect_until_notification={duration_fail_connect_until_notification}"
            logger.error(msg)
            vpn_status["earliest_fail_connect"] = None
            sys.exit(1)
    elif connect_success is True:
        vpn_status["earliest_fail_connect"] = None
    return connect_success is True


def _is_cron_job_paused(vpn_status: dict, time_now: DateTimeUTC) -> bool:
    pause_until = vpn_status.get("cron_pause_until", None)
    if pause_until is not None and time_now < DateTimeUTC(pause_until):
        logger.info(
            f"Skipping cron job;" f" time_now={time_now} < pause_until={pause_until};" " setting args.flag=status",
        )
        return True
    logger.info(f"Executing cron job; time_now={time_now} >= pause_until={pause_until}")
    vpn_status["cron_pause_until"] = None
    return False


def nordvpn_cmd_execution(flag, vpn_status, status, duration_fail_connect_until_notification, time_now):
    connect_success = None
    if flag == "connect":
        connect_success = connect(status)
    elif flag == "disconnect":
        _exec_cmd_w_exit_on_failure(_NORD_CMDS["disconnect"])
    elif flag == "login":
        login(status)
    elif flag == "logout":
        _exec_cmd_w_exit_on_failure(_NORD_CMDS["logout"], True)
    elif flag == "reconnect":
        _exec_cmd_w_exit_on_failure(_NORD_CMDS["disconnect"])
        connect_success = connect(get_status())
    else:
        assert False, flag

    return _track_connect_result(
        connect_success,
        vpn_status,
        duration_fail_connect_until_notification,
        time_now,
    )


def nordvpn_main(args: argparse.Namespace, vpn_status: dict) -> None:
    time_now = DateTimeUTC()

    logger.info("#### STATUS PRE CMD")
    status = get_status()

    if args.cron_job_pause_duration is not None:
        cron_pause_until = time_now + args.cron_job_pause_duration
        vpn_status["cron_pause_until"] = cron_pause_until.str
        logger.info(
            f"Set cron_pause_until={cron_pause_until};"
            f" time_now={time_now};"
            f" cron_pause_until_duration={args.cron_job_pause_duration}",
        )

    if args.cron_job and _is_cron_job_paused(vpn_status, time_now):
        args.flag = "status"

    pre_settings = get_settings()
    logger.info(
        "#### SETTINGS PRE CMD\n%s",
        "\n".join(
            f"      {setting_name}: {pre_value}"
            for setting_name, pre_value in sorted(list((k, v) for k, v in pre_settings.items()), key=lambda t: t[0])
        ),
    )
    logger.info("#### CHANGE SETTINGS PRE CMD")
    pre_connect_cmds = _NORD_FLAG_TO_PRE_RUN_CMDS[args.flag]
    if not _exec_nordvpn_set_cmds_w_error_handling(pre_connect_cmds, pre_settings):
        sys.exit(1)

    if args.flag == "status":
        if status:
            vpn_status["earliest_fail_connect"] = None
        return

    logger.info("#### CMD EXECUTION")
    nordvpn_cmd_execution(args.flag, vpn_status, status, args.duration_fail_connect_until_notification, time_now)

    logger.info("#### CHANGE SETTINGS POST CMD")
    post_settings = get_settings()
    post_connect_cmds = _NORD_FLAG_TO_POST_RUN_CMDS[args.flag]
    if not _exec_nordvpn_set_cmds_w_error_handling(post_connect_cmds, post_settings):
        sys.exit(1)

    final_settings = get_settings()

    logger.info("#### STATUS POST CMD")
    status = get_status()
    logger.info("#### SETTINGS CHANGED")
    for setting_name, pre_value in sorted(list((k, v) for k, v in pre_settings.items()), key=lambda t: t[0]):
        final_value = final_settings[setting_name]
        if pre_value != final_value:
            logger.info(f"changed '{setting_name}' from '{pre_value}' to '{final_value}'")


##########
## ProtonVPN (WireGuard via wg-quick)
##
## Proton has no always-on daemon like NordVPN's, so there is no client to ask for
## state: connecting is `wg-quick up <iface>` against a config generated at
## account.protonvpn.com, and "am I connected" is answered by the age of the last
## WireGuard handshake. wg-quick, wg and nft all need root, hence `sudo -n`; see
## _PROTON_SUDOERS_HINT for the sudoers entry that keeps the cron job working.

_VPN_PROVIDERS = ("nordvpn", "protonvpn")
_VPN_PROVIDER_DEFAULT = "protonvpn"
_VPN_CFG_FILE_DEFAULT = os.path.expanduser("~/.config/vpn-py/config.json")

_PROTON_IFACE_DEFAULT = "proton"
_PROTON_SETUP_STATE = "/etc/vpn-py/setup.json"
## realpath, not abspath: vpn.py is reached through a symlink in py/bin, and the
## setup script sits next to the real file (same convention as get_default_log_paths)
_PROTON_SETUP_SCRIPT = os.path.join(os.path.dirname(os.path.realpath(__file__)), "setup-protonvpn-host.sh")
## Where a downloaded Proton config plausibly landed, most likely first
_PROTON_CFG_SEARCH_DIRS = ("~/Downloads", "~", ".")
_PROTON_NFT_TABLE = "vpn-killswitch"
_PROTON_NFT_RULESET_DEFAULT = "/etc/vpn-py/killswitch.nft"
## A peer is considered live if it shook hands within this window; WireGuard
## re-keys every 120s, so anything older than that means the tunnel is dead.
_PROTON_HANDSHAKE_STALE_SECS = 180
_PROTON_HANDSHAKE_WAIT_SECS = 15
_PROTON_SUDOERS_HINT = (
    "root is required for wg-quick/wg/nft; run setup-protonvpn-host.sh to install "
    "/etc/sudoers.d/vpn-py, or the cron job will fail on the password prompt"
)


def _proton_sudo(*args: str) -> tuple[str, ...]:
    ## -n so a missing sudoers entry fails loudly instead of hanging on a password prompt
    return ("sudo", "-n", *args)


def _proton_iface_exists(iface: str) -> bool:
    return subprocess_run_wrapped(("ip", "link", "show", "dev", iface)).returncode == 0


def _proton_get_handshake_age_secs(iface: str) -> float | None:
    result = subprocess_run_wrapped(_proton_sudo("wg", "show", iface, "latest-handshakes"))
    if result.returncode != 0:
        _log_cmd_w_output(("wg", "show", iface, "latest-handshakes"), result)
        return None
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    ages = []
    for line in result.stdout.strip().split("\n"):
        fields = line.split()
        if len(fields) != 2 or fields[1] == "0":
            continue
        ages.append(now - int(fields[1]))
    return min(ages) if ages else None


def _proton_get_endpoint(iface: str) -> str | None:
    result = subprocess_run_wrapped(_proton_sudo("wg", "show", iface, "endpoints"))
    if result.returncode != 0:
        return None
    for line in result.stdout.strip().split("\n"):
        fields = line.split()
        if len(fields) == 2 and fields[1] != "(none)":
            return fields[1]
    return None


def proton_get_status(iface: str) -> bool:
    if not _proton_iface_exists(iface):
        logger.info(f"Status: Disconnected\n      Interface: {iface} (does not exist)")
        return False

    handshake_age = _proton_get_handshake_age_secs(iface)
    endpoint = _proton_get_endpoint(iface)
    if handshake_age is None:
        logger.info(f"Status: Connecting\n      Interface: {iface}\n      Server: {endpoint}")
        return False
    if handshake_age > _PROTON_HANDSHAKE_STALE_SECS:
        logger.info(
            f"Status: Disconnected\n"
            f"      Interface: {iface}\n"
            f"      Server: {endpoint}\n"
            f"      Last handshake: {int(handshake_age)}s ago (stale)",
        )
        return False

    logger.info(
        f"Status: Connected\n"
        f"      Interface: {iface}\n"
        f"      Server: {endpoint}\n"
        f"      Last handshake: {int(handshake_age)}s ago",
    )
    return True


def _proton_wait_for_handshake(iface: str) -> bool:
    ## wg-quick returns as soon as the interface is configured, which is before the
    ## first handshake; without this a connect would report success on a dead tunnel.
    deadline = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=_PROTON_HANDSHAKE_WAIT_SECS,
    )
    while datetime.datetime.now(datetime.timezone.utc) < deadline:
        handshake_age = _proton_get_handshake_age_secs(iface)
        if handshake_age is not None and handshake_age <= _PROTON_HANDSHAKE_STALE_SECS:
            return True
        time.sleep(0.5)
    return False


def proton_connect(iface: str, is_connected: bool = False) -> bool:
    if is_connected:
        logger.info("skipping connect due to already being connected.")
        return True

    ## An interface left over from a dead tunnel would make `wg-quick up` fail
    if _proton_iface_exists(iface):
        logger.info(f"tearing down stale interface {iface} before connecting")
        _exec_cmd_w_error_handling(_proton_sudo("wg-quick", "down", iface))

    if not _exec_cmd_w_error_handling(_proton_sudo("wg-quick", "up", iface)):
        logger.error(_PROTON_SUDOERS_HINT)
        return False

    if not _proton_wait_for_handshake(iface):
        logger.error(f"interface {iface} is up but no handshake within {_PROTON_HANDSHAKE_WAIT_SECS}s")
        return False
    return True


def proton_disconnect(iface: str) -> bool:
    if not _proton_iface_exists(iface):
        logger.info(f"skipping disconnect; interface {iface} does not exist")
        return True
    return _exec_cmd_w_error_handling(_proton_sudo("wg-quick", "down", iface))


def proton_killswitch_is_up() -> bool:
    return (
        subprocess_run_wrapped(
            _proton_sudo("nft", "list", "table", "inet", _PROTON_NFT_TABLE),
        ).returncode
        == 0
    )


def proton_killswitch_up(ruleset_path: str) -> bool:
    """Drop every packet that is not going through the tunnel, to the LAN or to lo.

    The ruleset is a fixed root owned file written by setup-protonvpn-host.sh rather
    than something generated here: that way the sudoers entry is a single exact
    command, and a process running as this user cannot rewrite what gets loaded.

    Docker's forward path is deliberately untouched. Only the output hook is filtered,
    so containers keep their own networking - and the qBittorrent container runs its
    own kill switch anyway.
    """
    if not os.path.exists(ruleset_path):
        logger.error(f"cannot enable killswitch; no ruleset at {ruleset_path}")
        logger.error("run setup-protonvpn-host.sh to install it")
        return False
    if not _exec_cmd_w_error_handling(_proton_sudo("nft", "-f", ruleset_path)):
        logger.error(_PROTON_SUDOERS_HINT)
        return False
    logger.info(f"killswitch enabled from {ruleset_path}")
    return True


def proton_killswitch_down() -> bool:
    if not proton_killswitch_is_up():
        logger.info("skipping killswitch removal; not enabled")
        return True
    return _exec_cmd_w_error_handling(
        _proton_sudo("nft", "delete", "table", "inet", _PROTON_NFT_TABLE),
    )


##########
## Provider selection and ProtonVPN host setup
##
## The provider is sticky: cron runs `vpn.py --cron-job --connect` with no flags, so
## switching has to persist somewhere rather than live in the command line. It is not
## kept in the status file, which lives in /tmp and does not survive a reboot.


def get_provider(file_cfg: str) -> str:
    return _get_dict_from_json_file(file_cfg).get("vpn_provider", _VPN_PROVIDER_DEFAULT)  # type: ignore[no-any-return]


def _disconnect_provider(provider: str, args: argparse.Namespace) -> None:
    """Best effort teardown of the provider being switched away from."""
    if provider == "protonvpn":
        if proton_killswitch_is_up():
            proton_killswitch_down()
        proton_disconnect(args.proton_iface)
    elif provider == "nordvpn":
        if shutil.which("nordvpn") is None:
            logger.info("skipping nordvpn teardown; the nordvpn client is not installed")
            return
        _exec_cmd_w_error_handling(_NORD_CMDS["disconnect"])


def set_provider(args: argparse.Namespace) -> None:
    provider_new = args.set_provider
    provider_old = get_provider(args.file_cfg)

    if provider_old == provider_new:
        logger.info(f"vpn provider is already '{provider_new}'")
    else:
        ## Leaving the old tunnel up would leave two clients fighting over the default route
        logger.info(f"#### SWITCHING PROVIDER '{provider_old}' -> '{provider_new}'")
        _disconnect_provider(provider_old, args)

        cfg = _get_dict_from_json_file(args.file_cfg)
        cfg["vpn_provider"] = provider_new
        os.makedirs(os.path.dirname(args.file_cfg), exist_ok=True)
        write_dict_to_file_as_json(cfg, args.file_cfg)
        logger.info(f"vpn provider set to '{provider_new}' in {args.file_cfg}")

    if provider_new == "protonvpn":
        problems, warnings = proton_check_setup(args)
        for warning in warnings:
            logger.warning(warning)
        if problems:
            proton_log_setup_instructions(problems)
        else:
            logger.info("protonvpn is set up on this host; connect with: vpn.py --connect")


def _proton_sudo_works(iface: str) -> bool:
    """Whether the NOPASSWD entry vpn.py depends on is in place and matches."""
    result = subprocess_run_wrapped(_proton_sudo("wg", "show", iface, "dump"))
    return "password" not in result.stderr.lower()


def proton_check_setup(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    """Reasons protonvpn cannot work here (fatal), and things merely worth saying.

    Readiness is probed rather than read off the state file alone: hosts set up before
    the state file existed are working installs, and failing those would take a running
    tunnel down at the next cron tick.
    """
    problems: list[str] = []
    warnings: list[str] = []

    sudo_works = _proton_sudo_works(args.proton_iface)

    ## /etc/wireguard is 0700 root, so an unprivileged vpn.py cannot stat the config to
    ## tell "not set up" from "not allowed to look"; the state file is the readable record.
    state = _get_dict_from_json_file(_PROTON_SETUP_STATE)
    if state == {}:
        if not sudo_works:
            problems.append(f"this host has not been initialised (no {_PROTON_SETUP_STATE})")
            return problems, warnings
        warnings.append(
            f"no {_PROTON_SETUP_STATE}; this host was set up before it was recorded. "
            "Re-run `vpn.py --setup` to record it (nothing else changes)",
        )
    else:
        if state.get("iface") != args.proton_iface:
            problems.append(
                f"setup installed interface '{state.get('iface')}' but --proton-iface is '{args.proton_iface}'",
            )
        user = getpass.getuser()
        if state.get("user") != user:
            problems.append(f"setup granted sudo to '{state.get('user')}' but vpn.py is running as '{user}'")

    if not sudo_works:
        problems.append("sudo asks for a password; the NOPASSWD entry is missing or does not match")
    if args.killswitch and not os.path.exists(args.killswitch_ruleset):
        problems.append(f"killswitch ruleset {args.killswitch_ruleset} is missing")

    return problems, warnings


def proton_log_setup_instructions(problems: Sequence[str]) -> None:
    logger.error("protonvpn is not ready on this host:")
    for problem in problems:
        logger.error(f"  - {problem}")
    logger.error("initialise it with:")
    logger.error("    vpn.py --setup <proton-wireguard.conf>")
    logger.error("    vpn.py --setup                  # picks it up from ~/Downloads if unambiguous")
    logger.error(f"that runs, under sudo, {_PROTON_SETUP_SCRIPT}")
    logger.error("which lists its prerequisites, then installs the WireGuard config, the killswitch")
    logger.error("ruleset and the NOPASSWD sudoers entry. Re-run it after fixing anything it reports.")


def proton_find_candidate_configs() -> list[str]:
    """WireGuard configs sitting where a browser download would have left them."""
    candidates = {}
    for dir_search in _PROTON_CFG_SEARCH_DIRS:
        dir_expanded = os.path.expanduser(dir_search)
        if not os.path.isdir(dir_expanded):
            continue
        for name in sorted(os.listdir(dir_expanded)):
            if not name.endswith(".conf"):
                continue
            path = os.path.realpath(os.path.join(dir_expanded, name))
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            if "[Peer]" in content and "Endpoint" in content:
                candidates[path] = None
    return list(candidates)


def _proton_resolve_setup_config(cfg_src: str) -> str | None:
    """The config to install: the one named, or the only plausible download found."""
    if cfg_src != "":
        if os.path.isfile(cfg_src):
            return cfg_src
        logger.error(f"no such config file: {cfg_src}")
        logger.error("get one from https://account.protonvpn.com -> Downloads -> WireGuard configuration")
        return None

    candidates = proton_find_candidate_configs()
    if len(candidates) == 1:
        logger.info(f"using the only WireGuard config found: {candidates[0]}")
        return candidates[0]

    if not candidates:
        logger.error(f"no WireGuard config found in {', '.join(_PROTON_CFG_SEARCH_DIRS)}")
        logger.error("get one from https://account.protonvpn.com -> Downloads -> WireGuard")
        logger.error("configuration (pick a P2P server, enable NAT-PMP for port forwarding),")
        logger.error("then: vpn.py --setup <path to the downloaded .conf>")
        return None

    logger.error(f"several WireGuard configs found in {', '.join(_PROTON_CFG_SEARCH_DIRS)}:")
    for candidate in candidates:
        logger.error(f"  - {candidate}")
    logger.error("re-run naming the one to install: vpn.py --setup <path>")
    return None


def proton_setup(args: argparse.Namespace) -> bool:
    if not os.path.isfile(_PROTON_SETUP_SCRIPT):
        logger.error(f"setup script not found at {_PROTON_SETUP_SCRIPT}")
        logger.error("it ships next to vpn.py; pull the whole tools/vpn directory")
        return False

    cfg_src = _proton_resolve_setup_config(args.setup)
    if cfg_src is None:
        return False

    cmd = (
        "sudo",
        _PROTON_SETUP_SCRIPT,
        "--iface",
        args.proton_iface,
        "--user",
        getpass.getuser(),
        cfg_src,
    )
    logger.info(f"executing cmd: {' '.join(cmd)}")
    logger.info("(sudo may prompt for your password; the setup itself is not run from cron)")
    ## Not captured: the script is interactive (sudo prompt) and its own output is the
    ## prerequisite report the user needs to read.
    if subprocess.run(cmd, check=False).returncode != 0:
        logger.error("setup failed; fix what it reported above and re-run: vpn.py --setup")
        return False

    problems, _ = proton_check_setup(args)
    if problems:
        proton_log_setup_instructions(problems)
        return False

    logger.info("protonvpn is ready; connect with: vpn.py --connect")
    return True


def _protonvpn_exec_flag(flag: str, iface: str, status: bool) -> bool | None:
    """Run the requested command; None when it was not a connect style command."""
    if flag == "connect":
        return proton_connect(iface, status)
    if flag == "reconnect":
        proton_disconnect(iface)
        return proton_connect(iface)
    if flag == "disconnect":
        ## Only an explicit disconnect lifts the killswitch; a failed connect leaves it
        ## in place, so a dead tunnel means no traffic rather than traffic in the clear.
        proton_killswitch_down()
        if not proton_disconnect(iface):
            sys.exit(1)
        return None
    raise ValueError(flag)


def protonvpn_main(args: argparse.Namespace, vpn_status: dict) -> None:
    time_now = DateTimeUTC()
    iface = args.proton_iface

    ## Fail here with instructions rather than deeper down with a sudo password
    ## prompt or a missing config, which is what an uninitialised host looks like.
    problems, warnings = proton_check_setup(args)
    for warning in warnings:
        logger.warning(warning)
    if problems:
        proton_log_setup_instructions(problems)
        if args.flag != "status":
            sys.exit(1)

    logger.info("#### STATUS PRE CMD")
    status = proton_get_status(iface)

    if args.cron_job_pause_duration is not None:
        cron_pause_until = time_now + args.cron_job_pause_duration
        vpn_status["cron_pause_until"] = cron_pause_until.str
        logger.info(
            f"Set cron_pause_until={cron_pause_until};"
            f" time_now={time_now};"
            f" cron_pause_until_duration={args.cron_job_pause_duration}",
        )

    if args.cron_job and _is_cron_job_paused(vpn_status, time_now):
        args.flag = "status"

    if args.flag == "status":
        if status:
            vpn_status["earliest_fail_connect"] = None
        return

    if args.flag in ("login", "logout"):
        ## Proton WireGuard configs carry their own key; there is no session to manage
        logger.info(f"nothing to do for '{args.flag}'; a WireGuard config needs no login")
        return

    logger.info("#### CMD EXECUTION")
    connect_success = _protonvpn_exec_flag(args.flag, iface, status)

    if connect_success and args.killswitch and not proton_killswitch_up(args.killswitch_ruleset):
        sys.exit(1)

    _track_connect_result(
        connect_success,
        vpn_status,
        args.duration_fail_connect_until_notification,
        time_now,
    )

    logger.info("#### STATUS POST CMD")
    proton_get_status(iface)


def _run_selected_mode(args: argparse.Namespace, vpn_status: dict) -> None:
    """Provider switching and host setup pre-empt the connect/disconnect commands."""
    if args.set_provider is not None:
        set_provider(args)
        return
    if args.setup is not None:
        if not proton_setup(args):
            sys.exit(1)
        return
    if args.vpn_provider == "nordvpn":
        nordvpn_main(args, vpn_status)
    elif args.vpn_provider == "protonvpn":
        protonvpn_main(args, vpn_status)
    else:
        raise ValueError(args.vpn_provider)


def main(argparse_args: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cron-job", action="store_true")
    parser.add_argument("--cron-job-pause-duration", "--pause")
    parser.add_argument("--duration-fail-connect-until-notification", "--dfc", default="5m")
    file_status = f'{os.environ["TEMP"]}/vpn-status.json' if os.name == "nt" else "/tmp/vpn-status.json"
    parser.add_argument("--file-out-vpn-status", default=file_status)
    parser.add_argument("--lock-timeout-duration-rm", default="120s")
    parser.add_argument("--log")
    parser.add_argument("--log-cfg", default=_LOG_CFG_DEFAULT, help="Log cfg; empty str uses LogManager default cfg")
    parser.add_argument(
        "--file-cfg",
        default=_VPN_CFG_FILE_DEFAULT,
        help="where the selected vpn provider is remembered",
    )
    parser.add_argument(
        "--vpn-provider",
        "--vpn",
        choices=_VPN_PROVIDERS,
        default=None,
        help="override the remembered provider for this run only",
    )
    parser.add_argument(
        "--set-provider",
        choices=_VPN_PROVIDERS,
        help="switch provider persistently (disconnects the previous one)",
    )
    parser.add_argument(
        "--setup",
        nargs="?",
        const="",
        default=None,
        metavar="CONFIG",
        help="initialise this host for protonvpn from a WireGuard config (searches ~/Downloads if omitted)",
    )
    parser.add_argument(
        "--proton-iface",
        default=_PROTON_IFACE_DEFAULT,
        help="wg-quick interface, i.e. /etc/wireguard/<iface>.conf",
    )
    parser.add_argument(
        "--killswitch",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="drop non tunnel traffic once connected (protonvpn only)",
    )
    parser.add_argument(
        "--killswitch-ruleset",
        default=_PROTON_NFT_RULESET_DEFAULT,
        help="nft ruleset installed by setup-protonvpn-host.sh",
    )
    flag_group = parser.add_mutually_exclusive_group()
    parser.set_defaults(flag="status")
    flag_group.add_argument("--connect", "-c", action="store_const", const="connect", dest="flag")
    flag_group.add_argument("--disconnect", "-d", action="store_const", const="disconnect", dest="flag")
    flag_group.add_argument("--login", "--li", "-l", action="store_const", const="login", dest="flag")
    flag_group.add_argument("--logout", "--lo", action="store_const", const="logout", dest="flag")
    flag_group.add_argument("--reconnect", "-r", action="store_const", const="reconnect", dest="flag")
    flag_group.add_argument("--status", "-s", action="store_const", const="status", dest="flag")
    args = parser.parse_args(argparse_args)

    log_manager.LogManager.setup_logger(globals(), log_cfg=args.log_cfg, log_file=args.log)

    ## An explicit --vpn wins for this run; otherwise use whatever --set-provider stored
    if args.vpn_provider is None:
        args.vpn_provider = get_provider(args.file_cfg)
    logger.debug(f"vpn_provider={args.vpn_provider}")

    time_script_start = DateTimeUTC()

    files_to_lock = (_LOG_FILE_PATH, args.file_out_vpn_status)
    lm = lock_manager.LockManager(*files_to_lock, timeout=10)

    vpn_status = _get_dict_from_json_file(args.file_out_vpn_status)  # write must be atomic or this can get corrupted

    locks_deleted_log_msgs = _delete_locks_if_timed_out(
        lm.lock_names,
        time_script_start,
        vpn_status.get("time_last_lock", None),
        args.lock_timeout_duration_rm,
    )

    with lm:
        time_lock = DateTimeUTC()
        vpn_status["time_last_lock"] = time_lock.str

        logger.debug(f"argparse args:\n{argparse_utils.parsed_args_to_str(args)}")
        for msg in locks_deleted_log_msgs:
            logger.warning(msg)
        logger.debug(f"files_locked={files_to_lock} at time={time_lock}")
        if args.cron_job:
            logger.info("Start automated execution by cron job")

        try:
            _run_selected_mode(args, vpn_status)
        finally:
            write_dict_to_file_as_json(vpn_status, args.file_out_vpn_status)


if __name__ == "__main__":
    main()
