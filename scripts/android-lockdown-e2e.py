#!/usr/bin/env python3
"""Android 15 independent-UID VPN process-death and OS lockdown regression.

Run only INSIDE the same live emulator after emulator-e2e.py has completed.
Never equate writing Settings.Secure keys with active lockdown: first prove an
unconnected independent UID is blocked, then check connected traffic and crash.
"""
import importlib.util
import json
import re
import time
from pathlib import Path

SCRIPT = Path(__file__).with_name("emulator-e2e.py")
spec = importlib.util.spec_from_file_location("omega_base_e2e", SCRIPT)
omega = importlib.util.module_from_spec(spec)
spec.loader.exec_module(omega)

OUT = Path("e2e-results")
OUT.mkdir(exist_ok=True)
RESULT = {"test":"android_os_lockdown_and_forced_app_process_death",
          "status":"NOT_RUN","package":"dev.omega.vpn"}
PKG = "dev.omega.vpn"
KEYS = ("always_on_vpn_app","always_on_vpn_lockdown")


def shell(*args, timeout=25):
    return omega.adb("shell", *args, timeout=timeout)


def settings_get(key):
    response = shell("settings","get","secure",key)
    if response.returncode:
        raise RuntimeError("read_android_secure_settings_failed")
    return response.stdout.strip()


def settings_set(key, value):
    if value in ("null","None",""):
        result = shell("settings","delete","secure",key)
    else:
        result = shell("settings","put","secure",key,str(value))
    if result.returncode:
        raise RuntimeError("write_android_secure_settings_failed")


def record():
    (OUT/"lockdown-results.json").write_text(json.dumps(
        RESULT, indent=2, ensure_ascii=False))
    print(json.dumps(RESULT, ensure_ascii=False), flush=True)


def main():
    originals = {}
    try:
        # Requires debug emulator with root. Physical phone is never modified.
        rooted = omega.adb("root")
        if rooted.returncode:
            raise RuntimeError("emulator_adb_root_not_available")
        omega.adb("wait-for-device",timeout=35)
        if shell("id","-u").stdout.strip() != "0":
            raise RuntimeError("emulator_root_not_active")

        for key in KEYS:
            originals[key] = settings_get(key)
        RESULT["original_lockdown_requested"] = originals.get(KEYS[1]) == "1"

        baseline = omega.probe("LOCK_BASELINE",wait=27)
        RESULT["baseline_https"] = baseline["result"]
        RESULT["baseline_default_vpn"] = baseline.get("vpn_default",False)
        if baseline["result"] != "PASS" or baseline.get("vpn_default",False):
            raise RuntimeError("lockdown_test_no_clean_direct_baseline")

        # The shell can configure Android's secure settings on THIS ephemeral
        # emulator; this is neither a supported API for the app nor a phone fix.
        # Settings.Secure readback alone does not activate VPN lockdown.
        # Ask ConnectivityService to apply it, then independently probe.
        help_result = shell("cmd", "connectivity", "help")
        RESULT["connectivity_shell_supports_always_on"] = (
            "set-always-on-vpn" in (help_result.stdout + help_result.stderr)
        )
        if not RESULT["connectivity_shell_supports_always_on"]:
            RESULT["status"] = "INCONCLUSIVE_NO_SUPPORTED_LOCKDOWN_CONTROL"
            raise RuntimeError("android_connectivity_shell_always_on_unavailable")
        applied = shell("cmd", "connectivity", "set-always-on-vpn",
                        "--user", "0", "--package", PKG, "--lockdown", "true")
        RESULT["connectivity_shell_command_accepted"] = applied.returncode == 0
        if applied.returncode:
            raise RuntimeError("android_connectivity_shell_always_on_rejected")
        time.sleep(5)
        RESULT["keys_readback_match"] = (settings_get(KEYS[0]) == PKG and
                                         settings_get(KEYS[1]) == "1")
        if not RESULT["keys_readback_match"]:
            raise RuntimeError("lockdown_settings_not_persisted")

        # Must prove ACTUAL egress blockade while no VPN is connected.
        # A Settings.Secure readback alone is not evidence of enforcement.
        offline = omega.probe("LOCK_OFFLINE",wait=25)
        RESULT["offline_https"] = offline["result"]
        RESULT["offline_vpn_default"] = offline.get("vpn_default",False)
        RESULT["lockdown_actually_enforced"] = offline["result"] == "FAIL"
        if not RESULT["lockdown_actually_enforced"]:
            RESULT["status"] = "INCONCLUSIVE_LOCKDOWN_NOT_APPLIED"
            raise RuntimeError("android_lockdown_not_demonstrated")

        # VPN was disconnected after the preceding standard Android E2E.
        if not omega.click("Подключиться к выбранному узлу",timeout=25):
            raise RuntimeError("lockdown_vpn_ui_reconnect_button_missing")
        time.sleep(12)
        online = omega.probe("LOCK_CONNECTED",wait=28)
        RESULT["vpn_https"] = online["result"]
        RESULT["vpn_default"] = online.get("vpn_default",False)
        RESULT["vpn_egress_not_baseline"] = bool(
            online["result"]=="PASS" and
            online.get("ip_fingerprint")!=baseline.get("ip_fingerprint"))
        if (online["result"]!="PASS" or not RESULT["vpn_default"] or
                not RESULT["vpn_egress_not_baseline"]):
            RESULT["status"]="FAIL_VPN_CANNOT_CONNECT_IN_LOCKDOWN"
            raise RuntimeError("vpn_transport_blocked_by_android_lockdown")

        # Kill the VPN APP process abruptly (not a user-initiated disconnect).
        # The VPN must not silently revert to direct HTTPS during process death.
        pid_result = shell("pidof",PKG)
        pids = pid_result.stdout.strip().split()
        if pid_result.returncode or len(pids) != 1 or not pids[0].isdigit():
            raise RuntimeError("vpn_process_pid_not_unique")
        if shell("kill","-9",pids[0]).returncode:
            raise RuntimeError("vpn_app_process_kill_failed")
        time.sleep(4)
        dead = omega.probe("LOCK_CRASH",wait=28)
        RESULT["after_crash_https"] = dead["result"]
        RESULT["after_crash_default_vpn"] = dead.get("vpn_default",False)
        RESULT["baseline_ip_leaked"] = bool(
            dead["result"]=="PASS" and
            dead.get("ip_fingerprint")==baseline.get("ip_fingerprint"))
        if dead["result"]=="PASS":
            RESULT["status"]="CRITICAL_CRASH_DIRECT_OR_UNEXPECTED_EGRESS"
            raise RuntimeError("lockdown_failed_to_block_egress_after_crash")
        RESULT["status"]="PASS_LOCKDOWN_PROCESS_DEATH"
    except Exception as error:
        RESULT["error_class"] = str(error)  # no secrets in exception codes
        if RESULT["status"] == "NOT_RUN":
            RESULT["status"]="INCONCLUSIVE_OR_FAIL"
        raise
    finally:
        # Always restore the emulator's old VPN settings, including on failure.
        failures = []
        if RESULT.get("connectivity_shell_command_accepted",False):
            try:
                previous = originals.get(KEYS[0], "null")
                shell("cmd", "connectivity", "set-always-on-vpn",
                      "--user", "0", "--package", previous,
                      "--lockdown",
                      "true" if originals.get(KEYS[1])=="1" else "false")
            except Exception:
                failures.append("connectivity_service_restore")
        for key,value in originals.items():
            try:
                settings_set(key,value)
            except Exception:
                failures.append(key)
        RESULT["settings_restored"] = not failures and len(originals)==len(KEYS)
        if failures:
            RESULT["settings_restore_failed"] = failures
        record()


if __name__ == "__main__":
    main()
