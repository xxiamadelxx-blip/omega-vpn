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



def _bounds(node):
    corners = [int(x) for x in re.findall(r"\d+", node.get("bounds", ""))]
    if len(corners) != 4:
        return None
    return corners


def _mid_y(node):
    b = _bounds(node)
    return (b[1] + b[3]) // 2 if b else -1


def _settings_nodes():
    return omega.ui()


def _find_label(nodes, needle):
    return next((n for n in nodes
                 if needle.lower() in (n.get("text", "") + " " +
                                       n.get("content-desc", "")).lower()), None)


def _settings_snapshot(stage):
    omega.screenshot("lockdown-" + stage)
    nodes = _settings_nodes()
    # Record only fixed, non-sensitive UI indicators, not arbitrary Settings text.
    RESULT["settings_ui_" + stage] = {
        "nodes": len(nodes),
        "vpn_page": bool(_find_label(nodes, "VPN")),
        "omega_entry": bool(_find_label(nodes, "Ω VPN") or
                            _find_label(nodes, "Omega VPN")),
        "always_on_toggle": bool(_find_label(nodes, "Always-on VPN")),
        "block_without_toggle": bool(_find_label(nodes, "Block connections without VPN"))
    }
    return nodes


def _tap_setting(needle, expect=None):
    nodes = _settings_nodes()
    label = _find_label(nodes, needle)
    if not label:
        raise RuntimeError("android_settings_missing_" + needle.lower().replace(" ", "_").replace("-", "_"))
    y = _mid_y(label)
    switches = [n for n in nodes
                if ("Switch" in n.get("class", "") or
                    "CheckBox" in n.get("class", "")) and
                abs(_mid_y(n) - y) < 58 and _bounds(n)]
    target = min(switches, key=lambda n: abs(_mid_y(n) - y)) if switches else label
    if expect is not None and target.get("checked") == ("true" if expect else "false"):
        return
    if not omega.click_node(target):
        raise RuntimeError("android_settings_toggle_click_failed")
    time.sleep(1)
    if expect:
        # Android may show a confirmation dialog for network lockdown.
        dialog = _settings_nodes()
        for reply in ("Turn on", "OK", "Allow"):
            candidate = _find_label(dialog, reply)
            if candidate and omega.click_node(candidate):
                time.sleep(1)
                break
    refreshed = _settings_nodes()
    fresh_label = _find_label(refreshed, needle)
    if not fresh_label:
        raise RuntimeError("android_settings_toggle_disappeared")
    y = _mid_y(fresh_label)
    checked = [n.get("checked") for n in refreshed
               if ("Switch" in n.get("class", "") or
                   "CheckBox" in n.get("class", "")) and
               abs(_mid_y(n) - y) < 58]
    if expect is not None and checked and ("true" if expect else "false") not in checked:
        raise RuntimeError("android_settings_toggle_not_applied")


def enable_lockdown_via_settings_ui():
    # Use actual Android Settings UI, not merely Settings.Secure writes.
    started = shell("am", "start", "-a", "android.settings.VPN_SETTINGS")
    if started.returncode:
        raise RuntimeError("android_vpn_settings_intent_failed")
    time.sleep(3)
    nodes = _settings_snapshot("vpn-list")
    entry = _find_label(nodes, "Ω VPN") or _find_label(nodes, "Omega VPN")
    if not entry:
        raise RuntimeError("android_settings_omega_vpn_entry_not_found")
    center_y = _mid_y(entry)
    candidates = [n for n in nodes if _bounds(n) and
                  abs(_mid_y(n)-center_y) < 60 and
                  ("Settings" in n.get("content-desc", "") or
                   "settings" in n.get("resource-id", "").lower())]
    if candidates:
        clicked = omega.click_node(candidates[-1])
    else:
        # Android stock VPN Settings row uses a gear on the right.
        size = shell("wm", "size").stdout
        m = re.search(r"(\d+)x(\d+)", size)
        if not m:
            raise RuntimeError("android_settings_screen_dimensions_missing")
        clicked = shell("input", "tap", str(int(m.group(1))-65),
                        str(center_y)).returncode == 0
    if not clicked:
        raise RuntimeError("android_vpn_settings_gear_click_failed")
    time.sleep(2)
    nodes = _settings_snapshot("vpn-options")
    if not _find_label(nodes, "Always-on VPN"):
        raise RuntimeError("android_vpn_settings_always_on_toggle_not_found")
    _tap_setting("Always-on VPN", expect=True)
    _tap_setting("Block connections without VPN", expect=True)
    _settings_snapshot("lockdown-enabled")
    RESULT["lockdown_enabled_via_android_settings_ui"] = True
    shell("input", "keyevent", "KEYCODE_HOME")


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

        # Settings.Secure key writes do not notify ConnectivityService.
        # Change system VPN options through real Android Settings screens.
        enable_lockdown_via_settings_ui()
        time.sleep(3)
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
        if RESULT.get("lockdown_enabled_via_android_settings_ui",False):
            try:
                shell("am", "start", "-a", "android.settings.VPN_SETTINGS")
                time.sleep(2)
                nodes = _settings_nodes()
                entry = _find_label(nodes, "Ω VPN") or _find_label(nodes, "Omega VPN")
                if entry:
                    y = _mid_y(entry)
                    size = re.search(r"(\d+)x(\d+)", shell("wm", "size").stdout)
                    if size:
                        shell("input", "tap", str(int(size.group(1))-65), str(y))
                        time.sleep(2)
                        _tap_setting("Block connections without VPN", expect=False)
                        _tap_setting("Always-on VPN", expect=False)
                shell("input", "keyevent", "KEYCODE_HOME")
            except Exception:
                failures.append("vpn_settings_ui_restore")
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
