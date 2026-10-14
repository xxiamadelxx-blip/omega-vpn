#!/usr/bin/env python3
"""Android 15 emulator, system VpnService, HTTPS in independent app UID."""
import json
import re
import secrets
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

OUT = Path("e2e-results")
OUT.mkdir(exist_ok=True)
SALT = secrets.token_hex(16)  # kept only in volatile test runner memory
RESULT = {"emulator": {}, "baseline": {}, "attempts": [], "vpn_verified": False}

def adb(*args, timeout=35):
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)

def log(s):
    print(s, flush=True)

def click_node(node):
    match = re.findall(r"\d+", node.get("bounds", ""))
    if len(match) != 4:
        return False
    x1, y1, x2, y2 = map(int, match)
    return adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2)).returncode == 0

def ui():
    adb("shell", "uiautomator", "dump", "/sdcard/omega_window.xml", timeout=40)
    x = adb("exec-out", "cat", "/sdcard/omega_window.xml")
    xml = x.stdout
    p = xml.find("<?xml")
    if p < 0: return []
    try:
        return [node.attrib for node in ET.fromstring(xml[p:]).iter("node")]
    except ET.ParseError:
        return []

def swipe():
    adb("shell","input","swipe","520","1510","520","430","300")

def click(needle, timeout=20, scroll=True):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for node in ui():
            text = node.get("text","") + " " + node.get("content-desc","")
            if needle in text and click_node(node):
                return True
        if scroll: swipe()
        time.sleep(1)
    return False

def tap_checkbox():
    for _ in range(6):
        for node in ui():
            if "CheckBox" in node.get("class",""):
                if node.get("checked")=="true": return True
                return click_node(node)
        swipe()
    return False

def screenshot(name):
    try:
        x=subprocess.run(["adb","exec-out","screencap","-p"],capture_output=True,timeout=25)
        if x.returncode==0: (OUT / (name+".png")).write_bytes(x.stdout)
    except Exception:
        pass

def probe(nonce, wait=30):
    adb("logcat","-c")
    adb("shell","am","force-stop","dev.omega.vpn.probe")
    launched=adb("shell","am","start","-n","dev.omega.vpn.probe/.ProbeActivity",
                 "--es","nonce",nonce,"--es","salt",SALT)
    if launched.returncode:
        return {"result":"FAIL","reason":"probe_activity_start"}
    deadline=time.monotonic()+wait
    while time.monotonic()<deadline:
        logcat=adb("logcat","-d","-s","OMEGA_PROBE:I","*:S").stdout
        m=re.search(r"nonce="+re.escape(nonce)+r" (PASS http=200 family=[46] iphash=[a-f0-9]{64} dns=PASS|FAIL reason=\w+)",logcat)
        if m:
            line=m.group(1)
            if line.startswith("PASS"):
                return {"result":"PASS","http":200,
                        "ip_fingerprint":re.search(r"iphash=([a-f0-9]+)",line).group(1),
                        "ip_family":re.search(r"family=([46])",line).group(1),
                        "dns":"PASS"}
            return {"result":"FAIL","reason":line.split("reason=")[1]}
        time.sleep(2)
    return {"result":"FAIL","reason":"timeout"}

def vpn_is_active():
    dump=adb("shell","dumpsys","connectivity",timeout=40).stdout
    return ("TRANSPORT_VPN" in dump or "type: VPN" in dump or
            re.search(r"NetworkAgentInfo.*VPN",dump) is not None)

def report():
    # Files contain no raw public IP, no VLESS credentials, no full logcat.
    (OUT/"results.json").write_text(json.dumps(RESULT,indent=2,ensure_ascii=False))
    log(json.dumps(RESULT,indent=2,ensure_ascii=False))

def main():
    try:
        abi=adb("shell","getprop","ro.product.cpu.abi").stdout.strip()
        sdk=adb("shell","getprop","ro.build.version.sdk").stdout.strip()
        RESULT["emulator"]={"abi":abi,"sdk":sdk}
        if abi != "x86_64": raise RuntimeError("emulator_not_x86_64")
        for apk in ["app/build/outputs/apk/debug/app-debug.apk",
                    "probe/build/outputs/apk/debug/probe-debug.apk"]:
            install=adb("install","-r",apk,timeout=120)
            if install.returncode:
                raise RuntimeError("apk_install_failed: "+apk)
        adb("shell","pm","grant","dev.omega.vpn","android.permission.POST_NOTIFICATIONS")
        adb("shell","input","keyevent","KEYCODE_WAKEUP")
        adb("shell","wm","dismiss-keyguard")
        # Android reports boot_complete before DNS/routing are guaranteed ready.
        # Retry baseline to distinguish transient emulator networking from VPN bugs.
        adb("shell","svc","wifi","enable")
        baseline={"result":"FAIL","reason":"network_not_ready"}
        for attempt in range(1,11):
            time.sleep(5)
            baseline=probe("BEFORE_"+str(attempt))
            log("Emulator unproxied HTTPS attempt "+str(attempt)+": "+baseline["result"]+
                ((" ("+baseline.get("reason","")+")") if baseline["result"]=="FAIL" else ""))
            if baseline["result"]=="PASS": break
        RESULT["baseline"]=baseline
        if baseline["result"]!="PASS":
            detail=adb("shell","dumpsys","connectivity",timeout=30).stdout
            RESULT["emulator"]["connectivity_service_present"]=bool(detail)
            RESULT["emulator"]["has_default_network"]=("DefaultNetwork" in detail)
            raise RuntimeError("emulator_baseline_https_failed_after_10_retries")

        adb("shell","am","start","-n","dev.omega.vpn/.MainActivity")
        time.sleep(4)
        screenshot("01-omega")
        if not click("Найти бесплатные узлы",25):
            raise RuntimeError("cannot_find_free_nodes_button")
        log("Clicked public feed UI; waiting for Android HTTPS catalogue download")
        deadline=time.monotonic()+65
        found=False
        while time.monotonic()<deadline:
            if any("В каталоге:" in n.get("text","")+n.get("content-desc","") for n in ui()):
                found=True
                break
            time.sleep(2)
        screenshot("02-catalogue")
        if not found: raise RuntimeError("public_catalogue_not_loaded")
        if not tap_checkbox(): raise RuntimeError("risk_checkbox_not_found")
        log("Risk acknowledgement selected explicitly in emulator UI")
        for attempt in range(1,5):
            if attempt>1 and not click("Попробовать другой сервер",20):
                raise RuntimeError("next_server_not_available")
            if not click("Подключиться к выбранному узлу",22):
                raise RuntimeError("connect_button_not_found")
            # Permission belongs to the Android OS, not the VPN app. Approve in UI.
            for _ in range(3):
                time.sleep(1)
                if (click("OK",2,False) or click("Разрешить",2,False) or
                    click("Allow",2,False) or click("ОК",2,False)):
                    log("Android VPN consent dialog accepted")
                    break
            time.sleep(9)
            screenshot("03-attempt-"+str(attempt))
            active=vpn_is_active()
            result=probe("AFTER_"+str(attempt))
            changed=(result["result"]=="PASS" and
                     result.get("ip_fingerprint")!=baseline.get("ip_fingerprint"))
            record={"node_index":attempt,"android_vpn_active":active,
                    "https":result["result"],
                    "dns":result.get("dns","NOT_PROVEN"),
                    "public_ip_changed":bool(changed),
                    "error":result.get("reason")}
            RESULT["attempts"].append(record)
            log("Node "+str(attempt)+": VPN="+str(active)+
                " HTTPS="+str(record["https"])+" IP_changed="+str(changed))
            if active and changed and result.get("dns")=="PASS":
                RESULT["vpn_verified"]=True
                RESULT["disconnect_clicked"]=click("Отключить VPN",15)
                time.sleep(6)
                # Full dumpsys connectivity includes historical NetworkAgentInfo entries;
                # a substring TRANSPORT_VPN is not proof of a LIVE VPN after teardown.
                # Routing back to the original IP from the second Android UID is decisive.
                after_disconnect=probe("DISCONNECT",wait=32)
                RESULT["disconnect_https"]=after_disconnect["result"]
                RESULT["disconnect_baseline_ip_restored"]=(
                    after_disconnect["result"]=="PASS" and
                    after_disconnect.get("ip_fingerprint")==baseline.get("ip_fingerprint"))
                RESULT["disconnect_vpn_history_hint"]=vpn_is_active()
                RESULT["disconnect_clean"]=(
                    RESULT["disconnect_clicked"] and
                    RESULT["disconnect_baseline_ip_restored"])
                break
            if not click("Отключить VPN",14):
                adb("shell","am","force-stop","dev.omega.vpn")
                adb("shell","am","start","-n","dev.omega.vpn/.MainActivity")
            time.sleep(4)
        report()
        if not RESULT["vpn_verified"]:
            raise RuntimeError("no_end_to_end_https_vpn_ip_change_after_4_nodes")
        if not RESULT.get("disconnect_clean",False):
            raise RuntimeError("vpn_disconnect_failed")
    except Exception as error:
        RESULT["blocker"]=str(error)
        screenshot("99-failure")
        report()
        raise

if __name__=="__main__":
    main()
