"""Turn raw scan results into device types, security findings and a score.

Every rule here is plain data so it is easy to read, test and extend.
"""

# --------------------------------------------------------------------------
# What kind of device is it?
# --------------------------------------------------------------------------

import re

# Network equipment usually announces itself in its hostname or web/SSH banner.
# "re505x", "archer-c6", "deco-m5", "eap225"... are TP-Link model names; dropbear is the
# tiny SSH server built into most routers, extenders and access points.
NETWORK_GEAR = re.compile(
    r"\b(re\d{3}\w*|archer[\w-]*|deco[\w-]*|eap\d+\w*|tl-\w+|extender|repeater|mesh|"
    r"access ?point|unifi|mikrotik|routeros|openwrt|dd-wrt|tp-?link|netgear|linksys|"
    r"asus ?wrt|fritz\S*|huawei|zte|dropbear)(?![a-z0-9])")

SERVER_PORTS = {445, 139, 1433, 3306, 5432, 3389, 25, 110, 143, 21}

DEVICE_RULES = [
    # (device type, ports that suggest it, minimum matches, banner keywords)
    ("Printer", {9100, 515, 631}, 1, ("printer", "jetdirect", "laserjet", "epson", "brother",
                                      "canon", "kyocera", "ricoh", "xerox", "cups")),
    ("Camera / NVR", {554}, 1, ("hikvision", "dahua", "camera", "nvr", "dvr", "rtsp", "onvif")),
    ("Windows PC / Server", {135, 139, 445, 3389}, 2, ("microsoft", "windows", "iis")),
    ("Database server", {1433, 3306, 5432}, 1, ("mysql", "mariadb", "postgres", "sql server")),
    ("Router / Gateway", {53}, 1, ("router", "gateway", "fortigate", "ubiquiti")),
    ("IoT device", {1883}, 1, ("mqtt", "esp", "tasmota")),
]

LINUX_SERVER_WORDS = ("ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "raspbian",
                      "almalinux", "rocky")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 5000}


def classify(device, gateway_ip=None):
    """Best guess at the device type, with the reason."""
    ports = set(device.get("open_ports", []))
    banners = " ".join(str(v) for v in device.get("banners", {}).values()).lower()
    hostname = (device.get("hostname") or "").lower()
    text = " ".join((banners, hostname, (device.get("vendor") or "").lower()))

    if gateway_ip and device.get("ip") == gateway_ip:
        return "Router / Gateway", "It is the network's default gateway (.1)"

    gear = NETWORK_GEAR.search(text)
    if gear and not ports & SERVER_PORTS:
        return ("Network device (Wi-Fi / AP)",
                "Identifies itself as '%s'" % gear.group(0))

    for name, rule_ports, minimum, keywords in DEVICE_RULES:
        keyword = next((k for k in keywords if k in text), None)
        hits = ports & rule_ports
        if keyword and (hits or name in ("Router / Gateway", "Printer", "Camera / NVR")):
            return name, "Identifies itself as '%s'" % keyword
        if len(hits) >= minimum:
            return name, "Open ports %s" % ", ".join(str(p) for p in sorted(hits))

    if 22 in ports:
        distro = next((w for w in LINUX_SERVER_WORDS if w in text), None)
        if distro:
            return "Linux / Unix server", "SSH banner mentions '%s'" % distro
        if ports & SERVER_PORTS:
            return "Linux / Unix server", "SSH plus server ports %s" % ", ".join(
                str(p) for p in sorted(ports & SERVER_PORTS))
        if ports & WEB_PORTS:
            return ("Appliance (embedded Linux)",
                    "Only SSH and a web admin page are open, typical of routers, extenders and NAS boxes")
        return "SSH device", "Only SSH (port 22) is open"

    if ports & WEB_PORTS:
        server = next((k for k in ("nginx", "apache", "lighttpd", "iis") if k in text), None)
        reason = ("Web server '%s'" % server) if server else "Open web ports %s" % ", ".join(
            str(p) for p in sorted(ports & WEB_PORTS))
        return "Web device", reason
    if not ports and device.get("found_by") == "arp":
        return ("Firewalled device", "Blocks ping and all checked ports, but answered on the local "
                "network (ARP). Often a Windows PC with the firewall on, a phone or a laptop")
    if not ports:
        return ("Quiet device (no services)",
                "Answers on the network but offers no services on the checked ports, which is good "
                "for security. Usually a phone, tablet, smart TV, games console or laptop")
    return "Unknown", "Open ports %s" % ", ".join(str(p) for p in sorted(ports))


# --------------------------------------------------------------------------
# Security findings
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_POINTS = {"high": 15, "medium": 7, "low": 2, "info": 0}

PORT_FINDINGS = {
    23: ("high", "Telnet is open",
         "Telnet sends passwords in plain text that anyone on the network can read.",
         "Turn Telnet off and use SSH (or the device's HTTPS admin page) instead."),
    21: ("medium", "FTP is open",
         "FTP sends usernames, passwords and files unencrypted.",
         "Disable FTP or replace it with SFTP/FTPS."),
    3389: ("medium", "Remote Desktop (RDP) is open",
           "RDP is a frequent target for password-guessing and ransomware.",
           "Allow RDP only from trusted machines or over a VPN, enable Network Level "
           "Authentication, and use strong passwords."),
    5900: ("medium", "VNC remote control is open",
           "VNC often has weak or no passwords and the traffic may be unencrypted.",
           "Disable VNC or protect it with a strong password and a VPN."),
    445: ("low", "Windows file sharing (SMB) is open",
          "Normal for file sharing, but old SMB versions have serious flaws (e.g. WannaCry).",
          "Keep Windows updated, disable SMBv1, and share only the folders that are needed."),
    139: ("low", "NetBIOS is open",
          "Legacy Windows networking that leaks computer and user names.",
          "Disable NetBIOS over TCP/IP if nothing on the network needs it."),
    161: ("low", "SNMP is open",
          "Devices often keep the default 'public' community string, exposing their settings.",
          "Change the SNMP community string or switch to SNMPv3, or turn SNMP off."),
    1433: ("medium", "SQL Server is reachable from the network",
           "Databases should only accept connections from the servers that need them.",
           "Restrict the port with a firewall rule to the application servers only."),
    3306: ("medium", "MySQL/MariaDB is reachable from the network",
           "Databases should only accept connections from the servers that need them.",
           "Bind the database to localhost or firewall it to the application servers."),
    5432: ("medium", "PostgreSQL is reachable from the network",
           "Databases should only accept connections from the servers that need them.",
           "Restrict access in pg_hba.conf and with a firewall rule."),
    1883: ("medium", "MQTT broker without encryption",
           "IoT messages and credentials on port 1883 are not encrypted.",
           "Use MQTT over TLS (port 8883) with authentication."),
    9100: ("low", "Raw printing port is open",
           "Anyone on the network can send jobs straight to the printer, bypassing any print server.",
           "Restrict printer access to the print server or trusted subnets if possible."),
    554: ("low", "Camera video stream (RTSP) is open",
          "Camera streams often use default passwords.",
          "Change the camera's default password and keep its firmware updated."),
}

HTTP_PORTS = {80, 8000, 8080, 5000}
HTTPS_PORTS = {443, 8443}


def findings_for(device, device_type):
    ports = set(device.get("open_ports", []))
    out = []
    for port in sorted(ports):
        if port in PORT_FINDINGS:
            severity, title, why, fix = PORT_FINDINGS[port]
            out.append({"severity": severity, "port": port, "title": title, "why": why, "fix": fix})
    if ports & HTTP_PORTS and not ports & HTTPS_PORTS and device_type not in ("Unknown",):
        out.append({
            "severity": "low", "port": min(ports & HTTP_PORTS),
            "title": "Web admin page without HTTPS",
            "why": "Logging in to this device's web page sends the password unencrypted.",
            "fix": "Enable HTTPS on the device if it supports it, and change any default password.",
        })
    for port, banner in device.get("banners", {}).items():
        lowered = str(banner).lower()
        if "ssh-1." in lowered:
            out.append({"severity": "high", "port": int(port), "title": "Outdated SSH version 1",
                        "why": "SSH protocol 1 is broken and can be decrypted.",
                        "fix": "Update the device firmware/OS and allow SSH protocol 2 only."})
    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["port"] or 0))
    return out


def ip_conflict_finding(device):
    """A finding when one IP address is used by two different devices, or None.

    The scanner reads the ARP cache several times; a healthy address keeps the same
    hardware (MAC) address every time. Two MACs on one IP means two devices are
    fighting over the address, the classic cause of 'it randomly disconnects'.
    """
    distinct = list(dict.fromkeys(device.get("macs") or []))
    if len(distinct) < 2:
        return None
    return {
        "severity": "high", "port": None, "title": "IP address conflict",
        "why": "Two different devices are using the address %s (hardware %s). They keep "
               "knocking each other off the network, which looks like random disconnects or "
               "'no internet' on both devices." % (device["ip"], " and ".join(distinct)),
        "fix": "Give one device a different address, or set both to get their address "
               "automatically (DHCP). Check that the router's DHCP range does not overlap any "
               "fixed/static addresses you have set by hand.",
    }


# --------------------------------------------------------------------------
# Whole report
# --------------------------------------------------------------------------

def gateway_guess(devices):
    """The .1 address of the scanned network, if it answered."""
    for device in devices:
        if device["ip"].endswith(".1"):
            return device["ip"]
    return None


def network_score(devices):
    """100 = nothing found. Each finding costs points; never below 0."""
    lost = sum(SEVERITY_POINTS[f["severity"]] for d in devices for f in d.get("findings", []))
    return max(0, 100 - lost)


def grade(score):
    for limit, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= limit:
            return letter
    return "F"


def analyse(scan):
    """Add type, reason and findings to each device, plus totals. Returns a new dict."""
    result = dict(scan)
    gateway = gateway_guess(scan["devices"])
    devices = []
    for raw in scan["devices"]:
        device = dict(raw)
        device["type"], device["type_reason"] = classify(device, gateway)
        device["findings"] = findings_for(device, device["type"])
        conflict = ip_conflict_finding(device)
        if conflict:
            device["findings"].insert(0, conflict)  # most serious, show first
        devices.append(device)
    by_mac = {}
    for device in devices:
        if device.get("mac"):
            by_mac.setdefault(device["mac"], []).append(device["ip"])
    for device in devices:
        others = [ip for ip in by_mac.get(device.get("mac"), []) if ip != device["ip"]]
        device["same_hardware_as"] = others
    # A second address on the same hardware inherits the more specific type.
    generic = ("Web device", "Unknown", "Quiet device (no services)", "SSH device", "Firewalled device",
               "Appliance (embedded Linux)")
    by_ip = {d["ip"]: d for d in devices}
    for device in devices:
        if device["type"] in generic:
            sibling = next((by_ip[ip] for ip in device["same_hardware_as"]
                            if by_ip[ip]["type"] not in generic), None)
            if sibling:
                device["type"] = sibling["type"]
                device["type_reason"] = "Same hardware as %s (%s)" % (sibling["ip"], sibling["type_reason"])
    result["devices"] = devices
    counts = {s: 0 for s in SEVERITY_ORDER}
    for device in devices:
        for finding in device["findings"]:
            counts[finding["severity"]] += 1
    types = {}
    for device in devices:
        types[device["type"]] = types.get(device["type"], 0) + 1
    conflicts = sum(1 for d in devices for f in d["findings"] if f["title"] == "IP address conflict")
    result["summary"] = {
        "devices": len(devices),
        "findings": counts,
        "ip_conflicts": conflicts,
        "device_types": dict(sorted(types.items(), key=lambda kv: -kv[1])),
        "score": network_score(devices),
    }
    result["summary"]["grade"] = grade(result["summary"]["score"])
    return result
