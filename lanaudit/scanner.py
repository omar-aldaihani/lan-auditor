"""Network discovery: which hosts are up, which ports are open, what they say.

Standard library only, and no administrator rights needed: hosts are found with
ordinary TCP connections (plus an optional system ping), and MAC addresses are
read from the operating system's ARP cache afterwards.
"""

import concurrent.futures
import ipaddress
import os
import platform
import re
import socket
import ssl
import subprocess
import time

# Ports worth checking on a small-business network, with a short service name.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    443: "https", 445: "smb", 515: "lpd", 554: "rtsp", 631: "ipp",
    1433: "mssql", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5000: "upnp/web",
    5432: "postgres", 5900: "vnc", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9100: "jetdirect",
}

# Ports used only to decide whether a host is alive (fast, common answers).
DISCOVERY_PORTS = (80, 443, 445, 139, 22, 135, 3389, 53, 9100, 554, 8080, 515, 631, 23)

MAX_HOSTS = 1024  # refuse to sweep anything bigger than a /22 by accident

_MAC_RE = re.compile(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


# --------------------------------------------------------------------------
# Choosing what to scan
# --------------------------------------------------------------------------

def local_ip():
    """This computer's main IPv4 address (no packets are actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_network(ip=None):
    """Guess the local network as the /24 around this computer's address."""
    ip = ip or local_ip()
    if not ip or ip.startswith("127."):
        raise ValueError("Could not find a local network address. Pass one with --target.")
    return ipaddress.ip_network(ip + "/24", strict=False)


def parse_target(target, allow_public=False):
    """Turn '192.168.1.0/24', '192.168.1.10' or '192.168.1.10-40' into a host list.

    Only private (RFC 1918), link-local and loopback ranges are allowed unless
    allow_public is True, so the tool can't be pointed at the internet by mistake.
    """
    target = target.strip()
    if "-" in target and "/" not in target:
        start_text, end_text = target.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end_text = end_text.strip()
        if "." not in end_text:  # short form: 192.168.1.10-40
            end_text = start_text.rsplit(".", 1)[0] + "." + end_text
        end = ipaddress.ip_address(end_text)
        if int(end) < int(start):
            raise ValueError("Range end is before range start.")
        hosts = [ipaddress.ip_address(n) for n in range(int(start), int(end) + 1)]
    else:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    if not hosts:
        raise ValueError("No addresses to scan.")
    if len(hosts) > MAX_HOSTS:
        raise ValueError("That is %d addresses; the limit is %d. Scan a smaller range."
                         % (len(hosts), MAX_HOSTS))
    if not allow_public:
        for host in hosts:
            if not (host.is_private or host.is_loopback or host.is_link_local):
                raise ValueError(
                    "%s is a public internet address. LAN Auditor only scans local networks "
                    "you own or manage. Use --allow-public only if you have written permission."
                    % host)
    return [str(h) for h in hosts]


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def tcp_probe(ip, port, timeout=0.5):
    """'open', 'closed' (host answered with a reset) or None (no answer)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return None


def ping(ip, timeout_ms=600):
    """True if the host answers an ICMP ping (uses the system ping command)."""
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    try:
        done = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout_ms / 1000 + 2, creationflags=_NO_WINDOW)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_alive(ip, timeout=0.5, use_ping=True):
    """A host counts as up if it answers a ping or any TCP port (open or reset)."""
    for port in DISCOVERY_PORTS:
        if tcp_probe(ip, port, timeout) is not None:
            return True
    return use_ping and ping(ip, int(timeout * 1000) + 300)


def discover(hosts, timeout=0.5, workers=128, use_ping=True, progress=None):
    """Return the hosts that are up, in address order."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(is_alive, ip, timeout, use_ping): ip for ip in hosts}
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            if future.result():
                alive.append(futures[future])
            if progress:
                progress(done, len(hosts))
    return sorted(alive, key=lambda ip: ipaddress.ip_address(ip))


def scan_ports(ip, ports=None, timeout=0.6, workers=32):
    """Open ports on one host, sorted."""
    ports = sorted(ports or COMMON_PORTS)
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, tcp_probe(ip, p, timeout)), ports)
        for port, state in results:
            if state == "open":
                found.append(port)
    return found


# --------------------------------------------------------------------------
# Banners: ask services politely who they are
# --------------------------------------------------------------------------

def grab_banner(ip, port, timeout=1.5):
    """A short text identifying the service, or '' if it says nothing useful."""
    try:
        if port in (443, 8443):
            return _http_banner(ip, port, timeout, tls=True)
        if port in (80, 8000, 8080, 5000):
            return _http_banner(ip, port, timeout, tls=False)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
        return _clean(data)
    except (OSError, ssl.SSLError):
        return ""


def _http_banner(ip, port, timeout, tls):
    request = ("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: lan-auditor\r\n\r\n" % ip).encode()
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # we only read the server header
            raw = context.wrap_socket(raw, server_hostname=ip)
        raw.settimeout(timeout)
        raw.sendall(request)
        data = raw.recv(1024)
    finally:
        raw.close()
    text = data.decode("latin-1", "replace")
    status = text.split("\r\n", 1)[0]
    server = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
    parts = [status.strip()] + ([server.group(1).strip()] if server else [])
    return _clean(" | ".join(p for p in parts if p).encode())


def _clean(data):
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return re.sub(r"\s+", " ", text).strip()[:120]


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except (OSError, UnicodeError):
        return ""


# --------------------------------------------------------------------------
# MAC addresses from the ARP cache
# --------------------------------------------------------------------------

def read_arp_table():
    """{ip: mac} from the operating system's ARP cache (best effort)."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as handle:
                text = handle.read()
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                    table[fields[0]] = fields[3].lower()
            if table:
                return table
        except OSError:
            pass
    try:
        done = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10,
                              creationflags=_NO_WINDOW)
        text = done.stdout
    except (OSError, subprocess.SubprocessError):
        return table
    return parse_arp_output(text)


def parse_arp_output(text):
    """Parse `arp -a` output from Windows, macOS or Linux."""
    table = {}
    for line in text.splitlines():
        mac = _MAC_RE.search(line)
        ip = _IP_RE.search(line)
        if mac and ip:
            value = mac.group(0).lower().replace("-", ":")
            if value not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[ip.group(1)] = value
    return table


def merge_arp_hosts(alive, arp, hosts):
    """Add hosts that answered ARP but blocked every probe (e.g. Windows Firewall).

    Every device on the same network segment must answer ARP to communicate, even
    when its firewall drops pings and connections, so sweeping the range fills the
    ARP cache with hosts the probes could not see.
    Returns (all hosts sorted, set of hosts found only through ARP).
    """
    wanted = set(hosts)
    seen = set(alive)
    extra = {ip for ip in arp if ip in wanted and ip not in seen}
    merged = sorted(seen | extra, key=lambda ip: ipaddress.ip_address(ip))
    return merged, extra


def sample_arp(hosts=None, times=3, gap=0.4, reprobe=True):
    """Read the ARP cache several times to catch IP address conflicts.

    A healthy address always maps to the same hardware (MAC) address. When two
    different devices are set to the same IP, the address flips between their two
    MACs, and that is exactly what makes a network "randomly disconnect". Reading
    ARP a few times (nudging each host with a quick TCP touch first, so both
    devices answer) catches a conflict that is happening right now.

    Returns {ip: [macs seen, most recent first]}. No admin rights needed.
    """
    seen = {}
    for round_index in range(max(1, times)):
        if reprobe and hosts:
            # A light touch so the operating system refreshes its ARP entry.
            for ip in hosts:
                tcp_probe(ip, 80, timeout=0.2)
        for ip, mac in read_arp_table().items():
            macs = seen.setdefault(ip, [])
            if mac in macs:
                macs.remove(mac)
            macs.insert(0, mac)  # keep most-recent first
        if round_index < times - 1:
            time.sleep(gap)
    return seen


def load_oui_file(path):
    """Read an IEEE 'oui.txt' (https://standards-oui.ieee.org/oui/oui.txt) into {prefix: vendor}."""
    vendors = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = re.match(r"^\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
            if match:
                vendors[match.group(1).replace("-", ":").lower()] = match.group(2).strip()
    return vendors


def vendor_for(mac, vendors):
    if not mac or not vendors:
        return ""
    return vendors.get(mac.lower()[:8], "")


# --------------------------------------------------------------------------
# Whole scan
# --------------------------------------------------------------------------

def scan(target=None, ports=None, timeout=0.5, use_ping=True, allow_public=False,
         oui_path=None, progress=None):
    """Run discovery, port scan and banner grabbing. Returns a plain dict."""
    started = time.time()
    if target:
        hosts = parse_target(target, allow_public=allow_public)
        label = target
    else:
        network = default_network()
        hosts = parse_target(str(network))
        label = str(network)

    alive = discover(hosts, timeout=timeout, use_ping=use_ping,
                     progress=(lambda d, t: progress("discover", d, t)) if progress else None)
    arp = read_arp_table()
    alive, arp_only = merge_arp_hosts(alive, arp, hosts)
    if progress:
        progress("conflicts", 0, 1)
    arp_macs = sample_arp(alive)  # several reads, to catch IP address conflicts
    vendors = load_oui_file(oui_path) if oui_path else {}
    me = local_ip()

    devices = []
    for index, ip in enumerate(alive, 1):
        if progress:
            progress("ports", index, len(alive))
        open_ports = scan_ports(ip, ports, timeout=timeout + 0.2)
        banners = {}
        for port in open_ports:
            banner = grab_banner(ip, port)
            if banner:
                banners[port] = banner
        macs = arp_macs.get(ip) or ([arp[ip]] if ip in arp else [])
        mac = macs[0] if macs else ""
        devices.append({
            "ip": ip,
            "hostname": reverse_dns(ip),
            "mac": mac,
            "macs": macs,
            "vendor": vendor_for(mac, vendors),
            "open_ports": open_ports,
            "services": {p: COMMON_PORTS.get(p, "unknown") for p in open_ports},
            "banners": banners,
            "is_this_computer": ip == me,
            "found_by": "arp" if ip in arp_only else "probe",
        })

    return {
        "target": label,
        "scanned_addresses": len(hosts),
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "scanner_host": socket.gethostname(),
        "scanner_ip": me,
        "platform": platform.platform(),
        "devices": devices,
    }
