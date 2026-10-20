import contextlib
import http.server
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lanaudit import analysis, cli, report, scanner  # noqa: E402


# --------------------------------------------------------------------------
# Small fake services on 127.0.0.1
# --------------------------------------------------------------------------

class BannerServer:
    """Accepts connections and sends a fixed banner (like SSH or FTP do)."""

    def __init__(self, banner=b""):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                if self.banner:
                    try:
                        conn.sendall(self.banner)
                    except OSError:
                        pass

    def close(self):
        self.stop = True
        self.sock.close()


class QuietHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TestPrinterWeb/1.0"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------
# Target parsing and safety
# --------------------------------------------------------------------------

class TargetTests(unittest.TestCase):
    def test_cidr(self):
        hosts = scanner.parse_target("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_single_and_ranges(self):
        self.assertEqual(scanner.parse_target("10.0.0.5"), ["10.0.0.5"])
        self.assertEqual(scanner.parse_target("10.0.0.5-7"), ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
        self.assertEqual(len(scanner.parse_target("172.16.0.250-172.16.1.5")), 12)

    def test_public_addresses_are_refused(self):
        with self.assertRaises(ValueError) as ctx:
            scanner.parse_target("8.8.8.0/30")
        self.assertIn("public", str(ctx.exception))
        self.assertEqual(scanner.parse_target("8.8.8.8", allow_public=True), ["8.8.8.8"])

    def test_too_big_and_backwards(self):
        with self.assertRaises(ValueError):
            scanner.parse_target("10.0.0.0/16")
        with self.assertRaises(ValueError):
            scanner.parse_target("10.0.0.9-3")

    def test_default_network(self):
        self.assertEqual(str(scanner.default_network("192.168.8.77")), "192.168.8.0/24")
        with self.assertRaises(ValueError):
            scanner.default_network("127.0.0.1")


# --------------------------------------------------------------------------
# Probing against real local services
# --------------------------------------------------------------------------

class ProbeTests(unittest.TestCase):
    def test_open_closed(self):
        server = BannerServer()
        try:
            self.assertEqual(scanner.tcp_probe("127.0.0.1", server.port), "open")
        finally:
            server.close()
        self.assertEqual(scanner.tcp_probe("127.0.0.1", free_port()), "closed")

    def test_scan_ports_and_banners(self):
        ssh = BannerServer(b"SSH-2.0-OpenSSH_9.6 Ubuntu\r\n")
        old = BannerServer(b"SSH-1.5-OldDevice\r\n")
        web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        web_port = web.server_address[1]
        closed = free_port()
        try:
            found = scanner.scan_ports("127.0.0.1", [ssh.port, old.port, web_port, closed])
            self.assertEqual(sorted(found), sorted([ssh.port, old.port, web_port]))
            self.assertIn("OpenSSH", scanner.grab_banner("127.0.0.1", ssh.port))
            self.assertEqual(scanner.grab_banner("127.0.0.1", closed), "")
            # HTTP banner reading is exercised through the ports it is used for.
            text = scanner._http_banner("127.0.0.1", web_port, 2, tls=False)
            self.assertIn("200", text)
            self.assertIn("TestPrinterWeb", text)
        finally:
            ssh.close()
            old.close()
            web.shutdown()
            web.server_close()

    def test_discover_finds_loopback(self):
        server = BannerServer()
        try:
            old = scanner.DISCOVERY_PORTS
            scanner.DISCOVERY_PORTS = (server.port,)
            self.assertEqual(scanner.discover(["127.0.0.1"], use_ping=False), ["127.0.0.1"])
        finally:
            scanner.DISCOVERY_PORTS = old
            server.close()

    def test_clean_banner(self):
        self.assertEqual(scanner._clean(b"220 FTP\r\n\x00ready  "), "220 FTP ready")


class ArpTests(unittest.TestCase):
    def test_windows_output(self):
        text = """
Interface: 192.168.1.20 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
        self.assertEqual(scanner.parse_arp_output(text), {"192.168.1.1": "a4:2b:b0:11:22:33"})

    def test_mac_linux_output(self):
        text = "? (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0\nrouter (10.0.0.2) at 00:1a:2b:3c:4d:5f [ether] on eth0"
        self.assertEqual(scanner.parse_arp_output(text), {"10.0.0.2": "00:1a:2b:3c:4d:5f"})

    def test_firewalled_hosts_found_through_arp(self):
        alive = ["192.168.0.1", "192.168.0.243"]
        arp = {"192.168.0.1": "aa:aa:aa:aa:aa:01", "192.168.0.50": "aa:aa:aa:aa:aa:50",
               "10.9.9.9": "aa:aa:aa:aa:aa:99"}  # last one is outside the scanned range
        hosts = ["192.168.0.%d" % i for i in range(1, 255)]
        merged, extra = scanner.merge_arp_hosts(alive, arp, hosts)
        self.assertEqual(merged, ["192.168.0.1", "192.168.0.50", "192.168.0.243"])
        self.assertEqual(extra, {"192.168.0.50"})
        dev = device("192.168.0.50", [])
        dev["found_by"] = "arp"
        self.assertEqual(analysis.classify(dev)[0], "Firewalled device")

    def test_oui_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as handle:
            handle.write("00-1A-2B   (hex)\t\tExample Networks Inc.\n001A2B     (base 16)\t\tExample\n")
        try:
            vendors = scanner.load_oui_file(handle.name)
        finally:
            os.unlink(handle.name)
        self.assertEqual(scanner.vendor_for("00:1a:2b:3c:4d:5f", vendors), "Example Networks Inc.")
        self.assertEqual(scanner.vendor_for("", vendors), "")


class ConflictTests(unittest.TestCase):
    def test_sample_arp_collects_both_macs(self):
        reads = [
            {"192.168.1.5": "aa:aa:aa:aa:aa:aa", "192.168.1.9": "bb:bb:bb:bb:bb:b1"},
            {"192.168.1.5": "aa:aa:aa:aa:aa:aa", "192.168.1.9": "cc:cc:cc:cc:cc:c2"},  # .9 flipped
            {"192.168.1.5": "aa:aa:aa:aa:aa:aa", "192.168.1.9": "bb:bb:bb:bb:bb:b1"},
        ]
        with mock.patch.object(scanner, "read_arp_table", side_effect=reads):
            seen = scanner.sample_arp(hosts=None, times=3, gap=0, reprobe=False)
        self.assertEqual(seen["192.168.1.5"], ["aa:aa:aa:aa:aa:aa"])
        self.assertEqual(set(seen["192.168.1.9"]), {"bb:bb:bb:bb:bb:b1", "cc:cc:cc:cc:cc:c2"})
        self.assertEqual(seen["192.168.1.9"][0], "bb:bb:bb:bb:bb:b1")  # most recent first

    def test_conflict_finding(self):
        dev = device("192.168.1.9", [])
        dev["macs"] = ["bb:bb:bb:bb:bb:b1", "cc:cc:cc:cc:cc:c2"]
        finding = analysis.ip_conflict_finding(dev)
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["title"], "IP address conflict")
        self.assertIsNone(finding["port"])
        self.assertIn("192.168.1.9", finding["why"])
        self.assertTrue(finding["fix"])
        # One MAC (or the same MAC twice) is not a conflict.
        ok = device("192.168.1.5", [])
        ok["macs"] = ["aa:aa:aa:aa:aa:aa", "aa:aa:aa:aa:aa:aa"]
        self.assertIsNone(analysis.ip_conflict_finding(ok))

    def test_analyse_reports_conflict(self):
        a = device("192.168.1.9", [80])
        a["macs"] = ["bb:bb:bb:bb:bb:b1", "cc:cc:cc:cc:cc:c2"]
        scan = {"target": "t", "scanned_addresses": 2, "started": "now", "duration_s": 1,
                "devices": [device("192.168.1.1", [53]), a]}
        result = analysis.analyse(scan)
        self.assertEqual(result["summary"]["ip_conflicts"], 1)
        self.assertEqual(result["summary"]["findings"]["high"], 1)
        self.assertEqual(result["devices"][1]["findings"][0]["title"], "IP address conflict")
        # The conflict (no port) must render without a stray "port None".
        text = report.to_text(result)
        self.assertIn("IP address conflict", text)
        self.assertNotIn("port None", text)
        page = report.to_html(result)
        self.assertIn("IP address conflict", page)
        self.assertNotIn("port None", page)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def device(ip, ports, banners=None, hostname=""):
    return {"ip": ip, "hostname": hostname, "mac": "", "vendor": "", "open_ports": ports,
            "services": {p: scanner.COMMON_PORTS.get(p, "unknown") for p in ports},
            "banners": banners or {}, "is_this_computer": False}


class ClassifyTests(unittest.TestCase):
    def test_types(self):
        cases = [
            (device("10.0.0.20", [9100, 80]), "Printer"),
            (device("10.0.0.21", [135, 445, 3389]), "Windows PC / Server"),
            (device("10.0.0.22", [554, 80]), "Camera / NVR"),
            (device("10.0.0.23", [22], {22: "SSH-2.0-OpenSSH_9.6 Ubuntu"}), "Linux / Unix server"),
            (device("10.0.0.24", [3306]), "Database server"),
            (device("10.0.0.25", [80], {80: "HTTP/1.0 200 OK | HP LaserJet"}), "Printer"),
            (device("10.0.0.26", []), "Quiet device (no services)"),
        ]
        for dev, expected in cases:
            self.assertEqual(analysis.classify(dev)[0], expected, dev)

    def test_network_gear_is_not_a_server(self):
        # Real case: a TP-Link RE505X range extender with SSH and a web admin page.
        extender = device("192.168.0.192", [22, 80, 443], hostname="RE505X")
        self.assertEqual(analysis.classify(extender)[0], "Network device (Wi-Fi / AP)")
        dropbear = device("10.0.0.40", [22, 80], {22: "SSH-2.0-dropbear_2020.81"})
        self.assertEqual(analysis.classify(dropbear)[0], "Network device (Wi-Fi / AP)")
        anonymous = device("10.0.0.41", [22, 443])
        self.assertEqual(analysis.classify(anonymous)[0], "Appliance (embedded Linux)")
        self.assertEqual(analysis.classify(device("10.0.0.42", [22]))[0], "SSH device")
        # A real Linux server still counts as one.
        server = device("10.0.0.43", [22, 80], {22: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"})
        self.assertEqual(analysis.classify(server)[0], "Linux / Unix server")
        self.assertEqual(analysis.classify(device("10.0.0.44", [22, 3306]))[0], "Database server")

    def test_same_hardware_is_linked(self):
        a = device("192.168.0.192", [22, 80, 443], hostname="RE505X")
        b = device("192.168.0.194", [80, 8443], {80: "HTTP/1.1 200 | nginx"})
        a["mac"] = b["mac"] = "ce:a7:f1:23:df:21"
        result = analysis.analyse({"target": "t", "scanned_addresses": 2, "started": "now",
                                   "duration_s": 1, "devices": [a, b]})
        self.assertEqual(result["devices"][0]["same_hardware_as"], ["192.168.0.194"])
        self.assertEqual(result["devices"][1]["same_hardware_as"], ["192.168.0.192"])
        self.assertIn("same hardware as 192.168.0.194", report.to_text(result))
        self.assertIn("Same hardware (MAC)", report.to_html(result))
        self.assertEqual(result["devices"][1]["type"], "Network device (Wi-Fi / AP)")

    def test_gateway(self):
        self.assertEqual(analysis.classify(device("10.0.0.1", [80]), "10.0.0.1")[0], "Router / Gateway")


class FindingTests(unittest.TestCase):
    def test_risky_ports(self):
        f = analysis.findings_for(device("10.0.0.5", [23, 21, 3389, 80]), "Router / Gateway")
        self.assertEqual([x["severity"] for x in f][0], "high")
        titles = " ".join(x["title"] for x in f)
        for word in ("Telnet", "FTP", "Remote Desktop", "without HTTPS"):
            self.assertIn(word, titles)
        self.assertTrue(all(x["fix"] for x in f))

    def test_https_present_means_no_http_warning(self):
        f = analysis.findings_for(device("10.0.0.6", [80, 443]), "Web device")
        self.assertFalse(any("HTTPS" in x["title"] for x in f))

    def test_ssh_v1(self):
        f = analysis.findings_for(device("10.0.0.7", [22], {"22": "SSH-1.5-Old"}), "Linux / Unix server")
        self.assertEqual(f[0]["title"], "Outdated SSH version 1")

    def test_score_and_grade(self):
        scan = {"target": "t", "scanned_addresses": 4, "started": "now", "duration_s": 1,
                "devices": [device("10.0.0.1", [53, 80, 443]), device("10.0.0.9", [23, 3389])]}
        result = analysis.analyse(scan)
        s = result["summary"]
        self.assertEqual(s["devices"], 2)
        self.assertEqual(s["findings"]["high"], 1)
        self.assertEqual(s["score"], 100 - 15 - 7)
        self.assertEqual(s["grade"], "B")
        self.assertEqual(analysis.grade(100), "A")
        self.assertEqual(analysis.grade(10), "F")
        self.assertEqual(analysis.network_score([{"findings": [{"severity": "high"}] * 10}]), 0)


# --------------------------------------------------------------------------
# Reports and command line
# --------------------------------------------------------------------------

SAMPLE = {"target": "192.168.1.0/24", "scanned_addresses": 254, "started": "2026-10-20 09:00:00",
          "duration_s": 12.3, "scanner_ip": "192.168.1.20",
          "devices": [device("192.168.1.1", [53, 80]),
                      device("192.168.1.30", [9100, 80], hostname="<script>x</script>"),
                      device("192.168.1.40", [23])]}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.result = analysis.analyse(SAMPLE)

    def test_text(self):
        text = report.to_text(self.result)
        self.assertIn("192.168.1.40", text)
        self.assertIn("Telnet", text)
        self.assertIn("grade", text)

    def test_html_is_escaped_and_complete(self):
        page = report.to_html(self.result)
        self.assertIn("<!doctype html>", page)
        self.assertIn("Network security audit", page)
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Telnet is open", page)

    def test_json_round_trip(self):
        data = json.loads(report.to_json(self.result))
        self.assertEqual(data["summary"]["devices"], 3)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(list(args))
        return code, out.getvalue()

    def test_parse_ports(self):
        self.assertEqual(cli.parse_ports("22,80-82"), [22, 80, 81, 82])
        for bad in ("0", "70000", "1-5000", ""):
            with self.assertRaises(Exception):
                cli.parse_ports(bad)

    def test_from_json_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "scan.json")
            with open(src, "w") as handle:
                json.dump(SAMPLE, handle)
            html_path = os.path.join(tmp, "r.html")
            code, out = self.run_cli("--from-json", src, "--html", html_path, "-q")
            self.assertEqual(code, 1)  # telnet = high finding
            self.assertTrue(os.path.getsize(html_path) > 1000)
            self.assertIn("HTML report saved", out)

    def test_public_target_refused(self):
        code, _ = self.run_cli("-t", "1.1.1.1", "-q")
        self.assertEqual(code, 2)

    def test_real_scan_of_loopback(self):
        server = BannerServer(b"SSH-2.0-OpenSSH_9.6\r\n")
        try:
            code, out = self.run_cli("-t", "127.0.0.1", "-p", str(server.port), "--no-ping", "-q")
        finally:
            server.close()
        self.assertEqual(code, 0)
        self.assertIn("127.0.0.1", out)
        self.assertIn(str(server.port), out)


if __name__ == "__main__":
    unittest.main()
