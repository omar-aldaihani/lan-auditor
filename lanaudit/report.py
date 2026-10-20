"""Reports: terminal table, JSON and a single-file HTML report."""

import html
import json

from lanaudit import __version__

SEV_COLOURS = {"high": "#c62828", "medium": "#e07b00", "low": "#2f6fb5", "info": "#6b7280"}


def to_json(result):
    return json.dumps(result, indent=2, default=str)


def to_text(result):
    s = result["summary"]
    lines = [
        "LAN Auditor %s  -  %s" % (__version__, result["target"]),
        "Scanned %d addresses in %ss, found %d devices. Security score %d/100 (grade %s)."
        % (result["scanned_addresses"], result["duration_s"], s["devices"], s["score"], s["grade"]),
        "",
        "%-15s %-27s %-20s %s" % ("IP", "TYPE", "OPEN PORTS", "ISSUES"),
        "-" * 78,
    ]
    for d in result["devices"]:
        ports = ",".join(str(p) for p in d["open_ports"]) or "-"
        issues = ", ".join(f["severity"].upper() for f in d["findings"]) or "none"
        name = d["ip"] + (" *" if d.get("is_this_computer") else "")
        lines.append("%-15s %-27s %-20s %s" % (name, d["type"][:27], ports[:20], issues))
        if d.get("same_hardware_as"):
            lines.append("%-15s (same hardware as %s)" % ("", ", ".join(d["same_hardware_as"])))
    findings = [(d, f) for d in result["devices"] for f in d["findings"]]
    if findings:
        lines += ["", "Findings (most serious first):"]
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for d, f in sorted(findings, key=lambda x: order[x[1]["severity"]]):
            where = (" port %s" % f["port"]) if f.get("port") else ""
            lines.append("  [%s] %s%s: %s" % (f["severity"].upper(), d["ip"], where, f["title"]))
            lines.append("         Fix: %s" % f["fix"])
    lines += ["", "* = the computer running the scan"]
    return "\n".join(lines)


def _e(value):
    return html.escape(str(value), quote=True)


def to_html(result):
    s = result["summary"]
    score_colour = "#2e7d32" if s["score"] >= 75 else ("#e07b00" if s["score"] >= 50 else "#c62828")

    rows = []
    for d in result["devices"]:
        ports = " ".join('<span class="port">%d<small>%s</small></span>' % (p, _e(d["services"].get(p, d["services"].get(str(p), ""))))
                         for p in d["open_ports"]) or '<span class="muted">none</span>'
        badges = " ".join('<span class="sev" style="background:%s">%s</span>'
                          % (SEV_COLOURS[f["severity"]], f["severity"]) for f in d["findings"]) \
            or '<span class="ok">OK</span>'
        who = _e(d["hostname"] or "")
        extra = " · ".join(x for x in (_e(d.get("mac") or ""), _e(d.get("vendor") or "")) if x)
        me = ' <span class="me">this computer</span>' if d.get("is_this_computer") else ""
        if d.get("same_hardware_as"):
            extra += "<div>Same hardware (MAC) as %s, probably one device with two addresses</div>" % _e(
                ", ".join(d["same_hardware_as"]))
        rows.append(
            "<tr><td><b>%s</b>%s<div class='muted'>%s</div><div class='muted mono'>%s</div></td>"
            "<td>%s<div class='muted'>%s</div></td><td>%s</td><td>%s</td></tr>"
            % (_e(d["ip"]), me, who, extra, _e(d["type"]), _e(d["type_reason"]), ports, badges))

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    cards = []
    for d, f in sorted(((d, f) for d in result["devices"] for f in d["findings"]),
                       key=lambda x: (order[x[1]["severity"]], x[0]["ip"])):
        where = "on %s, port %s" % (_e(d["ip"]), f["port"]) if f.get("port") else "on %s" % _e(d["ip"])
        cards.append(
            "<div class='finding' style='border-left-color:%s'>"
            "<div><span class='sev' style='background:%s'>%s</span> <b>%s</b> "
            "<span class='muted'>%s</span></div>"
            "<p>%s</p><p><b>Fix:</b> %s</p></div>"
            % (SEV_COLOURS[f["severity"]], SEV_COLOURS[f["severity"]], f["severity"],
               _e(f["title"]), where, _e(f["why"]), _e(f["fix"])))
    if not cards:
        cards.append("<p class='ok-box'>No security issues found on the scanned ports.</p>")

    types = "".join("<li><b>%d</b> %s</li>" % (n, _e(t)) for t, n in s["device_types"].items())
    f = s["findings"]

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAN Audit - {target}</title>
<style>
:root {{ --bg:#f4f6f9; --card:#fff; --text:#17202a; --muted:#64707d; --line:#e2e7ee; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f141a; --card:#18202a; --text:#e6edf3; --muted:#9aa7b5; --line:#2b3644; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:24px 16px 48px; background:var(--bg); color:var(--text);
       font:15px/1.5 "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; }}
main {{ max-width:1080px; margin:0 auto; }}
h1 {{ margin:0; font-size:26px; }} h2 {{ font-size:18px; margin:28px 0 10px; }}
.muted {{ color:var(--muted); font-size:13px; }} .mono {{ font-family:Consolas, monospace; }}
.top {{ display:flex; flex-wrap:wrap; gap:14px; margin:18px 0; }}
.tile {{ flex:1 1 160px; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
.tile .big {{ font-size:30px; font-weight:700; }}
.tile ul {{ margin:4px 0 0; padding-left:18px; }}
.table-wrap {{ overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:10px; }}
table {{ width:100%; border-collapse:collapse; min-width:720px; }}
th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); }}
tr:last-child td {{ border-bottom:0; }}
.port {{ display:inline-block; margin:0 4px 4px 0; padding:1px 7px; border-radius:6px;
         border:1px solid var(--line); font-family:Consolas, monospace; font-size:13px; }}
.port small {{ color:var(--muted); margin-left:4px; font-family:inherit; }}
.sev {{ display:inline-block; color:#fff; border-radius:5px; padding:0 7px; font-size:12px;
        font-weight:700; text-transform:uppercase; }}
.ok {{ color:#2e7d32; font-weight:700; }} .me {{ font-size:11px; background:#2f6fb5; color:#fff; border-radius:5px; padding:0 6px; }}
.finding {{ background:var(--card); border:1px solid var(--line); border-left:5px solid; border-radius:8px;
            padding:10px 14px; margin-bottom:10px; }}
.finding p {{ margin:6px 0 0; }}
.ok-box {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px; }}
footer {{ margin-top:30px; color:var(--muted); font-size:12px; }}
</style></head><body><main>
<h1>Network security audit</h1>
<div class="muted">Network <b>{target}</b> · scanned {started} from {scanner_ip} · {addresses} addresses in {duration}s</div>

<div class="top">
  <div class="tile"><div class="muted">Security score</div><div class="big" style="color:{score_colour}">{score}<small>/100</small></div><div>Grade <b>{grade}</b></div></div>
  <div class="tile"><div class="muted">Devices found</div><div class="big">{devices}</div><ul>{types}</ul></div>
  <div class="tile"><div class="muted">Issues</div>
    <div><span class="sev" style="background:{c_high}">high</span> {n_high}</div>
    <div><span class="sev" style="background:{c_med}">medium</span> {n_med}</div>
    <div><span class="sev" style="background:{c_low}">low</span> {n_low}</div></div>
</div>

<h2>What needs fixing</h2>
{cards}

<h2>All devices</h2>
<div class="table-wrap"><table>
<thead><tr><th>Device</th><th>Type</th><th>Open ports</th><th>Issues</th></tr></thead>
<tbody>{rows}</tbody></table></div>

<footer>Generated by LAN Auditor {version}. Checks common ports only; a clean result does not prove a
device is secure. Only scan networks you own or have permission to test.</footer>
</main></body></html>
""".format(
        target=_e(result["target"]), started=_e(result["started"]), scanner_ip=_e(result.get("scanner_ip") or ""),
        addresses=result["scanned_addresses"], duration=result["duration_s"], score=s["score"],
        grade=s["grade"], score_colour=score_colour, devices=s["devices"], types=types,
        c_high=SEV_COLOURS["high"], c_med=SEV_COLOURS["medium"], c_low=SEV_COLOURS["low"],
        n_high=f["high"], n_med=f["medium"], n_low=f["low"], cards="\n".join(cards),
        rows="\n".join(rows), version=__version__)
