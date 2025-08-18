#!/usr/bin/env python3
import re, sys, csv, io
from datetime import datetime
from pathlib import Path

OK="PASS"; BAD="FAIL"

def read_config(path:str)->str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return ""

def find_blocks(cfg:str, header:str)->list[str]:
    blocks=[]
    pat = re.compile(rf'(^|\n)config {re.escape(header)}\b.*?\nend\s*', re.S|re.I)
    for m in pat.finditer(cfg):
        blocks.append(m.group(0))
    return blocks

def get_lines(block:str)->list[str]:
    return [ln.strip() for ln in block.splitlines()]

def contains(block:str, rex:str)->bool:
    try:
        return bool(re.search(rex, block, re.I|re.M))
    except re.error:
        return False

def extract_kv(block:str, key:str)->list[str]:
    vals=[]
    r = re.compile(rf'^\s*set\s+{re.escape(key)}\s+(.+)$', re.I|re.M)
    for m in r.finditer(block):
        vals.append(m.group(1).strip())
    return vals

def csv_write(rows, outpath:str):
    # Force UTF-8 for Windows
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Benchmark", "Result", "Details", "Where to fix", "Suggested CLI"])
        w.writerows(rows)

def html_write(rows, outpath:str):
    total = len(rows); passed = sum(1 for r in rows if r[1]==OK); failed = total-passed
    html = [f"""
<html><head><meta charset='utf-8'>
<title>FortiGate CIS Audit Report (improved)</title>
<style>
body{{font-family:system-ui,Arial;margin:20px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#f5f5f5}}
.pass{{color:#2e7d32;font-weight:600}}
.fail{{color:#c62828;font-weight:600}}
pre{{white-space:pre-wrap;background:#fafafa;border:1px dashed #ccc;padding:8px;border-radius:8px}}
.summary{{margin:12px 0;font-weight:600}}
</style></head><body>
<h1>FortiGate CIS Audit Report (improved)</h1>
<div class='summary'>Total: {total} | Passed: {passed} | Failed: {failed}</div>
<table><tr><th>Benchmark</th><th>Result</th><th>Details</th><th>Where to fix</th><th>Suggested CLI</th></tr>"""]
    for b,res,det,where,cli in rows:
        klass = "pass" if res==OK else "fail"
        html.append(f"<tr><td>{b}</td><td class='{klass}'>{res}</td><td>{det}</td><td>{where}</td><td><pre>{cli if res==BAD and cli else ''}</pre></td></tr>")
    html.append("</table></body></html>")
    Path(outpath).write_text("".join(html), encoding="utf-8")

# ===================== CIS CHECKS =====================

def check_admin_timeout(cfg:str):
    for key in ("admin-timeout","admintimeout"):
        m = re.search(rf'set\s+{key}\s+(\d+)', cfg, re.I)
        if m:
            v=int(m.group(1))
            if v<=5:
                return ("1.1.1 Admin timeout ≤ 5 minutes", OK, f"{key}={v}",
                        "System > Settings > Administration",
                        f"config system global\n    set {key} 5\nend")
            else:
                return ("1.1.1 Admin timeout ≤ 5 minutes", BAD,
                        f"{key} is {v} (should be ≤5)",
                        "System > Settings > Administration",
                        f"config system global\n    set {key} 5\nend")
    return ("1.1.1 Admin timeout ≤ 5 minutes", BAD, "Not set",
            "System > Settings > Administration",
            "config system global\n    set admintimeout 5\nend")

def check_ssh_grace(cfg:str):
    key="admin-ssh-grace-time"
    m = re.search(rf'set\s+{key}\s+(\d+)', cfg, re.I)
    if m:
        v=int(m.group(1))
        return ("1.1.2 SSH grace-time ≤ 60s", OK if v<=60 else BAD,
                f"{key}={v}",
                "System > Settings > Administration",
                f"config system global\n    set {key} 60\nend" if v>60 else "")
    return ("1.1.2 SSH grace-time ≤ 60s", BAD, "Not set",
            "System > Settings > Administration",
            f"config system global\n    set {key} 60\nend")

def check_ssh_v1(cfg:str):
    if re.search(r'set\s+admin-ssh-v1\s+enable', cfg, re.I):
        return ("1.1.3 SSH v1 disabled", BAD, "admin-ssh-v1 is enable",
                "System > Settings > Administration",
                "config system global\n    set admin-ssh-v1 disable\nend")
    return ("1.1.3 SSH v1 disabled", OK, "admin-ssh-v1 not enabled", "", "")

def check_concurrent(cfg:str):
    for key in ("admin-concurrent-sessions","admin-concurrent"):
        m = re.search(rf'set\s+{key}\s+(\d+)', cfg, re.I)
        if m:
            v=int(m.group(1))
            return ("1.1.4 Concurrent admin sessions = 1",
                    OK if v==1 else BAD, f"{key}={v}",
                    "System > Settings > Administration",
                    f"config system global\n    set {key} 1\nend" if v!=1 else "")
    return ("1.1.4 Concurrent admin sessions = 1", BAD, "Not set",
            "System > Settings > Administration",
            "config system global\n    set admin-concurrent-sessions 1\nend")

def check_change_admin_port(cfg:str):
    m = re.search(r'set\s+admin-port\s+(\d+)', cfg, re.I)
    if m and m.group(1)=="80":
        return ("1.1.5 Change default admin HTTP port", BAD, "admin-port=80",
                "System > Settings > Administration",
                "config system global\n    set admin-port 8443\nend")
    return ("1.1.5 Change default admin HTTP port", OK,
            "Not using 80 for admin-port", "", "")

def check_trusted_hosts_admin(cfg:str):
    admin_blocks = find_blocks(cfg, "system admin")
    bad_admins=[]
    if not admin_blocks:
        return ("1.2.1 Trusted hosts on all admin accounts", BAD,
                "No 'config system admin' found",
                "System > Admin > Administrator",
                "config system admin\n  edit <user>\n    set trusthost1 <ip/mask>\n  next\nend")
    for blk in admin_blocks:
        edits = re.split(r'\n\s*edit\s+"?([^"\n]+)"?\s*\n', blk, flags=re.I)
        for i in range(1, len(edits), 2):
            name = edits[i].strip()
            body = edits[i+1]
            th = re.findall(r'set\s+trusthost\d+\s+([0-9\.]+\s+[0-9\.]+)', body, flags=re.I)
            ip6 = re.findall(r'set\s+ip6-trusthost\d+\s+([0-9A-Fa-f:\/]+)', body, flags=re.I)
            def is_open(v):
                return v.strip().startswith("0.0.0.0") or v.strip().startswith("::/0")
            if not th and not ip6:
                bad_admins.append((name, "no trusted hosts set"))
            elif any(is_open(v) for v in th) or any(v.strip()=="::/0" for v in ip6):
                bad_admins.append((name, "overly permissive trusted host (0.0.0.0/::/0)"))
    if bad_admins:
        det = "; ".join([f"{n}: {r}" for n,r in bad_admins])
        cli = "config system admin\n" + "\n".join(
            [f"  edit {n}\n    set trusthost1 192.0.2.0 255.255.255.0\n  next" for n,_ in bad_admins]
        ) + "\nend"
        return ("1.2.1 Trusted hosts on all admin accounts", BAD, det,
                "System > Admin > Administrator", cli)
    return ("1.2.1 Trusted hosts on all admin accounts", OK,
            "All admins have scoped trusted hosts", "", "")

def check_password_policy(cfg:str):
    pol = find_blocks(cfg,"system password-policy")
    needed = [
        r'set\s+status\s+enable',
        r'set\s+minimum-length\s+(8|9|1\d+)',
        r'set\s+expire-status\s+enable',
    ]
    ok = bool(pol) and all(re.search(n, pol[0], re.I) for n in needed)
    return ("1.2.2 Password policy enabled (min length ≥8, expire)", OK if ok else BAD,
            "Found" if ok else "Missing/partial",
            "System > Admin > Password Policy",
            "config system password-policy\n  set status enable\n  set minimum-length 12\n  set expire-status enable\nend" if not ok else "")

def check_https_only(cfg:str):
    intf_blocks = find_blocks(cfg, "system interface")
    bad_ifaces=[]
    for blk in intf_blocks:
        edits = re.split(r'\n\s*edit\s+"?([^"\n]+)"?\s*\n', blk, flags=re.I)
        for i in range(1, len(edits), 2):
            name = edits[i].strip().lower()
            body = edits[i+1]
            allow = " ".join(extract_kv(body, "allowaccess"))
            if ("wan" in name or re.search(r'\brole\s+wan\b', body, re.I)) and ("http" in allow):
                bad_ifaces.append(name)
    if bad_ifaces:
        where="Network > Interfaces"
        cli = "\n".join([f"config system interface\n  edit {n}\n    set allowaccess https ping\n    unset allowaccess http\n  next\nend" for n in bad_ifaces])
        return ("2.2.2 Administrative access via HTTPS only on WAN", BAD,
                "HTTP enabled on: "+", ".join(bad_ifaces), where, cli)
    has_https = any(contains(blk, r'set\s+allowaccess.*\bhttps\b') for blk in intf_blocks)
    any_http  = any(contains(blk, r'set\s+allowaccess.*\bhttp\b')  for blk in intf_blocks)
    if has_https and not any_http:
        return ("2.2.2 Administrative access via HTTPS only on WAN", OK,
                "No interfaces with HTTP allowaccess", "", "")
    return ("2.2.2 Administrative access via HTTPS only on WAN", BAD,
            "HTTP allowaccess detected", "Network > Interfaces",
            "edit <wanX> and remove 'http' from allowaccess")

def check_ntp_two_servers(cfg:str):
    ntp_blocks = find_blocks(cfg, "system ntp")
    if not ntp_blocks:
        return ("2.2.1 At least two NTP servers", BAD, "No NTP block",
                "System > Settings > Time & NTP",
                "config system ntp\n  set ntpsync enable\n  set type custom\n  set server \"0.pool.ntp.org\" \"1.pool.ntp.org\"\nend")
    servers = re.findall(r'\bset\s+server\b\s+(.+)', ntp_blocks[0], flags=re.I)
    count = 0
    if servers:
        count = len(re.findall(r'\"[^\"]+\"|\S+', servers[0]))
    if count >= 2:
        return ("2.2.1 At least two NTP servers", OK, f"{count} servers configured", "", "")
    return ("2.2.1 At least two NTP servers", BAD, f"Only {count} server(s) configured",
            "System > Settings > Time & NTP",
            "config system ntp\n  set ntpsync enable\n  set type custom\n  set server \"0.pool.ntp.org\" \"1.pool.ntp.org\"\nend")

def check_snmpv3_only(cfg:str):
    snmp = find_blocks(cfg, "system snmp")
    v3only = any(contains(b, r'set\s+v3-only\s+enable') for b in snmp)
    return ("2.4.1 Only SNMPv3 enabled", OK if v3only else BAD,
            "v3-only enable" if v3only else "SNMPv3-only not enforced",
            "System > SNMP",
            "config system snmp\n  set v3-only enable\nend" if not v3only else "")

# ======================================================

def run_all(cfg:str):
    checks = [
        check_admin_timeout,
        check_ssh_grace,
        check_ssh_v1,
        check_concurrent,
        check_change_admin_port,
        check_trusted_hosts_admin,
        check_password_policy,
        check_https_only,
        check_ntp_two_servers,
        check_snmpv3_only,
    ]
    rows = []
    for fn in checks:
        try:
            rows.append(fn(cfg))
        except Exception as e:
            rows.append((fn.__name__, BAD, f"Checker error: {e}", "", ""))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"FORTIGATE_CIS_AUDIT_v2_{ts}"
    csv_path = base + ".csv"
    html_path = base + ".html"
    csv_write(rows, csv_path)
    html_write(rows, html_path)
    return rows, csv_path, html_path

def main():
    if len(sys.argv)!=2:
        print("Usage: fortigate_cis_checker_v2.py <config.txt>")
        sys.exit(1)
    cfg = read_config(sys.argv[1])
    rows, csv_path, html_path = run_all(cfg)
    print("Results:")
    for r in rows:
        print(" -", r[0], "=>", r[1], "|", r[2])
    print("CSV:", csv_path)
    print("HTML:", html_path)

if __name__=="__main__":
    main()
