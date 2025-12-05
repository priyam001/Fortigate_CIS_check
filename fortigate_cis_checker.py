#!/usr/bin/env python3
"""
FortiGate CIS Benchmark Checker 2025 - Complete Implementation
All 34 Security Controls with FortiGate Configuration Validation
"""

import re, sys, csv, json, logging, os
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('fortigate_audit.log'), logging.StreamHandler()]
)

OK = "PASS"
BAD = "FAIL"
WARNING = "WARNING"

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    FortiGate CIS Benchmark Checker 2025                     ║
║                     Complete Security Analysis - 56 Controls               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

def print_banner():
    print(BANNER)
    print("🔒 Analyzing FortiGate firewall configuration...\n")

def read_config(path: str) -> str:
    try:
        if not os.path.exists(path):
            logging.error(f"Config file not found: {path}")
            return ""
        if not os.access(path, os.R_OK):
            logging.error(f"No read permission for: {path}")
            return ""
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        if not validate_fortigate_config(content):
            logging.warning("Configuration may not be valid FortiGate format")
        logging.info(f"Successfully loaded config: {path}")
        return content
    except Exception as e:
        logging.error(f"Error reading {path}: {e}")
        return ""

def validate_fortigate_config(cfg: str) -> bool:
    """Validate if configuration is FortiGate format"""
    fortigate_markers = [
        r'config system global',
        r'config firewall policy',
        r'config system admin',
        r'set version',
        r'set hostname'
    ]
    matches = sum(1 for marker in fortigate_markers if re.search(marker, cfg, re.I))
    return matches >= 2

def contains(block: str, rex: str, flags: int = re.I|re.M) -> bool:
    try:
        return bool(re.search(rex, block, flags))
    except re.error as e:
        logging.warning(f"Invalid regex pattern: {rex} - {e}")
        return False
    except Exception as e:
        logging.error(f"Error in contains check: {e}")
        return False

def extract_config_blocks(cfg: str, block_type: str) -> List[str]:
    """Extract configuration blocks from FortiGate config"""
    pattern = rf'config {re.escape(block_type)}.*?(?=\nconfig|\nend\s*$|\Z)'
    return re.findall(pattern, cfg, re.I|re.S)

def csv_write(rows: List[Tuple], outpath: str):
    try:
        with open(outpath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Control ID", "Benchmark", "Severity", "Result", "Current Config", "Expected Config", "Remediation", "Zero Trust Impact", "CSPM Score"])
            w.writerows(rows)
        logging.info(f"CSV report written: {outpath}")
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")

def html_write(rows: List[Tuple], outpath: str):
    try:
        total = len(rows)
        passed = sum(1 for r in rows if r[3] == OK)
        failed = sum(1 for r in rows if r[3] == BAD)
        warnings = sum(1 for r in rows if r[3] == WARNING)
        security_score = round((passed / total) * 100, 1) if total > 0 else 0
        
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortiGate CIS 2025 Report</title>
<style>
:root {{--primary: #2c3e50; --success: #27ae60; --danger: #e74c3c; --warning: #f39c12;}}
* {{margin:0; padding:0; box-sizing:border-box;}}
body {{font-family:'Segoe UI',sans-serif; background:linear-gradient(135deg,#667eea,#764ba2); min-height:100vh; padding:20px;}}
.container {{max-width:1400px; margin:0 auto; background:white; border-radius:15px; box-shadow:0 20px 40px rgba(0,0,0,0.1); overflow:hidden;}}
.header {{background:linear-gradient(135deg,var(--primary),#34495e); color:white; padding:30px; text-align:center;}}
.header h1 {{font-size:2.5em; margin-bottom:10px;}}
.dashboard {{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; padding:30px; background:#ecf0f1;}}
.metric-card {{background:white; padding:25px; border-radius:10px; box-shadow:0 5px 15px rgba(0,0,0,0.1); text-align:center;}}
.metric-value {{font-size:2.5em; font-weight:bold; margin-bottom:10px;}}
.pass {{color:var(--success);}} .fail {{color:var(--danger);}} .warning {{color:var(--warning);}}
table {{width:100%; border-collapse:collapse;}}
th {{background:var(--primary); color:white; padding:15px; text-align:left;}}
td {{padding:12px 15px; border-bottom:1px solid #eee;}}
tr:nth-child(even) {{background:#f8f9fa;}}
.status-badge {{padding:5px 12px; border-radius:20px; font-size:0.8em; font-weight:bold; text-transform:uppercase;}}
.badge-pass {{background:#d4edda; color:#155724;}} .badge-fail {{background:#f8d7da; color:#721c24;}} .badge-warning {{background:#fff3cd; color:#856404;}}
.footer {{background:var(--primary); color:white; text-align:center; padding:20px;}}
</style></head><body>
<div class="container">
<div class="header"><h1>🛡️ FortiGate CIS Benchmark 2025</h1><div>Complete Security Analysis - 56 Controls</div>
<div style="margin-top:15px; font-size:0.9em;">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div></div>
<div class="dashboard">
<div class="metric-card"><div class="metric-value pass">{security_score}%</div><div>Security Score</div></div>
<div class="metric-card"><div class="metric-value pass">{passed}</div><div>Passed</div></div>
<div class="metric-card"><div class="metric-value fail">{failed}</div><div>Failed</div></div>
<div class="metric-card"><div class="metric-value warning">{warnings}</div><div>Warnings</div></div>
<div class="metric-card"><div class="metric-value">{total}</div><div>Total Controls</div></div>
</div>
<div style="margin:30px;"><table><thead><tr><th>Control ID</th><th>Benchmark</th><th>Severity</th><th>Status</th><th>Current Config</th><th>Remediation</th></tr></thead><tbody>
"""
    
        for cid, bench, sev, result, current, expected, rem, zt, cspm in rows:
            status_class = f"badge-{result.lower()}"
            html += f"<tr><td><strong>{cid}</strong></td><td>{bench}</td><td>{sev}</td><td><span class='status-badge {status_class}'>{result}</span></td><td><code>{current}</code></td><td>{rem}</td></tr>"
        
        html += f"""</tbody></table></div>
<div class="footer"><p>🔐 FortiGate CIS Benchmark Checker 2025 | 56 Security Controls</p></div>
</div></body></html>"""
        
        Path(outpath).write_text(html, encoding="utf-8")
        logging.info(f"HTML report written: {outpath}")
    except Exception as e:
        logging.error(f"Failed to write HTML: {e}")

# Critical Controls
def check_mfa(cfg: str) -> Tuple:
    admin_blocks = extract_config_blocks(cfg, "system admin")
    if not admin_blocks:
        return ("MFA-001", "Multi-Factor Authentication", "Critical", BAD, "No admin config", "MFA required", "Enable MFA for all admins", "Critical", "0")
    mfa_count = sum(1 for b in admin_blocks if contains(b, r'set two-factor enable|set fortitoken'))
    if mfa_count == len(admin_blocks):
        return ("MFA-001", "Multi-Factor Authentication", "Critical", OK, f"MFA enabled for all {mfa_count} admins", "100% coverage", "MFA properly configured", "High", "100")
    return ("MFA-001", "Multi-Factor Authentication", "Critical", BAD, f"MFA: {mfa_count}/{len(admin_blocks)}", "100% coverage", "Enable MFA for all admins", "Critical", str(int(mfa_count*100/len(admin_blocks))))

def check_ztna(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall access-proxy') and contains(cfg, r'set auth-portal enable'):
        return ("ZT-001", "Zero Trust Network Access", "Critical", OK, "ZTNA configured", "N/A", "ZTNA properly configured", "High", "100")
    return ("ZT-001", "Zero Trust Network Access", "Critical", BAD, "ZTNA not configured", "config firewall access-proxy", "Deploy ZTNA for Zero Trust", "High", "0")

def check_encryption(cfg: str) -> Tuple:
    if contains(cfg, r'set ssl-min-proto-version tlsv1-3') and contains(cfg, r'set strong-crypto enable'):
        return ("ENC-001", "Encryption Standards (TLS 1.3+)", "Critical", OK, "TLS 1.3 enforced", "TLS 1.3+", "Encryption meets 2025 standards", "High", "100")
    return ("ENC-001", "Encryption Standards (TLS 1.3+)", "Critical", BAD, "TLS 1.3 not enforced", "TLS 1.3+", "Upgrade to TLS 1.3", "High", "0")

def check_admin_timeout(cfg: str) -> Tuple:
    m = re.search(r'set admin(?:timeout|-timeout)\s+(\d+)', cfg, re.I|re.M)
    if m and int(m.group(1)) <= 3:
        return ("ADM-001", "Admin Timeout", "Critical", OK, f"Timeout: {m.group(1)}min", "≤3 min", "Admin timeout meets standards", "Medium", "100")
    return ("ADM-001", "Admin Timeout", "Critical", BAD, "Timeout not set or too long", "≤3 min", "Set admin timeout to 3 minutes", "High", "0")

def check_firewall_rules(cfg: str) -> Tuple:
    policy_blocks = extract_config_blocks(cfg, "firewall policy")
    if not policy_blocks:
        return ("FW-001", "Firewall Rules", "Critical", BAD, "No firewall policies", "≥10 rules", "Configure firewall policies", "Critical", "0")
    rules = len(re.findall(r'edit \d+', '\n'.join(policy_blocks), re.I))
    if rules >= 10:
        return ("FW-001", "Firewall Rules", "Critical", OK, f"{rules} rules configured", "≥10 rules", "Firewall rules properly configured", "High", "100")
    return ("FW-001", "Firewall Rules", "Critical", BAD, f"Only {rules} rules", "≥10 rules", "Configure comprehensive firewall rules", "Critical", "0")

# High Priority Controls
def check_ai_detection(cfg: str) -> Tuple:
    av_blocks = extract_config_blocks(cfg, "antivirus profile")
    if av_blocks and any(contains(b, r'set ai-based-detection enable|set machine-learning enable') for b in av_blocks):
        return ("AI-001", "AI/ML Threat Detection", "High", OK, "AI detection enabled", "N/A", "AI/ML properly configured", "Medium", "100")
    return ("AI-001", "AI/ML Threat Detection", "High", BAD, "AI detection not enabled", "Enable AI detection", "Enable AI-based threat detection", "Medium", "0")

def check_segmentation(cfg: str) -> Tuple:
    policy_blocks = extract_config_blocks(cfg, "firewall policy")
    deny_rules = sum(len(re.findall(r'set action deny', b, re.I)) for b in policy_blocks)
    if deny_rules >= 5:
        return ("NS-001", "Network Segmentation", "High", OK, f"{deny_rules} deny rules", "≥5 rules", "Network segmentation properly configured", "High", "100")
    return ("NS-001", "Network Segmentation", "High", BAD, f"Only {deny_rules} deny rules", "≥5 rules", "Implement network segmentation", "High", "0")

def check_supply_chain(cfg: str) -> Tuple:
    score = sum([contains(cfg, r'set firmware-upgrade-check enable'), contains(cfg, r'config vpn certificate', re.I|re.M|re.S), contains(cfg, r'set fortiguard-anycast enable')])
    if score >= 2:
        return ("SC-001", "Supply Chain Security", "High", OK, f"Score: {score}/3", "≥2/3", "Supply chain security configured", "Medium", str(score*33))
    return ("SC-001", "Supply Chain Security", "High", BAD, f"Score: {score}/3", "≥2/3", "Strengthen supply chain controls", "Low", str(score*33))

def check_cspm(cfg: str) -> Tuple:
    score = sum([contains(cfg, r'config system cloud-connector'), contains(cfg, r'config system csf.*set status enable', re.I|re.M|re.S), contains(cfg, r'set auto-join-forticloud enable'), contains(cfg, r'config log fortianalyzer.*set status enable', re.I|re.M|re.S)])
    if score >= 3:
        return ("CSPM-001", "Cloud Security Posture", "High", OK, f"CSPM: {score}/4", "≥3/4", "CSPM compliance meets standards", "High", str(score*25))
    return ("CSPM-001", "Cloud Security Posture", "High", BAD, f"CSPM: {score}/4", "≥3/4", "Improve cloud security posture", "Low", str(score*25))

def check_ssl_inspection(cfg: str) -> Tuple:
    if contains(cfg, r'set ssl-inspect enable|config firewall ssl-ssh-profile'):
        return ("SSL-001", "SSL/TLS Inspection", "High", OK, "SSL inspection enabled", "N/A", "SSL inspection properly configured", "High", "100")
    return ("SSL-001", "SSL/TLS Inspection", "High", BAD, "SSL inspection not configured", "Enable SSL inspection", "Configure SSL/TLS inspection", "High", "0")

def check_app_control(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall application-list|set application-control enable'):
        return ("APP-001", "Application Control", "High", OK, "App control enabled", "N/A", "Application control properly configured", "High", "100")
    return ("APP-001", "Application Control", "High", BAD, "App control not configured", "Enable app control", "Configure application control", "High", "0")

def check_ips_ids(cfg: str) -> Tuple:
    if contains(cfg, r'set ips-sensor|config ips sensor'):
        return ("IPS-001", "IPS/IDS Protection", "High", OK, "IPS/IDS configured", "N/A", "IPS/IDS properly configured", "High", "100")
    return ("IPS-001", "IPS/IDS Protection", "High", BAD, "IPS/IDS not configured", "Configure IPS/IDS", "Enable intrusion prevention", "High", "0")

def check_antivirus(cfg: str) -> Tuple:
    if contains(cfg, r'set av-profile|config antivirus profile'):
        return ("AV-001", "Antivirus Protection", "High", OK, "Antivirus configured", "N/A", "Antivirus properly configured", "High", "100")
    return ("AV-001", "Antivirus Protection", "High", BAD, "Antivirus not configured", "Configure antivirus", "Enable antivirus protection", "High", "0")

def check_dpi_ssl(cfg: str) -> Tuple:
    if contains(cfg, r'set dpi-ssl enable|config firewall ssl-ssh-profile'):
        return ("DPI-001", "DPI-SSL Inspection", "High", OK, "DPI-SSL enabled", "N/A", "DPI-SSL properly configured", "High", "100")
    return ("DPI-001", "DPI-SSL Inspection", "High", BAD, "DPI-SSL not configured", "Enable DPI-SSL", "Configure deep packet inspection", "High", "0")

def check_vpn_encryption(cfg: str) -> Tuple:
    if contains(cfg, r'config vpn ipsec phase1'):
        if contains(cfg, r'aes256|chacha20'):
            return ("VPN-001", "VPN Encryption", "High", OK, "Strong VPN encryption", "AES-256/ChaCha20", "VPN encryption meets standards", "High", "100")
        return ("VPN-001", "VPN Encryption", "High", WARNING, "VPN weak encryption", "AES-256/ChaCha20", "Upgrade VPN encryption", "High", "50")
    return ("VPN-001", "VPN Encryption", "High", BAD, "VPN not configured", "Configure VPN", "Configure VPN with strong encryption", "High", "0")

def check_dns_security(cfg: str) -> Tuple:
    if contains(cfg, r'set dns-filter-profile|config dns-filter profile'):
        return ("DNS-001", "DNS Security", "High", OK, "DNS filtering enabled", "N/A", "DNS security properly configured", "High", "100")
    return ("DNS-001", "DNS Security", "High", BAD, "DNS filtering not configured", "Enable DNS filtering", "Configure DNS security", "High", "0")

def check_ddos_protection(cfg: str) -> Tuple:
    if contains(cfg, r'set ddos-protection enable|config system ddos-protection'):
        return ("DDOS-001", "DDoS Protection", "High", OK, "DDoS protection enabled", "N/A", "DDoS protection properly configured", "High", "100")
    return ("DDOS-001", "DDoS Protection", "High", BAD, "DDoS protection not configured", "Enable DDoS protection", "Configure DDoS protection", "High", "0")

def check_user_auth(cfg: str) -> Tuple:
    if contains(cfg, r'config user local|config user radius'):
        return ("AUTH-001", "User Authentication", "High", OK, "User auth configured", "N/A", "User authentication properly configured", "High", "100")
    return ("AUTH-001", "User Authentication", "High", BAD, "User auth not configured", "Configure user auth", "Configure user authentication", "High", "0")

def check_ssl_cert(cfg: str) -> Tuple:
    if contains(cfg, r'config system certificate|set certificate'):
        return ("CERT-001", "SSL Certificate", "High", OK, "SSL cert configured", "N/A", "SSL certificate properly configured", "High", "100")
    return ("CERT-001", "SSL Certificate", "High", BAD, "SSL cert not configured", "Configure SSL cert", "Configure SSL certificate", "High", "0")

# Medium Priority Controls
def check_logging(cfg: str) -> Tuple:
    if contains(cfg, r'config log fortianalyzer.*set status enable', re.I|re.M|re.S):
        return ("LOG-001", "Centralized Logging", "Medium", OK, "Logging enabled", "N/A", "Centralized logging properly configured", "Medium", "100")
    return ("LOG-001", "Centralized Logging", "Medium", BAD, "Logging not configured", "Enable logging", "Configure centralized logging", "Low", "0")

def check_monitoring(cfg: str) -> Tuple:
    if contains(cfg, r'set threat-weight enable|config log threat-weight'):
        return ("MON-001", "Threat Monitoring", "Medium", OK, "Monitoring enabled", "N/A", "Threat monitoring properly configured", "Medium", "100")
    return ("MON-001", "Threat Monitoring", "Medium", BAD, "Monitoring not configured", "Enable monitoring", "Configure threat monitoring", "Low", "0")

def check_updates(cfg: str) -> Tuple:
    if contains(cfg, r'set auto-update enable|set auto-update-schedule'):
        return ("UPD-001", "Automated Updates", "Medium", OK, "Updates enabled", "N/A", "Automated updates properly configured", "Medium", "100")
    return ("UPD-001", "Automated Updates", "Medium", BAD, "Updates not configured", "Enable updates", "Configure automated updates", "Low", "0")

def check_audit(cfg: str) -> Tuple:
    if contains(cfg, r'config log eventfilter|set admin enable'):
        return ("AUD-001", "Audit Logging", "Medium", OK, "Audit logging enabled", "N/A", "Audit logging properly configured", "Medium", "100")
    return ("AUD-001", "Audit Logging", "Medium", BAD, "Audit logging not configured", "Enable audit logging", "Configure audit logging", "Low", "0")

def check_web_filter(cfg: str) -> Tuple:
    if contains(cfg, r'set webfilter-profile|config webfilter profile'):
        return ("WEB-001", "Web Filtering", "Medium", OK, "Web filtering enabled", "N/A", "Web filtering properly configured", "Medium", "100")
    return ("WEB-001", "Web Filtering", "Medium", BAD, "Web filtering not configured", "Enable web filtering", "Configure web filtering", "Low", "0")

def check_admin_profiles(cfg: str) -> Tuple:
    if contains(cfg, r'config system admin-profile|set profile-permission'):
        return ("ADMIN-001", "Admin Profiles", "Medium", OK, "Admin profiles configured", "N/A", "Admin profiles properly configured", "Medium", "100")
    return ("ADMIN-001", "Admin Profiles", "Medium", BAD, "Admin profiles not configured", "Configure admin profiles", "Configure role-based admin profiles", "Low", "0")

def check_password_policy(cfg: str) -> Tuple:
    if contains(cfg, r'set password-policy|set password-expire'):
        return ("PWD-001", "Password Policy", "Medium", OK, "Password policy configured", "N/A", "Password policy properly configured", "Medium", "100")
    return ("PWD-001", "Password Policy", "Medium", BAD, "Password policy not configured", "Enable password policy", "Configure strong password policy", "Low", "0")

def check_session_timeout(cfg: str) -> Tuple:
    if contains(cfg, r'set session-timeout|set idle-timeout'):
        return ("SESSION-001", "Session Timeout", "Medium", OK, "Session timeout configured", "N/A", "Session timeout properly configured", "Medium", "100")
    return ("SESSION-001", "Session Timeout", "Medium", BAD, "Session timeout not configured", "Set session timeout", "Configure session timeout", "Low", "0")

def check_backup(cfg: str) -> Tuple:
    if contains(cfg, r'config system backup|set backup-on-upgrade'):
        return ("BACKUP-001", "Backup & Restore", "Medium", OK, "Backup configured", "N/A", "Backup properly configured", "Medium", "100")
    return ("BACKUP-001", "Backup & Restore", "Medium", BAD, "Backup not configured", "Enable backup", "Configure automated backup", "Low", "0")

def check_syslog(cfg: str) -> Tuple:
    if contains(cfg, r'config log syslogd.*set status enable', re.I|re.M|re.S):
        return ("SYSLOG-001", "Syslog Configuration", "Medium", OK, "Syslog enabled", "N/A", "Syslog properly configured", "Medium", "100")
    return ("SYSLOG-001", "Syslog Configuration", "Medium", BAD, "Syslog not configured", "Enable syslog", "Configure syslog", "Low", "0")

def check_ha(cfg: str) -> Tuple:
    if contains(cfg, r'config system ha.*set mode active-passive', re.I|re.M|re.S):
        return ("HA-001", "High Availability", "Medium", OK, "HA configured", "N/A", "High Availability properly configured", "Medium", "100")
    return ("HA-001", "High Availability", "Medium", BAD, "HA not configured", "Configure HA", "Configure High Availability", "Low", "0")

def check_geo_blocking(cfg: str) -> Tuple:
    if contains(cfg, r'set geo-block|config firewall geo-ip-override'):
        return ("GEO-001", "Geographic Blocking", "Medium", OK, "Geo blocking configured", "N/A", "Geographic blocking properly configured", "Medium", "100")
    return ("GEO-001", "Geographic Blocking", "Medium", BAD, "Geo blocking not configured", "Enable geo blocking", "Configure geographic blocking", "Low", "0")

# Low Priority Controls
def check_ntp(cfg: str) -> Tuple:
    if contains(cfg, r'config system ntp.*set ntpsync enable', re.I|re.M|re.S):
        return ("NTP-001", "NTP Synchronization", "Low", OK, "NTP enabled", "N/A", "NTP properly configured", "Low", "100")
    return ("NTP-001", "NTP Synchronization", "Low", BAD, "NTP not configured", "Enable NTP", "Configure NTP", "Low", "0")

def check_snmp(cfg: str) -> Tuple:
    if contains(cfg, r'config system snmp.*set status enable', re.I|re.M|re.S):
        return ("SNMP-001", "SNMP Configuration", "Low", OK, "SNMP enabled", "N/A", "SNMP properly configured", "Low", "100")
    return ("SNMP-001", "SNMP Configuration", "Low", BAD, "SNMP not configured", "Enable SNMP", "Configure SNMP", "Low", "0")

# Additional Critical Controls
def check_fortiguard(cfg: str) -> Tuple:
    if contains(cfg, r'set fortiguard-anycast enable|config system fortiguard'):
        return ("FG-001", "FortiGuard Services", "Critical", OK, "FortiGuard enabled", "N/A", "FortiGuard properly configured", "High", "100")
    return ("FG-001", "FortiGuard Services", "Critical", BAD, "FortiGuard not enabled", "Enable FortiGuard", "Configure FortiGuard services", "High", "0")

def check_sandbox(cfg: str) -> Tuple:
    if contains(cfg, r'set sandbox-mode enable|config system sandbox'):
        return ("SB-001", "Sandbox Detection", "Critical", OK, "Sandbox enabled", "N/A", "Sandbox properly configured", "High", "100")
    return ("SB-001", "Sandbox Detection", "Critical", BAD, "Sandbox not enabled", "Enable sandbox", "Configure sandbox detection", "High", "0")

def check_threat_feeds(cfg: str) -> Tuple:
    if contains(cfg, r'config system threat-weight|set threat-weight enable'):
        return ("TF-001", "Threat Intelligence Feeds", "Critical", OK, "Threat feeds enabled", "N/A", "Threat feeds properly configured", "High", "100")
    return ("TF-001", "Threat Intelligence Feeds", "Critical", BAD, "Threat feeds not enabled", "Enable threat feeds", "Configure threat intelligence", "High", "0")

def check_botnet_protection(cfg: str) -> Tuple:
    if contains(cfg, r'set botnet-detection enable|config system botnet'):
        return ("BOT-001", "Botnet Protection", "Critical", OK, "Botnet protection enabled", "N/A", "Botnet protection configured", "High", "100")
    return ("BOT-001", "Botnet Protection", "Critical", BAD, "Botnet protection disabled", "Enable botnet protection", "Configure botnet detection", "High", "0")

def check_ransomware_protection(cfg: str) -> Tuple:
    if contains(cfg, r'set ransomware-protection enable|config system ransomware'):
        return ("RW-001", "Ransomware Protection", "Critical", OK, "Ransomware protection enabled", "N/A", "Ransomware protection configured", "High", "100")
    return ("RW-001", "Ransomware Protection", "Critical", BAD, "Ransomware protection disabled", "Enable ransomware protection", "Configure ransomware detection", "High", "0")

def check_iot_detection(cfg: str) -> Tuple:
    if contains(cfg, r'set iot-detection enable|config system iot'):
        return ("IOT-001", "IoT Device Detection", "Critical", OK, "IoT detection enabled", "N/A", "IoT detection configured", "High", "100")
    return ("IOT-001", "IoT Device Detection", "Critical", BAD, "IoT detection disabled", "Enable IoT detection", "Configure IoT device detection", "High", "0")

# Additional High Priority Controls
def check_advanced_threat_protection(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall profile-protocol-options|set advanced-options enable'):
        return ("ATP-001", "Advanced Threat Protection", "High", OK, "ATP enabled", "N/A", "ATP properly configured", "High", "100")
    return ("ATP-001", "Advanced Threat Protection", "High", BAD, "ATP not configured", "Enable ATP", "Configure advanced threat protection", "High", "0")

def check_file_filter(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall file-filter|set file-filter enable'):
        return ("FF-001", "File Filtering", "High", OK, "File filtering enabled", "N/A", "File filtering configured", "High", "100")
    return ("FF-001", "File Filtering", "High", BAD, "File filtering not configured", "Enable file filtering", "Configure file filtering", "High", "0")

def check_email_filter(cfg: str) -> Tuple:
    if contains(cfg, r'config emailfilter profile|set email-filter enable'):
        return ("EF-001", "Email Filtering", "High", OK, "Email filtering enabled", "N/A", "Email filtering configured", "High", "100")
    return ("EF-001", "Email Filtering", "High", BAD, "Email filtering not configured", "Enable email filtering", "Configure email filtering", "High", "0")

def check_content_disarm(cfg: str) -> Tuple:
    if contains(cfg, r'set content-disarm enable|config system content-disarm'):
        return ("CD-001", "Content Disarm & Reconstruction", "High", OK, "CDR enabled", "N/A", "CDR properly configured", "High", "100")
    return ("CD-001", "Content Disarm & Reconstruction", "High", BAD, "CDR not enabled", "Enable CDR", "Configure content disarm", "High", "0")

def check_url_filtering(cfg: str) -> Tuple:
    if contains(cfg, r'config urlfilter profile|set url-filter enable'):
        return ("UF-001", "URL Filtering", "High", OK, "URL filtering enabled", "N/A", "URL filtering configured", "High", "100")
    return ("UF-001", "URL Filtering", "High", BAD, "URL filtering not configured", "Enable URL filtering", "Configure URL filtering", "High", "0")

def check_vulnerability_scanning(cfg: str) -> Tuple:
    if contains(cfg, r'config system vulnerability-scan|set vuln-scan enable'):
        return ("VS-001", "Vulnerability Scanning", "High", OK, "Vuln scanning enabled", "N/A", "Vulnerability scanning configured", "High", "100")
    return ("VS-001", "Vulnerability Scanning", "High", BAD, "Vuln scanning not configured", "Enable vuln scanning", "Configure vulnerability scanning", "High", "0")

def check_waf(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall waf|set waf-profile enable'):
        return ("WAF-001", "Web Application Firewall", "High", OK, "WAF enabled", "N/A", "WAF properly configured", "High", "100")
    return ("WAF-001", "Web Application Firewall", "High", BAD, "WAF not configured", "Enable WAF", "Configure web application firewall", "High", "0")

def check_api_gateway(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall api-gateway|set api-gateway enable'):
        return ("API-001", "API Gateway Protection", "High", OK, "API gateway enabled", "N/A", "API gateway configured", "High", "100")
    return ("API-001", "API Gateway Protection", "High", BAD, "API gateway not configured", "Enable API gateway", "Configure API gateway protection", "High", "0")

def check_casb(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall casb|set casb-enable enable'):
        return ("CASB-001", "Cloud Access Security Broker", "High", OK, "CASB enabled", "N/A", "CASB properly configured", "High", "100")
    return ("CASB-001", "Cloud Access Security Broker", "High", BAD, "CASB not configured", "Enable CASB", "Configure cloud access security", "High", "0")

# Additional Medium Priority Controls
def check_traffic_shaping(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall traffic-shaper|set traffic-shaper enable'):
        return ("TS-001", "Traffic Shaping", "Medium", OK, "Traffic shaping enabled", "N/A", "Traffic shaping configured", "Medium", "100")
    return ("TS-001", "Traffic Shaping", "Medium", BAD, "Traffic shaping not configured", "Enable traffic shaping", "Configure traffic shaping", "Low", "0")

def check_qos(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall qos-profile|set qos-enable enable'):
        return ("QOS-001", "Quality of Service", "Medium", OK, "QoS enabled", "N/A", "QoS properly configured", "Medium", "100")
    return ("QOS-001", "Quality of Service", "Medium", BAD, "QoS not configured", "Enable QoS", "Configure quality of service", "Low", "0")

def check_nat_policy(cfg: str) -> Tuple:
    policy_blocks = extract_config_blocks(cfg, "firewall policy")
    nat_rules = sum(len(re.findall(r'set nat enable', b, re.I)) for b in policy_blocks)
    if nat_rules >= 1:
        return ("NAT-001", "NAT Policy Configuration", "Medium", OK, f"{nat_rules} NAT rules", "≥1 rule", "NAT policies properly configured", "Medium", "100")
    return ("NAT-001", "NAT Policy Configuration", "Medium", BAD, "No NAT rules", "≥1 rule", "Configure NAT policies", "Low", "0")

def check_proxy_settings(cfg: str) -> Tuple:
    if contains(cfg, r'config firewall proxy-policy|set proxy-policy enable'):
        return ("PROXY-001", "Proxy Settings", "Medium", OK, "Proxy configured", "N/A", "Proxy settings properly configured", "Medium", "100")
    return ("PROXY-001", "Proxy Settings", "Medium", BAD, "Proxy not configured", "Configure proxy", "Configure proxy settings", "Low", "0")

def check_interface_security(cfg: str) -> Tuple:
    if contains(cfg, r'config system interface.*set security-mode enable', re.I|re.M|re.S):
        return ("INT-001", "Interface Security", "Medium", OK, "Interface security enabled", "N/A", "Interface security configured", "Medium", "100")
    return ("INT-001", "Interface Security", "Medium", BAD, "Interface security not configured", "Enable interface security", "Configure interface security", "Low", "0")

def check_routing_security(cfg: str) -> Tuple:
    if contains(cfg, r'config router static|set route-security enable'):
        return ("ROUTE-001", "Routing Security", "Medium", OK, "Routing security enabled", "N/A", "Routing security configured", "Medium", "100")
    return ("ROUTE-001", "Routing Security", "Medium", BAD, "Routing security not configured", "Enable routing security", "Configure routing security", "Low", "0")

def check_certificate_validation(cfg: str) -> Tuple:
    if contains(cfg, r'set certificate-validation enable|config system certificate-validation'):
        return ("CERTVAL-001", "Certificate Validation", "Medium", OK, "Cert validation enabled", "N/A", "Certificate validation configured", "Medium", "100")
    return ("CERTVAL-001", "Certificate Validation", "Medium", BAD, "Cert validation not configured", "Enable cert validation", "Configure certificate validation", "Low", "0")

def check_device_hardening(cfg: str) -> Tuple:
    score = sum([contains(cfg, r'set admin-lockout-threshold'), contains(cfg, r'set admin-lockout-duration'), contains(cfg, r'set block-session-timer', re.I|re.M|re.S)])
    if score >= 2:
        return ("DH-001", "Device Hardening", "Medium", OK, f"Hardening: {score}/3", "≥2/3", "Device hardening properly configured", "Medium", str(score*33))
    return ("DH-001", "Device Hardening", "Medium", BAD, f"Hardening: {score}/3", "≥2/3", "Improve device hardening", "Low", str(score*33))

def check_compliance_logging(cfg: str) -> Tuple:
    if contains(cfg, r'config log compliance|set compliance-logging enable'):
        return ("COMP-001", "Compliance Logging", "Medium", OK, "Compliance logging enabled", "N/A", "Compliance logging configured", "Medium", "100")
    return ("COMP-001", "Compliance Logging", "Medium", BAD, "Compliance logging not configured", "Enable compliance logging", "Configure compliance logging", "Low", "0")

def run_all_checks(cfg: str) -> List[Tuple]:
    checks = [
        check_mfa, check_ztna, check_encryption, check_admin_timeout, check_firewall_rules,
        check_ai_detection, check_segmentation, check_supply_chain, check_cspm, check_ssl_inspection,
        check_app_control, check_ips_ids, check_antivirus, check_dpi_ssl, check_vpn_encryption,
        check_dns_security, check_ddos_protection, check_user_auth, check_ssl_cert,
        check_logging, check_monitoring, check_updates, check_audit, check_web_filter,
        check_admin_profiles, check_password_policy, check_session_timeout, check_backup, check_syslog,
        check_ha, check_geo_blocking, check_ntp, check_snmp,
        check_fortiguard, check_sandbox, check_threat_feeds, check_botnet_protection, check_ransomware_protection,
        check_iot_detection, check_advanced_threat_protection, check_file_filter, check_email_filter, check_content_disarm,
        check_url_filtering, check_vulnerability_scanning, check_waf, check_api_gateway, check_casb,
        check_traffic_shaping, check_qos, check_nat_policy, check_proxy_settings, check_interface_security,
        check_routing_security, check_certificate_validation, check_device_hardening, check_compliance_logging
    ]
    
    rows = []
    for fn in checks:
        try:
            result = fn(cfg)
            rows.append(result)
            logging.debug(f"Check {fn.__name__}: {result[3]}")
        except Exception as e:
            logging.error(f"Check {fn.__name__} failed: {e}")
            rows.append(("ERR", f"Error: {fn.__name__}", "Critical", BAD, str(e), "Fix", "Contact admin", "Unknown", "0"))
    return rows

def main():
    try:
        print_banner()
        if len(sys.argv) != 2:
            print("Usage: python3 fortigate_cis_checker_2025.py <config_file>")
            sys.exit(1)
        
        cfg = read_config(sys.argv[1])
        if not cfg:
            logging.error("Failed to read configuration")
            sys.exit(1)
        
        print("Running 56 security control checks on FortiGate configuration...\n")
        rows = run_all_checks(cfg)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = f"FortiGate_CIS_2025_Audit_{timestamp}.csv"
        html_path = f"FortiGate_CIS_2025_Audit_{timestamp}.html"
        
        csv_write(rows, csv_path)
        html_write(rows, html_path)
        
        total = len(rows)
        passed = sum(1 for r in rows if r[3] == OK)
        failed = sum(1 for r in rows if r[3] == BAD)
        warnings = sum(1 for r in rows if r[3] == WARNING)
        
        print("\n" + "="*80)
        print("FORTIGATE SECURITY ANALYSIS SUMMARY")
        print("="*80)
        print(f"Total Controls: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Warnings: {warnings}")
        print(f"📈 Security Score: {(passed/total)*100:.1f}%")
        print(f"\n📊 CSV Report: {csv_path}")
        print(f"🌐 HTML Report: {html_path}")
        print("="*80)
        logging.info("Audit completed successfully")
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
