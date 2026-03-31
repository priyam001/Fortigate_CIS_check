"""
CIS FortiGate Benchmark v1.3.0 – Level 1 Rules
=================================================
Level 1 rules represent basic security settings that should be applied to
every FortiGate deployment. These are the minimum recommended controls.

CIS Sections covered:
  1.x   – Network Configuration
  2.1.x – System Settings
  2.2.x – Password Configuration
  2.3.x – SNMP Configuration
  2.4.x – Admin Access & HA
  3.x   – Firewall Policy
  4.x   – Security Profiles (IPS, AV, DNS, App Control)
  5.x   – Automation & Security Fabric
  6.x   – VPN
  7.x   – Logging & Monitoring
"""

import re
from typing import List
from cis_benchmark.rules.base import (
    CISRule, CallableCISRule, RuleResult, CISLevel, RuleSeverity,
)


# =============================================================================
# Rule Evaluator Functions
# Each function receives (rule: CISRule, config: FortiGateConfig) -> RuleResult
# =============================================================================

# --- 1.x Network Configuration ---

def _eval_dns_configured(rule, config):
    blocks = config.get_blocks("system dns")
    if blocks:
        servers = []
        for b in blocks:
            if b.has("primary"):
                servers.append(b.get("primary"))
            if b.has("secondary"):
                servers.append(b.get("secondary"))
        if servers:
            return rule._make_result(True, f"DNS servers: {', '.join(servers)}")
        return rule._make_result(True, "DNS section configured")
    # Fallback: search raw
    if config.search(r'config system dns'):
        return rule._make_result(True, "DNS configured (raw match)")
    return rule._make_result(False, "No DNS configuration found")


def _eval_intra_zone_deny(rule, config):
    val = config.get_global_setting("intra-zone-deny", "")
    if val.lower() == "enable":
        return rule._make_result(True, "intra-zone-deny: enable")
    return rule._make_result(False, f"intra-zone-deny: {val or 'not set'}")


def _eval_wan_management(rule, config):
    interfaces = config.get_interface_blocks()
    wan_issues = []
    for block in interfaces:
        for sub in block.sub_blocks:
            role = sub.get("role", "").lower()
            if role == "wan":
                access = sub.get("allowaccess", "")
                insecure = [s for s in ["http", "telnet", "fgfm"] if s in access.lower()]
                if insecure:
                    wan_issues.append(f"{sub.name}: {', '.join(insecure)}")
    if not wan_issues:
        return rule._make_result(True, "No insecure services on WAN ports")
    return rule._make_result(False, f"Insecure services: {'; '.join(wan_issues)}")


# --- 2.1.x System Settings ---

def _eval_pre_login_banner(rule, config):
    val = config.get_global_setting("pre-login-banner", "")
    if val.lower() == "enable":
        return rule._make_result(True, "Pre-login banner is enabled")
    return rule._make_result(False, f"pre-login-banner: {val or 'not set (disable)'}")


def _eval_post_login_banner(rule, config):
    val = config.get_global_setting("post-login-banner", "")
    if val.lower() == "enable":
        return rule._make_result(True, "Post-login banner is enabled")
    return rule._make_result(False, f"post-login-banner: {val or 'not set (disable)'}")


def _eval_timezone(rule, config):
    val = config.get_global_setting("timezone", "")
    if val:
        return rule._make_result(True, f"Timezone set: {val}")
    return rule._make_result(False, "Timezone not configured")


def _eval_ntp(rule, config):
    ntp_blocks = config.get_blocks("system ntp")
    if ntp_blocks:
        for b in ntp_blocks:
            if b.get("ntpsync", "").lower() == "enable" or b.get("type", ""):
                return rule._make_result(True, "NTP synchronization enabled")
        return rule._make_result(True, "NTP section configured")
    if config.search(r'config system ntp'):
        return rule._make_result(True, "NTP configured (raw match)")
    return rule._make_result(False, "NTP not configured")


def _eval_hostname(rule, config):
    hostname = config.hostname
    if hostname and hostname != "FortiGate":
        return rule._make_result(True, f"Hostname: {hostname}")
    return rule._make_result(False, f"Hostname: {hostname or 'not set'}")


def _eval_usb_disable(rule, config):
    val = config.get_global_setting("usb-auto-install", "")
    if val.lower() == "disable":
        return rule._make_result(True, "USB auto-install disabled")
    # If not explicitly set, FortiGate defaults to enable
    if not val:
        return rule._make_result(False, "usb-auto-install not explicitly set (defaults to enable)")
    return rule._make_result(False, f"usb-auto-install: {val}")


def _eval_static_keys_tls(rule, config):
    val = config.get_global_setting("strong-crypto", "")
    if val.lower() == "enable":
        return rule._make_result(True, "Strong crypto enabled (static keys disabled)")
    return rule._make_result(False, f"strong-crypto: {val or 'not set'}")


def _eval_global_strong_encryption(rule, config):
    val = config.get_global_setting("strong-crypto", "")
    if val.lower() == "enable":
        return rule._make_result(True, "Global strong encryption enabled")
    return rule._make_result(False, f"strong-crypto: {val or 'not set'}")


def _eval_tls_management_gui(rule, config):
    val = config.get_global_setting("admin-https-ssl-versions", "")
    if val:
        insecure = any(v in val.lower() for v in ["tlsv1-0", "sslv3"])
        if not insecure:
            return rule._make_result(True, f"TLS versions: {val}")
        return rule._make_result(False, f"Insecure TLS versions enabled: {val}")
    return rule._make_result(False, "admin-https-ssl-versions not configured")


def _eval_cdn(rule, config):
    val = config.get_global_setting("gui-cdn-usage", "")
    if val.lower() == "enable":
        return rule._make_result(True, "CDN enabled for GUI")
    return rule._make_result(False, f"gui-cdn-usage: {val or 'not set'}")


# --- 2.2.x Password Configuration ---

def _eval_password_policy(rule, config):
    if config.search(r'config system password-policy'):
        return rule._make_result(True, "Password policy configured")
    val = config.get_global_setting("password-policy", "")
    if val:
        return rule._make_result(True, f"Password policy: {val}")
    return rule._make_result(False, "Password policy not configured")


def _eval_admin_lockout(rule, config):
    threshold = config.get_global_setting("admin-lockout-threshold", "")
    duration = config.get_global_setting("admin-lockout-duration", "")
    if threshold and duration:
        return rule._make_result(True, f"Lockout: threshold={threshold}, duration={duration}s")
    return rule._make_result(False, f"Lockout: threshold={threshold or 'not set'}, duration={duration or 'not set'}")


# --- 2.3.x SNMP Configuration ---

def _eval_snmpv3_only(rule, config):
    if config.search(r'config system snmp'):
        if config.search(r'set\s+v3-only\s+enable'):
            return rule._make_result(True, "SNMPv3 only mode enabled")
        return rule._make_result(False, "SNMP configured but v3-only not enabled")
    return rule._make_result(False, "SNMP not configured")


# --- 2.4.x Admin Access ---

def _eval_admin_timeout(rule, config):
    val = config.get_global_setting("admintimeout", "")
    if not val:
        val = config.get_global_setting("admin-timeout", "")
    if val:
        try:
            timeout = int(val)
            if timeout <= 15:
                return rule._make_result(True, f"Admin timeout: {timeout} minutes")
            return rule._make_result(False, f"Admin timeout too long: {timeout} minutes")
        except ValueError:
            return rule._make_result(False, f"Invalid timeout value: {val}")
    return rule._make_result(False, "Admin timeout not configured")


def _eval_encrypted_access(rule, config):
    val = config.get_global_setting("admin-ssh-v1", "")
    https_redirect = config.get_global_setting("admin-https-redirect", "")
    issues = []
    if val.lower() != "disable":
        issues.append("SSH v1 not disabled")
    if https_redirect.lower() != "enable":
        issues.append("HTTPS redirect not enabled")
    if not issues:
        return rule._make_result(True, "SSH v1 disabled, HTTPS redirect enabled")
    return rule._make_result(False, "; ".join(issues))


# --- 3.x Firewall Policy ---

def _eval_no_all_service(rule, config):
    if config.search(r'set\s+service\s+"?ALL"?'):
        count = len(re.findall(r'set\s+service\s+"?ALL"?', config.raw_content, re.I))
        return rule._make_result(False, f"{count} policies use 'ALL' as service")
    return rule._make_result(True, "No policies use 'ALL' as service")


def _eval_logging_on_policies(rule, config):
    policies = config.get_policy_blocks()
    total = 0
    logged = 0
    for block in policies:
        for sub in block.sub_blocks:
            total += 1
            logtraffic = sub.get("logtraffic", "")
            if logtraffic and logtraffic.lower() != "disable":
                logged += 1
    if total == 0:
        return rule._make_result(False, "No firewall policies found")
    if logged == total:
        return rule._make_result(True, f"Logging enabled on all {total} policies")
    return rule._make_result(False, f"Logging: {logged}/{total} policies")


# --- 4.x Security Profiles ---

def _eval_av_updates(rule, config):
    if config.search(r'config antivirus|config system autoupdate schedule'):
        if config.search(r'set\s+update-schedule|set\s+scheduled-update-status\s+enable|config system autoupdate schedule\s+set\s+status\s+enable\s+set\s+frequency'):
            return rule._make_result(True, "Antivirus update schedule configured")
        return rule._make_result(False, "Antivirus configured but updates not scheduled")
    return rule._make_result(False, "Antivirus not configured")


def _eval_ai_malware(rule, config):
    if config.search(r'set\s+analytics-db\s+enable|set\s+machine-learning-detection\s+enable|set\s+use-heuristic\s+enable'):
        return rule._make_result(True, "AI/ML malware detection enabled")
    return rule._make_result(False, "AI/ML malware detection not enabled")


def _eval_grayware(rule, config):
    if config.search(r'set\s+scan-botnet-connections|set\s+use-botnet\s+enable'):
        return rule._make_result(True, "Grayware/botnet detection enabled")
    return rule._make_result(False, "Grayware detection not enabled")


def _eval_botnet_cnc_blocking(rule, config):
    if config.search(r'config dnsfilter profile|config dns-filter profile'):
        if config.search(r'set\s+botnet\s+enable|set\s+block-botnet\s+enable'):
            return rule._make_result(True, "Botnet C&C domain blocking enabled")
        return rule._make_result(False, "DNS filter configured but botnet blocking not enabled")
    return rule._make_result(False, "DNS filter not configured")


def _eval_ips_profile(rule, config):
    if config.search(r'config ips sensor|config ips global'):
        return rule._make_result(True, "IPS sensor configured")
    if config.search(r'set\s+ips-sensor'):
        return rule._make_result(True, "IPS sensor applied to policies")
    return rule._make_result(False, "IPS not configured")


def _eval_app_control(rule, config):
    if config.search(r'config application list|config firewall profile-protocol-options'):
        return rule._make_result(True, "Application control configured")
    if config.search(r'set\s+application-list'):
        return rule._make_result(True, "Application control applied to policies")
    return rule._make_result(False, "Application control not configured")


# --- 5.x Security Fabric ---

def _eval_compromised_host_quarantine(rule, config):
    if config.search(r'set\s+quarantine\s+enable|set\s+chq\s+enable'):
        return rule._make_result(True, "Compromised host quarantine enabled")
    return rule._make_result(False, "Compromised host quarantine not enabled")


def _eval_security_fabric(rule, config):
    if config.search(r'config system csf'):
        if config.search(r'set\s+status\s+enable', re.I | re.M):
            return rule._make_result(True, "Security Fabric enabled")
        return rule._make_result(False, "Security Fabric configured but not enabled")
    return rule._make_result(False, "Security Fabric not configured")


# --- 7.x Logging ---

def _eval_event_logging(rule, config):
    if config.search(r'config log eventfilter|config log disk filter'):
        return rule._make_result(True, "Event logging configured")
    if config.search(r'set\s+disk-log\s+enable'):
        return rule._make_result(True, "Disk logging enabled")
    return rule._make_result(False, "Event logging not configured")


def _eval_fortianalyzer_logging(rule, config):
    if config.search(r'config log fortianalyzer'):
        if config.search(r'set\s+status\s+enable'):
            return rule._make_result(True, "FortiAnalyzer logging enabled")
        return rule._make_result(False, "FortiAnalyzer configured but not enabled")
    return rule._make_result(False, "FortiAnalyzer logging not configured")


def _eval_syslog(rule, config):
    if config.search(r'config log syslogd'):
        if config.search(r'set\s+status\s+enable'):
            return rule._make_result(True, "Syslog logging enabled")
        return rule._make_result(False, "Syslog configured but not enabled")
    return rule._make_result(False, "Syslog not configured")


# =============================================================================
# Rule Definitions
# =============================================================================

def get_level1_rules() -> List[CISRule]:
    """Return all CIS Level 1 rules."""
    L1 = CISLevel.LEVEL_1

    rules = [
        # --- 1.x Network Configuration ---
        CallableCISRule(
            _eval_dns_configured,
            rule_id="1.1",
            title="Ensure DNS server is configured",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Verify that DNS servers are configured for name resolution.",
            expected_value="DNS servers configured",
            remediation="Configure DNS: config system dns → set primary <IP> → set secondary <IP>",
            category="Network", cis_section="1.1",
            remediation_cli="config system dns\n  set primary 8.8.8.8\n  set secondary 8.8.4.4\nend",
        ),
        CallableCISRule(
            _eval_intra_zone_deny,
            rule_id="1.2",
            title="Ensure intra-zone traffic is restricted",
            level=L1, severity=RuleSeverity.HIGH,
            description="Intra-zone traffic should be denied by default to enforce segmentation.",
            expected_value="intra-zone-deny: enable",
            remediation="Set intra-zone-deny enable under config system global",
            category="Network", cis_section="1.2",
            remediation_cli="config system global\n  set intra-zone-deny enable\nend",
        ),
        CallableCISRule(
            _eval_wan_management,
            rule_id="1.3",
            title="Ensure management services are disabled on WAN port",
            level=L1, severity=RuleSeverity.CRITICAL,
            description="Management services (HTTP, Telnet) should be disabled on WAN interfaces.",
            expected_value="No insecure management services on WAN ports",
            remediation="Remove HTTP/Telnet from WAN interface allowaccess",
            category="Network", cis_section="1.3",
            remediation_cli="config system interface\n  edit <wan_port>\n    set allowaccess ping https ssh\n  next\nend",
        ),

        # --- 2.1.x System Settings ---
        CallableCISRule(
            _eval_pre_login_banner,
            rule_id="2.1.1",
            title="Ensure Pre-Login Banner is set",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="A pre-login banner warns unauthorized users before authentication.",
            expected_value="pre-login-banner: enable",
            remediation="Enable pre-login banner in system global settings",
            category="System", cis_section="2.1.1",
            remediation_cli="config system global\n  set pre-login-banner enable\nend",
        ),
        CallableCISRule(
            _eval_post_login_banner,
            rule_id="2.1.2",
            title="Ensure Post-Login Banner is set",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="A post-login banner provides legal notice after authentication.",
            expected_value="post-login-banner: enable",
            remediation="Enable post-login banner in system global settings",
            category="System", cis_section="2.1.2",
            remediation_cli="config system global\n  set post-login-banner enable\nend",
        ),
        CallableCISRule(
            _eval_timezone,
            rule_id="2.1.3",
            title="Ensure timezone is properly configured",
            level=L1, severity=RuleSeverity.LOW,
            description="Correct timezone ensures accurate log timestamps for forensic analysis.",
            expected_value="Timezone configured",
            remediation="Configure timezone in system global settings",
            category="System", cis_section="2.1.3",
            remediation_cli="config system global\n  set timezone <TIMEZONE_ID>\nend",
        ),
        CallableCISRule(
            _eval_ntp,
            rule_id="2.1.4",
            title="Ensure correct system time is configured through NTP",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="NTP ensures accurate and synchronized time across devices.",
            expected_value="NTP synchronization enabled",
            remediation="Configure NTP: config system ntp → set ntpsync enable",
            category="System", cis_section="2.1.4",
            remediation_cli="config system ntp\n  set ntpsync enable\n  set server-mode enable\nend",
        ),
        CallableCISRule(
            _eval_hostname,
            rule_id="2.1.5",
            title="Ensure hostname is set",
            level=L1, severity=RuleSeverity.LOW,
            description="A meaningful hostname helps identify the device in logs and monitoring.",
            expected_value="Custom hostname configured",
            remediation="Set a meaningful hostname in system global",
            category="System", cis_section="2.1.5",
            remediation_cli='config system global\n  set hostname "<HOSTNAME>"\nend',
        ),
        CallableCISRule(
            _eval_usb_disable,
            rule_id="2.1.7",
            title="Ensure USB firmware and configuration installation is disabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="USB auto-install should be disabled to prevent unauthorized firmware changes.",
            expected_value="usb-auto-install: disable",
            remediation="Disable USB auto-install in system global",
            category="System", cis_section="2.1.7",
            remediation_cli="config system global\n  set usb-auto-install disable\nend",
        ),
        CallableCISRule(
            _eval_static_keys_tls,
            rule_id="2.1.8",
            title="Ensure static keys for TLS are disabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="Enable strong-crypto to disable weak static key cipher suites.",
            expected_value="strong-crypto: enable",
            remediation="Enable strong crypto in system global",
            category="System", cis_section="2.1.8",
            remediation_cli="config system global\n  set strong-crypto enable\nend",
        ),
        CallableCISRule(
            _eval_global_strong_encryption,
            rule_id="2.1.9",
            title="Ensure Global Strong Encryption is enabled",
            level=L1, severity=RuleSeverity.CRITICAL,
            description="Strong encryption ensures all management communications use secure ciphers.",
            expected_value="strong-crypto: enable",
            remediation="Enable strong-crypto in system global",
            category="System", cis_section="2.1.9",
            remediation_cli="config system global\n  set strong-crypto enable\nend",
        ),
        CallableCISRule(
            _eval_tls_management_gui,
            rule_id="2.1.10",
            title="Ensure management GUI listens on secure TLS version",
            level=L1, severity=RuleSeverity.HIGH,
            description="Management GUI should only accept TLS 1.2 or higher.",
            expected_value="TLS 1.2+ only",
            remediation="Configure admin-https-ssl-versions to TLS 1.2+",
            category="System", cis_section="2.1.10",
            remediation_cli="config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend",
        ),
        CallableCISRule(
            _eval_cdn,
            rule_id="2.1.11",
            title="Ensure CDN is enabled for improved GUI performance",
            level=L1, severity=RuleSeverity.LOW,
            description="CDN improves GUI loading performance for distributed management.",
            expected_value="gui-cdn-usage: enable",
            remediation="Enable CDN in system global",
            category="System", cis_section="2.1.11",
            remediation_cli="config system global\n  set gui-cdn-usage enable\nend",
        ),

        # --- 2.2.x Password Configuration ---
        CallableCISRule(
            _eval_password_policy,
            rule_id="2.2.1",
            title="Ensure Password Policy is enabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="Password policy enforces complexity requirements for admin accounts.",
            expected_value="Password policy configured",
            remediation="Configure password policy with minimum length and complexity",
            category="Password", cis_section="2.2.1",
            remediation_cli="config system password-policy\n  set status enable\n  set min-length 8\n  set min-upper-case-letter 1\n  set min-lower-case-letter 1\n  set min-number 1\n  set min-non-alphanumeric 1\nend",
        ),
        CallableCISRule(
            _eval_admin_lockout,
            rule_id="2.2.2",
            title="Ensure administrator password retries and lockout are configured",
            level=L1, severity=RuleSeverity.HIGH,
            description="Account lockout prevents brute-force attacks on admin accounts.",
            expected_value="Lockout threshold and duration configured",
            remediation="Configure admin-lockout-threshold and admin-lockout-duration",
            category="Password", cis_section="2.2.2",
            remediation_cli="config system global\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 60\nend",
        ),

        # --- 2.3.x SNMP Configuration ---
        CallableCISRule(
            _eval_snmpv3_only,
            rule_id="2.3.1",
            title="Ensure only SNMPv3 is enabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="SNMPv1/v2 send community strings in cleartext. Only SNMPv3 should be used.",
            expected_value="SNMPv3 only",
            remediation="Enable SNMPv3 only mode",
            category="SNMP", cis_section="2.3.1",
            remediation_cli="config system snmp sysinfo\n  set status enable\nend",
        ),

        # --- 2.4.x Admin Access ---
        CallableCISRule(
            _eval_admin_timeout,
            rule_id="2.4.4",
            title="Ensure idle timeout time is configured",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Admin sessions should timeout after inactivity to prevent unauthorized access.",
            expected_value="Admin timeout ≤ 15 minutes",
            remediation="Set admintimeout to 15 minutes or less",
            category="Admin", cis_section="2.4.4",
            remediation_cli="config system global\n  set admintimeout 10\nend",
        ),
        CallableCISRule(
            _eval_encrypted_access,
            rule_id="2.4.5",
            title="Ensure only encrypted access channels are enabled",
            level=L1, severity=RuleSeverity.CRITICAL,
            description="Only encrypted protocols (HTTPS, SSH) should be used for management.",
            expected_value="SSH v1 disabled, HTTPS redirect enabled",
            remediation="Disable SSH v1 and enable HTTPS redirect",
            category="Admin", cis_section="2.4.5",
            remediation_cli="config system global\n  set admin-ssh-v1 disable\n  set admin-https-redirect enable\nend",
        ),

        # --- 3.x Firewall Policy ---
        CallableCISRule(
            _eval_no_all_service,
            rule_id="3.2",
            title="Ensure policies do not use 'ALL' as Service",
            level=L1, severity=RuleSeverity.HIGH,
            description="Using 'ALL' as service allows unrestricted traffic through the policy.",
            expected_value="No policies with service=ALL",
            remediation="Replace 'ALL' service with specific required services",
            category="Firewall", cis_section="3.2",
            remediation_cli="config firewall policy\n  edit <policy_id>\n    set service <specific_services>\n  next\nend",
        ),
        CallableCISRule(
            _eval_logging_on_policies,
            rule_id="3.4",
            title="Ensure logging is enabled on all firewall policies",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="All firewall policies should have traffic logging enabled for audit trails.",
            expected_value="Logging enabled on all policies",
            remediation="Enable logtraffic on all firewall policies",
            category="Firewall", cis_section="3.4",
            remediation_cli="config firewall policy\n  edit <policy_id>\n    set logtraffic all\n  next\nend",
        ),

        # --- 4.x Security Profiles ---
        CallableCISRule(
            _eval_ips_profile,
            rule_id="4.1.2",
            title="Ensure IPS Security Profile is applied to policies",
            level=L1, severity=RuleSeverity.HIGH,
            description="IPS detects and prevents network-based attacks.",
            expected_value="IPS sensor configured and applied",
            remediation="Configure IPS sensor and apply to policies",
            category="Security Profiles", cis_section="4.1.2",
            remediation_cli="config ips sensor\n  edit <sensor_name>\n    config entries\n      edit 1\n        set status enable\n      next\n    end\n  next\nend",
        ),
        CallableCISRule(
            _eval_av_updates,
            rule_id="4.2.1",
            title="Ensure Antivirus Definition Push Updates are configured",
            level=L1, severity=RuleSeverity.HIGH,
            description="Antivirus definitions must be updated regularly to detect new threats.",
            expected_value="AV update schedule configured",
            remediation="Configure antivirus update schedule",
            category="Security Profiles", cis_section="4.2.1",
            remediation_cli="config antivirus settings\n  set default-db extended\nend",
        ),
        CallableCISRule(
            _eval_ai_malware,
            rule_id="4.2.4",
            title="Ensure AI/heuristic-based malware detection is enabled",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="AI-based detection catches zero-day and unknown malware variants.",
            expected_value="AI/ML detection enabled",
            remediation="Enable machine-learning and heuristic-based detection",
            category="Security Profiles", cis_section="4.2.4",
            remediation_cli="config antivirus profile\n  edit <profile_name>\n    config content-disarm\n      set machine-learning-detection enable\n    end\n  next\nend",
        ),
        CallableCISRule(
            _eval_grayware,
            rule_id="4.2.5",
            title="Ensure Grayware detection on antivirus is enabled",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Grayware includes potentially unwanted programs and adware.",
            expected_value="Grayware detection enabled",
            remediation="Enable grayware/botnet detection",
            category="Security Profiles", cis_section="4.2.5",
            remediation_cli="config antivirus settings\n  set grayware enable\nend",
        ),
        CallableCISRule(
            _eval_botnet_cnc_blocking,
            rule_id="4.3.1",
            title="Ensure Botnet C&C Domain Blocking DNS Filter is enabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="DNS filtering blocks known C&C domain resolutions.",
            expected_value="Botnet C&C DNS blocking enabled",
            remediation="Configure DNS filter profile with botnet blocking",
            category="Security Profiles", cis_section="4.3.1",
            remediation_cli="config dnsfilter profile\n  edit <profile_name>\n    set block-botnet enable\n  next\nend",
        ),
        CallableCISRule(
            _eval_app_control,
            rule_id="4.4.3",
            title="Ensure Application Control Security Profile is applied",
            level=L1, severity=RuleSeverity.HIGH,
            description="Application control identifies and controls network applications.",
            expected_value="Application control configured",
            remediation="Configure and apply application control profile to policies",
            category="Security Profiles", cis_section="4.4.3",
            remediation_cli="config application list\n  edit <list_name>\n    config entries\n      edit 1\n        set action block\n        set category <category_id>\n      next\n    end\n  next\nend",
        ),

        # --- 5.x Security Fabric ---
        CallableCISRule(
            _eval_compromised_host_quarantine,
            rule_id="5.1.1",
            title="Ensure Compromised Host Quarantine is enabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="Quarantine automatically isolates compromised hosts on the network.",
            expected_value="Quarantine enabled",
            remediation="Enable compromised host quarantine",
            category="Security Fabric", cis_section="5.1.1",
            remediation_cli="config system global\n  set quarantine enable\nend",
        ),
        CallableCISRule(
            _eval_security_fabric,
            rule_id="5.2.1.1",
            title="Ensure Security Fabric is configured",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Security Fabric provides coordinated security across Fortinet devices.",
            expected_value="Security Fabric enabled",
            remediation="Configure and enable Security Fabric (CSF)",
            category="Security Fabric", cis_section="5.2.1.1",
            remediation_cli="config system csf\n  set status enable\n  set group-name <name>\nend",
        ),

        # --- 7.x Logging ---
        CallableCISRule(
            _eval_event_logging,
            rule_id="7.1.1",
            title="Ensure Event Logging is enabled",
            level=L1, severity=RuleSeverity.HIGH,
            description="Event logging captures security events for analysis and forensics.",
            expected_value="Event logging enabled",
            remediation="Enable event logging to disk",
            category="Logging", cis_section="7.1.1",
            remediation_cli="config log disk setting\n  set status enable\n  set diskfull overwrite\nend",
        ),
        CallableCISRule(
            _eval_fortianalyzer_logging,
            rule_id="7.2.2",
            title="Ensure Log Transmission to FortiAnalyzer/FortiManager is enabled",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Centralized logging via FortiAnalyzer enables SIEM correlation.",
            expected_value="FortiAnalyzer logging enabled",
            remediation="Configure FortiAnalyzer logging",
            category="Logging", cis_section="7.2.2",
            remediation_cli="config log fortianalyzer setting\n  set status enable\n  set server <FAZ_IP>\nend",
        ),
        CallableCISRule(
            _eval_syslog,
            rule_id="7.3.1",
            title="Ensure Centralized Logging and Reporting (Syslog) is enabled",
            level=L1, severity=RuleSeverity.MEDIUM,
            description="Syslog enables centralized logging to external SIEM systems.",
            expected_value="Syslog enabled",
            remediation="Configure syslog server",
            category="Logging", cis_section="7.3.1",
            remediation_cli="config log syslogd setting\n  set status enable\n  set server <syslog_ip>\nend",
        ),
    ]

    return rules
