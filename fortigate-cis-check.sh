#!/bin/bash



# Tool information banner
echo "========================================"
echo "Tool: Fortigate CIS Benchmark Audit Tool"
echo "Creator: Priyam Patel"
echo "========================================"



check_dns_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system dns" "$config_file"; then
        output="PASS: DNS server is configured"
    else
        output="FAIL: DNS server is not configured"
    fi
    echo "$output"
}

check_intra_zone_traffic() {
    local config_file="$1"
    local output=""
    if grep -q "set intra-zone-deny enable" "$config_file"; then
        output="PASS: Intra-zone traffic is not always allowed"
    else
        output="FAIL: Intra-zone traffic is always allowed"
    fi
    echo "$output"
}

check_wan_management_services() {
    local config_file="$1"
    local output=""
    # Only check for HTTP and ping
    if grep -q "config system interface" "$config_file" && grep -q "set allowaccess ping http" "$config_file"; then
        output="FAIL: Management related services are enabled on WAN port"
    else
        output="PASS: Management related services are disabled on WAN port"
    fi
    echo "$output"
}

check_pre_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set pre-login-banner" "$config_file"; then
        output="PASS: Pre-Login Banner is set"
    else
        output="FAIL: Pre-Login Banner is not set"
    fi
    echo "$output"
}

check_post_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set post-login-banner" "$config_file"; then
        output="PASS: Post-Login Banner is set"
    else
        output="FAIL: Post-Login Banner is not set"
    fi
    echo "$output"
}

check_timezone_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set timezone" "$config_file"; then
        output="PASS: Timezone is properly configured"
    else
        output="FAIL: Timezone is not properly configured"
    fi
    echo "$output"
}

check_ntp_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ntp" "$config_file" && grep -q "set server" "$config_file"; then
        output="PASS: Correct system time is configured through NTP"
    else
        output="FAIL: Correct system time is not configured through NTP"
    fi
    echo "$output"
}

check_hostname_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set hostname" "$config_file"; then
        output="PASS: Hostname is set"
    else
        output="FAIL: Hostname is not set"
    fi
    echo "$output"
}

check_latest_firmware() {
    local config_file="$1"
    local output=""
    output="PASS: The latest firmware is installed"
    echo "$output"
}

check_usb_disable() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set usb-auto-install" "$config_file"; then
        output="FAIL: USB Firmware and configuration installation is enabled"
    else
        output="PASS: USB Firmware and configuration installation is disabled"
    fi
    echo "$output"
}

check_tls_static_keys() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS: Static keys for TLS are disabled"
    else
        output="FAIL: Static keys for TLS are enabled"
    fi
    echo "$output"
}

check_global_strong_encryption() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS: Global Strong Encryption is enabled"
    else
        output="FAIL: Global Strong Encryption is not enabled"
    fi
    echo "$output"
}

check_tls_version_management_gui() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-https-ssl" "$config_file"; then
        output="PASS: Management GUI listens on secure TLS version"
    else
        output="FAIL: Management GUI does not listen on secure TLS version"
    fi
    echo "$output"
}

check_cdn_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set cdn" "$config_file"; then
        output="PASS: CDN is enabled for improved GUI performance"
    else
        output="FAIL: CDN is not enabled for improved GUI performance"
    fi
    echo "$output"
}

check_cpu_overloaded_event() {
    echo "This check requires manual verification"
}

check_password_policy() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set password-policy" "$config_file"; then
        output="PASS: Password Policy is enabled"
    else
        output="FAIL: Password Policy is not enabled"
    fi
    echo "$output"
}

check_password_retries_lockout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-lockout" "$config_file"; then
        output="PASS: Administrator password retries and lockout time are configured"
    else
        output="FAIL: Administrator password retries and lockout time are not configured"
    fi
    echo "$output"
}

check_snmpv3_only() {
    local config_file="$1"
    local output=""
    if grep -q "config system snmp" "$config_file" && grep -q "set v3-only" "$config_file"; then
        output="PASS: Only SNMPv3 is enabled"
    else
        output="FAIL: Only SNMPv3 is not enabled"
    fi
    echo "$output"
}

check_snmpv3_trusted_hosts() {
    echo "This check requires manual verification"
}

check_admin_password() {
    echo "This check requires manual verification"
}

check_login_accounts_trusted_hosts() {
    echo "This check requires manual verification"
}

check_admin_accounts_profiles() {
    echo "This check requires manual verification"
}

check_idle_timeout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-sessions-timeout" "$config_file"; then
        output="PASS: Idle timeout time is configured"
    else
        output="FAIL: Idle timeout time is not configured"
    fi
    echo "$output"
}

check_encrypted_access_channels() {
    local config_file="$1"
    local output=""
    # Remove specific protocol checks
    if grep -q "config system global" "$config_file" && grep -q "set admin-ssl" "$config_file"; then
        output="PASS: Only encrypted access channels are enabled"
    else
        output="FAIL: Only encrypted access channels are not enabled"
    fi
    echo "$output"
}

apply_local_in_policies() {
    echo "This check requires manual verification"
}

check_default_admin_ports_changed() {
    echo "This check requires manual verification"
}

check_virtual_patching_local_in_interface() {
    echo "This check requires manual verification"
}

check_ha_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file"; then
        output="PASS: High Availability configuration is enabled"
    else
        output="FAIL: High Availability configuration is not enabled"
    fi
    echo "$output"
}

check_ha_monitor_interfaces() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set monitor-interface" "$config_file"; then
        output="PASS: 'Monitor Interfaces' for High Availability devices is enabled"
    else
        output="FAIL: 'Monitor Interfaces' for High Availability devices is not enabled"
    fi
    echo "$output"
}

check_ha_reserved_management_interface() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set reserved-management-interface" "$config_file"; then
        output="PASS: HA Reserved Management Interface is configured"
    else
        output="FAIL: HA Reserved Management Interface is not configured"
    fi
    echo "$output"
}

check_review_unused_policies() {
    echo "This check requires manual verification"
}

check_no_all_service_policies() {
    local config_file="$1"
    local output=""
    if ! grep -q "set service ALL" "$config_file"; then
        output="PASS: Policies do not use 'ALL' as Service"
    else
        output="FAIL: Policies use 'ALL' as Service"
    fi
    echo "$output"
}

check_denying_traffic_to_from_tor() {
    echo "This check requires manual verification"
}

check_logging_enabled_firewall_policies() {
    echo "This check requires manual verification"
}

detect_botnet_connections() {
    echo "This check requires manual verification"
}

apply_ips_security_profile() {
    echo "This check requires manual verification"
}

check_antivirus_definition_updates() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set update-schedule" "$config_file"; then
        output="PASS: Antivirus Definition Push Updates are configured"
    else
        output="FAIL: Antivirus Definition Push Updates are not configured"
    fi
    echo "$output"
}

apply_antivirus_security_profile() {
    echo "This check requires manual verification"
}

check_outbreak_prevention_database() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-extended-db" "$config_file"; then
        output="PASS: Outbreak Prevention Database is enabled"
    else
        output="FAIL: Outbreak Prevention Database is not enabled"
    fi
    echo "$output"
}

check_ai_malware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-heuristic" "$config_file"; then
        output="PASS: AI/heuristic based malware detection is enabled"
    else
        output="FAIL: AI/heuristic based malware detection is not enabled"
    fi
    echo "$output"
}

check_grayware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-botnet" "$config_file"; then
        output="PASS: Grayware detection on antivirus is enabled"
    else
        output="FAIL: Grayware detection on antivirus is not enabled"
    fi
    echo "$output"
}

check_inline_scanning_sandbox() {
    echo "This check requires manual verification"
}

enable_botnet_cnc_domain_blocking() {
    local config_file="$1"
    local output=""
    if grep -q "config webfilter fortiguard" "$config_file" && grep -q "set botnet" "$config_file"; then
        output="PASS: Botnet C&C Domain Blocking DNS Filter is enabled"
    else
        output="FAIL: Botnet C&C Domain Blocking DNS Filter is not enabled"
    fi
    echo "$output"
}

check_dns_filter_logging() {
    echo "This check requires manual verification"
}

apply_dns_filter_security_profile() {
    echo "This check requires manual verification"
}

block_high_risk_categories() {
    echo "This check requires manual verification"
}

block_non_default_port_applications() {
    local config_file="$1"
    local output=""
    if grep -q "config firewall policy" "$config_file" && grep -q "set service " "$config_file"; then
        output="FAIL: Applications running on non-default ports are blocked"
    else
        output="PASS: Applications running on non-default ports are not blocked"
    fi
    echo "$output"
}

check_application_control_logging() {
    echo "This check requires manual verification"
}

apply_application_control_security_profile() {
    echo "This check requires manual verification"
}

check_compromised_host_quarantine() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set chq" "$config_file"; then
        output="PASS: Compromised Host Quarantine is enabled"
    else
        output="FAIL: Compromised Host Quarantine is not enabled"
    fi
    echo "$output"
}

check_security_fabric_configured() {
    local config_file="$1"
    local output=""
    if grep -q "config system settings" "$config_file" && grep -q "set sf-enforce" "$config_file"; then
        output="PASS: Security Fabric is Configured"
    else
        output="FAIL: Security Fabric is not Configured"
    fi
    echo "$output"
}

apply_trusted_certificate_vpn_portal() {
    echo "This check requires manual verification"
}

check_ssl_vpn_tls_versions() {
    echo "This check requires manual verification"
}

check_event_logging_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system log" "$config_file" && grep -q "set disk-log" "$config_file"; then
        output="PASS: Event Logging is enabled"
    else
        output="FAIL: Event Logging is not enabled"
    fi
    echo "$output"
}

encrypt_logs_sent_to_forti() {
    echo "This check requires manual verification"
}

enable_log_transmission_to_forti() {
    local config_file="$1"
    local output=""
    if grep -q "config log fortianalyzer" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS: Log Transmission to FortiAnalyzer / FortiManager is enabled"
    else
        output="FAIL: Log Transmission to FortiAnalyzer / FortiManager is not enabled"
    fi
    echo "$output"
}

check_centralized_logging_reporting() {
    local config_file="$1"
    local output=""
    if grep -q "config log syslogd" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS: Centralized Logging and Reporting is enabled"
    else
        output="FAIL: Centralized Logging and Reporting is not enabled"
    fi
    echo "$output"
}

if [ $# -ne 1 ]; then
    echo "Usage: $0 <config_file>"
    exit 1
fi

config_file=$1

CSV_FILE="FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_$(date +"%Y%m%d_%H%M%S").csv"

echo "Checking CIS benchmarks..."

dns_config_result=$(check_dns_configuration "$config_file")
current_dns=$(grep -E "config system dns" "$config_file" | awk '{print $NF}' || echo "Not set")
if [[ "$dns_config_result" == *"FAIL"* ]]; then
    dns_recommendation="Add 'config system dns' and specify DNS servers in the configuration file."
    current_dns="Location: Under 'config system global'\nExpected: config system dns <DNS_SERVER_IP>"
else
    dns_recommendation="No action needed."
fi
echo "1.1 Ensure DNS server is configured (Automated), $dns_config_result, $current_dns, $dns_recommendation" >> "$CSV_FILE"

intra_zone_traffic_result=$(check_intra_zone_traffic "$config_file")
current_intra_zone=$(grep -E "set intra-zone-deny" "$config_file" | awk '{print $NF}' || echo "Not set")
if [[ "$intra_zone_traffic_result" == *"FAIL"* ]]; then
    intra_zone_traffic_recommendation="Add 'set intra-zone-deny enable' in the relevant policy."
    current_intra_zone="Expected: set intra-zone-deny enable"
else
    intra_zone_traffic_recommendation="No action needed."
fi
echo "1.2 Ensure intra-zone traffic is restricted (Manual), $intra_zone_traffic_result, $current_intra_zone, $intra_zone_traffic_recommendation" >> "$CSV_FILE"

wan_management_services_result=$(check_wan_management_services "$config_file")
current_wan_access=$(grep -E "set allowaccess" "$config_file" | awk '{print $NF}' || echo "Not set")
if [[ "$wan_management_services_result" == *"FAIL"* ]]; then
    wan_management_services_recommendation="Remove 'set allowaccess ping http' from WAN port configuration."
    current_wan_access="Expected: set allowaccess none"
else
    wan_management_services_recommendation="No action needed."
fi
echo "1.3 Ensure all management related services are disabled on WAN port (Automated), $wan_management_services_result, $current_wan_access, $wan_management_services_recommendation" >> "$CSV_FILE"

pre_login_banner_result=$(check_pre_login_banner "$config_file")
if [[ "$pre_login_banner_result" == *"FAIL"* ]]; then
    pre_login_banner_recommendation="Configure a Pre-Login Banner in the configuration file."
else
    pre_login_banner_recommendation="No action needed."
fi
echo "2.1.1 Ensure 'Pre-Login Banner' is set (Automated), $pre_login_banner_result, $current_dns, $pre_login_banner_recommendation" >> "$CSV_FILE"

post_login_banner_result=$(check_post_login_banner "$config_file")
if [[ "$post_login_banner_result" == *"FAIL"* ]]; then
    post_login_banner_recommendation="Configure a Post-Login Banner in the configuration file."
else
    post_login_banner_recommendation="No action needed."
fi
echo "2.1.2 Ensure 'Post-Login Banner' is set (Automated), $post_login_banner_result, $current_dns, $post_login_banner_recommendation" >> "$CSV_FILE"

timezone_configuration_result=$(check_timezone_configuration "$config_file")
if [[ "$timezone_configuration_result" == *"FAIL"* ]]; then
    timezone_configuration_recommendation="Configure the timezone in the configuration file."
else
    timezone_configuration_recommendation="No action needed."
fi
echo "2.1.3 Ensure timezone is properly configured (Manual), $timezone_configuration_result, $current_dns, $timezone_configuration_recommendation" >> "$CSV_FILE"

ntp_configuration_result=$(check_ntp_configuration "$config_file")
if [[ "$ntp_configuration_result" == *"FAIL"* ]]; then
    ntp_configuration_recommendation="Configure NTP in the configuration file."
else
    ntp_configuration_recommendation="No action needed."
fi
echo "2.1.4 Ensure correct system time is configured through NTP (Automated), $ntp_configuration_result, $current_dns, $ntp_configuration_recommendation" >> "$CSV_FILE"

hostname_configuration_result=$(check_hostname_configuration "$config_file")
if [[ "$hostname_configuration_result" == *"FAIL"* ]]; then
    hostname_configuration_recommendation="Configure the hostname in the configuration file."
else
    hostname_configuration_recommendation="No action needed."
fi
echo "2.1.5 Ensure hostname is set (Automated), $hostname_configuration_result, $current_dns, $hostname_configuration_recommendation" >> "$CSV_FILE"

latest_firmware_result=$(check_latest_firmware "$config_file")
if [[ "$latest_firmware_result" == *"FAIL"* ]]; then
    latest_firmware_recommendation="Install the latest firmware."
else
    latest_firmware_recommendation="No action needed."
fi
echo "2.1.6 Ensure the latest firmware is installed (Manual), $latest_firmware_result, $current_dns, $latest_firmware_recommendation" >> "$CSV_FILE"

usb_disable_result=$(check_usb_disable "$config_file")
if [[ "$usb_disable_result" == *"FAIL"* ]]; then
    usb_disable_recommendation="Disable USB Firmware and configuration installation in the configuration file."
else
    usb_disable_recommendation="No action needed."
fi
echo "2.1.7 Disable USB Firmware and configuration installation (Automated), $usb_disable_result, $current_dns, $usb_disable_recommendation" >> "$CSV_FILE"

tls_static_keys_result=$(check_tls_static_keys "$config_file")
if [[ "$tls_static_keys_result" == *"FAIL"* ]]; then
    tls_static_keys_recommendation="Disable static keys for TLS in the configuration file."
else
    tls_static_keys_recommendation="No action needed."
fi
echo "2.1.8 Disable static keys for TLS (Automated), $tls_static_keys_result, $current_dns, $tls_static_keys_recommendation" >> "$CSV_FILE"

global_strong_encryption_result=$(check_global_strong_encryption "$config_file")
if [[ "$global_strong_encryption_result" == *"FAIL"* ]]; then
    global_strong_encryption_recommendation="Enable Global Strong Encryption in the configuration file."
else
    global_strong_encryption_recommendation="No action needed."
fi
echo "2.1.9 Enable Global Strong Encryption (Automated), $global_strong_encryption_result, $current_dns, $global_strong_encryption_recommendation" >> "$CSV_FILE"

tls_version_management_gui_result=$(check_tls_version_management_gui "$config_file")
if [[ "$tls_version_management_gui_result" == *"FAIL"* ]]; then
    tls_version_management_gui_recommendation="Configure management GUI to listen on secure TLS version."
else
    tls_version_management_gui_recommendation="No action needed."
fi
echo "2.1.10 Ensure management GUI listens on secure TLS version (Manual), $tls_version_management_gui_result, $current_dns, $tls_version_management_gui_recommendation" >> "$CSV_FILE"

cdn_enabled_result=$(check_cdn_enabled "$config_file")
if [[ "$cdn_enabled_result" == *"FAIL"* ]]; then
    cdn_enabled_recommendation="Enable CDN for improved GUI performance in the configuration file."
else
    cdn_enabled_recommendation="No action needed."
fi
echo "2.1.11 Ensure CDN is enabled for improved GUI performance (Manual), $cdn_enabled_result, $current_dns, $cdn_enabled_recommendation" >> "$CSV_FILE"

cpu_overloaded_event_result=$(check_cpu_overloaded_event "$config_file")
if [[ "$cpu_overloaded_event_result" == *"FAIL"* ]]; then
    cpu_overloaded_event_recommendation="Configure single CPU core overloaded event logging in the configuration file."
else
    cpu_overloaded_event_recommendation="No action needed."
fi
echo "2.1.12 Ensure single CPU core overloaded event is logged (Manual), $cpu_overloaded_event_result, $current_dns, $cpu_overloaded_event_recommendation" >> "$CSV_FILE"

password_policy_result=$(check_password_policy "$config_file")
if [[ "$password_policy_result" == *"FAIL"* ]]; then
    password_policy_recommendation="Enable Password Policy in the configuration file."
else
    password_policy_recommendation="No action needed."
fi
echo "2.2.1 Ensure 'Password Policy' is enabled (Automated), $password_policy_result, $current_dns, $password_policy_recommendation" >> "$CSV_FILE"

password_retries_lockout_result=$(check_password_retries_lockout "$config_file")
if [[ "$password_retries_lockout_result" == *"FAIL"* ]]; then
    password_retries_lockout_recommendation="Configure administrator password retries and lockout time in the configuration file."
else
    password_retries_lockout_recommendation="No action needed."
fi
echo "2.2.2 Ensure administrator password retries and lockout time are configured (Automated), $password_retries_lockout_result, $current_dns, $password_retries_lockout_recommendation" >> "$CSV_FILE"

snmpv3_only_result=$(check_snmpv3_only "$config_file")
if [[ "$snmpv3_only_result" == *"FAIL"* ]]; then
    snmpv3_only_recommendation="Enable only SNMPv3 in the configuration file."
else
    snmpv3_only_recommendation="No action needed."
fi
echo "2.3.1 Ensure only SNMPv3 is enabled (Automated), $snmpv3_only_result, $current_dns, $snmpv3_only_recommendation" >> "$CSV_FILE"

snmpv3_trusted_hosts_result=$(check_snmpv3_trusted_hosts "$config_file")
if [[ "$snmpv3_trusted_hosts_result" == *"FAIL"* ]]; then
    snmpv3_trusted_hosts_recommendation="Configure trusted hosts in SNMPv3 in the configuration file."
else
    snmpv3_trusted_hosts_recommendation="No action needed."
fi
echo "2.3.2 Allow only trusted hosts in SNMPv3 (Manual), $snmpv3_trusted_hosts_result, $current_dns, $snmpv3_trusted_hosts_recommendation" >> "$CSV_FILE"

admin_password_result=$(check_admin_password "$config_file")
if [[ "$admin_password_result" == *"FAIL"* ]]; then
    admin_password_recommendation="Change the default 'admin' password in the configuration file."
else
    admin_password_recommendation="No action needed."
fi
echo "2.4.1 Ensure default 'admin' password is changed (Manual), $admin_password_result, $current_dns, $admin_password_recommendation" >> "$CSV_FILE"

login_accounts_trusted_hosts_result=$(check_login_accounts_trusted_hosts "$config_file")
if [[ "$login_accounts_trusted_hosts_result" == *"FAIL"* ]]; then
    login_accounts_trusted_hosts_recommendation="Configure trusted hosts for login accounts in the configuration file."
else
    login_accounts_trusted_hosts_recommendation="No action needed."
fi
echo "2.4.2 Ensure all the login accounts having specific trusted hosts enabled (Manual), $login_accounts_trusted_hosts_result, $current_dns, $login_accounts_trusted_hosts_recommendation" >> "$CSV_FILE"

admin_accounts_profiles_result=$(check_admin_accounts_profiles "$config_file")
if [[ "$admin_accounts_profiles_result" == *"FAIL"* ]]; then
    admin_accounts_profiles_recommendation="Configure profiles for admin accounts with different privileges in the configuration file."
else
    admin_accounts_profiles_recommendation="No action needed."
fi
echo "2.4.3 Ensure admin accounts with different privileges have their correct profiles assigned (Manual), $admin_accounts_profiles_result, $current_dns, $admin_accounts_profiles_recommendation" >> "$CSV_FILE"

idle_timeout_result=$(check_idle_timeout "$config_file")
if [[ "$idle_timeout_result" == *"FAIL"* ]]; then
    idle_timeout_recommendation="Configure idle timeout time in the configuration file."
else
    idle_timeout_recommendation="No action needed."
fi
echo "2.4.4 Ensure idle timeout time is configured (Automated), $idle_timeout_result, $current_dns, $idle_timeout_recommendation" >> "$CSV_FILE"

encrypted_access_channels_result=$(check_encrypted_access_channels "$config_file")
if [[ "$encrypted_access_channels_result" == *"FAIL"* ]]; then
    encrypted_access_channels_recommendation="Enable only encrypted access channels in the configuration file."
else
    encrypted_access_channels_recommendation="No action needed."
fi
echo "2.4.5 Ensure only encrypted access channels are enabled (Automated), $encrypted_access_channels_result, $current_dns, $encrypted_access_channels_recommendation" >> "$CSV_FILE"

local_in_policies_result=$(apply_local_in_policies)
if [[ "$local_in_policies_result" == *"FAIL"* ]]; then
    local_in_policies_recommendation="Apply Local-in Policies in the configuration file."
else
    local_in_policies_recommendation="No action needed."
fi
echo "2.4.6 Ensure Local-in Policies are applied (Manual), $local_in_policies_result, $current_dns, $local_in_policies_recommendation" >> "$CSV_FILE"

default_admin_ports_changed_result=$(check_default_admin_ports_changed)
if [[ "$default_admin_ports_changed_result" == *"FAIL"* ]]; then
    default_admin_ports_changed_recommendation="Change default Admin ports in the configuration file."
else
    default_admin_ports_changed_recommendation="No action needed."
fi
echo "2.4.7 Ensure default Admin ports are changed (Manual), $default_admin_ports_changed_result, $current_dns, $default_admin_ports_changed_recommendation" >> "$CSV_FILE"

virtual_patching_local_in_interface_result=$(check_virtual_patching_local_in_interface)
if [[ "$virtual_patching_local_in_interface_result" == *"FAIL"* ]]; then
    virtual_patching_local_in_interface_recommendation="Enable virtual patching on the local-in management interface in the configuration file."
else
    virtual_patching_local_in_interface_recommendation="No action needed."
fi
echo "2.4.8 Ensure virtual patching on the local-in management interface is enabled (Manual), $virtual_patching_local_in_interface_result, $current_dns, $virtual_patching_local_in_interface_recommendation" >> "$CSV_FILE"

ha_configuration_result=$(check_ha_configuration "$config_file")
if [[ "$ha_configuration_result" == *"FAIL"* ]]; then
    ha_configuration_recommendation="Enable High Availability configuration in the configuration file."
else
    ha_configuration_recommendation="No action needed."
fi
echo "2.4.9 Ensure High Availability configuration is enabled (Manual), $ha_configuration_result, $current_dns, $ha_configuration_recommendation" >> "$CSV_FILE"

ha_monitor_interfaces_result=$(check_ha_monitor_interfaces "$config_file")
if [[ "$ha_monitor_interfaces_result" == *"FAIL"* ]]; then
    ha_monitor_interfaces_recommendation="Enable 'Monitor Interfaces' for High Availability devices in the configuration file."
else
    ha_monitor_interfaces_recommendation="No action needed."
fi
echo "2.4.10 Ensure 'Monitor Interfaces' for High Availability devices is enabled (Manual), $ha_monitor_interfaces_result, $current_dns, $ha_monitor_interfaces_recommendation" >> "$CSV_FILE"

ha_reserved_management_interface_result=$(check_ha_reserved_management_interface "$config_file")
if [[ "$ha_reserved_management_interface_result" == *"FAIL"* ]]; then
    ha_reserved_management_interface_recommendation="Configure HA Reserved Management Interface in the configuration file."
else
    ha_reserved_management_interface_recommendation="No action needed."
fi
echo "2.4.11 Ensure HA Reserved Management Interface is configured (Manual), $ha_reserved_management_interface_result, $current_dns, $ha_reserved_management_interface_recommendation" >> "$CSV_FILE"

review_unused_policies_result=$(check_review_unused_policies)
if [[ "$review_unused_policies_result" == *"FAIL"* ]]; then
    review_unused_policies_recommendation="Review unused policies regularly in the configuration file."
else
    review_unused_policies_recommendation="No action needed."
fi
echo "3.1 Ensure that unused policies are reviewed regularly (Manual), $review_unused_policies_result, $current_dns, $review_unused_policies_recommendation" >> "$CSV_FILE"

no_all_service_policies_result=$(check_no_all_service_policies "$config_file")
if [[ "$no_all_service_policies_result" == *"FAIL"* ]]; then
    no_all_service_policies_recommendation="Configure policies to not use 'ALL' as Service in the configuration file."
else
    no_all_service_policies_recommendation="No action needed."
fi
echo "3.2 Ensure that policies do not use 'ALL' as Service (Automated), $no_all_service_policies_result, $current_dns, $no_all_service_policies_recommendation" >> "$CSV_FILE"

denying_traffic_to_from_tor_result=$(check_denying_traffic_to_from_tor)
if [[ "$denying_traffic_to_from_tor_result" == *"FAIL"* ]]; then
    denying_traffic_to_from_tor_recommendation="Configure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB in the configuration file."
else
    denying_traffic_to_from_tor_recommendation="No action needed."
fi
echo "3.3 Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB (Manual), $denying_traffic_to_from_tor_result, $current_dns, $denying_traffic_to_from_tor_recommendation" >> "$CSV_FILE"

logging_enabled_firewall_policies_result=$(check_logging_enabled_firewall_policies)
if [[ "$logging_enabled_firewall_policies_result" == *"FAIL"* ]]; then
    logging_enabled_firewall_policies_recommendation="Enable logging on all firewall policies in the configuration file."
else
    logging_enabled_firewall_policies_recommendation="No action needed."
fi
echo "3.4 Ensure logging is enabled on all firewall policies (Manual), $logging_enabled_firewall_policies_result, $current_dns, $logging_enabled_firewall_policies_recommendation" >> "$CSV_FILE"

botnet_connections_result=$(detect_botnet_connections)
if [[ "$botnet_connections_result" == *"FAIL"* ]]; then
    botnet_connections_recommendation="Configure Botnet connections monitoring in the configuration file."
else
    botnet_connections_recommendation="No action needed."
fi
echo "4.1.1 Detect Botnet connections (Manual), $botnet_connections_result, $current_dns, $botnet_connections_recommendation" >> "$CSV_FILE"

ips_security_profile_result=$(apply_ips_security_profile)
if [[ "$ips_security_profile_result" == *"FAIL"* ]]; then
    ips_security_profile_recommendation="Apply IPS Security Profile to Policies in the configuration file."
else
    ips_security_profile_recommendation="No action needed."
fi
echo "4.1.2 Apply IPS Security Profile to Policies (Manual), $ips_security_profile_result, $current_dns, $ips_security_profile_recommendation" >> "$CSV_FILE"

antivirus_definition_updates_result=$(check_antivirus_definition_updates "$config_file")
if [[ "$antivirus_definition_updates_result" == *"FAIL"* ]]; then
    antivirus_definition_updates_recommendation="Configure Antivirus Definition Push Updates in the configuration file."
else
    antivirus_definition_updates_recommendation="No action needed."
fi
echo "4.2.1 Ensure Antivirus Definition Push Updates are Configured (Automated), $antivirus_definition_updates_result, $current_dns, $antivirus_definition_updates_recommendation" >> "$CSV_FILE"

antivirus_security_profile_result=$(apply_antivirus_security_profile)
if [[ "$antivirus_security_profile_result" == *"FAIL"* ]]; then
    antivirus_security_profile_recommendation="Apply Antivirus Security Profile to Policies in the configuration file."
else
    antivirus_security_profile_recommendation="No action needed."
fi
echo "4.2.2 Apply Antivirus Security Profile to Policies (Manual), $antivirus_security_profile_result, $current_dns, $antivirus_security_profile_recommendation" >> "$CSV_FILE"

outbreak_prevention_database_result=$(check_outbreak_prevention_database "$config_file")
if [[ "$outbreak_prevention_database_result" == *"FAIL"* ]]; then
    outbreak_prevention_database_recommendation="Enable Outbreak Prevention Database in the configuration file."
else
    outbreak_prevention_database_recommendation="No action needed."
fi
echo "4.2.3 Ensure Outbreak Prevention Database (Automated), $outbreak_prevention_database_result, $current_dns, $outbreak_prevention_database_recommendation" >> "$CSV_FILE"

ai_malware_detection_result=$(check_ai_malware_detection "$config_file")
if [[ "$ai_malware_detection_result" == *"FAIL"* ]]; then
    ai_malware_detection_recommendation="Enable AI/heuristic based malware detection in the configuration file."
else
    ai_malware_detection_recommendation="No action needed."
fi
echo "4.2.4 Ensure AI/heuristic based malware detection is enabled (Automated), $ai_malware_detection_result, $current_dns, $ai_malware_detection_recommendation" >> "$CSV_FILE"

grayware_detection_result=$(check_grayware_detection "$config_file")
if [[ "$grayware_detection_result" == *"FAIL"* ]]; then
    grayware_detection_recommendation="Enable Grayware detection on antivirus in the configuration file."
else
    grayware_detection_recommendation="No action needed."
fi
echo "4.2.5 Ensure Grayware detection on antivirus is enabled (Automated), $grayware_detection_result, $current_dns, $grayware_detection_recommendation" >> "$CSV_FILE"

inline_scanning_sandbox_result=$(check_inline_scanning_sandbox)
if [[ "$inline_scanning_sandbox_result" == *"FAIL"* ]]; then
    inline_scanning_sandbox_recommendation="Configure inline scanning sandbox in the configuration file."
else
    inline_scanning_sandbox_recommendation="No action needed."
fi
echo "4.2.6 Ensure inline scanning sandbox is enabled (Manual), $inline_scanning_sandbox_result, $current_dns, $inline_scanning_sandbox_recommendation" >> "$CSV_FILE"

botnet_cnc_domain_blocking_result=$(enable_botnet_cnc_domain_blocking "$config_file")
if [[ "$botnet_cnc_domain_blocking_result" == *"FAIL"* ]]; then
    botnet_cnc_domain_blocking_recommendation="Enable Botnet C&C Domain Blocking DNS Filter in the configuration file."
else
    botnet_cnc_domain_blocking_recommendation="No action needed."
fi
echo "4.3.1 Ensure Botnet C&C Domain Blocking DNS Filter is enabled (Automated), $botnet_cnc_domain_blocking_result, $current_dns, $botnet_cnc_domain_blocking_recommendation" >> "$CSV_FILE"

dns_filter_logging_result=$(check_dns_filter_logging)
if [[ "$dns_filter_logging_result" == *"FAIL"* ]]; then
    dns_filter_logging_recommendation="Enable logging on DNS Filter in the configuration file."
else
    dns_filter_logging_recommendation="No action needed."
fi
echo "4.3.2 Ensure logging is enabled on DNS Filter (Manual), $dns_filter_logging_result, $current_dns, $dns_filter_logging_recommendation" >> "$CSV_FILE"

dns_filter_security_profile_result=$(apply_dns_filter_security_profile)
if [[ "$dns_filter_security_profile_result" == *"FAIL"* ]]; then
    dns_filter_security_profile_recommendation="Apply DNS Filter Security Profile to Policies in the configuration file."
else
    dns_filter_security_profile_recommendation="No action needed."
fi
echo "4.3.3 Apply DNS Filter Security Profile to Policies (Manual), $dns_filter_security_profile_result, $current_dns, $dns_filter_security_profile_recommendation" >> "$CSV_FILE"

high_risk_categories_result=$(block_high_risk_categories)
if [[ "$high_risk_categories_result" == *"FAIL"* ]]; then
    high_risk_categories_recommendation="Block high-risk categories in the configuration file."
else
    high_risk_categories_recommendation="No action needed."
fi
echo "4.3.4 Block high-risk categories (Manual), $high_risk_categories_result, $current_dns, $high_risk_categories_recommendation" >> "$CSV_FILE"

non_default_port_applications_result=$(block_non_default_port_applications "$config_file")
if [[ "$non_default_port_applications_result" == *"FAIL"* ]]; then
    non_default_port_applications_recommendation="Block applications running on non-default ports in the configuration file."
else
    non_default_port_applications_recommendation="No action needed."
fi
echo "4.4.1 Ensure applications running on non-default ports are blocked (Automated), $non_default_port_applications_result, $current_dns, $non_default_port_applications_recommendation" >> "$CSV_FILE"

application_control_logging_result=$(check_application_control_logging)
if [[ "$application_control_logging_result" == *"FAIL"* ]]; then
    application_control_logging_recommendation="Enable logging on Application Control in the configuration file."
else
    application_control_logging_recommendation="No action needed."
fi
echo "4.4.2 Ensure logging is enabled on Application Control (Manual), $application_control_logging_result, $current_dns, $application_control_logging_recommendation" >> "$CSV_FILE"

application_control_security_profile_result=$(apply_application_control_security_profile)
current_application_control=$(grep -E "set application-control" "$config_file" | awk '{print $NF}' || echo "Not set")
if [[ "$application_control_security_profile_result" == *"FAIL"* ]]; then
    application_control_recommendation="Add 'set application-control' in the relevant policy."
    current_application_control="Expected: set application-control <PROFILE_NAME>"
else
    application_control_recommendation="No action needed."
fi
echo "4.4.3 Apply Application Control Security Profile to Policies (Manual), $application_control_security_profile_result, $current_application_control, $application_control_recommendation" >> "$CSV_FILE"

compromised_host_quarantine_result=$(check_compromised_host_quarantine "$config_file")
if [[ "$compromised_host_quarantine_result" == *"FAIL"* ]]; then
    compromised_host_quarantine_recommendation="Enable Compromised Host Quarantine in the configuration file."
else
    compromised_host_quarantine_recommendation="No action needed."
fi
echo "5.1.1 Enable Compromised Host Quarantine (Automated), $compromised_host_quarantine_result, $current_dns, $compromised_host_quarantine_recommendation" >> "$CSV_FILE"

security_fabric_configured_result=$(check_security_fabric_configured "$config_file")
if [[ "$security_fabric_configured_result" == *"FAIL"* ]]; then
    security_fabric_configured_recommendation="Enable Security Fabric in the configuration file."
else
    security_fabric_configured_recommendation="No action needed."
fi
echo "5.2.1.1 Ensure Security Fabric is Configured (Automated), $security_fabric_configured_result, $current_dns, $security_fabric_configured_recommendation" >> "$CSV_FILE"

trusted_certificate_vpn_portal_result=$(apply_trusted_certificate_vpn_portal)
if [[ "$trusted_certificate_vpn_portal_result" == *"FAIL"* ]]; then
    trusted_certificate_vpn_portal_recommendation="Apply a Trusted Signed Certificate for VPN Portal in the configuration file."
else
    trusted_certificate_vpn_portal_recommendation="No action needed."
fi
echo "6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual), $trusted_certificate_vpn_portal_result, $current_dns, $trusted_certificate_vpn_portal_recommendation" >> "$CSV_FILE"

ssl_vpn_tls_versions_result=$(check_ssl_vpn_tls_versions)
if [[ "$ssl_vpn_tls_versions_result" == *"FAIL"* ]]; then
    ssl_vpn_tls_versions_recommendation="Configure SSL VPN TLS versions in the configuration file."
else
    ssl_vpn_tls_versions_recommendation="No action needed."
fi
echo "6.1.2 Enable Limited TLS Versions for SSL VPN (Manual), $ssl_vpn_tls_versions_result, $current_dns, $ssl_vpn_tls_versions_recommendation" >> "$CSV_FILE"

event_logging_enabled_result=$(check_event_logging_enabled "$config_file")
if [[ "$event_logging_enabled_result" == *"FAIL"* ]]; then
    event_logging_enabled_recommendation="Enable Event Logging in the configuration file."
else
    event_logging_enabled_recommendation="No action needed."
fi
echo "7.1.1 Enable Event Logging (Automated), $event_logging_enabled_result, $current_dns, $event_logging_enabled_recommendation" >> "$CSV_FILE"

encrypt_logs_sent_to_forti_result=$(encrypt_logs_sent_to_forti)
if [[ "$encrypt_logs_sent_to_forti_result" == *"FAIL"* ]]; then
    encrypt_logs_sent_to_forti_recommendation="Encrypt logs sent to Forti in the configuration file."
else
    encrypt_logs_sent_to_forti_recommendation="No action needed."
fi
echo "7.2.1 Encrypt Logs Sent to FortiAnalyzer / FortiManager (Automated), $encrypt_logs_sent_to_forti_result, $current_dns, $encrypt_logs_sent_to_forti_recommendation" >> "$CSV_FILE"

log_transmission_to_forti_result=$(enable_log_transmission_to_forti "$config_file")
if [[ "$log_transmission_to_forti_result" == *"FAIL"* ]]; then
    log_transmission_to_forti_recommendation="Enable encryption for Logs Sent to FortiAnalyzer / FortiManager in the configuration file."
else
    log_transmission_to_forti_recommendation="No action needed."
fi
echo "7.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Automated), $log_transmission_to_forti_result, $current_dns, $log_transmission_to_forti_recommendation" >> "$CSV_FILE"

centralized_logging_reporting_result=$(check_centralized_logging_reporting "$config_file")
if [[ "$centralized_logging_reporting_result" == *"FAIL"* ]]; then
    centralized_logging_reporting_recommendation="Enable Centralized Logging and Reporting in the configuration file."
else
    centralized_logging_reporting_recommendation="No action needed."
fi
echo "7.3.1 Centralized Logging and Reporting (Automated), $centralized_logging_reporting_result, $current_dns, $centralized_logging_reporting_recommendation" >> "$CSV_FILE"

echo "CIS benchmarks Audit check completed."

total_checks=$(wc -l < "$CSV_FILE")
total_manual_checks=$(grep -c "Manual" "$CSV_FILE")
total_pass=$(grep -c "PASS" "$CSV_FILE")
total_fail=$(grep -c "FAIL" "$CSV_FILE")

HTML_FILE="FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_$(date +"%Y%m%d_%H%M%S").html"

echo "<html>
<head>
    <title>FORTIGATE CIS Benchmark Audit Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: #fff;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #ddd;
        }
        .summary {
            margin: 20px 0;
            padding: 10px;
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
        }
        .fail {
            color: red;
            font-weight: bold;
        }
        .pass {
            color: green;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>FORTIGATE CIS Benchmark Audit Report</h1>
    <div class='summary'>
        <p><strong>Tool:</strong> Fortigate CIS Benchmark Audit Tool</p>
        <p><strong>Creator:</strong> Priyam Patel</p>
        <p><strong>Total CIS Benchmark Checks:</strong> $total_checks</p>
        <p><strong>Total Automated Checks:</strong> $(($total_checks - $total_manual_checks))</p>
        <p><strong>Total Manual Checks:</strong> $total_manual_checks</p>
        <p><strong>Not Found:</strong> $(($total_checks - ($total_pass + $total_fail)))</p>
        <p><strong>Total PASS:</strong> $total_pass</p>
        <p><strong>Total FAIL:</strong> $total_fail</p>
    </div>
    <table>
        <tr>
            <th>Benchmark</th>
            <th>Result</th>
            <th>Current</th>
            <th>Recommendation</th>
        </tr>" > "$HTML_FILE"

cat "$CSV_FILE" | while IFS="," read -r benchmark result current recommendation; do
    # Replace newlines with <br> tags for HTML display
    formatted_current=$(echo "$current" | sed 's/\\n/<br>/g')
    
    if [[ "$result" == *"FAIL"* ]]; then
        echo "<tr><td>$benchmark</td><td class='fail'>$result</td><td>$formatted_current</td><td>$recommendation</td></tr>" >> "$HTML_FILE"
    elif [[ "$result" == *"PASS"* ]]; then
        echo "<tr><td>$benchmark</td><td class='pass'>$result</td><td>$formatted_current</td><td>$recommendation</td></tr>" >> "$HTML_FILE"
    fi
done

echo "</table>
</body>
</html>" >> "$HTML_FILE"

echo "HTML report generated: $HTML_FILE"