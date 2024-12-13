#!/usr/bin/env python3

import os
import re
from datetime import datetime
import csv

class FortigateCISAudit:
    def __init__(self, config_file):
        self.config_file = config_file
        self.csv_file = f"FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.html_file = f"FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        # Load the config content during initialization
        try:
            with open(self.config_file, 'r') as f:
                self.config_content = f.read()
        except Exception as e:
            print(f"Error reading config file: {e}")
            self.config_content = ""

    def print_banner(self):
        print("========================================")
        print("Tool: Fortigate CIS Benchmark Audit Tool")
        print("Creator: Priyam Patel")
        print("========================================")

    def grep_config(self, pattern):
        """Simulates grep functionality for config file"""
        try:
            return bool(re.search(pattern, self.config_content))
        except Exception as e:
            print(f"Error searching config file: {e}")
            return False

    def check_dns_configuration(self):
        """Check DNS server configuration"""
        if self.grep_config(r"config system dns"):
            return "PASS: DNS server is configured"
        return "FAIL: DNS server is not configured"

    def check_intra_zone_traffic(self):
        """Check intra-zone traffic configuration"""
        if self.grep_config(r"set intra-zone-deny enable"):
            return "PASS: Intra-zone traffic is not always allowed"
        return "FAIL: Intra-zone traffic is always allowed"

    def check_wan_management_services(self):
        """Check WAN management services"""
        if (self.grep_config(r"config system interface") and 
            self.grep_config(r"set allowaccess ping http")):
            return "FAIL: Management related services are enabled on WAN port"
        return "PASS: Management related services are disabled on WAN port"

    def check_pre_login_banner(self):
        """Check pre-login banner configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set pre-login-banner")):
            return "PASS: Pre-Login Banner is set"
        return "FAIL: Pre-Login Banner is not set"

    def check_post_login_banner(self):
        """Check post-login banner configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set post-login-banner")):
            return "PASS: Post-Login Banner is set"
        return "FAIL: Post-Login Banner is not set"

    def check_timezone_configuration(self):
        """Check timezone configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set timezone")):
            return "PASS: Timezone is properly configured"
        return "FAIL: Timezone is not properly configured"

    def check_ntp_configuration(self):
        """Check NTP configuration"""
        if (self.grep_config(r"config system ntp") and 
            self.grep_config(r"set server")):
            return "PASS: Correct system time is configured through NTP"
        return "FAIL: Correct system time is not configured through NTP"

    def check_hostname_configuration(self):
        """Check hostname configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set hostname")):
            return "PASS: Hostname is set"
        return "FAIL: Hostname is not set"

    def check_usb_disable(self):
        """Check USB firmware and configuration installation"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set usb-auto-install")):
            return "FAIL: USB Firmware and configuration installation is enabled"
        return "PASS: USB Firmware and configuration installation is disabled"

    def check_global_strong_encryption(self):
        """Check global strong encryption settings"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set strong-crypto")):
            return "PASS: Global Strong Encryption is enabled"
        return "FAIL: Global Strong Encryption is not enabled"

    def check_password_policy(self):
        """Check password policy configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set password-policy")):
            return "PASS: Password Policy is enabled"
        return "FAIL: Password Policy is not enabled"

    def check_password_retries_lockout(self):
        """Check password retries and lockout configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-lockout")):
            return "PASS: Administrator password retries and lockout time are configured"
        return "FAIL: Administrator password retries and lockout time are not configured"

    def check_snmpv3_only(self):
        """Check SNMPv3 configuration"""
        if (self.grep_config(r"config system snmp") and 
            self.grep_config(r"set v3-only")):
            return "PASS: Only SNMPv3 is enabled"
        return "FAIL: Only SNMPv3 is not enabled"

    def check_idle_timeout(self):
        """Check idle timeout configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-sessions-timeout")):
            return "PASS: Idle timeout time is configured"
        return "FAIL: Idle timeout time is not configured"

    def check_ha_configuration(self):
        """Check High Availability configuration"""
        if self.grep_config(r"config system ha"):
            return "PASS: High Availability configuration is enabled"
        return "FAIL: High Availability configuration is not enabled"

    def check_ha_monitor_interfaces(self):
        """Check HA monitor interfaces configuration"""
        if (self.grep_config(r"config system ha") and 
            self.grep_config(r"set monitor-interface")):
            return "PASS: 'Monitor Interfaces' for High Availability devices is enabled"
        return "FAIL: 'Monitor Interfaces' for High Availability devices is not enabled"

    def check_antivirus_updates(self):
        """Check antivirus definition updates configuration"""
        if (self.grep_config(r"config antivirus settings") and 
            self.grep_config(r"set update-schedule enable")):
            return "PASS: Antivirus definition updates are enabled"
        return "FAIL: Antivirus definition updates are not enabled"

    def check_ips_signatures(self):
        """Check IPS signature updates configuration"""
        if (self.grep_config(r"config ips global") and 
            self.grep_config(r"set database regular")):
            return "PASS: IPS signature updates are configured"
        return "FAIL: IPS signature updates are not configured"

    def check_ssl_inspection(self):
        """Check SSL/SSH inspection configuration"""
        if (self.grep_config(r"config firewall ssl-ssh-profile") and 
            self.grep_config(r"set inspect-all")):
            return "PASS: SSL/SSH inspection is properly configured"
        return "FAIL: SSL/SSH inspection is not properly configured"

    def check_web_filtering(self):
        """Check web filtering configuration"""
        if (self.grep_config(r"config webfilter profile") and 
            self.grep_config(r"set web-filter-activation enable")):
            return "PASS: Web filtering is enabled"
        return "FAIL: Web filtering is not enabled"

    def check_application_control(self):
        """Check application control configuration"""
        if (self.grep_config(r"config application list") and 
            self.grep_config(r"set deep-app-inspection enable")):
            return "PASS: Application control is properly configured"
        return "FAIL: Application control is not properly configured"

    def check_dos_policy(self):
        """Check DoS policy configuration"""
        if (self.grep_config(r"config firewall DoS-policy") and 
            self.grep_config(r"set status enable")):
            return "PASS: DoS protection is enabled"
        return "FAIL: DoS protection is not enabled"

    def check_admin_https_redirect(self):
        """Check admin HTTPS redirect configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-https-redirect enable")):
            return "PASS: Admin HTTPS redirect is enabled"
        return "FAIL: Admin HTTPS redirect is not enabled"

    def check_admin_ssh_grace_time(self):
        """Check SSH grace time configuration"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-ssh-grace-time 120")):
            return "PASS: SSH grace time is properly configured"
        return "FAIL: SSH grace time is not properly configured"

    def check_admin_ssh_port(self):
        """Check SSH port configuration"""
        if (self.grep_config(r"config system global") and 
            not self.grep_config(r"set admin-ssh-port 22")):
            return "PASS: SSH port is not using default port 22"
        return "FAIL: SSH port is using default port 22"

    def check_syslog_server(self):
        """Check syslog server configuration"""
        if (self.grep_config(r"config log syslogd setting") and 
            self.grep_config(r"set status enable")):
            return "PASS: Syslog server is configured"
        return "FAIL: Syslog server is not configured"

    def check_log_disk_usage(self):
        """Check log disk usage configuration"""
        if (self.grep_config(r"config log disk setting") and 
            self.grep_config(r"set full-first-warning")):
            return "PASS: Log disk usage alerts are configured"
        return "FAIL: Log disk usage alerts are not configured"

    def check_fortianalyzer_logging(self):
        """Check FortiAnalyzer logging configuration"""
        if (self.grep_config(r"config log fortianalyzer setting") and 
            self.grep_config(r"set status enable")):
            return "PASS: FortiAnalyzer logging is enabled"
        return "FAIL: FortiAnalyzer logging is not enabled"

    def check_sdwan_configuration(self):
        """Check SD-WAN configuration"""
        if (self.grep_config(r"config system sdwan") and 
            self.grep_config(r"set status enable")):
            return "PASS: SD-WAN is configured"
        return "FAIL: SD-WAN is not configured"

    def check_bgp_neighbor_authentication(self):
        """Check BGP neighbor authentication"""
        if (self.grep_config(r"config router bgp") and 
            self.grep_config(r"set password")):
            return "PASS: BGP neighbor authentication is configured"
        return "FAIL: BGP neighbor authentication is not configured"

    def check_ospf_authentication(self):
        """Check OSPF authentication"""
        if (self.grep_config(r"config router ospf") and 
            self.grep_config(r"set authentication")):
            return "PASS: OSPF authentication is configured"
        return "FAIL: OSPF authentication is not configured"

    def check_admin_timeout(self):
        """1.1.1 Ensure 'admin-timeout' is set to 5 minutes or less"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-timeout [1-5]")):
            return "PASS: Admin timeout is set to 5 minutes or less"
        return "FAIL: Admin timeout is not properly configured"

    def check_admin_ssh_grace_time(self):
        """1.1.2 Ensure 'admin-ssh-grace-time' is set to 60 seconds or less"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-ssh-grace-time [1-6][0-9]")):
            return "PASS: SSH grace time is set to 60 seconds or less"
        return "FAIL: SSH grace time exceeds 60 seconds"

    def check_admin_ssh_v1(self):
        """1.1.3 Ensure SSH v1 is disabled"""
        if not self.grep_config(r"set admin-ssh-v1 enable"):
            return "PASS: SSH v1 is disabled"
        return "FAIL: SSH v1 is enabled"

    def check_admin_concurrent_sessions(self):
        """1.1.4 Ensure concurrent admin sessions is set to 1"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-concurrent-sessions 1")):
            return "PASS: Concurrent admin sessions limited to 1"
        return "FAIL: Concurrent admin sessions not properly limited"

    def check_admin_port(self):
        """1.1.5 Ensure default 'admin' port is changed"""
        if not self.grep_config(r"set admin-port 80"):
            return "PASS: Default admin port is changed"
        return "FAIL: Default admin port (80) is still in use"

    def check_trusted_hosts(self):
        """1.2.1 Ensure trusted hosts are configured for all admin accounts"""
        if (self.grep_config(r"config system admin") and 
            self.grep_config(r"set trustedhost")):
            return "PASS: Trusted hosts are configured"
        return "FAIL: Trusted hosts are not configured"

    def check_password_policy(self):
        """1.2.2 Ensure password policy is enabled"""
        conditions = [
            r"set status enable",
            r"set minimum-length 8",
            r"set must-contain upper-case-letter lower-case-letter number special-character",
            r"set change-4-characters enable",
            r"set expire-status enable",
            r"set expire-day 90"
        ]
        
        if all(self.grep_config(cond) for cond in conditions):
            return "PASS: Password policy is properly configured"
        return "FAIL: Password policy is not properly configured"

    def check_password_hash_algorithm(self):
        """1.2.3 Ensure strong password hash algorithm is used"""
        if (self.grep_config(r"config system password-policy") and 
            self.grep_config(r"set hash sha256")):
            return "PASS: Strong password hash algorithm is used"
        return "FAIL: Weak password hash algorithm in use"

    def check_admin_lockout(self):
        """1.2.4 Ensure administrator account lockout is enabled"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set admin-lockout-threshold") and
            self.grep_config(r"set admin-lockout-duration")):
            return "PASS: Administrator account lockout is enabled"
        return "FAIL: Administrator account lockout is not enabled"

    def check_interface_trusted_hosts(self):
        """1.3.1 Ensure interfaces have trusted hosts configured"""
        if (self.grep_config(r"config system interface") and 
            self.grep_config(r"set allowaccess") and
            self.grep_config(r"set trusted-hosts")):
            return "PASS: Interface trusted hosts are configured"
        return "FAIL: Interface trusted hosts are not configured"

    def check_default_admin_profile(self):
        """1.3.2 Ensure default admin profile is not used"""
        if not self.grep_config(r"set accprofile default"):
            return "PASS: Default admin profile is not used"
        return "FAIL: Default admin profile is in use"

    def check_admin_password_change(self):
        """1.3.3 Ensure admin password change on first login"""
        if (self.grep_config(r"config system admin") and 
            self.grep_config(r"set force-password-change enable")):
            return "PASS: Admin password change on first login is enabled"
        return "FAIL: Admin password change on first login is not enabled"

    def check_strong_encryption(self):
        """2.1.1 Ensure strong encryption is used"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set strong-crypto enable")):
            return "PASS: Strong encryption is enabled"
        return "FAIL: Strong encryption is not enabled"

    def check_ssl_versions(self):
        """2.1.2 Ensure only approved SSL/TLS versions are used"""
        conditions = [
            r"set ssl-min-proto-version tls1-2",
            not self.grep_config(r"ssl-min-proto-version ssl3"),
            not self.grep_config(r"ssl-min-proto-version tls1-0"),
            not self.grep_config(r"ssl-min-proto-version tls1-1")
        ]
        
        if all(conditions):
            return "PASS: Only approved SSL/TLS versions are enabled"
        return "FAIL: Insecure SSL/TLS versions are enabled"

    def check_fips_mode(self):
        """2.1.3 Ensure FIPS mode is enabled"""
        if (self.grep_config(r"config system global") and 
            self.grep_config(r"set fips-mode enable")):
            return "PASS: FIPS mode is enabled"
        return "FAIL: FIPS mode is not enabled"

    def check_ntp_servers(self):
        """2.2.1 Ensure at least two NTP servers are configured"""
        if (self.grep_config(r"config system ntp") and 
            len(re.findall(r"set server", self.config_content)) >= 2):
            return "PASS: At least two NTP servers are configured"
        return "FAIL: Less than two NTP servers are configured"

    def check_admin_https(self):
        """2.2.2 Ensure administrative access via HTTPS only"""
        if (self.grep_config(r"config system interface") and 
            self.grep_config(r"set allowaccess https") and
            not self.grep_config(r"set allowaccess http")):
            return "PASS: Administrative access is HTTPS only"
        return "FAIL: HTTP access is enabled"

    def get_benchmark_config_template(self, benchmark_id):
        """Return the recommended configuration template for a given benchmark ID"""
        templates = {
            "1.1.1": """config system global
    set admin-timeout 5
end""",
            
            "1.1.2": """config system global
    set admin-ssh-grace-time 60
end""",
            
            "1.1.3": """config system global
    set admin-ssh-v1 disable
end""",
            
            "1.1.4": """config system global
    set admin-concurrent-sessions 1
end""",
            
            "1.1.5": """config system global
    set admin-port 8443    # Example: using port 8443 instead of 80
end""",
            
            "1.2.1": """config system admin
    edit "admin"
        set trustedhost 192.168.1.0/24 10.0.0.0/24    # Example trusted networks
    next
end""",
            
            "1.2.2": """config system password-policy
    set status enable
    set minimum-length 8
    set must-contain upper-case-letter lower-case-letter number special-character
    set change-4-characters enable
    set expire-status enable
    set expire-day 90
end""",
            
            "1.2.3": """config system password-policy
    set hash sha256
end""",
            
            "1.2.4": """config system global
    set admin-lockout-threshold 3
    set admin-lockout-duration 300
end""",
            
            "1.3.1": """config system interface
    edit "port1"
        set allowaccess ping https ssh
        set trusted-hosts 192.168.1.0/24
    next
end""",
            
            "2.1.1": """config system global
    set strong-crypto enable
end""",
            
            "2.1.2": """config system global
    set ssl-min-proto-version tls1-2
end""",
            
            "2.1.3": """config system global
    set fips-mode enable
end""",
            
            "2.2.1": """config system ntp
    set ntpsync enable
    set type custom
    set server "0.pool.ntp.org" "1.pool.ntp.org"
end""",
            
            "2.2.2": """config system interface
    edit "port1"
        set allowaccess https
        unset allowaccess http    # Ensure HTTP is disabled
    next
end"""
        }
        return templates.get(benchmark_id, "No template available for this benchmark")

    def get_fix_commands(self, benchmark_id):
        """Return the CLI commands needed to fix a failed check"""
        fix_commands = {
            "1.1.1": """config system global
    set admin-timeout 5
end""",
            
            "1.1.2": """config system global
    set admin-ssh-grace-time 60
end""",
            
            "1.1.3": """config system global
    set admin-ssh-v1 disable
end""",
            
            "1.1.4": """config system global
    set admin-concurrent-sessions 1
end""",
            
            "1.1.5": """config system global
    set admin-port 8443
end""",
            
            "1.2.1": """config system admin
    edit "admin"
        set trustedhost 192.168.1.0/24 10.0.0.0/24
    next
end""",
            
            "1.2.2": """config system password-policy
    set status enable
    set minimum-length 8
    set must-contain upper-case-letter lower-case-letter number special-character
    set change-4-characters enable
    set expire-status enable
    set expire-day 90
end""",
            
            "2.1.1": """config system global
    set strong-crypto enable
end""",
            
            "2.1.2": """config system global
    set ssl-min-proto-version tls1-2
end""",

            "2.3.1": """config log memory setting
    set status enable
    set event enable
    set admin enable
end""",
            
            "2.3.2": """config log disk setting
    set status enable
    set uploadtime 00:00
    set uploadzip enable
end""",

            "2.4.1": """config system snmp community
    edit 1
        set name "Community_Name"
        set events cpu-high mem-low log-full
        set status enable
        config hosts
            edit 1
                set ip 192.168.1.100
            next
        end
    next
end"""
        }
        return fix_commands.get(benchmark_id, "No fix commands available")

    def generate_csv_report(self, results):
        """Generate CSV report from results"""
        try:
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Benchmark ID', 'Description', 'Result', 'Fix Location', 'Fix Commands'])
                
                # Write results
                for benchmark, result, _, _ in results:
                    benchmark_id = benchmark.split()[0]
                    description = ' '.join(benchmark.split()[1:])
                    fix_location = self.get_fix_location(benchmark_id)
                    fix_commands = self.get_fix_commands(benchmark_id) if "FAIL" in result else "No fixes needed"
                    
                    writer.writerow([
                        benchmark_id,
                        description,
                        result,
                        fix_location,
                        fix_commands
                    ])
            print(f"CSV report generated: {self.csv_file}")
        except Exception as e:
            print(f"Error generating CSV report: {e}")

    def get_fix_location(self, benchmark_id):
        """Get the web interface location for fixing a benchmark"""
        locations = {
            "1.1": "System > Settings > Administration Settings",
            "1.2": "System > Admin > Administrator",
            "2.1": "System > Settings > Security Settings",
            "2.2": "System > Settings > Time & NTP",
            "2.3": "Log & Report > Log Settings",
            "2.4": "System > SNMP"
        }
        
        for prefix, location in locations.items():
            if benchmark_id.startswith(prefix):
                return location
        return "Location not specified"

    def generate_html_report(self, results):
        """Generate minimalistic HTML report"""
        total_checks = len(results)
        total_pass = sum(1 for check in results if "PASS" in check[1])
        total_fail = sum(1 for check in results if "FAIL" in check[1])

        html_content = f"""
        <html>
        <head>
            <title>FortiGate CIS Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .summary {{ margin-bottom: 20px; }}
                .fix-commands {{ background-color: #f8f9fa; padding: 10px; margin-top: 5px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <h1>FortiGate CIS Audit Report</h1>
            <div class="summary">
                <p>Total Checks: {total_checks} | Passed: {total_pass} | Failed: {total_fail}</p>
            </div>
            <table>
                <tr>
                    <th>Benchmark</th>
                    <th>Result</th>
                    <th>Fix Location</th>
                    <th>Fix Commands</th>
                </tr>"""

        for benchmark, result, _, _ in results:
            benchmark_id = benchmark.split()[0]
            result_class = "pass" if "PASS" in result else "fail"
            fix_location = self.get_fix_location(benchmark_id)
            fix_commands = self.get_fix_commands(benchmark_id) if "FAIL" in result else ""

            html_content += f"""
                <tr>
                    <td>{benchmark}</td>
                    <td class="{result_class}">{result}</td>
                    <td>{fix_location if "FAIL" in result else ""}</td>
                    <td>
                        <div class="fix-commands">{fix_commands if "FAIL" in result else ""}</div>
                    </td>
                </tr>"""

        html_content += """
            </table>
        </body>
        </html>"""

        try:
            with open(self.html_file, 'w') as f:
                f.write(html_content)
            print(f"HTML report generated: {self.html_file}")
        except Exception as e:
            print(f"Error generating HTML report: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 fortigate_cis_audit.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]
    auditor = FortigateCISAudit(config_file)
    auditor.print_banner()
    
    # Run all checks and collect results
    results = []
    for method_name in dir(auditor):
        if method_name.startswith('check_') and callable(getattr(auditor, method_name)):
            check_method = getattr(auditor, method_name)
            result = check_method()
            results.append((method_name, result, "", ""))
    
    # Generate both HTML and CSV reports
    auditor.generate_html_report(results)
    auditor.generate_csv_report(results)

if __name__ == "__main__":
    import sys
    main()