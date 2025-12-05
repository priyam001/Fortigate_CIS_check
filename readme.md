# Fortigate CIS Benchmark Checker

## Purpose

This tool automates the process of checking Fortigate firewall configurations against CIS (Center for Internet Security) benchmarks. It helps security professionals and network administrators to:

- Audit Fortigate configurations for security best practices
- Identify potential security misconfigurations
- Generate detailed reports in both CSV and HTML formats
- Track compliance with CIS security standards

## Implementations

This tool is available in two implementations:
1. Bash script (`fortigate-cis-check.sh`)
2. Python script (`fortigate_cis_checker.py`)

Choose the implementation that best suits your environment and requirements.

## Features

- Automated checking of 50+ CIS benchmark controls
- Detailed pass/fail status for each control
- Current configuration status
- Specific recommendations for failed checks
- HTML report with color-coded results
- CSV output for further analysis
- Summary statistics of overall compliance
- Configuration location guidance for failed checks

## Prerequisites

### For Bash Implementation
- Bash shell environment (version 4.0 or higher)
- Access to Fortigate configuration file
- Read permissions for the configuration file
- Minimum 100MB free disk space for reports
- Internet connectivity (optional, for updates)

### For Python Implementation
- Python 3.6 or higher
- Required Python packages:
  ```
  pip install argparse logging typing
  ```
- Access to Fortigate configuration file
- Read permissions for the configuration file

## Installation

### Bash Implementation
1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/example/fortigate-cis-check/main/fortigate-cis-check.sh
   chmod +x fortigate-cis-check.sh
   ```

2. Run the script:
   ```bash
   ./fortigate-cis-check.sh /path/to/fortigate-config.txt
   ```

### Python Implementation
1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/example/fortigate-cis-check/main/fortigate_cis_checker.py
   ```

2. Install required dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Run the script:
   ```bash
   python3 fortigate_cis_checker.py /path/to/fortigate-config.txt
   ```

## Output Files

The script generates two output files in the current directory:
<img width="1734" height="742" alt="image" src="https://github.com/user-attachments/assets/ecf09344-253d-4435-a3f0-606e486137f3" />

1. CSV Report: `FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_YYYYMMDD_HHMMSS.csv`
2. HTML Report: `FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_YYYYMMDD_HHMMSS.html`

## Checks Performed

The script checks various security aspects including:

- DNS Configuration
- Intra-zone Traffic Settings
- Management Services Configuration
- Banner Settings
- System Time and NTP
- Firmware Status
- USB Port Security
- TLS Configuration
- Password Policies
- SNMP Settings
- Admin Access Controls
- High Availability Settings
- Firewall Policies
- Security Profiles
- Logging Configuration
- And many more...

## Sample Output

The HTML report includes:

- Summary statistics
- Detailed results table
- Color-coded pass/fail indicators
- Current configuration values
- Specific recommendations for failed checks
- Configuration location guidance for failed checks

### Output Format
For failed checks, the report shows:
- Status: FAIL
- Current: Location: [configuration path]
- Recommendation: [specific fix details]

For passed checks, the report shows:
- Status: PASS
- Current: [actual configured value]
- Recommendation: N/A

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Priyam Patel](https://www.linkedin.com/in/priyam-patel-450307206/)

## Version

1.0.0

## Note

- This tool is designed for Fortigate version 7.0.x configurations
- Results may vary for other versions
- Always review results and recommendations before implementing changes
- Backup your configuration before making any changes

## Troubleshooting

Common issues and solutions:

1. Permission denied
```bash
chmod +x fortigate-cis-check.sh
```

2. Invalid configuration file
- Ensure the configuration file is in plain text format
- Verify file permissions
- Check for file corruptio

