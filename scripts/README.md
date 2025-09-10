# Security Validation Scripts

This directory contains scripts for validating CodeQL security analysis results against the CVE datasheet.

## Files

- `validate_codeql_results.py` - Main validation script
- `requirements.txt` - Python dependencies

## Usage

### Basic Usage (CVE Database Overview Only)
```bash
python validate_codeql_results.py --cve-datasheet ../CVE_Datasheet_Populated_v3.xlsx
```

### With CodeQL SARIF Results
```bash
python validate_codeql_results.py \
  --cve-datasheet ../CVE_Datasheet_Populated_v3.xlsx \
  --sarif-results path/to/codeql/results.sarif \
  --output security_report.md
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Integration with GitHub Actions

The script is automatically executed as part of the CodeQL workflow in `.github/workflows/codeql.yml`. It will:

1. Parse CodeQL SARIF results
2. Match findings with the CVE datasheet by CWE ID
3. Generate a comprehensive security compliance report
4. Upload the report as a workflow artifact
5. Comment a summary on pull requests

## Report Contents

The generated report includes:

- **Executive Summary** - Total findings and match statistics
- **Critical Findings with Regulatory Impact** - Detailed analysis including:
  - Vulnerability details (CVE ID, CWE ID, CVSS score)
  - Affected code locations
  - Regulatory compliance impacts (HIPAA, GDPR, ISO 27001, etc.)
  - Remediation information
- **Additional Security Findings** - Unmatched findings from CodeQL
- **Recommendations** - Action items for remediation

## CVE Database Mapping

The script maps CodeQL findings to the CVE Register sheet based on CWE identifiers and provides regulatory compliance information for:

- HIPAA Rules
- GDPR Articles
- ISO 27001 Controls
- IEC 81001-5-1 Clauses
- FDA Premarket Topics
- Healthcare Capabilities
- PHI/PII Impact Assessment

## Requirements

- Python 3.x
- pandas
- openpyxl
- CVE_Datasheet_Populated_v3.xlsx in the repository root