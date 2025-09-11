# C++ Vulnerable Application

This is a deliberately vulnerable C++ application for testing the vulnerability scanner.

## Vulnerabilities Included

1. **Buffer Overflow** - `strcpy()` in class methods
2. **Command Injection** - Unsanitized input to `system()`
3. **SQL Injection** - Direct string concatenation in queries
4. **Format String** - User input passed to `printf()`
5. **Memory Management Issues**:
   - Use after free
   - Double free
   - Memory leaks with smart pointers
6. **Path Traversal** - No validation on file paths
7. **Unsafe Casting** - `reinterpret_cast` without validation
8. **Integer Overflow** - Unchecked arithmetic
9. **Array Bounds** - No bounds checking in containers
10. **Template Safety** - Unsafe template implementations

## C++-Specific Issues

- Missing virtual destructors
- Raw pointer usage instead of smart pointers
- Unsafe STL container access
- Template instantiation vulnerabilities

## Building

```bash
make
```

## Running

```bash
./vulnerable_cpp_app "test input"
```

**Warning**: This application contains security vulnerabilities and should only be used for testing purposes in a safe environment.

## Security Analysis and Compliance Validation

This repository includes an enhanced CodeQL workflow that automatically validates security findings against a comprehensive CVE database (`CVE_Datasheet_Populated_v3.xlsx`). 

### Features

- **Automated Security Analysis**: CodeQL scans detect vulnerabilities in C++ code
- **CVE Database Mapping**: Findings are matched with known CVE entries by CWE ID
- **Regulatory Compliance Assessment**: Automatic evaluation against:
  - HIPAA Rules
  - GDPR Articles  
  - ISO 27001 Controls
  - IEC 81001-5-1 Clauses
  - FDA Premarket Requirements
- **Detailed Reporting**: Comprehensive security compliance reports with remediation guidance
- **CI/CD Integration**: Automated validation on every push and pull request
- **Interactive Dashboard**: Professional web-based dashboard for visualizing security findings

### Security Compliance Dashboard

The repository includes a professional, interactive dashboard that displays security findings from `security_compliance_report.xlsx` with correlation analysis and filtering capabilities.

#### Dashboard Features

- **Professional Visualization**: Clean, intuitive interface with modern styling
- **Interactive Filtering**: Filter findings by severity, component, and match source
- **Correlation Analysis**: Visual correlation matrix showing relationships between security metrics
- **Compliance Impact Analysis**: Regulatory compliance impact across HIPAA, GDPR, and FDA
- **Detailed Findings View**: Expandable cards showing comprehensive vulnerability details
- **Real-time Metrics**: Key performance indicators with dynamic updates based on filters
- **Export Capabilities**: Download data as CSV and charts as PNG

#### Quick Start Dashboard

**Linux/macOS:**
```bash
# Launch the interactive dashboard
./launch_dashboard.sh
```

**Windows:**
```cmd
REM Launch the interactive dashboard
launch_dashboard.bat
```

Or manually (cross-platform):

```bash
# Install dependencies
pip install -r scripts/requirements.txt

# Launch the dashboard
streamlit run scripts/security_dashboard.py
```

The dashboard will be available at: http://localhost:8501

#### Dashboard Fields

The dashboard displays the following fields from the Security_Findings sheet:
- Rule_Name: Security rule that was violated
- Full_Description: Detailed description of the vulnerability
- Severity: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
- CWE_ID: Common Weakness Enumeration identifier
- CVE_ID: Common Vulnerabilities and Exposures identifier
- CVSS_Base_Score: Common Vulnerability Scoring System score
- Component_Package: Affected software component
- HIPAA_Rules_Impacted: HIPAA regulation sections affected
- GDPR_Articles_Impacted: GDPR articles affected
- FDA_Premarket_Topic: FDA premarket requirements impacted
- Medical_Tech_Impact: Medical technology impact assessment
- Match_Source: Source of the security finding match

### Security Report Generation

The workflow generates detailed reports that include:
- Vulnerability details with CVE and CWE identifiers
- CVSS base scores and severity levels
- Affected code locations
- Regulatory compliance violations
- Cost of violation assessments
- Remediation recommendations and timelines

### Manual Report Generation

You can also generate security reports manually:

```bash
# Install dependencies
pip install pandas openpyxl

# Generate report from CodeQL results
python scripts/validate_codeql_results.py \
  --cve-datasheet CVE_Datasheet_Populated_v3.xlsx \
  --sarif-results path/to/results.sarif \
  --output security_report.md

# Generate CVE database overview (without CodeQL results)
python scripts/validate_codeql_results.py \
  --cve-datasheet CVE_Datasheet_Populated_v3.xlsx
```