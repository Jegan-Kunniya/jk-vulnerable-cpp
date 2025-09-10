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