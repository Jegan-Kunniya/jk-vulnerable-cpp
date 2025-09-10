#!/usr/bin/env python3
"""
CodeQL Results Validator
This script validates CodeQL SARIF results against the CVE datasheet,
providing detailed compliance and regulatory impact analysis.
"""

import json
import pandas as pd
import sys
import os
from pathlib import Path
from datetime import datetime
import argparse

class CodeQLValidator:
    def __init__(self, cve_datasheet_path, sarif_results_path=None):
        self.cve_datasheet_path = cve_datasheet_path
        self.sarif_results_path = sarif_results_path
        self.cve_data = None
        self.sarif_data = None
        self.load_cve_data()
        
    def load_cve_data(self):
        """Load CVE data from the Excel datasheet."""
        try:
            self.cve_data = pd.read_excel(self.cve_datasheet_path, sheet_name="CVE Register")
            print(f"Loaded CVE data: {len(self.cve_data)} records")
        except Exception as e:
            print(f"Error loading CVE datasheet: {e}")
            sys.exit(1)
    
    def load_sarif_results(self, sarif_path):
        """Load SARIF results from CodeQL analysis."""
        try:
            with open(sarif_path, 'r') as f:
                self.sarif_data = json.load(f)
            print(f"Loaded SARIF results from: {sarif_path}")
        except Exception as e:
            print(f"Error loading SARIF results: {e}")
            return False
        return True
    
    def extract_cwe_from_sarif(self, rule):
        """Extract CWE ID from CodeQL rule."""
        # CodeQL rules often include CWE information in tags or metadata
        cwe_id = None
        
        # Check rule tags for CWE information
        if 'tags' in rule and rule['tags']:
            for tag in rule['tags']:
                if tag.startswith('external/cwe/cwe-'):
                    cwe_id = tag.replace('external/cwe/cwe-', 'CWE-')
                    break
        
        # Check rule properties for CWE
        if not cwe_id and 'properties' in rule:
            props = rule['properties']
            if 'tags' in props:
                for tag in props['tags']:
                    if 'cwe' in tag.lower():
                        # Extract CWE number
                        import re
                        match = re.search(r'cwe[/-](\d+)', tag, re.IGNORECASE)
                        if match:
                            cwe_id = f"CWE-{match.group(1)}"
                            break
        
        # Check rule metadata
        if not cwe_id and 'relatedLocations' in rule:
            # Sometimes CWE is mentioned in related locations or descriptions
            pass
        
        return cwe_id
    
    def match_findings_with_cve_data(self):
        """Match SARIF findings with CVE datasheet entries."""
        if not self.sarif_data:
            return []
        
        matched_findings = []
        unmatched_findings = []
        
        # Extract results from SARIF
        for run in self.sarif_data.get('runs', []):
            rules = {}
            # Build rule lookup
            if 'tool' in run and 'driver' in run['tool']:
                driver = run['tool']['driver']
                if 'rules' in driver:
                    for rule in driver['rules']:
                        rules[rule['id']] = rule
            
            # Process results
            for result in run.get('results', []):
                rule_id = result.get('ruleId', '')
                rule = rules.get(rule_id, {})
                
                finding = {
                    'rule_id': rule_id,
                    'rule_name': rule.get('name', ''),
                    'short_description': rule.get('shortDescription', {}).get('text', ''),
                    'full_description': rule.get('fullDescription', {}).get('text', ''),
                    'message': result.get('message', {}).get('text', ''),
                    'level': result.get('level', 'unknown'),
                    'locations': []
                }
                
                # Extract CWE from rule
                cwe_id = self.extract_cwe_from_sarif(rule)
                finding['cwe_id'] = cwe_id
                
                # Extract locations
                for location in result.get('locations', []):
                    if 'physicalLocation' in location:
                        phys_loc = location['physicalLocation']
                        loc_info = {
                            'file': phys_loc.get('artifactLocation', {}).get('uri', ''),
                            'line': phys_loc.get('region', {}).get('startLine', 0),
                            'column': phys_loc.get('region', {}).get('startColumn', 0)
                        }
                        finding['locations'].append(loc_info)
                
                # Try to match with CVE data
                matched_cve = None
                if cwe_id:
                    # Look for matching CWE in CVE data
                    matched_rows = self.cve_data[self.cve_data['CWE'] == cwe_id]
                    if not matched_rows.empty:
                        matched_cve = matched_rows.iloc[0].to_dict()
                
                if matched_cve:
                    finding['cve_match'] = matched_cve
                    matched_findings.append(finding)
                else:
                    unmatched_findings.append(finding)
        
        return matched_findings, unmatched_findings
    
    def generate_compliance_report(self, matched_findings, unmatched_findings):
        """Generate detailed compliance and regulatory impact report."""
        report = []
        
        report.append("# CodeQL Security Analysis Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        total_findings = len(matched_findings) + len(unmatched_findings)
        report.append("## Executive Summary")
        report.append(f"- **Total Security Findings**: {total_findings}")
        report.append(f"- **Matched with CVE Database**: {len(matched_findings)}")
        report.append(f"- **Unmatched Findings**: {len(unmatched_findings)}")
        report.append("")
        
        if matched_findings:
            report.append("## Critical Findings with Regulatory Impact")
            report.append("")
            
            for i, finding in enumerate(matched_findings, 1):
                cve_data = finding['cve_match']
                
                report.append(f"### {i}. {finding['short_description'] or finding['rule_name']}")
                report.append("")
                
                # Vulnerability Details
                report.append("**Vulnerability Details:**")
                report.append(f"- **CodeQL Rule ID**: {finding['rule_id']}")
                report.append(f"- **CWE ID**: {finding['cwe_id']}")
                report.append(f"- **CVE ID**: {cve_data.get('CVE ID', 'N/A')}")
                report.append(f"- **Severity**: {finding['level'].upper()}")
                report.append(f"- **CVSS Base Score**: {cve_data.get('CVSS Base', 'N/A')}")
                report.append("")
                
                # Description
                if finding['full_description']:
                    report.append(f"**Description**: {finding['full_description']}")
                elif finding['message']:
                    report.append(f"**Description**: {finding['message']}")
                report.append("")
                
                # Locations
                if finding['locations']:
                    report.append("**Affected Locations:**")
                    for loc in finding['locations']:
                        report.append(f"- {loc['file']}:{loc['line']}:{loc['column']}")
                    report.append("")
                
                # Regulatory Impact
                report.append("**Regulatory and Standards Impact:**")
                
                # HIPAA
                hipaa_rules = cve_data.get('HIPAA Rules Impacted')
                if pd.notna(hipaa_rules) and str(hipaa_rules).strip():
                    report.append(f"- **HIPAA Violation**: {hipaa_rules}")
                
                # GDPR
                gdpr_articles = cve_data.get('GDPR Articles Impacted')
                if pd.notna(gdpr_articles) and str(gdpr_articles).strip():
                    report.append(f"- **GDPR Violation**: {gdpr_articles}")
                
                # ISO 27001
                iso_control = cve_data.get('ISO 27001 Control')
                if pd.notna(iso_control) and str(iso_control).strip():
                    report.append(f"- **ISO 27001 Control**: {iso_control}")
                
                # IEC 81001-5-1
                iec_clause = cve_data.get('IEC 81001-5-1 Clause')
                if pd.notna(iec_clause) and str(iec_clause).strip():
                    report.append(f"- **IEC 81001-5-1 Clause**: {iec_clause}")
                
                # FDA
                fda_topic = cve_data.get('FDA Premarket Topic')
                if pd.notna(fda_topic) and str(fda_topic).strip():
                    report.append(f"- **FDA Premarket Impact**: {fda_topic}")
                
                # Data Impact
                phi_impact = cve_data.get('PHI/PII Impact Summary')
                if pd.notna(phi_impact) and str(phi_impact).strip():
                    report.append(f"- **PHI/PII Impact**: {phi_impact}")
                
                # Healthcare Capability
                healthcare_cap = cve_data.get('Healthcare Capability (from Capabilities)')
                if pd.notna(healthcare_cap) and str(healthcare_cap).strip():
                    report.append(f"- **Healthcare Capability Impact**: {healthcare_cap}")
                
                report.append("")
                
                # Remediation
                report.append("**Remediation Information:**")
                
                fix_available = cve_data.get('Fix Available?')
                if pd.notna(fix_available):
                    report.append(f"- **Fix Available**: {fix_available}")
                
                workaround = cve_data.get('Workaround Available?')
                if pd.notna(workaround):
                    report.append(f"- **Workaround Available**: {workaround}")
                
                target_fix = cve_data.get('Target Fix Version/Release')
                if pd.notna(target_fix) and str(target_fix).strip():
                    report.append(f"- **Target Fix Version**: {target_fix}")
                
                remediation_owner = cve_data.get('Remediation Owner')
                if pd.notna(remediation_owner) and str(remediation_owner).strip():
                    report.append(f"- **Remediation Owner**: {remediation_owner}")
                
                report.append("")
                report.append("---")
                report.append("")
        
        # Unmatched findings
        if unmatched_findings:
            report.append("## Additional Security Findings")
            report.append("*These findings were not matched with the CVE database but still require attention.*")
            report.append("")
            
            for i, finding in enumerate(unmatched_findings, 1):
                report.append(f"### {i}. {finding['short_description'] or finding['rule_name']}")
                report.append(f"- **Rule ID**: {finding['rule_id']}")
                report.append(f"- **CWE ID**: {finding['cwe_id'] or 'Not identified'}")
                report.append(f"- **Severity**: {finding['level'].upper()}")
                
                if finding['locations']:
                    report.append("- **Locations**:")
                    for loc in finding['locations']:
                        report.append(f"  - {loc['file']}:{loc['line']}")
                
                report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        report.append("")
        report.append("1. **Immediate Action Required**: Address all CRITICAL and HIGH severity findings")
        report.append("2. **Regulatory Compliance**: Review all findings with regulatory impact")
        report.append("3. **Remediation Planning**: Prioritize fixes based on CVSS scores and regulatory requirements")
        report.append("4. **Documentation**: Ensure all remediation activities are properly documented")
        report.append("5. **Continuous Monitoring**: Implement regular security scans and reviews")
        report.append("")
        
        return "\n".join(report)
    
    def find_sarif_files(self, search_path="."):
        """Find SARIF files in the given path."""
        sarif_files = []
        search_patterns = ["**/*.sarif", "**/results/*.sarif", "**/*sarif*"]
        
        path = Path(search_path)
        for pattern in search_patterns:
            sarif_files.extend(path.glob(pattern))
        
        return [str(f) for f in sarif_files]
    
    def validate_and_report(self, output_file="security_compliance_report.md"):
        """Main validation function."""
        # If no SARIF path provided, try to find SARIF files
        if not self.sarif_results_path:
            sarif_files = self.find_sarif_files()
            if sarif_files:
                print(f"Found SARIF files: {sarif_files}")
                self.sarif_results_path = sarif_files[0]  # Use the first one
            else:
                print("No SARIF files found. Creating example report with CVE data only.")
                return self.create_example_report(output_file)
        
        if not self.load_sarif_results(self.sarif_results_path):
            return False
        
        matched_findings, unmatched_findings = self.match_findings_with_cve_data()
        report_content = self.generate_compliance_report(matched_findings, unmatched_findings)
        
        # Write report
        with open(output_file, 'w') as f:
            f.write(report_content)
        
        print(f"Security compliance report generated: {output_file}")
        
        # Print summary to console
        print(f"\nSUMMARY:")
        print(f"  Total findings: {len(matched_findings) + len(unmatched_findings)}")
        print(f"  Matched with CVE database: {len(matched_findings)}")
        print(f"  Unmatched findings: {len(unmatched_findings)}")
        
        if matched_findings:
            print(f"\nREGULATORY IMPACT SUMMARY:")
            hipaa_count = sum(1 for f in matched_findings 
                            if pd.notna(f['cve_match'].get('HIPAA Rules Impacted')))
            gdpr_count = sum(1 for f in matched_findings 
                           if pd.notna(f['cve_match'].get('GDPR Articles Impacted')))
            iso_count = sum(1 for f in matched_findings 
                          if pd.notna(f['cve_match'].get('ISO 27001 Control')))
            
            print(f"  HIPAA violations: {hipaa_count}")
            print(f"  GDPR violations: {gdpr_count}")
            print(f"  ISO 27001 violations: {iso_count}")
        
        return True
    
    def create_example_report(self, output_file):
        """Create an example report showing the CVE database structure."""
        report = []
        report.append("# Security Compliance Report (CVE Database Overview)")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        report.append("## CVE Database Summary")
        report.append(f"Total CVE records: {len(self.cve_data)}")
        report.append("")
        
        # Show sample entries
        report.append("## Sample CVE Entries")
        for i, (_, row) in enumerate(self.cve_data.head(5).iterrows(), 1):
            report.append(f"### {i}. {row.get('CVE ID', 'N/A')}")
            report.append(f"- **CWE**: {row.get('CWE', 'N/A')}")
            report.append(f"- **Title**: {row.get('Title/Short Description', 'N/A')}")
            report.append(f"- **CVSS Base**: {row.get('CVSS Base', 'N/A')}")
            
            if pd.notna(row.get('HIPAA Rules Impacted')):
                report.append(f"- **HIPAA Impact**: {row.get('HIPAA Rules Impacted')}")
            if pd.notna(row.get('GDPR Articles Impacted')):
                report.append(f"- **GDPR Impact**: {row.get('GDPR Articles Impacted')}")
            if pd.notna(row.get('ISO 27001 Control')):
                report.append(f"- **ISO 27001**: {row.get('ISO 27001 Control')}")
            
            report.append("")
        
        report.append("## Available Regulatory Standards")
        report.append("The CVE database includes compliance mapping for:")
        report.append("- HIPAA Rules")
        report.append("- GDPR Articles") 
        report.append("- ISO 27001 Controls")
        report.append("- IEC 81001-5-1 Clauses")
        report.append("- FDA Premarket Topics")
        report.append("")
        
        content = "\n".join(report)
        with open(output_file, 'w') as f:
            f.write(content)
        
        print(f"CVE database overview report generated: {output_file}")
        return True


def main():
    parser = argparse.ArgumentParser(description='Validate CodeQL results against CVE database')
    parser.add_argument('--cve-datasheet', 
                       default='CVE_Datasheet_Populated_v3.xlsx',
                       help='Path to CVE datasheet Excel file')
    parser.add_argument('--sarif-results',
                       help='Path to SARIF results file from CodeQL')
    parser.add_argument('--output',
                       default='security_compliance_report.md',
                       help='Output report file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.cve_datasheet):
        print(f"Error: CVE datasheet not found: {args.cve_datasheet}")
        sys.exit(1)
    
    validator = CodeQLValidator(args.cve_datasheet, args.sarif_results)
    
    try:
        success = validator.validate_and_report(args.output)
        if success:
            print("Validation completed successfully!")
        else:
            print("Validation completed with warnings.")
    except Exception as e:
        print(f"Error during validation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()