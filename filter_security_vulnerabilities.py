#!/usr/bin/env python3
"""
Filter security vulnerabilities from Bandit analysis report.
Extracts issues containing security-related keywords.
"""
import json
import sys
from pathlib import Path


def is_security_vulnerability(issue):
    """
    Check if an issue is a security vulnerability based on keywords.

    Args:
        issue: Dictionary containing issue details

    Returns:
        bool: True if issue is a security vulnerability
    """
    security_keywords = [
        'security implications',
        'security issue',
        'security',
        'vulnerability',
        'vulnerable'
    ]

    issue_text = issue.get('issue_text', '').lower()

    # Check if any security keyword is present in the issue text
    return any(keyword in issue_text for keyword in security_keywords)


def filter_security_vulnerabilities(input_file, output_file):
    """
    Filter security vulnerabilities from Bandit JSON report.

    Args:
        input_file: Path to input JSON file
        output_file: Path to output JSON file
    """
    # Read the input file
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Filter results to only include security vulnerabilities
    filtered_results = []

    if 'results' in data:
        for issue in data['results']:
            if is_security_vulnerability(issue):
                filtered_results.append(issue)

    # Create output structure
    output_data = {
        'total_vulnerabilities': len(filtered_results),
        'source_report': str(input_file),
        'filter_criteria': 'Issues containing security-related keywords',
        'results': filtered_results
    }

    # Add metrics breakdown
    severity_counts = {}
    confidence_counts = {}

    for issue in filtered_results:
        severity = issue.get('issue_severity', 'UNKNOWN')
        confidence = issue.get('issue_confidence', 'UNKNOWN')

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

    output_data['severity_breakdown'] = severity_counts
    output_data['confidence_breakdown'] = confidence_counts

    # Write filtered results
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"Filtered {len(filtered_results)} security vulnerabilities from {len(data.get('results', []))} total issues")
    print(f"Output saved to: {output_file}")
    print(f"\nSeverity breakdown:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")


if __name__ == '__main__':
    input_file = Path('analysis_results/httpie/full_scan_20251025_210542.json')
    output_file = Path('analysis_results/httpie/security_vulnerabilities.json')

    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    filter_security_vulnerabilities(input_file, output_file)
