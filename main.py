import os
import sys
import json
from uuid import uuid4
from pathlib import Path
from datetime import datetime
from onnx_scanner import ONNXScanner


def scan_onnx_file(onnx_path):
    """
    Scan a single ONNX file for security vulnerabilities.

    Args:
        onnx_path (Path): Path to the ONNX file to scan

    Returns:
        dict: Scan results with metadata and vulnerabilities
    """
    print(f"Scanning file: {onnx_path}")

    # Create a unique ID for this scan
    file_id = uuid4()

    # Initialize the scanner
    try:
        scanner = ONNXScanner(onnx_path, file_id)
    except Exception as e:
        print(f"Error initializing scanner: {str(e)}")
        return {
            "file_id": str(file_id),
            "file_path": str(onnx_path),
            "scan_status": "FAILED",
            "error": f"Failed to initialize scanner: {str(e)}"
        }

    # Extract metadata
    try:
        metadata_str = scanner.metadata_extractor()
        metadata = json.loads(metadata_str) if metadata_str else {}
    except Exception as e:
        print(f"Warning: Could not extract metadata: {str(e)}")
        metadata = {"extraction_error": str(e)}

    # Perform vulnerability scan
    try:
        scan_results = scanner.weakness_scan()
    except Exception as e:
        print(f"Error during vulnerability scan: {str(e)}")
        return {
            "file_id": str(file_id),
            "file_path": str(onnx_path),
            "scan_status": "FAILED",
            "error": f"Scan error: {str(e)}",
            "metadata": metadata
        }

    # Count vulnerabilities by type and certainty
    vulnerability_counts = {
        "total": len(scan_results.get("vulnerabilities", [])),
        "by_type": {},
        "by_certainty": {
            "PROVEN": 0,
            "SUSPECTED": 0
        }
    }

    for vuln in scan_results.get("vulnerabilities", []):
        # Count by type
        vuln_type = vuln.get("type", "UNKNOWN")
        if vuln_type not in vulnerability_counts["by_type"]:
            vulnerability_counts["by_type"][vuln_type] = 0
        vulnerability_counts["by_type"][vuln_type] += 1

        # Count by certainty
        certainty = vuln.get("certainty", "SUSPECTED")
        vulnerability_counts["by_certainty"][certainty] += 1

    # Prepare final report
    final_report = {
        "file_id": str(file_id),
        "file_path": str(onnx_path),
        "file_size_bytes": os.path.getsize(onnx_path),
        "scan_time": datetime.now().isoformat(),
        "scan_status": "COMPLETED",
        "is_anomaly": scanner.is_anomaly,
        "vulnerability_counts": vulnerability_counts,
        "metadata": metadata,
        "vulnerabilities": scan_results.get("vulnerabilities", [])
    }

    # If specified, filter to include only proven vulnerabilities
    # Uncomment this line to only include proven vulnerabilities in the report
    # final_report["vulnerabilities"] = [v for v in final_report["vulnerabilities"] if v["certainty"] == "PROVEN"]

    return final_report


def save_report(report, output_dir=None):
    """
    Save the scan report to a JSON file.

    Args:
        report (dict): The scan report to save
        output_dir (str, optional): Directory to save the report. Defaults to current directory.

    Returns:
        str: Path to the saved report file
    """
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"scan_report_{report['file_id']}.json")
    else:
        output_path = f"scan_report_{report['file_id']}.json"

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    return output_path


def print_summary(report):
    """Print a summary of the scan results."""
    print("\n--- SCAN SUMMARY ---")
    print(f"File: {report['file_path']}")
    print(f"Scan ID: {report['file_id']}")
    print(f"Scan Status: {report['scan_status']}")
    print(f"Anomaly Detected: {report['is_anomaly']}")

    if report["scan_status"] == "COMPLETED":
        vuln_counts = report["vulnerability_counts"]
        print(f"Total Vulnerabilities: {vuln_counts['total']}")
        print(f"Proven Vulnerabilities: {vuln_counts['by_certainty']['PROVEN']}")
        print(f"Suspected Vulnerabilities: {vuln_counts['by_certainty']['SUSPECTED']}")

        if vuln_counts["by_type"]:
            print("\nVulnerabilities by Type:")
            for vuln_type, count in vuln_counts["by_type"].items():
                print(f"  - {vuln_type}: {count}")

        if report["vulnerabilities"]:
            print("\nDetailed Vulnerabilities:")
            for i, vuln in enumerate(report["vulnerabilities"]):
                print(f"\n{i + 1}. {vuln['type']} ({vuln['certainty']})")
                print(f"   Description: {vuln['description']}")
                print(f"   Severity: {vuln['severity']}")
    else:
        print(f"Error: {report.get('error', 'Unknown error')}")


def main():
    """Main function to run the ONNX scanner."""
    # Define the base project directory
    base_dir = Path(r"C:\Users\maya5\Desktop\Scanner_implement")

    # Define the ONNX files to scan
    onnx_files = [
        base_dir / "ONNX_FILES" / "botnet26t_256_Opset17.onnx",
        base_dir / "ONNX_FILES" / "cait_xxs36_224_Opset18.onnx"
    ]

    # Output directory for reports
    output_dir = base_dir / "reports"
    os.makedirs(output_dir, exist_ok=True)

    # Scan each file
    for onnx_path in onnx_files:
        if not onnx_path.exists():
            print(f"Error: File not found: {onnx_path}")
            continue

        # Perform the scan
        report = scan_onnx_file(onnx_path)

        # Save the report
        report_path = save_report(report, output_dir)
        print(f"Report saved to: {report_path}")

        # Print summary
        print_summary(report)
        print("\n" + "-" * 50 + "\n")


if __name__ == "__main__":
    main()