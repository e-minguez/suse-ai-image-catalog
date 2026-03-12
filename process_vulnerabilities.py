#!/usr/bin/env python3
"""
Process extracted SBOMs and add vulnerability summaries to data files.
Designed to run after fetch_suse_registry_images.py in GitHub Actions.
"""

import os
import json
import glob
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

VULNS_DIR = "vulns"
DATA_FILE = "data/suse_registry_images.json"

def ensure_vulns_dir():
    """Create vulns/ directory if missing"""
    os.makedirs(VULNS_DIR, exist_ok=True)

def trivy_is_installed():
    """Check if trivy is installed."""
    try:
        result = subprocess.run(["trivy", "version"], capture_output=True, check=True)
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def scan_sbom_with_trivy(sbom_path: str, output_path: str) -> bool:
    """
    Execute Trivy scan on SBOM file using trivy sbom command.
    Returns True on success.
    """
    try:
        # trivy sbom --format json --output <output> <sbom_file>
        logger.debug(f"Running: trivy sbom --format json --output {output_path} {sbom_path}")
        result = subprocess.run(
            ["trivy", "sbom", "--format", "json", "--output", output_path, sbom_path],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            logger.warning(f"Trivy scan failed for {sbom_path}: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"Trivy scan timed out for {sbom_path}")
        return False
    except Exception as e:
        logger.error(f"Error scanning {sbom_path}: {e}")
        return False

def extract_vulnerability_summary(trivy_json_path: str) -> dict:
    """
    Parse Trivy JSON output and extract vulnerability counts per severity.
    """
    try:
        with open(trivy_json_path, 'r') as f:
            trivy_data = json.load(f)

        # Trivy JSON structure: {"Results": [{"Vulnerabilities": [...]}]}
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}

        for result in trivy_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").lower()
                counts[severity] = counts.get(severity, 0) + 1

        total = sum(counts.values())

        return {
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "total": total,
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "details_path": trivy_json_path
        }
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {trivy_json_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting summary from {trivy_json_path}: {e}")
        return None

def main():
    # Check if trivy is installed
    if not trivy_is_installed():
        logger.warning("Trivy is not installed or not in PATH. Skipping vulnerability scanning.")
        return 0

    ensure_vulns_dir()

    # Load existing data
    if not os.path.exists(DATA_FILE):
        logger.error(f"Data file {DATA_FILE} not found")
        return 1

    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    updated_count = 0
    skipped_count = 0

    # Process each image entry
    for item in data:
        sboms = item.get("sboms", [])
        if not sboms:
            skipped_count += 1
            continue

        # Get first SBOM path
        sbom_path = sboms[0].get("path")
        if not sbom_path or not os.path.exists(sbom_path):
            logger.warning(f"SBOM path not found or doesn't exist: {sbom_path}")
            skipped_count += 1
            continue

        # Generate output path for vulnerability scan
        sbom_basename = os.path.basename(sbom_path).replace("-cyclonedx.json", "")
        vuln_output = os.path.join(VULNS_DIR, f"{sbom_basename}-vulns.json")

        # Scan SBOM
        logger.info(f"Scanning {sbom_path}...")
        if scan_sbom_with_trivy(sbom_path, vuln_output):
            # Extract summary
            summary = extract_vulnerability_summary(vuln_output)
            if summary:
                item["vulnerabilities"] = summary
                updated_count += 1
                logger.info(f"  Found {summary['total']} vulnerabilities (C:{summary['critical']}, H:{summary['high']}, M:{summary['medium']}, L:{summary['low']})")
            else:
                logger.warning(f"  Failed to extract summary from {vuln_output}")
                skipped_count += 1
        else:
            logger.warning(f"  Scan failed for {sbom_path}, skipping")
            skipped_count += 1

    # Write updated data back
    if updated_count > 0:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"\nUpdated {updated_count} images with vulnerability data")
        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} images (no SBOM or scan failed)")
    else:
        logger.info("\nNo images were updated")
        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} images")

    return 0

if __name__ == "__main__":
    exit(main())
