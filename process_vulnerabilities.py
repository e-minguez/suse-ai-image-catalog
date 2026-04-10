#!/usr/bin/env python3
"""
Process vulnerability data for container images.

For SUSE registry images: vulnerability data is now extracted directly from
embedded cosign attestations during fetch_suse_registry_images.py. This script
only aggregates that data for Helm charts and optionally scans GHCR images with Trivy.
"""

import os
import json
import shutil
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

VULNS_DIR = "vulns"
SBOM_DIR = "sboms"
DATA_FILE = "data/suse_registry_images.json"
GHCR_DATA_FILE = "data/ghcr_images.json"
REGISTRY = "registry.suse.com"

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

def normalize_chart_image_ref(img_ref):
    """
    Normalize a chart image reference to a fully-qualified registry.suse.com ref.
    Only handles registry.suse.com images (ai/ and bci/ namespaces).
    Returns the full ref, or None if it can't be mapped to registry.suse.com.
    """
    if img_ref.startswith(f"{REGISTRY}/"):
        return img_ref
    if img_ref.startswith("dp.apps.rancher.io/"):
        return None  # External AppCo registry — cannot scan without auth
    if img_ref.startswith("ai/") or img_ref.startswith("bci/"):
        ref = f"{REGISTRY}/{img_ref}"
        if ":" not in img_ref.split("/")[-1]:
            ref += ":latest"
        return ref
    return None

def aggregate_chart_vulnerabilities(data):
    """
    For each registry chart entry, aggregate vulnerability data from its component
    container images (which now have vuln data from embedded attestations).

    Returns the number of chart items updated.
    """
    # Build a fast lookup: image_name → vulnerabilities (from container items)
    container_vuln_map = {}
    for item in data:
        if "/charts/" not in item.get("repository", "") and item.get("vulnerabilities"):
            container_vuln_map[item.get("image_name", "")] = item["vulnerabilities"]

    updated = 0
    for item in data:
        if "/charts/" not in item.get("repository", ""):
            continue
        chart_images = item.get("chart_images", [])
        if not chart_images:
            continue

        vuln_list = []
        for img_ref in chart_images:
            # Strip registry prefix for lookup
            short_ref = img_ref.replace(f"{REGISTRY}/", "") if img_ref.startswith(f"{REGISTRY}/") else img_ref
            if short_ref in container_vuln_map:
                vuln_list.append(container_vuln_map[short_ref])

        if vuln_list:
            total = sum(v.get("total", 0) for v in vuln_list)
            aggregated = {
                "total": total,
                "critical": sum(v.get("critical", 0) for v in vuln_list),
                "high": sum(v.get("high", 0) for v in vuln_list),
                "medium": sum(v.get("medium", 0) for v in vuln_list),
                "low": sum(v.get("low", 0) for v in vuln_list),
                "scan_date": max((v.get("scan_date", "") for v in vuln_list if v.get("scan_date")), default=""),
                "source": "aggregated",
                "component_count": len(vuln_list),
            }
            item["vulnerabilities"] = aggregated
            chart_name = item.get("image_name", item.get("repository", "unknown"))
            logger.info(f"  Chart {chart_name}: aggregated {total} vulns from {len(vuln_list)} image(s)")
            updated += 1

    return updated

def scan_sbom_with_trivy(sbom_path: str, output_path: str) -> bool:
    """Execute Trivy scan on an SBOM file. Returns True on success."""
    try:
        result = subprocess.run(
            ["trivy", "sbom", "--format", "json", "--output", output_path, sbom_path],
            capture_output=True, text=True, timeout=300
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
    """Parse Trivy JSON output and extract vulnerability counts per severity."""
    try:
        with open(trivy_json_path, 'r') as f:
            trivy_data = json.load(f)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for result in trivy_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").lower()
                counts[severity] = counts.get(severity, 0) + 1

        total = sum(counts.values())
        return {
            "scan_date": datetime.utcnow().strftime('%Y-%m-%d %H:%M'),
            "total": total,
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "source": "trivy",
            "details_path": trivy_json_path,
        }
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {trivy_json_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting summary from {trivy_json_path}: {e}")
        return None

def main():
    ensure_vulns_dir()
    os.makedirs(SBOM_DIR, exist_ok=True)

    # Load registry data
    if not os.path.exists(DATA_FILE):
        logger.error(f"Data file {DATA_FILE} not found")
        return 1

    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    # Step 1: Aggregate vuln data for registry charts from their component images.
    # Registry container images already have vulnerability data from embedded cosign
    # attestations (extracted by fetch_suse_registry_images.py). Charts just need
    # their component vuln data aggregated.
    logger.info("Aggregating vulnerabilities for registry charts...")
    chart_updated = aggregate_chart_vulnerabilities(data)
    if chart_updated:
        logger.info(f"Updated {chart_updated} chart(s) with aggregated vulnerability data")
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    else:
        logger.info("No registry charts needed vulnerability aggregation updates")

    # Step 2: Scan SBOM files for GHCR container images using Trivy
    if not os.path.exists(GHCR_DATA_FILE):
        return 0

    logger.info("\nProcessing GHCR images with Trivy...")
    if not trivy_is_installed():
        logger.warning("Trivy is not installed or not in PATH. Skipping GHCR vulnerability scanning.")
        return 0

    with open(GHCR_DATA_FILE, 'r') as f:
        ghcr_data = json.load(f)

    ghcr_updated = 0
    ghcr_skipped = 0

    for item in ghcr_data:
        sboms = item.get("sboms", [])
        if not sboms:
            ghcr_skipped += 1
            continue

        sbom_path = sboms[0].get("path")
        if not sbom_path or not os.path.exists(sbom_path):
            logger.warning(f"SBOM path not found or doesn't exist: {sbom_path}")
            ghcr_skipped += 1
            continue

        sbom_basename = os.path.basename(sbom_path).replace("-cyclonedx.json", "")
        vuln_output = os.path.join(VULNS_DIR, f"{sbom_basename}-vulns.json")

        logger.info(f"Scanning {sbom_path}...")
        if scan_sbom_with_trivy(sbom_path, vuln_output):
            summary = extract_vulnerability_summary(vuln_output)
            if summary:
                item["vulnerabilities"] = summary
                ghcr_updated += 1
                logger.info(f"  Found {summary['total']} vulnerabilities (C:{summary['critical']}, H:{summary['high']}, M:{summary['medium']}, L:{summary['low']})")
            else:
                logger.warning(f"  Failed to extract summary from {vuln_output}")
                ghcr_skipped += 1
        else:
            logger.warning(f"  Scan failed for {sbom_path}, skipping")
            ghcr_skipped += 1

    if ghcr_updated > 0:
        with open(GHCR_DATA_FILE, 'w') as f:
            json.dump(ghcr_data, f, indent=2)
        logger.info(f"Updated {ghcr_updated} GHCR image(s) with vulnerability data")
    if ghcr_skipped > 0:
        logger.info(f"Skipped {ghcr_skipped} GHCR image(s) (no SBOM or scan failed)")

    return 0

if __name__ == "__main__":
    exit(main())

