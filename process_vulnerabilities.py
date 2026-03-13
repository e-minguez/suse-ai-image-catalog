#!/usr/bin/env python3
"""
Process extracted SBOMs and add vulnerability summaries to data files.
Also scans chart-referenced images from registry.suse.com that are not yet in registry data.
Designed to run after fetch_suse_registry_images.py in GitHub Actions.
"""

import os
import json
import glob
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

def cosign_is_installed():
    """Check if cosign is installed."""
    return shutil.which("cosign") is not None

def extract_sbom_for_chart_image(full_image_ref, sbom_dir):
    """
    Try to extract a CycloneDX SBOM via cosign attestation for a registry.suse.com image.
    Returns the local SBOM path on success, or None on failure.
    """
    if not cosign_is_installed():
        return None

    safe_name = full_image_ref.replace(f"{REGISTRY}/", "").replace("/", "-").replace(":", "-").replace(".", "-")
    sbom_path = os.path.join(sbom_dir, f"{safe_name}-cyclonedx.json")

    if os.path.exists(sbom_path):
        return sbom_path

    logger.info(f"    Extracting SBOM for chart image {full_image_ref}...")
    try:
        import base64
        result = subprocess.run(
            ["cosign", "verify-attestation", "--type", "cyclonedx",
             "--certificate-identity-regexp", ".*",
             "--certificate-oidc-issuer-regexp", ".*",
             full_image_ref],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            logger.debug(f"    cosign failed for {full_image_ref}: {result.stderr.strip()[:200]}")
            return None

        for line in result.stdout.strip().split('\n'):
            try:
                attestation = json.loads(line)
                payload = json.loads(base64.b64decode(attestation.get('payload', '') + '=='))
                predicate = payload.get('predicate', {})
                if predicate:
                    with open(sbom_path, 'w') as f:
                        json.dump(predicate, f)
                    return sbom_path
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"    SBOM extraction error for {full_image_ref}: {e}")
    return None

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

def scan_chart_referenced_images(data, sbom_dir):
    """
    For each registry chart entry with chart_images, scan any registry.suse.com images
    that are not already covered by the registry container data.
    Stores aggregated vulnerability data on chart items that currently lack it.

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
            # Try to match against existing container data first (strips registry prefix for matching)
            short_ref = img_ref.replace(f"{REGISTRY}/", "") if img_ref.startswith(f"{REGISTRY}/") else img_ref
            if short_ref in container_vuln_map:
                vuln_list.append(container_vuln_map[short_ref])
                continue

            # Try to scan images from registry.suse.com that we don't have data for
            full_ref = normalize_chart_image_ref(img_ref)
            if not full_ref:
                logger.debug(f"    Skipping chart image (external registry): {img_ref}")
                continue

            sbom_path = extract_sbom_for_chart_image(full_ref, sbom_dir)
            if not sbom_path:
                continue

            safe_name = full_ref.replace(f"{REGISTRY}/", "").replace("/", "-").replace(":", "-").replace(".", "-")
            vuln_output = os.path.join(VULNS_DIR, f"{safe_name}-vulns.json")
            if scan_sbom_with_trivy(sbom_path, vuln_output):
                summary = extract_vulnerability_summary(vuln_output)
                if summary:
                    vuln_list.append(summary)
                    container_vuln_map[short_ref] = summary  # Cache for other charts

        if vuln_list:
            total = sum(v.get("total", 0) for v in vuln_list)
            aggregated = {
                "total": total,
                "critical": sum(v.get("critical", 0) for v in vuln_list),
                "high": sum(v.get("high", 0) for v in vuln_list),
                "medium": sum(v.get("medium", 0) for v in vuln_list),
                "low": sum(v.get("low", 0) for v in vuln_list),
                "scan_date": max((v.get("scan_date","") for v in vuln_list if v.get("scan_date")), default=""),
                "source": "aggregated",
                "component_count": len(vuln_list),
            }
            item["vulnerabilities"] = aggregated
            chart_name = item.get("image_name", item.get("repository","unknown"))
            logger.info(f"  Chart {chart_name}: aggregated {total} vulns from {len(vuln_list)} image(s)")
            updated += 1

    return updated

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
    os.makedirs(SBOM_DIR, exist_ok=True)

    # Load existing data
    if not os.path.exists(DATA_FILE):
        logger.error(f"Data file {DATA_FILE} not found")
        return 1

    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    updated_count = 0
    skipped_count = 0

    # Step 1: Scan SBOM files for container images
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

    # Step 2: Aggregate vulnerabilities for registry chart entries from their component images
    logger.info("\nAggregating vulnerabilities for registry charts...")
    chart_updated = scan_chart_referenced_images(data, SBOM_DIR)
    if chart_updated:
        logger.info(f"Updated {chart_updated} chart(s) with aggregated vulnerability data")

    # Write updated data back
    total_updated = updated_count + chart_updated
    if total_updated > 0:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"\nUpdated {updated_count} images with vulnerability data")
        if chart_updated:
            logger.info(f"Updated {chart_updated} charts with aggregated vulnerability data")
        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} images (no SBOM or scan failed)")
    else:
        logger.info("\nNo images were updated")
        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} images")

    return 0

if __name__ == "__main__":
    exit(main())
