#!/usr/bin/env python3
"""
Fetch container images from GHCR (ghcr.io) and extract metadata and SBOMs.

To track additional GHCR images, add their full repository reference
(without tag) to the GHCR_IMAGES list below.
"""

import subprocess
import json
import logging
import re
import os
import shutil
from base64 import b64decode

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration: full GHCR repository references to track (no tag)
# ─────────────────────────────────────────────────────────────────────────────
GHCR_IMAGES = [
    "ghcr.io/suse/suse-ai-lifecycle-manager",
]

OUTPUT_FILE = "data/ghcr_images.json"
CHANGES_FILE = "data/ghcr_changes.json"
SBOM_DIR = "sboms"


def normalize_timestamp(ts):
    """Normalize any ISO 8601-like timestamp to 'YYYY-MM-DD HH:MM' format."""
    if not ts:
        return ts
    m = re.match(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})', str(ts))
    return f"{m.group(1)} {m.group(2)}" if m else ts


def cosign_is_installed():
    return shutil.which("cosign") is not None


def run_command(cmd):
    try:
        if cmd[0] == "crane":
            try:
                subprocess.run(["crane", "version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("crane command not found in PATH")
                return None

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        cmd_str = ' '.join(cmd)
        if "UNAUTHORIZED" in e.stderr:
            logger.warning(f"Access to {cmd_str} is unauthorized. The image might be private.")
        else:
            logger.error(f"Command failed: {cmd_str}")
            logger.error(f"Exit Code: {e.returncode}")
            logger.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error running command {' '.join(cmd)}: {e}")
        return None


def get_tags(full_image_base):
    """List all tags for a GHCR image repository, filtering out signatures and attestations."""
    logger.info(f"  Fetching tags for {full_image_base}")
    output = run_command(["crane", "ls", full_image_base])
    if not output:
        return []
    return [t for t in output.splitlines() if not (t.endswith(".sig") or t.endswith(".att"))]


def extract_sbom(full_image_ref, image_data):
    """
    Try to extract a CycloneDX SBOM via cosign attestation (keyless/Sigstore).
    Gracefully skips if cosign is unavailable or no attestation exists.
    """
    if not cosign_is_installed():
        logger.warning("cosign is not installed, skipping SBOM extraction.")
        return

    # e.g. ghcr.io/suse/suse-ai-lifecycle-manager:v1.0
    #   -> ghcr-suse-suse-ai-lifecycle-manager-v1-0-cyclonedx.json
    safe_name = re.sub(r'[:/.]', '-', full_image_ref.replace("ghcr.io/", "ghcr-"))
    sbom_filename = f"{safe_name}-cyclonedx.json"
    sbom_filepath = os.path.join(SBOM_DIR, sbom_filename)

    logger.info(f"    Extracting SBOM for {full_image_ref}")

    cmd = [
        "cosign", "verify-attestation",
        "--type", "cyclonedx",
        "--certificate-identity-regexp", ".*",
        "--certificate-oidc-issuer-regexp", ".*",
        "--insecure-ignore-tlog",
        full_image_ref,
    ]

    env = os.environ.copy()
    cosign_cache = os.path.join(os.getcwd(), ".cosign-cache")
    os.makedirs(cosign_cache, exist_ok=True)
    env["COSIGN_CACHE"] = cosign_cache
    env["SIGSTORE_ROOT"] = cosign_cache
    env["TUF_ENABLED"] = "0"

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            env=env,
        )

        found_sbom = False
        for line in result.stdout.strip().splitlines():
            try:
                attestation = json.loads(line)
                payload = json.loads(b64decode(attestation['payload']))
                sbom_data = payload.get('predicate')
                if sbom_data:
                    with open(sbom_filepath, 'w') as f:
                        json.dump(sbom_data, f, indent=2)
                    logger.info(f"      Extracted SBOM to {sbom_filepath}")
                    if "sboms" not in image_data:
                        image_data["sboms"] = []
                    if not any(s.get("path") == sbom_filepath for s in image_data["sboms"]):
                        image_data["sboms"].append({"path": sbom_filepath, "format": "CycloneDX"})
                    found_sbom = True
                    break
            except Exception as parse_err:
                logger.debug(f"      Failed to parse attestation line: {parse_err}")
                continue

        if not found_sbom:
            logger.warning(f"      No CycloneDX SBOM predicate found for {full_image_ref}")

    except subprocess.CalledProcessError as e:
        logger.warning(f"      No SBOM attestation found for {full_image_ref}.")
        if e.stderr:
            logger.debug(f"      cosign: {e.stderr.strip()}")
    except Exception as e:
        logger.error(f"      Unexpected error during SBOM extraction for {full_image_ref}: {e}")


def get_image_details(full_image_base, tag, cache=None):
    """Fetch metadata for a specific GHCR image tag. Returns (image_data, change_msg)."""
    full_image_ref = f"{full_image_base}:{tag}"

    digest = run_command(["crane", "digest", full_image_ref])
    if not digest:
        return None, None

    # Split "ghcr.io/suse/suse-ai-lifecycle-manager" into registry + repository
    parts = full_image_base.split("/", 1)
    registry = parts[0]
    repository = parts[1] if len(parts) > 1 else full_image_base

    cache_key = (full_image_base, tag)
    change_msg = None

    if cache and cache_key in cache:
        cached_item = cache[cache_key]
        if cached_item.get("digest") == digest:
            # Re-extract SBOM if file is missing from disk
            needs_sbom = (
                "sboms" not in cached_item
                or any(
                    s.get("path") and not os.path.exists(s["path"])
                    for s in cached_item.get("sboms", [])
                )
            )
            if needs_sbom:
                logger.info(f"    Cache hit for {full_image_ref} but SBOM missing. Retrying extraction...")
                image_data = cached_item.copy()
                extract_sbom(full_image_ref, image_data)
                return image_data, None

            logger.info(f"    Cache hit for {full_image_ref} (digest: {digest})")
            return cached_item, None

        # Digest changed — record as an update
        config_json = run_command(["crane", "config", full_image_ref])
        if config_json:
            try:
                config = json.loads(config_json)
                raw_arch = config.get("architecture", "N/A")
                arch = "x86_64" if raw_arch == "amd64" else raw_arch
                change_msg = f"Updated Container (GHCR): {repository}:{tag} ({arch})"
            except Exception:
                pass

    logger.info(f"    Inspecting {full_image_ref} (cache miss or digest changed)")

    config_json = run_command(["crane", "config", full_image_ref])
    if not config_json:
        return None, None

    try:
        config = json.loads(config_json)
        raw_arch = config.get("architecture", "N/A")
        arch = "x86_64" if raw_arch == "amd64" else raw_arch
        if not change_msg:
            change_msg = f"New Container (GHCR): {repository}:{tag} ({arch})"
    except json.JSONDecodeError:
        logger.error(f"Failed to decode config for {full_image_ref}")
        return None, None

    image_data = {
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "image_name": f"{repository}:{tag}",
        "full_image_ref": full_image_ref,
        "architecture": config.get("architecture"),
        "os": config.get("os"),
        "digest": digest,
        "created": normalize_timestamp(config.get("created")),
        "labels": config.get("config", {}).get("Labels", {}),
        "entrypoint": config.get("config", {}).get("Entrypoint"),
        "cmd": config.get("config", {}).get("Cmd"),
        "sboms": [],
        "vulnerabilities": {},
    }

    extract_sbom(full_image_ref, image_data)

    return image_data, change_msg


def main():
    os.makedirs(SBOM_DIR, exist_ok=True)

    # Load existing data as digest cache
    cache = {}
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                old_data = json.load(f)
            for item in old_data:
                reg = item.get('registry', 'ghcr.io')
                repo = item.get('repository', '')
                key = (f"{reg}/{repo}", item.get('tag'))
                cache[key] = item
            logger.info(f"Loaded {len(cache)} item(s) from cache.")
        except Exception as e:
            logger.warning(f"Could not load cache from {OUTPUT_FILE}: {e}")

    all_images = []
    changes = []

    for full_image_base in GHCR_IMAGES:
        tags = get_tags(full_image_base)
        if not tags:
            logger.warning(f"  No tags found for {full_image_base}")
            continue

        logger.info(f"  Found {len(tags)} tag(s) for {full_image_base}")
        for tag in tags:
            details, change_msg = get_image_details(full_image_base, tag, cache)
            if details:
                all_images.append(details)
                if change_msg:
                    changes.append(change_msg)
            else:
                logger.warning(f"    Failed to get details for {full_image_base}:{tag}")

    logger.info(f"Found {len(all_images)} GHCR image(s) total.")

    # Only write if something changed
    data_changed = True
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                if json.load(f) == all_images:
                    data_changed = False
        except Exception:
            pass

    if data_changed:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(all_images, f, indent=2)
        logger.info(f"Results saved to {OUTPUT_FILE}")

        if changes:
            with open(CHANGES_FILE, 'w') as f:
                json.dump(changes, f, indent=2)

        print("CHANGE_DETECTED")
    else:
        logger.info("No changes detected in GHCR images.")


if __name__ == "__main__":
    main()
