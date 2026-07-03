import subprocess
import json
import logging
import re
import os
import shutil
import tempfile
import time
import collections
from base64 import b64decode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Lightweight profiling: wall-clock seconds per phase and call counts.
# Safe as module-level state because the fetch loop runs serially.
TIMINGS = collections.defaultdict(float)
COUNTS = collections.defaultdict(int)

REGISTRY = "registry.suse.com"
NAMESPACE = "ai/"
OUTPUT_FILE = "data/suse_registry_images.json"
SBOM_DIR = "sboms"
VULNS_DIR = "vulns"
COSIGN_KEY = "https://documentation.suse.com/suse-ai/files/sr-pubkey.pem"

def normalize_timestamp(ts):
    """Normalize any ISO 8601-like timestamp to 'YYYY-MM-DD HH:MM' format."""
    if not ts:
        return ts
    m = re.match(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})', str(ts))
    return f"{m.group(1)} {m.group(2)}" if m else ts

def cosign_is_installed():
    """Check if cosign is installed."""
    return shutil.which("cosign") is not None

def helm_is_installed():
    """Check if helm is installed."""
    return shutil.which("helm") is not None

def _extract_images_from_value(value, images):
    """Recursively walk a parsed YAML structure and collect all container image references.

    Handles both the plain-string form and the repository/tag dict form:
      image: "registry.suse.com/ai/containers/foo:1.0"
      image:
        registry: "registry.suse.com"
        repository: "ai/containers/foo"
        tag: "1.0"
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "image":
                if isinstance(v, str) and v.strip():
                    images.add(v.strip())
                elif isinstance(v, dict):
                    registry = v.get("registry", "")
                    repository = v.get("repository", "")
                    tag = v.get("tag", "")
                    if repository:
                        ref = f"{registry}/{repository}" if registry else repository
                        if tag:
                            ref = f"{ref}:{tag}"
                        images.add(ref.strip())
            else:
                _extract_images_from_value(v, images)
    elif isinstance(value, list):
        for item in value:
            _extract_images_from_value(item, images)

def extract_chart_images(repo, tag, image_data):
    """Timing wrapper around _extract_chart_images_impl."""
    _t0 = time.perf_counter()
    try:
        return _extract_chart_images_impl(repo, tag, image_data)
    finally:
        TIMINGS["charts"] += time.perf_counter() - _t0

def _extract_chart_images_impl(repo, tag, image_data):
    """
    Pulls a Helm chart from the OCI registry, renders it with `helm template`,
    and extracts all container image references into image_data["chart_images"].
    """
    if not helm_is_installed():
        logger.warning("helm is not installed, skipping chart image extraction.")
        image_data["chart_images"] = []
        return

    full_ref = f"oci://{REGISTRY}/{repo}"
    chart_name = repo.split("/")[-1]

    with tempfile.TemporaryDirectory(prefix="chart_extract_") as tmpdir:
        # Pull the chart
        pull_cmd = ["helm", "pull", full_ref, "--version", tag, "--untar", "--destination", tmpdir]
        logger.info(f"    Pulling chart {full_ref}:{tag}")
        result = subprocess.run(pull_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"    helm pull failed for {full_ref}:{tag}: {result.stderr.strip()}")
            image_data["chart_images"] = []
            return

        chart_dir = os.path.join(tmpdir, chart_name)
        if not os.path.isdir(chart_dir):
            # Try to find the extracted dir (chart name may differ from repo segment)
            subdirs = [d for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d))]
            if not subdirs:
                logger.warning(f"    No chart directory found after helm pull for {full_ref}:{tag}")
                image_data["chart_images"] = []
                return
            chart_dir = os.path.join(tmpdir, subdirs[0])

        # Render the chart templates
        template_cmd = ["helm", "template", "release", chart_dir, "--include-crds"]
        logger.info(f"    Rendering chart templates for {chart_name}:{tag}")
        result = subprocess.run(template_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"    helm template failed for {chart_name}:{tag}: {result.stderr.strip()}")
            image_data["chart_images"] = []
            return

        # Parse rendered YAML (multi-document) and extract image references
        try:
            import yaml
            raw_images = set()
            for doc in yaml.safe_load_all(result.stdout):
                if doc:
                    _extract_images_from_value(doc, raw_images)
        except ImportError:
            # Fallback: regex extraction if PyYAML not available
            raw_images = set(re.findall(r'^\s+image:\s+"?([^"\s]+)"?\s*$', result.stdout, re.MULTILINE))
        except Exception as e:
            logger.warning(f"    Failed to parse rendered chart YAML for {chart_name}:{tag}: {e}")
            image_data["chart_images"] = []
            return

        # Normalize: strip registry prefix if present
        chart_images = []
        for img in sorted(raw_images):
            normalized = img
            if normalized.startswith(f"{REGISTRY}/"):
                normalized = normalized[len(f"{REGISTRY}/"):]
            chart_images.append(normalized)

        image_data["chart_images"] = chart_images
        logger.info(f"    Extracted {len(chart_images)} image(s) from chart {chart_name}:{tag}: {chart_images}")

def _build_cosign_cmd(attest_type, image_ref):
    """Build a cosign verify-attestation command for the given type and image ref."""
    cmd = [
        "cosign", "verify-attestation",
        "--type", attest_type,
        "--key", COSIGN_KEY,
        "--insecure-ignore-tlog",
        "--output", "json",
    ]
    registry_user = os.getenv("REGISTRY_USER")
    registry_pass = os.getenv("REGISTRY_PASSWORD")
    if registry_user and registry_pass:
        cmd.extend(["--registry-username", registry_user, "--registry-password", registry_pass])
    cmd.append(image_ref)
    return cmd


def _cosign_env():
    """Return an environment dict with cosign cache settings."""
    env = os.environ.copy()
    cosign_cache = os.path.join(os.getcwd(), ".cosign-cache")
    os.makedirs(cosign_cache, exist_ok=True)
    env["COSIGN_CACHE"] = cosign_cache
    env["SIGSTORE_ROOT"] = cosign_cache
    env["TUF_ENABLED"] = "0"
    return env


def _run_cosign_attestation(attest_type, image_ref):
    """
    Run cosign verify-attestation for attest_type on image_ref.
    Returns the parsed predicate dict on success, None on failure.
    """
    cmd = _build_cosign_cmd(attest_type, image_ref)
    _t0 = time.perf_counter()
    COUNTS["cosign_calls"] += 1
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=True, env=_cosign_env()
        )
        for line in result.stdout.strip().splitlines():
            try:
                attestation = json.loads(line)
                payload = json.loads(b64decode(attestation['payload']))
                predicate = payload.get('predicate')
                if predicate:
                    return predicate
            except Exception as e:
                logger.debug(f"      Failed to parse attestation line for {image_ref}: {e}")
                continue
    except subprocess.CalledProcessError as e:
        logger.debug(f"      cosign {attest_type} failed for {image_ref}: {e.stderr.strip()[:200] if e.stderr else ''}")
    except Exception as e:
        logger.debug(f"      Unexpected error running cosign {attest_type} for {image_ref}: {e}")
    finally:
        TIMINGS["cosign"] += time.perf_counter() - _t0
    return None


def _parse_vuln_predicate(predicate):
    """
    Parse a CosignVulnPredicate and return a vulnerability summary dict.
    Returns None if the predicate has no usable data.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    scanner_result = predicate.get("scanner", {}).get("result", {})
    for res in scanner_result.get("Results", []):
        for vuln in res.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").lower()
            counts[sev] = counts.get(sev, 0) + 1

    total = sum(counts.values())

    # Extract scan date from metadata
    metadata = predicate.get("metadata", {})
    raw_date = metadata.get("scanFinishedOn") or metadata.get("scanStartedOn") or ""
    scan_date = normalize_timestamp(raw_date) or ""

    return {
        "total": total,
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "scan_date": scan_date,
        "source": "attestation",
    }


def extract_attestations_per_arch(full_image, image_data):
    """Timing wrapper around _extract_attestations_per_arch_impl."""
    _t0 = time.perf_counter()
    try:
        return _extract_attestations_per_arch_impl(full_image, image_data)
    finally:
        TIMINGS["attestations"] += time.perf_counter() - _t0

def _extract_attestations_per_arch_impl(full_image, image_data):
    """
    For each architecture in the image manifest, extract the CycloneDX SBOM
    and vulnerability attestation using cosign, saving them to disk.
    Populates image_data["sboms"] and image_data["vulnerabilities"].
    """
    if not full_image.startswith(f"{REGISTRY}/ai/containers/"):
        return

    if not cosign_is_installed():
        logger.warning("cosign is not installed, skipping attestation extraction.")
        return

    logger.info(f"    Extracting per-arch attestations for {full_image}")

    # Get per-arch digests from the manifest index
    manifest_json = run_command(["crane", "manifest", full_image])
    if not manifest_json:
        logger.warning(f"      Could not fetch manifest for {full_image}")
        return

    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        logger.error(f"      Failed to parse manifest for {full_image}: {e}")
        return

    manifests = manifest.get("manifests", [])
    if not manifests:
        # Single-arch image — use the image digest directly
        digest = run_command(["crane", "digest", full_image])
        if digest:
            manifests = [{"platform": {"architecture": "amd64"}, "digest": digest}]
        else:
            logger.warning(f"      No manifests found and could not get digest for {full_image}")
            return

    # Base image ref without tag (for @digest addressing)
    image_base = full_image.rsplit(":", 1)[0]
    safe_base = re.sub(r'[:/]', '-', full_image.replace(f"{REGISTRY}/", ""))

    sboms = []
    vuln_summaries = []

    for entry in manifests:
        platform = entry.get("platform", {})
        arch = platform.get("architecture", "")
        if not arch or arch == "unknown":
            continue

        digest = entry.get("digest", "")
        if not digest:
            continue

        arch_ref = f"{image_base}@{digest}"
        logger.info(f"      Processing arch={arch} digest={digest[:19]}...")

        # --- CycloneDX SBOM ---
        sbom_filename = f"{safe_base}-{arch}-cyclonedx.json"
        sbom_filepath = os.path.join(SBOM_DIR, sbom_filename)

        if os.path.exists(sbom_filepath):
            logger.info(f"        SBOM already exists: {sbom_filepath}")
            sbom_ok = True
        else:
            sbom_predicate = _run_cosign_attestation("cyclonedx", arch_ref)
            if sbom_predicate:
                with open(sbom_filepath, 'w') as f:
                    json.dump(sbom_predicate, f, indent=2)
                logger.info(f"        Saved SBOM to {sbom_filepath}")
                sbom_ok = True
            else:
                logger.warning(f"        No CycloneDX SBOM found for {arch_ref}")
                sbom_ok = False

        if sbom_ok:
            sboms.append({"path": sbom_filepath, "format": "CycloneDX", "arch": arch})

        # --- Vulnerability attestation ---
        vuln_filename = f"{safe_base}-{arch}-vuln.json"
        vuln_filepath = os.path.join(VULNS_DIR, vuln_filename)

        if os.path.exists(vuln_filepath):
            logger.info(f"        Vuln attestation already exists: {vuln_filepath}")
            try:
                with open(vuln_filepath) as f:
                    vuln_predicate = json.load(f)
                summary = _parse_vuln_predicate(vuln_predicate)
                if summary:
                    summary["arch"] = arch
                    summary["details_path"] = vuln_filepath
                    vuln_summaries.append(summary)
            except Exception as e:
                logger.warning(f"        Could not re-parse cached vuln attestation {vuln_filepath}: {e}")
        else:
            vuln_predicate = _run_cosign_attestation("vuln", arch_ref)
            if vuln_predicate:
                with open(vuln_filepath, 'w') as f:
                    json.dump(vuln_predicate, f, indent=2)
                logger.info(f"        Saved vuln attestation to {vuln_filepath}")
                summary = _parse_vuln_predicate(vuln_predicate)
                if summary:
                    summary["arch"] = arch
                    summary["details_path"] = vuln_filepath
                    vuln_summaries.append(summary)
            else:
                logger.info(f"        No vuln attestation found for {arch_ref}")

    if sboms:
        image_data["sboms"] = sboms

    if vuln_summaries:
        # Aggregate across arches: use max scan_date, sum counts
        total = sum(v["total"] for v in vuln_summaries)
        image_data["vulnerabilities"] = {
            "total": total,
            "critical": sum(v["critical"] for v in vuln_summaries),
            "high": sum(v["high"] for v in vuln_summaries),
            "medium": sum(v["medium"] for v in vuln_summaries),
            "low": sum(v["low"] for v in vuln_summaries),
            "scan_date": max((v["scan_date"] for v in vuln_summaries if v.get("scan_date")), default=""),
            "source": "attestation",
            "details_files": [
                {"arch": v.get("arch", ""), "path": v["details_path"]}
                for v in vuln_summaries if v.get("details_path")
            ],
            "details_path": next((v["details_path"] for v in vuln_summaries if v.get("details_path")), None),
        }
        logger.info(f"      Vuln summary: total={total} (from {len(vuln_summaries)} arch(es))")
    else:
        logger.info(f"      No vuln attestation data available for {full_image}")


def run_command(cmd):
    try:
        # Check if crane is even available before running
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
            logger.warning(f"Access to {cmd_str} is unauthorized. This repository might be private or require login.")
        else:
            logger.error(f"Command failed: {cmd_str}")
            logger.error(f"Exit Code: {e.returncode}")
            logger.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error running command {' '.join(cmd)}: {e}")
        return None


# Known repositories to check if catalog is incomplete
KNOWN_REPOS = [
    "ai/charts/litellm",
    "ai/charts/qdrant",
    "ai/containers/litellm",
    "ai/containers/litellm-database",
    "ai/containers/qdrant"
]

def get_repositories():
    logger.info(f"Fetching catalog for {REGISTRY}")
    _t0 = time.perf_counter()
    output = run_command(["crane", "catalog", REGISTRY])
    TIMINGS["catalog"] += time.perf_counter() - _t0
    
    repos = []
    if output:
        lines = output.splitlines()
        logger.info(f"Total repositories found in catalog: {len(lines)}")
        repos = [line for line in lines if line.startswith(NAMESPACE)]
    else:
        logger.error(f"No catalog output from {REGISTRY}")

    # If no repositories found in catalog, try known ones
    if not repos:
        logger.warning(f"No repositories found in catalog for namespace {NAMESPACE}. Trying known list...")
        for repo in KNOWN_REPOS:
            # Verify repository exists by trying to list tags
            logger.info(f"  Verifying {repo}...")
            if run_command(["crane", "ls", f"{REGISTRY}/{repo}"]):
                repos.append(repo)
    
    return repos

def get_tags(repo):
    logger.info(f"  Fetching tags for {repo}")
    _t0 = time.perf_counter()
    output = run_command(["crane", "ls", f"{REGISTRY}/{repo}"])
    TIMINGS["tags_ls"] += time.perf_counter() - _t0
    COUNTS["tags_ls_calls"] += 1
    if not output:
        return []
    
    # Filter out .sig and .att tags
    tags = [line for line in output.splitlines() if not (line.endswith(".sig") or line.endswith(".att"))]
    return tags

def get_image_details(repo, tag, cache=None):
    full_image = f"{REGISTRY}/{repo}:{tag}"

    _t0 = time.perf_counter()
    digest = run_command(["crane", "digest", full_image])
    TIMINGS["digest"] += time.perf_counter() - _t0
    COUNTS["digest_calls"] += 1
    if not digest:
        return None, None

    # Check cache
    # Use (repo, tag) as the unique key for the artifact
    cache_key = (repo, tag)
    change_msg = None
    if cache and cache_key in cache:
        cached_item = cache[cache_key]
        if cached_item.get("digest") == digest:
            # If it's a container image, check if SBOM files actually exist
            needs_sbom_extraction = False
            if "/containers/" in repo:
                if "sboms" not in cached_item:
                    needs_sbom_extraction = True
                else:
                    # Check if the SBOM files actually exist on disk
                    for sbom in cached_item.get("sboms", []):
                        sbom_path = sbom.get("path")
                        if sbom_path and not os.path.exists(sbom_path):
                            needs_sbom_extraction = True
                            break
                # Re-extract if vulnerabilities are missing, came from Trivy (old format),
                # or if the per-arch vuln files are missing from disk (e.g. cache was cleared)
                # or if details_files is absent (migration from older attestation format)
                if not needs_sbom_extraction:
                    vuln = cached_item.get("vulnerabilities", {})
                    vuln_source = vuln.get("source", "")
                    if vuln_source != "attestation":
                        needs_sbom_extraction = True
                    elif not vuln.get("details_files"):
                        # details_files missing — older attestation run, force re-extraction
                        needs_sbom_extraction = True
                    else:
                        # Check that the vuln files actually exist on disk
                        for df in vuln.get("details_files", []):
                            if df.get("path") and not os.path.exists(df["path"]):
                                needs_sbom_extraction = True
                                break

            if needs_sbom_extraction:
                logger.info(f"    Cache hit for {full_image} but attestations missing or not on disk. Retrying extraction...")
                image_data = cached_item.copy()
                extract_attestations_per_arch(full_image, image_data)
                return image_data, None

            # If it's a chart, check if chart_images have been extracted yet
            needs_chart_extraction = False
            if "/charts/" in repo and "chart_images" not in cached_item:
                needs_chart_extraction = True

            if needs_chart_extraction:
                logger.info(f"    Cache hit for {full_image} but chart_images missing. Retrying extraction...")
                image_data = cached_item.copy()
                extract_chart_images(repo, tag, image_data)
                return image_data, None

            logger.info(f"    Cache hit for {full_image} (digest: {digest})")
            COUNTS["cache_hit"] += 1
            return cached_item, None

        # We need config to get arch for updated artifacts too
        COUNTS["digest_changed"] += 1
        _t0 = time.perf_counter()
        config_json = run_command(["crane", "config", full_image])
        TIMINGS["config"] += time.perf_counter() - _t0
        if config_json:
            try:
                config = json.loads(config_json)
                raw_arch = config.get("architecture", "N/A")
                arch = "x86_64" if raw_arch == "amd64" else raw_arch
                is_chart = "/charts/" in repo.lower()
                artifact_type = "Chart" if is_chart else "Container"
                change_msg = f"Updated {artifact_type} (Registry): {repo}:{tag} ({arch})"
            except:
                pass
    
    # If it's new, we'll get arch below after the cache block
    logger.info(f"    Inspecting {full_image} (Cache miss or digest changed)")
    COUNTS["inspect_new"] += 1

    _t0 = time.perf_counter()
    config_json = run_command(["crane", "config", full_image])
    TIMINGS["config"] += time.perf_counter() - _t0
    if not config_json:
        return None, None
    
    try:
        config = json.loads(config_json)
        raw_arch = config.get("architecture", "N/A")
        arch = "x86_64" if raw_arch == "amd64" else raw_arch
        if not change_msg:
            is_chart = "/charts/" in repo.lower()
            artifact_type = "Chart" if is_chart else "Container"
            change_msg = f"New {artifact_type} (Registry): {repo}:{tag} ({arch})"
    except json.JSONDecodeError:
        logger.error(f"Failed to decode config for {full_image}")
        return None, None

    image_data = {
        "repository": repo,
        "tag": tag,
        "image_name": f"{repo}:{tag}",
        "architecture": config.get("architecture"),
        "os": config.get("os"),
        "digest": digest,
        "created": normalize_timestamp(config.get("created")),
        "labels": config.get("config", {}).get("Labels", {}),
        "entrypoint": config.get("config", {}).get("Entrypoint"),
        "cmd": config.get("config", {}).get("Cmd")
    }

    # Extract per-arch attestations (SBOM + vuln) for container images
    extract_attestations_per_arch(full_image, image_data)

    # Extract image references from Helm charts
    if "/charts/" in repo.lower():
        extract_chart_images(repo, tag, image_data)
    
    return image_data, change_msg

def _log_profile(wall):
    """Print a phase-timing / call-count summary to stderr for CI diagnosis."""
    logger.info("──────── registry fetch profile ────────")
    logger.info(f"  total wall time        : {wall:6.1f}s")
    for phase in ("catalog", "tags_ls", "digest", "config", "attestations", "charts"):
        if TIMINGS.get(phase):
            logger.info(f"  {phase:22s}: {TIMINGS[phase]:6.1f}s")
    logger.info("  ── call counts ──")
    for name in ("tags_ls_calls", "digest_calls", "cache_hit", "digest_changed",
                 "inspect_new", "cosign_calls"):
        if COUNTS.get(name):
            logger.info(f"  {name:22s}: {COUNTS[name]}")
    logger.info("────────────────────────────────────────")

def main():
    # Create output directories if they don't exist
    os.makedirs(SBOM_DIR, exist_ok=True)
    os.makedirs(VULNS_DIR, exist_ok=True)

    # Load existing data for caching
    cache = {}
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                old_data = json.load(f)
                for item in old_data:
                    # Using repo:tag as key to uniquely identify the artifact
                    key = (item.get('repository'), item.get('tag'))
                    cache[key] = item
            logger.info(f"Loaded {len(cache)} items from cache.")
        except Exception as e:
            logger.warning(f"Could not load cache from {OUTPUT_FILE}: {e}")

    repos = get_repositories()
    if not repos:
        logger.error(f"No repositories found in {NAMESPACE}")
        return

    logger.info(f"Found {len(repos)} repositories in {NAMESPACE}")
    
    all_images = []
    changes = []
    for repo in repos:
        tags = get_tags(repo)
        if not tags:
            logger.warning(f"  No tags found for {repo}")
            continue
            
        for tag in tags:
            details, change_msg = get_image_details(repo, tag, cache)
            if details:
                all_images.append(details)
                if change_msg:
                    changes.append(change_msg)
            else:
                logger.warning(f"    Failed to get details for {repo}:{tag}")
                
    logger.info(f"Found total of {len(all_images)} images.")
    
    # Check if data actually changed
    data_changed = True
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                if json.load(f) == all_images:
                    data_changed = False
        except:
            pass

    if data_changed:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(all_images, f, indent=2)
        logger.info(f"Results saved to {OUTPUT_FILE}")
        
        # Save changes for the changelog
        if changes:
            with open("data/registry_changes.json", "w") as f:
                json.dump(changes, f, indent=2)

        # Signal change via exit code or print (we'll use print for now)
        print("CHANGE_DETECTED")
    else:
        logger.info("No changes detected in registry images.")

if __name__ == "__main__":
    _wall0 = time.perf_counter()
    try:
        main()
    finally:
        _log_profile(time.perf_counter() - _wall0)
