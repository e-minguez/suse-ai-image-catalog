import json
import os
import re
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# File paths
RANCHER_JSON = "data/suse_ai_images.json"
REGISTRY_JSON = "data/suse_registry_images.json"
CHANGELOG_JSON = "data/changelog.json"
OUTPUT_HTML = "index.html"
TEMPLATE_DIR = "templates"
TEMPLATE_FILE = "dashboard.html.j2"

# External Links
GITHUB_URL = "https://github.com/e-minguez/suse-ai-image-catalog"
APPCO_URL = "https://apps.rancher.io/stacks/suse-ai"
DOCS_URL = "https://documentation.suse.com/suse-ai"
LANDING_URL = "https://www.suse.com/solutions/ai/"
LOGO_URL = "static/logo_unofficial.svg"
FAVICON_URL = "static/favicon_unofficial.svg"
REGISTRY_LOGO_PLACEHOLDER = "static/placeholder-logo.svg"

def load_json(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return []

def build_registry_container_map(registry_data):
    """Build a lookup {image_name: item} from registry non-chart entries."""
    container_map = {}
    for item in registry_data:
        if "/charts/" not in item.get("repository", ""):
            container_map[item.get("image_name")] = item
    return container_map

def _sum_vulns(vuln_list):
    """Sum a list of vulnerability dicts into one aggregated dict. Returns None if list is empty."""
    if not vuln_list:
        return None
    total = critical = high = medium = low = 0
    scan_dates = []
    for v in vuln_list:
        total += v.get("total", 0)
        critical += v.get("critical", 0)
        high += v.get("high", 0)
        medium += v.get("medium", 0)
        low += v.get("low", 0)
        sd = v.get("scan_date", "")
        if sd:
            scan_dates.append(sd)
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "scan_date": max(scan_dates) if scan_dates else "",
        "source": "aggregated",
        "component_count": len(vuln_list),
        "artifact_url": None,
        "details_path": None,
    }

def aggregate_registry_chart_vulns(chart_images, registry_container_map):
    """
    Aggregate vulnerabilities for a registry Helm chart from its rendered image list.
    Returns an aggregated vulnerability dict, or None if no data available.
    """
    if not chart_images:
        return None

    vuln_list = []
    for img_ref in chart_images:
        item = registry_container_map.get(img_ref)
        if item:
            v = item.get("vulnerabilities")
            if v and isinstance(v, dict):
                vuln_list.append(v)

    return _sum_vulns(vuln_list)

def get_registry_logo(item):
    """Resolve a logo for a registry image.
    1. If org.opencontainers.image.source is a GitHub URL and the OCI title/vendor
       relates to the actual project (not a base image), use the org's avatar.
    2. Otherwise return a local placeholder icon.
    """
    labels = item.get('labels') or {}
    source = labels.get('org.opencontainers.image.source', '')
    title = labels.get('org.opencontainers.image.title', '').lower()
    vendor = labels.get('org.opencontainers.image.vendor', '').lower()

    if 'github.com' in source:
        # Derive the project name from the image path (last segment, no tag)
        image_name = item.get('image_name', '')
        project = image_name.split('/')[-1].split(':')[0].lower()
        # Only use the GitHub logo if title or vendor actually mentions the project
        if project and (project in title or project in vendor):
            path = source.replace('https://github.com/', '').replace('http://github.com/', '')
            org = path.split('/')[0]
            if org:
                return f"https://github.com/{org}.png"
    return REGISTRY_LOGO_PLACEHOLDER

def slugify(text):
    if not text: return ""
    # Replace non-alphanumeric with hyphen, then collapse hyphens
    return re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')

def normalize_arch(arch):
    if not arch: return "N/A"
    a = arch.lower()
    if a == "amd64": return "x86_64"
    return a

def format_date(d):
    if not d or d == "N/A": return "N/A"
    try: return datetime.fromisoformat(d.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
    except: return d

def to_json_encoded(obj):
    return json.dumps(obj).replace('"', '%22').replace("'", "%27")

def generate_html():
    rancher_data = load_json(RANCHER_JSON)
    registry_data = load_json(REGISTRY_JSON)
    changelog_data = load_json(CHANGELOG_JSON)

    # Build lookup map for registry chart vulnerability aggregation
    registry_container_map = build_registry_container_map(registry_data)

    # Add anchor IDs to changelog entries
    for entry in changelog_data:
        entry["anchor_id"] = f"change-{slugify(entry.get('date', ''))}"

    merged_data = []
    for item in rancher_data:
        image_name = item.get("image_name")
        tag = image_name.split(":", 1)[1] if ":" in image_name else None
        pkg_format = item.get("packaging_format", "CONTAINER")
        prefix = "dp.apps.rancher.io/charts/" if pkg_format == "HELM_CHART" else "dp.apps.rancher.io/containers/"
        full_path = f"{prefix}{image_name}" if image_name else "N/A"
        
        # Process SBOMs
        sboms = item.get("sboms", [])
        processed_sboms = []
        digest = item.get("digest", "")
        # Extract the hash from "SHA256:hash"
        hash_val = digest.split(":", 1)[1] if ":" in digest else digest
        
        origin_url = f"https://apps.rancher.io/artifacts/{hash_val}" if hash_val else None

        for sbom in sboms:
            filename = sbom.get("filename")
            if filename and hash_val:
                processed_sboms.append({
                    "format": sbom.get("format"),
                    "url": f"https://apps.rancher.io/artifacts/{hash_val}/resources/{filename}"
                })
        # Sort SBOMs by format name to ensure consistent UI order
        processed_sboms.sort(key=lambda x: x.get("format", ""))
        item["processed_sboms"] = processed_sboms
        item["origin_url"] = origin_url

        os_family = item.get('os_family') or ''
        os_version = item.get('os_version') or ''
        os_str = f"{os_family} {os_version}".strip() or "N/A"
        
        arch = normalize_arch(item.get("architecture"))
        version = item.get("version")
        anchor_id = slugify(f"{image_name}-{version}-{arch}")

        # AppCo charts have vulnerabilities pre-aggregated from component images during fetch.
        # Registry charts aggregate from their rendered image list at dashboard-generation time.
        if pkg_format == "HELM_CHART":
            vulnerabilities = item.get("vulnerabilities")
        else:
            vulnerabilities = item.get("vulnerabilities")

        merged_data.append({
            "source": "AppCo",
            "name": full_path,
            "version": version,
            "tag": tag,
            "arch": arch,
            "os": os_str,
            "last_updated": item.get("last_updated"),
            "digest": item.get("digest"),
            "details": item,
            "type": "Chart" if pkg_format == "HELM_CHART" else "Container",
            "logo": item.get("app_logo_url"),
            "sboms": processed_sboms,
            "vulnerabilities": vulnerabilities,
            "anchor_id": anchor_id
        })

    for item in registry_data:
        image_name = item.get("image_name")
        full_path = f"registry.suse.com/{image_name}" if image_name else "N/A"
        is_chart = "/charts/" in full_path.lower()

        # Process local SBOMs
        processed_sboms = []
        if "sboms" in item:
            for sbom in item["sboms"]:
                processed_sboms.append({
                    "format": sbom.get("format"),
                    "url": sbom.get("path")  # The path is already correct
                })
        
        # Sort SBOMs by format name
        processed_sboms.sort(key=lambda x: x.get("format", ""))
        item["processed_sboms"] = processed_sboms
        
        arch = normalize_arch(item.get("architecture"))
        version = item.get("tag")
        anchor_id = slugify(f"{image_name}-{version}-{arch}")

        # Registry charts have vulnerabilities aggregated by process_vulnerabilities.py from
        # their chart_images list (scanning registry.suse.com images).
        # Fall back to on-the-fly aggregation from registry container data for older data.
        if is_chart:
            vulnerabilities = item.get("vulnerabilities") or aggregate_registry_chart_vulns(
                item.get("chart_images", []), registry_container_map
            )
        else:
            vulnerabilities = item.get("vulnerabilities")

        merged_data.append({
            "source": "SUSE Registry",
            "name": full_path,
            "version": version,
            "tag": item.get("tag"),
            "arch": arch,
            "os": item.get("os") or "N/A",
            "last_updated": item.get("created"),
            "digest": item.get("digest"),
            "details": item,
            "type": "Chart" if is_chart else "Container",
            "logo": get_registry_logo(item),
            "sboms": processed_sboms,
            "vulnerabilities": vulnerabilities,
            "anchor_id": anchor_id
        })

    groups = {}
    for item in merged_data:
        full_path = item['name']
        base_name = full_path.rsplit(":", 1)[0] if ":" in full_path else full_path
        if base_name not in groups:
            groups[base_name] = {
                "base_name": base_name, 
                "source": item['source'], 
                "versions": [], 
                "type": item['type'],
                "logo": item['logo'],
                "anchor_id": slugify(base_name)
            }
        groups[base_name]['versions'].append(item)

    final_groups = []
    for base_name, group_data in groups.items():
        group_data['versions'].sort(key=lambda x: x.get('last_updated') or '', reverse=True)
        latest = group_data['versions'][0]
        group_data['latest_version'] = latest['version']
        group_data['latest_tag'] = latest['tag']
        group_data['count'] = len(group_data['versions'])
        unique_archs = sorted(list(set(v['arch'] for v in group_data['versions'] if v['arch'] and v['arch'] != "N/A")))
        group_data['arch_list'] = unique_archs
        group_data['os'] = latest['os']
        group_data['last_updated'] = latest['last_updated']

        # Add vulnerability data from latest version
        if latest.get('vulnerabilities'):
            group_data['latest_vulnerabilities'] = latest['vulnerabilities']

        final_groups.append(group_data)

    final_groups.sort(key=lambda x: (x['type'], x['base_name']))
    
    app_count = len([g for g in final_groups if g['type'] == "Container"])
    chart_count = len([g for g in final_groups if g['type'] == "Chart"])

    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    env.filters['format_date'] = format_date
    env.filters['to_json_encoded'] = to_json_encoded
    
    template = env.get_template(TEMPLATE_FILE)
    
    context = {
        "GITHUB_URL": GITHUB_URL,
        "FAVICON_URL": FAVICON_URL,
        "LOGO_URL": LOGO_URL,
        "DOCS_URL": DOCS_URL,
        "LANDING_URL": LANDING_URL,
        "APPCO_URL": APPCO_URL,
        "total_versions": len(merged_data),
        "app_count": app_count,
        "chart_count": chart_count,
        "rancher_count": len(rancher_data),
        "registry_count": len(registry_data),
        "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M'),
        "groups": final_groups,
        "changelog": changelog_data
    }

    output = template.render(context)
    
    with open(OUTPUT_HTML, 'w') as f:
        f.write(output)
    
    print(f"Dashboard generated: {OUTPUT_HTML}")

if __name__ == "__main__":
    generate_html()
