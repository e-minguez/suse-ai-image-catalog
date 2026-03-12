import subprocess
import os
import sys
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

CHANGELOG_FILE = "data/changelog.json"

def run_script(script_name, env=None):
    logger.info(f"Running {script_name}...")
    try:
        # Use sys.executable to ensure we use the same python interpreter
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            env={**os.environ, **(env or {})}
        )
        # Log stderr anyway if there's any
        if result.stderr:
            logger.error(f"Error in {script_name}:\n{result.stderr}")
        
        # Log stdout to help debugging
        logger.debug(f"Output from {script_name}:\n{result.stdout}")
        
        return "CHANGE_DETECTED" in result.stdout
    except Exception as e:
        logger.error(f"Failed to run {script_name}: {e}")
        return False

def update_changelog():
    all_changes = []
    
    # Load AppCo changes
    if os.path.exists("data/ai_changes.json"):
        try:
            with open("data/ai_changes.json", "r") as f:
                all_changes.extend(json.load(f))
            os.remove("data/ai_changes.json")
        except Exception as e:
            logger.error(f"Error reading data/ai_changes.json: {e}")
    
    # Load Registry changes
    if os.path.exists("data/registry_changes.json"):
        try:
            with open("data/registry_changes.json", "r") as f:
                all_changes.extend(json.load(f))
            os.remove("data/registry_changes.json")
        except Exception as e:
            logger.error(f"Error reading data/registry_changes.json: {e}")
    
    if not all_changes:
        return False
        
    # Load existing changelog
    changelog = []
    if os.path.exists(CHANGELOG_FILE):
        try:
            with open(CHANGELOG_FILE, "r") as f:
                changelog = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load existing changelog: {e}")
            
    # Add new entry
    new_entry = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "changes": all_changes
    }
    
    # Keep it at the top (newest first)
    changelog.insert(0, new_entry)
    
    # Limit changelog size (last 20 entries)
    changelog = changelog[:20]
    
    with open(CHANGELOG_FILE, "w") as f:
        json.dump(changelog, f, indent=2)
    
    return True

def main():
    # Registry credentials from environment
    registry_env = {
        "REGISTRY_USER": os.getenv("REGISTRY_USER", ""),
        "REGISTRY_PASSWORD": os.getenv("REGISTRY_PASSWORD", "")
    }

    # Step 1: Fetch AppCo Data
    ai_changed = run_script("fetch_suse_ai_images.py")
    
    # Step 2: Fetch Registry Data
    registry_changed = run_script("fetch_suse_registry_images.py", env=registry_env)

    # Step 3: Scan SBOMs for vulnerabilities (if any exist)
    vuln_scan_run = False
    if os.path.exists("sboms"):
        logger.info("Running vulnerability scanning...")
        try:
            result = subprocess.run(
                [sys.executable, "process_vulnerabilities.py"],
                capture_output=True,
                text=True
            )
            if result.stderr:
                logger.warning(f"Vulnerability scanning warnings:\n{result.stderr}")
            if result.stdout:
                logger.debug(f"Vulnerability scanning output:\n{result.stdout}")
            vuln_scan_run = True
        except Exception as e:
            logger.warning(f"Vulnerability scanning failed (continuing anyway): {e}")

    # Step 4: Update Changelog if anything changed
    changelog_updated = update_changelog()

    # Step 5: Check if dashboard needs rebuilding
    # Also check if index.html exists, if not, we must build it
    dashboard_exists = os.path.exists("index.html")
    force_rebuild = os.getenv("FORCE_REBUILD", "false").lower() == "true"

    if ai_changed or registry_changed or changelog_updated or vuln_scan_run or not dashboard_exists or force_rebuild:
        logger.info("Changes detected, changelog updated, vulnerabilities scanned, dashboard missing, or force rebuild requested. Rebuilding dashboard...")
        try:
            subprocess.run([sys.executable, "generate_dashboard.py"], check=True)
            logger.info("Dashboard successfully rebuilt.")
            
            # Set GitHub Action output if running in GHA
            if os.getenv('GITHUB_OUTPUT'):
                with open(os.getenv('GITHUB_OUTPUT'), 'a') as f:
                    f.write("data_changed=true\n")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to rebuild dashboard: {e}")
            sys.exit(1)
    else:
        logger.info("No changes detected. Skipping dashboard rebuild.")
        # Set GitHub Action output if running in GHA
        if os.getenv('GITHUB_OUTPUT'):
            with open(os.getenv('GITHUB_OUTPUT'), 'a') as f:
                f.write("data_changed=false\n")

if __name__ == "__main__":
    main()
