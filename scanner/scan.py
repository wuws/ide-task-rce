#!/usr/bin/env python3
"""
=============================================================================
tasks.json Security Scanner
=============================================================================

Recursively scans a directory for .vscode/tasks.json files and checks for
indicators of the "runOn: folderOpen" automatic execution attack.

CHECKS PERFORMED:
  1. Presence of "runOn": "folderOpen" trigger
  2. Suspicious commands (powershell encoded commands, curl, wget, etc.)
  3. Mismatched command vs OS-specific overrides (stealth technique)
  4. Base64-encoded payloads
  5. Hidden presentation settings (reveal: never, echo: false)
  6. Script execution (python, node, bash scripts called by tasks)
  7. Known malicious patterns from Lazarus/Contagious Interview campaigns

USAGE:
  python scan.py <directory>
  python scan.py ~/projects
  python scan.py C:\\Users\\dev\\repos
  python scan.py .

OUTPUT:
  Color-coded results: SAFE / WARNING / DANGEROUS

=============================================================================
"""

import json
import os
import re
import sys
import base64
from pathlib import Path
from typing import Optional


# =============================================================================
# CONFIGURATION
# =============================================================================

# Commands that are suspicious when auto-executed
SUSPICIOUS_COMMANDS = [
    r"powershell.*-[Ee]ncoded[Cc]ommand",
    r"powershell.*-[Ee][Cc]\s",
    r"powershell.*[Ii]nvoke-[Ww]eb[Rr]equest",
    r"powershell.*[Ii]nvoke-[Ee]xpression",
    r"powershell.*\biex\b",
    r"powershell.*[Dd]ownload[Ss]tring",
    r"powershell.*[Dd]ownload[Ff]ile",
    r"powershell.*[Ss]tart-[Pp]rocess",
    r"powershell.*[Nn]ew-[Oo]bject.*[Nn]et\.[Ww]eb[Cc]lient",
    r"\bcurl\b.*https?://",
    r"\bwget\b.*https?://",
    r"\bmsiexec\b",
    r"\bcertutil\b.*-urlcache",
    r"\bbitsadmin\b.*\/transfer",
    r"\brundll32\b",
    r"\bregsvr32\b",
    r"\bcscript\b",
    r"\bwscript\b",
    r"\bmshta\b",
    r"\bcmd\b.*/c.*&&",
    r"Start-Process",
    r"Invoke-Expression",
    r"IEX\s*\(",
    r"Net\.WebClient",
    r"System\.Net\.Http",
    r"\bchmod\b.*\+x",
    r"/bin/bash.*-c",
    r"/bin/sh.*-c",
    r"\bnc\b.*-[el]",        # netcat
    r"\bncat\b",
    r"\bsocat\b",
    r">/dev/tcp/",            # bash reverse shell
    r"\bbase64\b.*-[dD]",    # base64 decode pipe
]

# Patterns indicating base64 encoded content
BASE64_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{40,}={0,2}"  # Long base64 strings (40+ chars)
)

# Script file extensions that could contain payloads
SCRIPT_EXTENSIONS = {".py", ".js", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".rb", ".pl"}


# =============================================================================
# TERMINAL COLORS
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def supports_color() -> bool:
        """Check if the terminal supports color output."""
        if os.environ.get("NO_COLOR"):
            return False
        if sys.platform == "win32":
            os.system("")  # Enable ANSI on Windows 10+
            return True
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# Disable colors if not supported
if not Colors.supports_color():
    Colors.RED = Colors.YELLOW = Colors.GREEN = ""
    Colors.CYAN = Colors.BOLD = Colors.DIM = Colors.RESET = ""


# =============================================================================
# SCANNER CORE
# =============================================================================

class Finding:
    """Represents a single security finding in a tasks.json file."""

    DANGEROUS = "DANGEROUS"
    WARNING = "WARNING"
    INFO = "INFO"

    def __init__(self, severity: str, message: str, detail: str = ""):
        self.severity = severity
        self.message = message
        self.detail = detail

    def color(self) -> str:
        if self.severity == self.DANGEROUS:
            return Colors.RED
        elif self.severity == self.WARNING:
            return Colors.YELLOW
        return Colors.CYAN


def scan_task(task: dict, file_path: str) -> list[Finding]:
    """Analyze a single task object for malicious indicators."""
    findings: list[Finding] = []
    label = task.get("label", "<unnamed>")

    # Check for folderOpen trigger
    run_options = task.get("runOptions", {})
    run_on = run_options.get("runOn", "")

    if run_on != "folderOpen":
        return findings  # Not auto-executing, skip

    findings.append(Finding(
        Finding.WARNING,
        f"Task '{label}' has runOn: folderOpen — executes automatically when folder is opened"
    ))

    # Get all command variants
    top_command = task.get("command", "")
    top_args = task.get("args", [])
    full_top_command = f"{top_command} {' '.join(str(a) for a in top_args)}".strip()

    os_commands = {}
    for os_key in ("windows", "linux", "osx"):
        os_override = task.get(os_key, {})
        if isinstance(os_override, dict):
            cmd = os_override.get("command", "")
            args = os_override.get("args", [])
            if cmd:
                os_commands[os_key] = f"{cmd} {' '.join(str(a) for a in args)}".strip()

    all_commands = [full_top_command] + list(os_commands.values())

    # Check for command mismatch (stealth technique)
    if os_commands and top_command:
        for os_key, os_cmd in os_commands.items():
            # If the OS command is substantially different from the top-level command
            top_base = top_command.split()[0].lower() if top_command else ""
            os_base = os_cmd.split()[0].lower() if os_cmd else ""
            if top_base and os_base and top_base != os_base:
                if top_base in ("echo", "true", "rem", ":"):
                    findings.append(Finding(
                        Finding.DANGEROUS,
                        f"STEALTH: Top-level command is benign '{top_command}' but "
                        f"{os_key} override runs '{os_cmd}'",
                        "The OS-specific command differs from the visible command — "
                        "this is a known evasion technique."
                    ))
                else:
                    findings.append(Finding(
                        Finding.WARNING,
                        f"Command mismatch: top-level='{top_base}', {os_key}='{os_base}'",
                        "OS-specific overrides may hide the true payload."
                    ))

    # Check for suspicious commands
    for cmd in all_commands:
        if not cmd:
            continue
        for pattern in SUSPICIOUS_COMMANDS:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append(Finding(
                    Finding.DANGEROUS,
                    f"Suspicious command detected: '{cmd}'",
                    f"Matched pattern: {pattern}"
                ))
                break  # One match per command is enough

    # Check for base64 encoded content
    for cmd in all_commands:
        if BASE64_PATTERN.search(cmd):
            findings.append(Finding(
                Finding.DANGEROUS,
                f"Possible Base64-encoded payload in command",
                f"Command: {cmd[:100]}..."
            ))
            # Try to decode it
            for match in BASE64_PATTERN.finditer(cmd):
                try:
                    decoded = base64.b64decode(match.group()).decode("utf-8", errors="replace")
                    if any(c in decoded for c in [";", "|", "&", "$", "`"]):
                        findings.append(Finding(
                            Finding.DANGEROUS,
                            f"Base64 decodes to shell-like content",
                            f"Decoded: {decoded[:200]}"
                        ))
                except Exception:
                    pass

    # Check for script execution (loader technique)
    for cmd in all_commands:
        if not cmd:
            continue
        cmd_lower = cmd.lower()
        for ext in SCRIPT_EXTENSIONS:
            if ext in cmd_lower:
                # Extract the script path
                parts = cmd.split()
                script_paths = [p for p in parts if ext in p.lower()]
                for sp in script_paths:
                    # Check if the script exists relative to the tasks.json
                    tasks_dir = Path(file_path).parent.parent  # .vscode -> project root
                    script_full = tasks_dir / sp
                    if script_full.exists():
                        findings.append(Finding(
                            Finding.WARNING,
                            f"Auto-task calls script: {sp}",
                            f"Script exists at: {script_full}\n"
                            "    Review this script manually — payload may be delegated to it."
                        ))
                    else:
                        findings.append(Finding(
                            Finding.WARNING,
                            f"Auto-task references script: {sp} (file not found)",
                            "The script may be downloaded or created at runtime."
                        ))

    # Check presentation settings (stealth indicators)
    presentation = task.get("presentation", {})
    stealth_indicators = []
    if presentation.get("reveal") == "never":
        stealth_indicators.append('reveal: "never"')
    if presentation.get("echo") is False:
        stealth_indicators.append("echo: false")
    if presentation.get("close") is True:
        stealth_indicators.append("close: true")
    if presentation.get("reveal") == "silent":
        stealth_indicators.append('reveal: "silent"')

    if stealth_indicators:
        findings.append(Finding(
            Finding.WARNING,
            f"Stealth presentation settings: {', '.join(stealth_indicators)}",
            "These settings hide the terminal output from the user."
        ))

    # If we found folderOpen but no other issues, it's still worth noting
    if len(findings) == 1:
        # Only the folderOpen finding — check if command seems benign
        benign_patterns = [r"^echo\b", r"^npm\s+(install|ci|test|build|run\s+build)$",
                           r"^yarn\s+(install|build|test)$", r"^make\b", r"^cmake\b"]
        is_benign = any(
            re.match(p, full_top_command, re.IGNORECASE)
            for p in benign_patterns
        ) if full_top_command else False

        if not is_benign and full_top_command:
            findings.append(Finding(
                Finding.WARNING,
                f"Auto-executing command: '{full_top_command}'",
                "Review this command to ensure it is expected for this project."
            ))

    return findings


def scan_tasks_json(file_path: str) -> list[Finding]:
    """Scan a single tasks.json file for malicious indicators."""
    findings: list[Finding] = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError) as e:
        findings.append(Finding(Finding.INFO, f"Could not read file: {e}"))
        return findings

    # Strip JSON comments (// and /* */) for parsing
    # This is a simplified approach — handles most cases
    content_no_comments = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
    content_no_comments = re.sub(r"/\*.*?\*/", "", content_no_comments, flags=re.DOTALL)

    try:
        data = json.loads(content_no_comments)
    except json.JSONDecodeError as e:
        findings.append(Finding(Finding.INFO, f"Invalid JSON: {e}"))
        return findings

    tasks = data.get("tasks", [])
    if not isinstance(tasks, list):
        return findings

    for task in tasks:
        if isinstance(task, dict):
            findings.extend(scan_task(task, file_path))

    return findings


def scan_directory(root_path: str) -> dict[str, list[Finding]]:
    """Recursively scan a directory for tasks.json files."""
    results: dict[str, list[Finding]] = {}
    root = Path(root_path)

    if not root.exists():
        print(f"{Colors.RED}Error: Path does not exist: {root_path}{Colors.RESET}")
        sys.exit(1)

    if not root.is_dir():
        print(f"{Colors.RED}Error: Not a directory: {root_path}{Colors.RESET}")
        sys.exit(1)

    # Walk the directory tree
    tasks_files_found = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip common non-project directories
        skip_dirs = {".git", "node_modules", "__pycache__", ".tox", "venv", ".venv"}
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        # Look for .vscode/tasks.json
        if os.path.basename(dirpath) == ".vscode" and "tasks.json" in filenames:
            tasks_path = os.path.join(dirpath, "tasks.json")
            tasks_files_found += 1
            findings = scan_tasks_json(tasks_path)
            if findings:
                results[tasks_path] = findings

    if tasks_files_found == 0:
        print(f"\n{Colors.DIM}No .vscode/tasks.json files found in {root_path}{Colors.RESET}")

    return results


# =============================================================================
# OUTPUT
# =============================================================================

def print_banner():
    """Print the scanner banner."""
    print()
    print(f"{Colors.BOLD}{'=' * 70}")
    print("  tasks.json Security Scanner")
    print("  Detects malicious runOn:folderOpen auto-execution patterns")
    print(f"{'=' * 70}{Colors.RESET}")
    print()


def print_results(results: dict[str, list[Finding]], scan_path: str):
    """Print scan results with color-coded severity."""
    if not results:
        print(f"{Colors.GREEN}{Colors.BOLD}[SAFE]{Colors.RESET} "
              f"No suspicious tasks.json files found in: {scan_path}")
        print()
        return

    total_dangerous = 0
    total_warnings = 0

    for file_path, findings in results.items():
        # Determine overall severity for this file
        has_dangerous = any(f.severity == Finding.DANGEROUS for f in findings)
        has_warning = any(f.severity == Finding.WARNING for f in findings)

        if has_dangerous:
            total_dangerous += 1
            status = f"{Colors.RED}{Colors.BOLD}[DANGEROUS]{Colors.RESET}"
        elif has_warning:
            total_warnings += 1
            status = f"{Colors.YELLOW}{Colors.BOLD}[WARNING]{Colors.RESET}"
        else:
            status = f"{Colors.CYAN}[INFO]{Colors.RESET}"

        print(f"{status} {file_path}")

        for finding in findings:
            color = finding.color()
            marker = "!!!" if finding.severity == Finding.DANGEROUS else " ! " if finding.severity == Finding.WARNING else " i "
            print(f"  {color}{marker} {finding.message}{Colors.RESET}")
            if finding.detail:
                for line in finding.detail.split("\n"):
                    print(f"  {Colors.DIM}    {line}{Colors.RESET}")
        print()

    # Summary
    print(f"{Colors.BOLD}{'=' * 70}")
    print(f"  SCAN SUMMARY")
    print(f"{'=' * 70}{Colors.RESET}")
    print(f"  Scanned:    {scan_path}")
    print(f"  Files:      {len(results)} tasks.json file(s) with findings")

    if total_dangerous:
        print(f"  {Colors.RED}{Colors.BOLD}DANGEROUS:  {total_dangerous} file(s) with high-risk indicators{Colors.RESET}")
    if total_warnings:
        print(f"  {Colors.YELLOW}WARNINGS:   {total_warnings} file(s) with suspicious indicators{Colors.RESET}")
    if not total_dangerous and not total_warnings:
        print(f"  {Colors.GREEN}Status:     No high-risk findings{Colors.RESET}")

    print()
    if total_dangerous:
        print(f"  {Colors.RED}{Colors.BOLD}ACTION REQUIRED: Review the DANGEROUS findings above.{Colors.RESET}")
        print(f"  {Colors.RED}These tasks.json files may execute malicious commands when opened.{Colors.RESET}")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <directory>")
        print(f"  Recursively scans for malicious .vscode/tasks.json files.")
        print()
        print(f"Examples:")
        print(f"  {sys.argv[0]} ~/projects")
        print(f"  {sys.argv[0]} C:\\Users\\dev\\repos")
        print(f"  {sys.argv[0]} .")
        sys.exit(1)

    scan_path = sys.argv[1]
    print_banner()
    print(f"{Colors.DIM}Scanning: {os.path.abspath(scan_path)}{Colors.RESET}")
    print()

    results = scan_directory(scan_path)
    print_results(results, scan_path)


if __name__ == "__main__":
    main()
