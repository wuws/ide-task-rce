# Enterprise Group Policy Mitigations

This guide covers how to deploy IDE security settings across an organization using Group Policy (GPO), MDM, and configuration management tools.

## Overview

For enterprise environments, manually configuring each developer's IDE is impractical. These methods allow centralized deployment of the `task.allowAutomaticTasks: "off"` setting.

## Method 1: VS Code Policy Settings (Recommended)

VS Code supports machine-level policies that users cannot override.

### Windows Group Policy

1. Download the VS Code ADMX templates from Microsoft (if available for your version).
2. Alternatively, deploy a machine-level `settings.json`:

**Policy path (machine-wide, overrides user settings):**

```
Windows: %ProgramFiles%\Microsoft VS Code\resources\app\product.json
```

**Or use a startup script to write the policy file:**

```powershell
# deploy-vscode-policy.ps1
# Deploy as a Computer Startup Script via GPO

$policyDir = "$env:ProgramFiles\Microsoft VS Code\resources\app"
$settingsDir = "$env:APPDATA\..\Local\Programs\Microsoft VS Code\resources\app"

# VS Code policy settings (cannot be overridden by user)
$policyContent = @'
{
    "configurationDefaults": {
        "task.allowAutomaticTasks": "off",
        "security.workspace.trust.enabled": true
    }
}
'@

# Write to all possible VS Code installation paths
$paths = @(
    "$env:ProgramFiles\Microsoft VS Code",
    "$env:LocalAppData\Programs\Microsoft VS Code",
    "$env:ProgramFiles\Cursor",
    "$env:LocalAppData\Programs\Cursor"
)

foreach ($path in $paths) {
    $policyFile = Join-Path $path "resources\app\policy-settings.json"
    if (Test-Path (Join-Path $path "resources\app")) {
        $policyContent | Out-File -FilePath $policyFile -Encoding UTF8 -Force
        Write-Host "Policy deployed to: $policyFile"
    }
}
```

### Registry-Based Policy (Alternative)

VS Code reads policy from the Windows Registry:

```
HKLM\SOFTWARE\Policies\Microsoft\VSCode
```

Deploy via GPO Registry Preferences:

| Key Path | Value Name | Type | Value |
|----------|-----------|------|-------|
| `HKLM\SOFTWARE\Policies\Microsoft\VSCode` | `task.allowAutomaticTasks` | REG_SZ | `off` |
| `HKLM\SOFTWARE\Policies\Microsoft\VSCode` | `security.workspace.trust.enabled` | REG_DWORD | `1` |

## Method 2: Deploy User Settings via Login Script

If machine-level policies are not available, deploy user-level settings:

```powershell
# deploy-user-settings.ps1
# Deploy as a User Logon Script via GPO

$settingsPaths = @(
    "$env:APPDATA\Code\User\settings.json",
    "$env:APPDATA\Cursor\User\settings.json"
)

$requiredSettings = @{
    "task.allowAutomaticTasks" = "off"
    "security.workspace.trust.enabled" = $true
}

foreach ($settingsPath in $settingsPaths) {
    $dir = Split-Path $settingsPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $settings = @{}
    if (Test-Path $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $settings = @{}
        }
    }

    foreach ($key in $requiredSettings.Keys) {
        $settings[$key] = $requiredSettings[$key]
    }

    $settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $settingsPath -Encoding UTF8 -Force
}
```

## Method 3: Ansible / Configuration Management

### Ansible Playbook

```yaml
---
- name: Secure IDE task auto-execution settings
  hosts: developer_workstations
  tasks:
    - name: Ensure VS Code settings directory exists
      file:
        path: "{{ ansible_env.HOME }}/.config/Code/User"
        state: directory
        mode: '0755'

    - name: Read existing VS Code settings
      slurp:
        src: "{{ ansible_env.HOME }}/.config/Code/User/settings.json"
      register: existing_settings
      ignore_errors: true

    - name: Deploy secure VS Code settings
      template:
        src: vscode-settings.json.j2
        dest: "{{ ansible_env.HOME }}/.config/Code/User/settings.json"
        mode: '0644'
```

## Method 4: Git Pre-Receive Hook (Repository-Level)

Block commits that introduce malicious tasks.json files:

```bash
#!/bin/bash
# pre-receive hook for Git server
# Rejects pushes containing tasks.json with folderOpen

while read oldrev newrev refname; do
    if [ "$oldrev" = "0000000000000000000000000000000000000000" ]; then
        range="$newrev"
    else
        range="$oldrev..$newrev"
    fi

    files=$(git diff --name-only "$range" 2>/dev/null | grep '\.vscode/tasks\.json$')

    for file in $files; do
        content=$(git show "$newrev:$file" 2>/dev/null)
        if echo "$content" | grep -qi 'folderOpen'; then
            echo "REJECTED: $file contains 'runOn: folderOpen' auto-execution trigger."
            echo "This is a known attack vector. Please remove the folderOpen trigger."
            echo "See: https://github.com/your-org/ide-folderopen-rce-poc"
            exit 1
        fi
    done
done
```

## Method 5: EDR / Endpoint Detection Rules

Configure your endpoint protection to:

1. **Alert** on creation of `.vscode/tasks.json` files containing `folderOpen`.
2. **Alert** on VS Code / Cursor spawning `powershell.exe` with encoded commands.
3. **Block** VS Code terminal processes from making outbound network connections to unknown hosts (if feasible in your environment).

Use the YARA rules and Sigma rules included in this repository's `detection/` folder.

## Verification

After deployment, verify the policy is working:

```powershell
# Check user settings
$paths = @(
    "$env:APPDATA\Code\User\settings.json",
    "$env:APPDATA\Cursor\User\settings.json"
)

foreach ($p in $paths) {
    if (Test-Path $p) {
        $content = Get-Content $p -Raw | ConvertFrom-Json
        $value = $content.'task.allowAutomaticTasks'
        Write-Host "$p : task.allowAutomaticTasks = $value"
    }
}
```

## Monitoring

Set up monitoring for:

- Changes to IDE settings files that re-enable auto-tasks
- New `.vscode/tasks.json` files in developer project directories
- IDE processes spawning unexpected child processes

Use the Sigma rule in `detection/sigma_rule.yml` for SIEM integration.
