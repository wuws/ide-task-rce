<#
.SYNOPSIS
    tasks.json Security Scanner (PowerShell)

.DESCRIPTION
    Recursively scans a directory for .vscode/tasks.json files and checks for
    indicators of the "runOn: folderOpen" automatic execution vulnerability.

    Checks performed:
      - runOn: folderOpen triggers
      - Suspicious commands (powershell encoded, curl, wget, msiexec, etc.)
      - Mismatched command vs OS-specific overrides (stealth technique)
      - Base64-encoded payloads
      - Hidden presentation settings
      - Script execution references

.PARAMETER Path
    The root directory to scan recursively.

.EXAMPLE
    .\scan.ps1 -Path C:\Users\dev\repos
    .\scan.ps1 -Path .
    .\scan.ps1 -Path "$env:USERPROFILE\projects"

.NOTES
    Part of the IDE Folder-Open RCE research repository.
    For educational and defensive purposes only.
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

# =============================================================================
# Configuration
# =============================================================================

$SuspiciousPatterns = @(
    'powershell.*-[Ee]ncoded[Cc]ommand'
    'powershell.*-[Ee][Cc]\s'
    'powershell.*Invoke-WebRequest'
    'powershell.*Invoke-Expression'
    'powershell.*\biex\b'
    'powershell.*DownloadString'
    'powershell.*DownloadFile'
    'powershell.*Start-Process'
    'powershell.*New-Object.*Net\.WebClient'
    '\bcurl\b.*https?://'
    '\bwget\b.*https?://'
    '\bmsiexec\b'
    '\bcertutil\b.*-urlcache'
    '\bbitsadmin\b.*\/transfer'
    '\brundll32\b'
    '\bregsvr32\b'
    '\bcscript\b'
    '\bwscript\b'
    '\bmshta\b'
    'Start-Process'
    'Invoke-Expression'
    'IEX\s*\('
    'Net\.WebClient'
    'System\.Net\.Http'
)

$ScriptExtensions = @('.py', '.js', '.sh', '.bat', '.cmd', '.ps1', '.vbs', '.rb', '.pl')

# =============================================================================
# Scanner Functions
# =============================================================================

function Write-Banner {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor White
    Write-Host "  tasks.json Security Scanner (PowerShell)" -ForegroundColor White
    Write-Host "  Detects malicious runOn:folderOpen auto-execution patterns" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor White
    Write-Host ""
}

function Remove-JsonComments {
    param([string]$Json)
    # Remove single-line comments
    $result = $Json -replace '//.*$', '' -replace '(?m)//.*$', ''
    # Remove multi-line comments
    $result = $result -replace '/\*[\s\S]*?\*/', ''
    return $result
}

function Test-SuspiciousCommand {
    param([string]$Command)

    foreach ($pattern in $SuspiciousPatterns) {
        if ($Command -match $pattern) {
            return @{
                IsSuspicious = $true
                Pattern      = $pattern
            }
        }
    }
    return @{ IsSuspicious = $false; Pattern = $null }
}

function Test-Base64Content {
    param([string]$Command)
    if ($Command -match '[A-Za-z0-9+/]{40,}={0,2}') {
        return $true
    }
    return $false
}

function Test-ScriptReference {
    param([string]$Command)
    foreach ($ext in $ScriptExtensions) {
        if ($Command -match [regex]::Escape($ext)) {
            return $true
        }
    }
    return $false
}

function Scan-TasksJson {
    param([string]$FilePath)

    $findings = @()

    try {
        $rawContent = Get-Content -Path $FilePath -Raw -ErrorAction Stop
    }
    catch {
        Write-Host "  [i] Could not read: $FilePath" -ForegroundColor DarkGray
        return $findings
    }

    $cleanJson = Remove-JsonComments -Json $rawContent

    try {
        $data = $cleanJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "  [i] Invalid JSON: $FilePath" -ForegroundColor DarkGray
        return $findings
    }

    if (-not $data.tasks) { return $findings }

    foreach ($task in $data.tasks) {
        $label = if ($task.label) { $task.label } else { "<unnamed>" }

        # Check for folderOpen
        $runOn = $null
        if ($task.runOptions -and $task.runOptions.runOn) {
            $runOn = $task.runOptions.runOn
        }

        if ($runOn -ne "folderOpen") { continue }

        $findings += @{
            Severity = "WARNING"
            Message  = "Task '$label' has runOn: folderOpen - executes automatically"
        }

        # Gather all commands
        $topCommand = if ($task.command) { $task.command } else { "" }
        $topArgs = if ($task.args) { $task.args -join " " } else { "" }
        $fullTopCommand = ("$topCommand $topArgs").Trim()

        $allCommands = @($fullTopCommand)

        # Check OS-specific overrides
        $osOverrides = @{}
        foreach ($osKey in @("windows", "linux", "osx")) {
            $override = $task.$osKey
            if ($override -and $override.command) {
                $osArgs = if ($override.args) { $override.args -join " " } else { "" }
                $osCmd = ("$($override.command) $osArgs").Trim()
                $osOverrides[$osKey] = $osCmd
                $allCommands += $osCmd
            }
        }

        # Check for command mismatch (stealth)
        if ($osOverrides.Count -gt 0 -and $topCommand) {
            foreach ($entry in $osOverrides.GetEnumerator()) {
                $topBase = ($topCommand -split '\s')[0].ToLower()
                $osBase = ($entry.Value -split '\s')[0].ToLower()
                if ($topBase -and $osBase -and $topBase -ne $osBase) {
                    if ($topBase -in @('echo', 'true', 'rem', ':')) {
                        $findings += @{
                            Severity = "DANGEROUS"
                            Message  = "STEALTH: Benign top command '$topCommand' but $($entry.Key) runs '$($entry.Value)'"
                        }
                    }
                    else {
                        $findings += @{
                            Severity = "WARNING"
                            Message  = "Command mismatch: top='$topBase', $($entry.Key)='$osBase'"
                        }
                    }
                }
            }
        }

        # Check for suspicious commands
        foreach ($cmd in $allCommands) {
            if (-not $cmd) { continue }
            $result = Test-SuspiciousCommand -Command $cmd
            if ($result.IsSuspicious) {
                $findings += @{
                    Severity = "DANGEROUS"
                    Message  = "Suspicious command: '$cmd'"
                }
            }
        }

        # Check for base64
        foreach ($cmd in $allCommands) {
            if (-not $cmd) { continue }
            if (Test-Base64Content -Command $cmd) {
                $findings += @{
                    Severity = "DANGEROUS"
                    Message  = "Possible Base64-encoded payload in command"
                }
            }
        }

        # Check for script references
        foreach ($cmd in $allCommands) {
            if (-not $cmd) { continue }
            if (Test-ScriptReference -Command $cmd) {
                $findings += @{
                    Severity = "WARNING"
                    Message  = "Auto-task references external script: '$cmd'"
                }
            }
        }

        # Check presentation settings (stealth)
        $stealthSettings = @()
        if ($task.presentation) {
            if ($task.presentation.reveal -eq "never") { $stealthSettings += 'reveal:"never"' }
            if ($task.presentation.reveal -eq "silent") { $stealthSettings += 'reveal:"silent"' }
            if ($task.presentation.echo -eq $false) { $stealthSettings += 'echo:false' }
            if ($task.presentation.close -eq $true) { $stealthSettings += 'close:true' }
        }
        if ($stealthSettings.Count -gt 0) {
            $findings += @{
                Severity = "WARNING"
                Message  = "Stealth presentation: $($stealthSettings -join ', ')"
            }
        }
    }

    return $findings
}

# =============================================================================
# Main Execution
# =============================================================================

$resolvedPath = Resolve-Path -Path $Path -ErrorAction SilentlyContinue
if (-not $resolvedPath) {
    Write-Host "Error: Path does not exist: $Path" -ForegroundColor Red
    exit 1
}

Write-Banner
Write-Host "Scanning: $resolvedPath" -ForegroundColor DarkGray
Write-Host ""

$tasksFiles = Get-ChildItem -Path $resolvedPath -Recurse -Filter "tasks.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq ".vscode" }

if ($tasksFiles.Count -eq 0) {
    Write-Host "No .vscode/tasks.json files found in: $resolvedPath" -ForegroundColor DarkGray
    Write-Host ""
    exit 0
}

$totalDangerous = 0
$totalWarnings = 0
$filesWithFindings = 0

foreach ($file in $tasksFiles) {
    $findings = Scan-TasksJson -FilePath $file.FullName

    if ($findings.Count -eq 0) { continue }

    $filesWithFindings++
    $hasDangerous = ($findings | Where-Object { $_.Severity -eq "DANGEROUS" }).Count -gt 0
    $hasWarning = ($findings | Where-Object { $_.Severity -eq "WARNING" }).Count -gt 0

    if ($hasDangerous) {
        $totalDangerous++
        Write-Host "[DANGEROUS] $($file.FullName)" -ForegroundColor Red
    }
    elseif ($hasWarning) {
        $totalWarnings++
        Write-Host "[WARNING]   $($file.FullName)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[INFO]      $($file.FullName)" -ForegroundColor Cyan
    }

    foreach ($finding in $findings) {
        $color = switch ($finding.Severity) {
            "DANGEROUS" { "Red" }
            "WARNING" { "Yellow" }
            default { "Cyan" }
        }
        $marker = switch ($finding.Severity) {
            "DANGEROUS" { "!!!" }
            "WARNING" { " ! " }
            default { " i " }
        }
        Write-Host "  $marker $($finding.Message)" -ForegroundColor $color
    }
    Write-Host ""
}

# Summary
Write-Host ("=" * 70) -ForegroundColor White
Write-Host "  SCAN SUMMARY" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor White
Write-Host "  Scanned:    $resolvedPath"
Write-Host "  Files:      $($tasksFiles.Count) tasks.json file(s) found, $filesWithFindings with findings"

if ($totalDangerous -gt 0) {
    Write-Host "  DANGEROUS:  $totalDangerous file(s) with high-risk indicators" -ForegroundColor Red
}
if ($totalWarnings -gt 0) {
    Write-Host "  WARNINGS:   $totalWarnings file(s) with suspicious indicators" -ForegroundColor Yellow
}
if ($totalDangerous -eq 0 -and $totalWarnings -eq 0) {
    Write-Host "  [SAFE] No suspicious tasks.json files found" -ForegroundColor Green
}

Write-Host ""
if ($totalDangerous -gt 0) {
    Write-Host "  ACTION REQUIRED: Review the DANGEROUS findings above." -ForegroundColor Red
}
Write-Host ""
