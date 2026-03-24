/*
 * =============================================================================
 * YARA Rules: Malicious VS Code tasks.json Detection
 * =============================================================================
 *
 * Detects .vscode/tasks.json files that use the "runOn: folderOpen"
 * auto-execution feature with suspicious payloads.
 *
 * These rules are designed for:
 *   - Endpoint Detection and Response (EDR) scanning
 *   - CI/CD pipeline security checks
 *   - Repository auditing
 *   - Incident response file triage
 *
 * Reference: IDE Folder-Open RCE vulnerability
 * Used by: Lazarus Group / Contagious Interview campaign
 *
 * =============================================================================
 */

rule VSCode_Tasks_FolderOpen_Basic
{
    meta:
        description = "Detects VS Code tasks.json with runOn:folderOpen auto-execution trigger"
        author = "IDE Folder-Open RCE Research"
        severity = "medium"
        category = "execution"
        mitre_attack = "T1204.001"
        reference = "https://code.visualstudio.com/docs/editor/tasks"

    strings:
        $version = "\"version\"" ascii wide
        $tasks = "\"tasks\"" ascii wide
        $runOn = "\"runOn\"" ascii wide
        $folderOpen = "\"folderOpen\"" ascii wide nocase

    condition:
        filesize < 100KB and
        all of them
}

rule VSCode_Tasks_FolderOpen_Powershell
{
    meta:
        description = "Detects tasks.json with folderOpen trigger executing PowerShell commands"
        author = "IDE Folder-Open RCE Research"
        severity = "high"
        category = "execution"
        mitre_attack = "T1059.001"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-EC " ascii wide nocase
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX" ascii wide
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $sp = "Start-Process" ascii wide nocase

    condition:
        filesize < 100KB and
        $folderOpen and
        ($ps1 or $ps2) and
        any of ($enc*, $iex*, $dl*, $sp)
}

rule VSCode_Tasks_FolderOpen_Download
{
    meta:
        description = "Detects tasks.json with folderOpen trigger containing download commands"
        author = "IDE Folder-Open RCE Research"
        severity = "high"
        category = "execution"
        mitre_attack = "T1105"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $curl = "curl " ascii wide nocase
        $wget = "wget " ascii wide nocase
        $certutil = "certutil" ascii wide nocase
        $bitsadmin = "bitsadmin" ascii wide nocase
        $msiexec = "msiexec" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase

    condition:
        filesize < 100KB and
        $folderOpen and
        any of ($curl, $wget, $certutil, $bitsadmin, $msiexec, $urlcache)
}

rule VSCode_Tasks_FolderOpen_Stealth
{
    meta:
        description = "Detects tasks.json with folderOpen and hidden presentation (stealth technique)"
        author = "IDE Folder-Open RCE Research"
        severity = "high"
        category = "defense-evasion"
        mitre_attack = "T1564"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $reveal_never = "\"never\"" ascii wide
        $reveal_silent = "\"silent\"" ascii wide
        $echo_false = "\"echo\"" ascii wide
        $presentation = "\"presentation\"" ascii wide

    condition:
        filesize < 100KB and
        $folderOpen and
        $presentation and
        ($reveal_never or $reveal_silent) and
        $echo_false
}

rule VSCode_Tasks_FolderOpen_OSMismatch
{
    meta:
        description = "Detects tasks.json with folderOpen and OS-specific command overrides (potential stealth)"
        author = "IDE Folder-Open RCE Research"
        severity = "medium"
        category = "defense-evasion"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $echo_cmd = /\"command\"\s*:\s*\"echo\s/ ascii wide
        $windows = "\"windows\"" ascii wide
        $linux = "\"linux\"" ascii wide
        $osx = "\"osx\"" ascii wide

    condition:
        filesize < 100KB and
        $folderOpen and
        $echo_cmd and
        any of ($windows, $linux, $osx)
}

rule VSCode_Tasks_FolderOpen_ScriptLoader
{
    meta:
        description = "Detects tasks.json with folderOpen executing external scripts (loader technique)"
        author = "IDE Folder-Open RCE Research"
        severity = "medium"
        category = "execution"
        mitre_attack = "T1059"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $py1 = ".py" ascii wide
        $py2 = "python" ascii wide nocase
        $js1 = "node " ascii wide nocase
        $js2 = ".js" ascii wide
        $sh1 = ".sh" ascii wide
        $sh2 = "bash " ascii wide nocase
        $bat = ".bat" ascii wide
        $cmd = ".cmd" ascii wide
        $ps = ".ps1" ascii wide

    condition:
        filesize < 100KB and
        $folderOpen and
        any of ($py*, $js*, $sh*, $bat, $cmd, $ps)
}

rule VSCode_Tasks_FolderOpen_Base64
{
    meta:
        description = "Detects tasks.json with folderOpen and Base64-encoded content"
        author = "IDE Folder-Open RCE Research"
        severity = "critical"
        category = "execution"
        mitre_attack = "T1027"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        // Match long base64 strings (likely encoded commands)
        $b64 = /[A-Za-z0-9+\/]{60,}={0,2}/ ascii wide

    condition:
        filesize < 100KB and
        $folderOpen and
        $b64
}

rule VSCode_Tasks_FolderOpen_ReverseShell
{
    meta:
        description = "Detects tasks.json with folderOpen and reverse shell indicators"
        author = "IDE Folder-Open RCE Research"
        severity = "critical"
        category = "execution"
        mitre_attack = "T1059"

    strings:
        $folderOpen = "folderOpen" ascii wide nocase
        $nc1 = "nc " ascii wide
        $nc2 = "ncat " ascii wide
        $nc3 = "netcat " ascii wide
        $socat = "socat " ascii wide
        $devtcp = "/dev/tcp/" ascii wide
        $bash_i = "bash -i" ascii wide
        $mkfifo = "mkfifo" ascii wide

    condition:
        filesize < 100KB and
        $folderOpen and
        any of ($nc*, $socat, $devtcp, $bash_i, $mkfifo)
}
