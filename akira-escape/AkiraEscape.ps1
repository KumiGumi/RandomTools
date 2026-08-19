<#
.SYNOPSIS
    Akira Escape Tool - offline incident-response triage, artifact collection and
    return-to-service readiness reporting for Windows hosts hit by Akira ransomware.

.DESCRIPTION
    Read-only (non-remediating) triage tool for a responder with local administrator
    rights working an Akira ransomware incident. It runs entirely offline: no
    network callouts, no reputation lookups, no cloud services.

    It answers four questions per host:

      1. Is anything still holding on?   -> persistence sweep (registry, tasks,
                                            services, WMI, logon, accessibility,
                                            LSA, netsh, print monitors, BITS, ...)
      2. Which Akira is this?            -> variant fingerprinting from ransom
                                            notes, appended extensions, encrypted
                                            file structure and host-side behaviour
      3. What do we keep?                -> artifact collection with SHA-256
                                            manifest (notes, samples, event logs,
                                            prefetch, task XML, registry exports)
      4. Can the client go back online?  -> scored readiness checklist and verdict

    Output is written to a single case folder containing an HTML report (hand to
    the client), a Markdown report, a machine-readable findings.json, and an
    AI-HANDOFF.md that can be pasted straight into Claude to produce a polished
    written report.

    THIS TOOL DOES NOT REMOVE MALWARE, DELETE FILES, KILL PROCESSES, CHANGE
    CONFIGURATION, OR DECRYPT ANYTHING. Everything it does is observation and
    copying. Remediation decisions stay with the responder.

.PARAMETER CaseId
    Case / engagement reference recorded in the report. Defaults to a timestamp.

.PARAMETER Operator
    Name or initials of the responder running the tool (chain of custody).

.PARAMETER OutputRoot
    Folder that will receive the case folder. Default: the folder the script is
    run from. Point this at removable media to keep the evidence off the host.

.PARAMETER Scope
    Quick    - fast pass, no event-log export, shallow file scan (5 min budget).
    Standard - default. Key event logs exported, user/data paths scanned.
    Deep     - full fixed-drive scan, registry hive export, prefetch/Amcache,
               longer scan budget.

.PARAMETER ScanPath
    Explicit roots to scan for encrypted files and ransom notes. Overrides the
    scope defaults. Example: -ScanPath 'D:\Shares','E:\'

.PARAMETER ScanTimeoutMinutes
    Wall-clock budget for the file system scan. The scan stops cleanly when the
    budget is spent and the report records that results are partial.

.PARAMETER DaysBack
    How far back the event-log triage looks. Default 45 days.

.PARAMETER IncidentStart
    Known or suspected start of the incident (any parseable date string). Used to
    judge "created during the incident" for accounts, tasks, services and files.
    If omitted it is estimated from the earliest encrypted file timestamp.

.PARAMETER MaxEncryptedSamples
    Maximum encrypted files to fingerprint / sample. Default 25.

.PARAMETER MaxNoteSamples
    Maximum ransom notes to collect. Default 25.

.PARAMETER CollectEventLogs
    Force event-log export on (implied by Standard/Deep).

.PARAMETER CollectRegistryHives
    Export SYSTEM / SOFTWARE / SAM / SECURITY hives (implied by Deep).

.PARAMETER SkipCollection
    Triage and report only - copy no artifacts. Useful for a very fast first look.

.PARAMETER NoZip
    Do not compress the case folder when finished.

.PARAMETER Menu
    Show the interactive menu instead of running immediately. Also the default
    when the script is started with no parameters in an interactive console.

.EXAMPLE
    .\AkiraEscape.ps1
    Interactive menu.

.EXAMPLE
    .\AkiraEscape.ps1 -CaseId IR-2026-014 -Operator "J. Doe" -OutputRoot E:\Evidence -Scope Deep
    Full deep triage with evidence written to removable media.

.EXAMPLE
    .\AkiraEscape.ps1 -Scope Quick -SkipCollection
    Fast look with no artifact copying.

.NOTES
    Requires  : Windows PowerShell 5.1 (built in on Windows 10/11/Server 2016+),
                run as Administrator.
    Offline   : yes - no outbound connections are made.
    Read-only : yes - see the banner printed at start.
#>

[CmdletBinding()]
param(
    [string]$CaseId,
    [string]$Operator,
    [string]$OutputRoot,
    [ValidateSet('Quick', 'Standard', 'Deep')]
    [string]$Scope = 'Standard',
    [string[]]$ScanPath,
    [int]$ScanTimeoutMinutes = 20,
    [int]$DaysBack = 45,
    [string]$IncidentStart,
    [int]$MaxEncryptedSamples = 25,
    [int]$MaxNoteSamples = 25,
    [switch]$CollectEventLogs,
    [switch]$CollectRegistryHives,
    [switch]$SkipCollection,
    [switch]$NoZip,
    [switch]$Menu
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'Continue'

$script:CommandLine = $MyInvocation.Line
$script:ToolName    = 'Akira Escape Tool'
$script:ToolVersion = '1.0.0'

# -------------------------------------------------------------------------
#  RUN STATE
# -------------------------------------------------------------------------
$script:Findings     = New-Object System.Collections.ArrayList
$script:Sections     = [ordered]@{}
$script:Manifest     = New-Object System.Collections.ArrayList
$script:ModuleStatus = New-Object System.Collections.ArrayList
$script:Readiness    = New-Object System.Collections.ArrayList
$script:Enabled      = @{}
$script:CaseDir      = $null
$script:ArtifactDir  = $null
$script:LogFile      = $null
$script:IncidentStartTime = $null
$script:RunStart     = Get-Date
$script:SeverityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

# -------------------------------------------------------------------------
#  CONSOLE HELPERS
# -------------------------------------------------------------------------
function Write-Head {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor Cyan
}

function Write-Sub {
    param([string]$Title)
    Write-Host ''
    Write-Host "  -- $Title" -ForegroundColor DarkCyan
}

function Write-Ok   { param([string]$m) Write-Host "     [OK] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "     [! ] $m" -ForegroundColor Yellow }
function Write-Bad  { param([string]$m) Write-Host "     [XX] $m" -ForegroundColor Red }
function Write-Note { param([string]$m) Write-Host "     [i ] $m" -ForegroundColor Gray }

function Write-Kv {
    param([string]$Label, $Value)
    if ($null -eq $Value -or "$Value" -eq '') { $Value = '(not available)' }
    Write-Host ("     {0,-26}: {1}" -f $Label, $Value) -ForegroundColor White
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}" -f (Get-Date), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
    }
    Write-Verbose $line
}

# -------------------------------------------------------------------------
#  FINDINGS / SECTIONS
# -------------------------------------------------------------------------
function New-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Detail = '',
        $Evidence = @(),
        [string]$Recommendation = '',
        [string[]]$Mitre = @(),
        [switch]$Quiet
    )

    $ev = @()
    foreach ($e in @($Evidence)) {
        if ($null -eq $e) { continue }
        if ($e -is [string]) { $ev += $e }
        else { $ev += (($e | Format-List | Out-String) -split "`r?`n" | Where-Object { $_.Trim() -ne '' }) }
    }

    $f = [pscustomobject]@{
        Id             = ('F{0:D3}' -f ($script:Findings.Count + 1))
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Detail         = $Detail
        Evidence       = $ev
        Recommendation = $Recommendation
        Mitre          = $Mitre
        Observed       = (Get-Date).ToString('s')
    }
    [void]$script:Findings.Add($f)
    Write-Log ("FINDING [{0}] {1} :: {2}" -f $Severity, $Category, $Title)

    if (-not $Quiet) {
        switch ($Severity) {
            'Critical' { Write-Bad  "$Title" }
            'High'     { Write-Bad  "$Title" }
            'Medium'   { Write-Warn "$Title" }
            'Low'      { Write-Warn "$Title" }
            default    { Write-Note "$Title" }
        }
        if ($Detail) { Write-Host "          $Detail" -ForegroundColor DarkGray }
    }
    return $f
}

function Add-Section {
    param([Parameter(Mandatory = $true)][string]$Name, $Data)
    $script:Sections[$Name] = $Data
}

function Test-ModuleEnabled {
    param([string]$Name)
    if ($script:Enabled.Count -eq 0) { return $true }
    return [bool]$script:Enabled[$Name]
}

function Invoke-Module {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    if (-not (Test-ModuleEnabled $Name)) { return }

    Write-Head $Title
    $sw     = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Completed'
    $err    = ''
    try {
        & $Body
    } catch {
        $status = 'Failed'
        $err    = $_.Exception.Message
        Write-Bad "Module '$Name' failed: $err"
        Write-Log "Module '$Name' failed: $($_ | Out-String)" 'ERROR'
    }
    $sw.Stop()
    [void]$script:ModuleStatus.Add([pscustomobject]@{
        Module   = $Name
        Title    = $Title
        Status   = $status
        Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Error    = $err
    })
}

# -------------------------------------------------------------------------
#  GENERAL HELPERS
# -------------------------------------------------------------------------
function Test-Administrator {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-Sha256 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return $null }
}

function ConvertTo-SafeName {
    param([string]$Value)
    if (-not $Value) { return 'unnamed' }
    $bad = [System.IO.Path]::GetInvalidFileNameChars() + [char[]]@(' ')
    $sb  = New-Object System.Text.StringBuilder
    foreach ($c in $Value.ToCharArray()) {
        if ($bad -contains $c) { [void]$sb.Append('_') } else { [void]$sb.Append($c) }
    }
    return $sb.ToString()
}

function New-CaseFolder {
    param([string]$Root, [string]$Case)
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $name  = 'AkiraEscape_{0}_{1}_{2}Z' -f (ConvertTo-SafeName $env:COMPUTERNAME), (ConvertTo-SafeName $Case), $stamp
    $dir   = Join-Path $Root $name
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    foreach ($sub in 'artifacts', 'artifacts\notes', 'artifacts\samples', 'artifacts\system',
                     'artifacts\eventlogs', 'artifacts\registry', 'artifacts\tasks',
                     'artifacts\prefetch', 'logs') {
        New-Item -ItemType Directory -Path (Join-Path $dir $sub) -Force -ErrorAction SilentlyContinue | Out-Null
    }
    return $dir
}

function Add-ManifestEntry {
    param([string]$LocalPath, [string]$SourcePath, [string]$Category, [string]$Description)
    try {
        $fi   = Get-Item -LiteralPath $LocalPath -Force -ErrorAction Stop
        $rel  = $fi.FullName.Substring($script:CaseDir.Length).TrimStart('\')
        [void]$script:Manifest.Add([pscustomobject]@{
            Category    = $Category
            File        = $rel
            SizeBytes   = $fi.Length
            SHA256      = (Get-Sha256 $fi.FullName)
            Source      = $SourcePath
            Description = $Description
            CollectedUtc= (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        })
    } catch {
        Write-Log "Manifest entry failed for ${LocalPath}: $($_.Exception.Message)" 'WARN'
    }
}

function Copy-Artifact {
    <# Copies a file into the case folder and records it in the manifest.
       Falls back to esentutl for locked files (registry hives, Amcache). #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SubFolder,
        [string]$NewName,
        [string]$Category = 'artifact',
        [string]$Description = ''
    )
    if ($script:SkipCollectionMode) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $destDir = Join-Path $script:ArtifactDir $SubFolder
    if (-not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not $NewName) { $NewName = Split-Path $Path -Leaf }
    $dest = Join-Path $destDir $NewName
    $i = 1
    while (Test-Path -LiteralPath $dest) {
        $dest = Join-Path $destDir ("{0}_{1}{2}" -f [System.IO.Path]::GetFileNameWithoutExtension($NewName), $i, [System.IO.Path]::GetExtension($NewName))
        $i++
    }

    $copied = $false
    try {
        Copy-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        $copied = $true
    } catch {
        # locked file - try the ESE copy trick, which can read open handles
        try {
            $null = & esentutl.exe /y "$Path" /vss /d "$dest" 2>&1
            if (Test-Path -LiteralPath $dest) { $copied = $true }
        } catch { }
        if (-not $copied) {
            try {
                $null = & esentutl.exe /y "$Path" /d "$dest" 2>&1
                if (Test-Path -LiteralPath $dest) { $copied = $true }
            } catch { }
        }
    }

    if ($copied) {
        Add-ManifestEntry -LocalPath $dest -SourcePath $Path -Category $Category -Description $Description
        Write-Log "Collected: $Path -> $dest"
        return $dest
    }
    Write-Log "Could not collect (locked/denied): $Path" 'WARN'
    return $null
}

function Save-Artifact {
    <# Writes generated text (command output, listings) into the case folder. #>
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$SubFolder,
        [Parameter(Mandatory = $true)][string]$FileName,
        [string]$Category = 'generated',
        [string]$Description = ''
    )
    if ($script:SkipCollectionMode) { return $null }
    $destDir = Join-Path $script:ArtifactDir $SubFolder
    if (-not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $dest = Join-Path $destDir $FileName
    try {
        Set-Content -LiteralPath $dest -Value $Content -Encoding UTF8 -Force -ErrorAction Stop
        Add-ManifestEntry -LocalPath $dest -SourcePath "(generated by $script:ToolName)" -Category $Category -Description $Description
        return $dest
    } catch {
        Write-Log "Save-Artifact failed for ${FileName}: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Invoke-Capture {
    <# Runs a native command and stores its output as an artifact. #>
    param([string]$FileName, [string]$Command, [string]$Description)
    try {
        $out = (cmd.exe /c $Command 2>&1 | Out-String)
    } catch {
        $out = "command failed: $($_.Exception.Message)"
    }
    Save-Artifact -Content ("> $Command`r`n`r`n$out") -SubFolder 'system' -FileName $FileName `
                  -Category 'command-output' -Description $Description | Out-Null
    return $out
}

function Get-RegValues {
    <# Returns the values of a registry key as PSCustomObjects, or nothing. #>
    param([string]$Path)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch { return @() }
    $out = @()
    foreach ($name in $k.GetValueNames()) {
        $out += [pscustomobject]@{
            Key   = $Path
            Name  = $(if ($name -eq '') { '(default)' } else { $name })
            Value = ($k.GetValue($name, '', 'DoNotExpandEnvironmentNames') | Out-String).Trim()
            Type  = $k.GetValueKind($name).ToString()
        }
    }
    return $out
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-SignatureState {
    <# Cheap authenticode summary for a binary path. #>
    param([string]$Path)
    if (-not $Path) { return 'Unknown' }
    $clean = $Path.Trim('"')
    if (-not (Test-Path -LiteralPath $clean)) { return 'FileMissing' }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $clean -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -match 'O=Microsoft Corporation') { return 'Valid (Microsoft)' }
            $cn = 'Unknown'
            if ($subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
            return "Valid ($cn)"
        }
        return $sig.Status.ToString()
    } catch { return 'Unknown' }
}

function Resolve-ImagePath {
    <# Pull the executable path out of a service ImagePath / command line. #>
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $c = $CommandLine.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring(1, $end - 1) }
    }
    if ($c -match '^(\\\?\?\\)?([a-zA-Z]:\\[^\s]+?\.(exe|dll|sys|bat|cmd|ps1|js|vbs))\b') { return $Matches[2] }
    $first = ($c -split '\s+')[0]
    return $first
}

function Test-SuspiciousPath {
    <# Directories that legitimate autostart binaries rarely live in. #>
    param([string]$Path)
    if (-not $Path) { return $false }
    $p = $Path.ToLower()
    $patterns = @(
        '\\users\\public\\', '\\appdata\\local\\temp\\', '\\appdata\\roaming\\',
        '\\windows\\temp\\', '\\programdata\\', '\\perflogs\\', '\\temp\\',
        '\\downloads\\', '\\desktop\\', '\\recycle', '\\$recycle.bin\\',
        '\\windows\\tasks\\', '\\windows\\debug\\', '\\intel\\', '\\music\\'
    )
    foreach ($pat in $patterns) { if ($p -like "*$pat*") { return $true } }
    if ($p -match '^[a-z]:\\[^\\]+\.(exe|dll|bat|cmd|ps1|vbs|js)$') { return $true }  # drive root
    return $false
}

function Test-SuspiciousCommand {
    param([string]$Command)
    if (-not $Command) { return $false }
    $patterns = @(
        'powershell.*-e(nc|ncodedcommand)?\s', '-nop\b', '-w\s+hidden', 'windowstyle\s+hidden',
        'iex\b', 'invoke-expression', 'downloadstring', 'downloadfile', 'frombase64string',
        'mshta', 'rundll32.*javascript', 'regsvr32.*/i:http', 'certutil.*-urlcache',
        'bitsadmin.*transfer', 'wscript', 'cscript', 'vssadmin.*delete', 'wbadmin.*delete',
        'bcdedit.*recoveryenabled', 'wevtutil.*cl\b', 'net\s+user\s+.*\s+/add',
        'schtasks.*/create', 'reg\s+add.*run', 'remove-wmiobject.*shadowcopy',
        'win32_shadowcopy', 'cipher\s+/w', 'taskkill.*/f.*/im'
    )
    foreach ($pat in $patterns) { if ($Command -imatch $pat) { return $true } }
    return $false
}

function Format-Age {
    param([datetime]$When)
    if (-not $When) { return '' }
    $span = (Get-Date) - $When
    if ($span.TotalDays -ge 1) { return ('{0:N0} days ago' -f $span.TotalDays) }
    if ($span.TotalHours -ge 1) { return ('{0:N0} hours ago' -f $span.TotalHours) }
    return ('{0:N0} minutes ago' -f $span.TotalMinutes)
}

function Test-InIncidentWindow {
    param($When)
    if (-not $script:IncidentStartTime -or -not $When) { return $false }
    try { return ([datetime]$When -ge $script:IncidentStartTime) } catch { return $false }
}

# -------------------------------------------------------------------------
#  FILE SYSTEM WALKER
# -------------------------------------------------------------------------
function Invoke-FileWalk {
    <#
        Iterative, budgeted directory walk. Returns a summary object and calls
        -OnFile for every file found. Never follows reparse points.
    #>
    param(
        [string[]]$Roots,
        [scriptblock]$OnFile,
        [int]$MaxDepth = 24,
        [int]$TimeoutSeconds = 900,
        [long]$MaxFiles = 3000000,
        [string[]]$ExcludeDirNames = @('winsxs', 'servicing', 'assembly', 'driverstore',
                                       'softwaredistribution', 'node_modules',
                                       '$recycle.bin', 'system volume information')
    )
    $sw        = [System.Diagnostics.Stopwatch]::StartNew()
    $stack     = New-Object System.Collections.Stack
    $fileCount = 0
    $dirCount  = 0
    $denied    = 0
    $truncated = $false
    $reason    = ''

    # Normalise and drop any root that already sits under another root, so nothing
    # is walked - or counted - twice.
    $normalised = @()
    foreach ($r in @($Roots)) {
        if ([string]::IsNullOrWhiteSpace($r)) { continue }
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try { $full = (Resolve-Path -LiteralPath $r -ErrorAction Stop).Path } catch { $full = $r }
        $normalised += $full.TrimEnd('\')
    }
    $normalised = @($normalised | Sort-Object { $_.Length })
    $roots = @()
    foreach ($r in $normalised) {
        $nested = $false
        foreach ($kept in $roots) {
            if ($r -eq $kept -or $r.ToLower().StartsWith(($kept.ToLower() + '\'))) { $nested = $true; break }
        }
        if (-not $nested) { $roots += $r }
    }
    foreach ($r in $roots) {
        # a bare drive letter ("C:") means "current directory on C", so make it a real root
        $push = $r
        if ($push -match '^[A-Za-z]:$') { $push = $push + '\' }
        $stack.Push([pscustomobject]@{ Path = $push; Depth = 0 })
    }

    while ($stack.Count -gt 0 -and -not $truncated) {
        if ($sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            $truncated = $true; $reason = 'time budget reached'; break
        }
        $cur = $stack.Pop()
        $dirCount++

        if ($dirCount % 250 -eq 0) {
            Write-Progress -Activity 'Scanning file system' `
                           -Status ("{0:N0} files / {1:N0} folders - {2}" -f $fileCount, $dirCount, $cur.Path) `
                           -PercentComplete ([math]::Min(99, ($sw.Elapsed.TotalSeconds / [math]::Max(1, $TimeoutSeconds)) * 100))
        }

        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($cur.Path)) {
                $fileCount++
                if ($fileCount -gt $MaxFiles) { $truncated = $true; $reason = 'file count cap reached'; break }
                try { & $OnFile $f } catch { }
                if ($fileCount % 20000 -eq 0 -and $sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                    $truncated = $true; $reason = 'time budget reached'; break
                }
            }
        } catch [System.UnauthorizedAccessException] { $denied++ }
          catch { }

        if ($truncated) { break }
        if ($cur.Depth -ge $MaxDepth) { continue }

        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($cur.Path)) {
                $leaf = (Split-Path $d -Leaf).ToLower()
                $skip = $false
                foreach ($x in $ExcludeDirNames) { if ($leaf -eq $x) { $skip = $true; break } }
                if ($skip) { continue }
                try {
                    $attr = [System.IO.File]::GetAttributes($d)
                    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                } catch { continue }
                $stack.Push([pscustomobject]@{ Path = $d; Depth = $cur.Depth + 1 })
            }
        } catch [System.UnauthorizedAccessException] { $denied++ }
          catch { }
    }

    $sw.Stop()
    Write-Progress -Activity 'Scanning file system' -Completed
    return [pscustomobject]@{
        FilesSeen      = $fileCount
        FoldersSeen    = $dirCount
        AccessDenied   = $denied
        Truncated      = $truncated
        TruncateReason = $reason
        Seconds        = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Roots          = @($roots)
    }
}

# -------------------------------------------------------------------------
#  REFERENCE DATA
#
#  Everything below is heuristic matching data drawn from public reporting on
#  Akira (including CISA/FBI/EC3/NCSC-NL advisory AA24-109A and vendor write-ups).
#  It is deliberately kept in one place so it can be edited between engagements
#  as new variants appear. Nothing here is authoritative attribution - the tool
#  reports ranked candidates with the evidence that produced them.
# -------------------------------------------------------------------------

# Ransom-note file names seen with Akira and its Megazord branch.
$script:NoteFileNames = @(
    'akira_readme.txt',
    'powerranges.txt',
    'akira_readme.html',
    'megazord_readme.txt'
)

# Regex for note names we have not seen before but that look like a note.
$script:NoteNameRegex = '^(akira|megazord|powerrange[s]?|how[_\- ]?to[_\- ]?(decrypt|restore|recover)|read[_\- ]?me[_\- ]?(now|first)|restore[_\- ]?(my[_\- ])?files|recover[_\- ]?files|decrypt[_\- ]?(my[_\- ])?files)[^\\]*\.(txt|html|hta)$'

# Known appended extensions.
$script:KnownEncryptedExtensions = @('.akira', '.powerranges', '.akiranew')

# Text markers used to fingerprint the note itself.
$script:NoteMarkers = @(
    [pscustomobject]@{ Name = 'akira-onion-leak-site'; Pattern = 'akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad'; Meaning = 'Classic Akira leak/negotiation onion address' }
    [pscustomobject]@{ Name = 'akira-brand';           Pattern = '\bakira\b';                                            Meaning = 'Note self-identifies as Akira' }
    [pscustomobject]@{ Name = 'megazord-brand';        Pattern = '\bmegazord\b|powerrange';                              Meaning = 'Note self-identifies as Megazord (Rust branch)' }
    [pscustomobject]@{ Name = 'tor-negotiation';       Pattern = '[a-z2-7]{16,56}\.onion';                               Meaning = 'Tor negotiation/leak address present' }
    [pscustomobject]@{ Name = 'tox-contact';           Pattern = '(?i)tox[^a-z0-9]{0,3}(id)?\s*[:=]?\s*[A-F0-9]{76}';    Meaning = 'Tox contact ID present' }
    [pscustomobject]@{ Name = 'victim-key-blob';       Pattern = '(?i)(your\s+(unique\s+)?(code|key|id)|corporate\s+id)'; Meaning = 'Victim-unique negotiation identifier present' }
    [pscustomobject]@{ Name = 'no-recovery-claim';     Pattern = '(?i)(without our (software|decryptor)|you (will|won.t) (not )?(be able to )?(recover|decrypt))'; Meaning = 'Standard Akira coercion wording' }
)

# Variant fingerprints. Confidence is scored from the indicators that hit.
$script:AkiraVariants = @(
    [pscustomobject]@{
        Variant     = 'Akira (C++ / Windows) - original line'
        FirstSeen   = '2023-03'
        Extensions  = @('.akira')
        NoteNames   = @('akira_readme.txt')
        NoteMarkers = @('akira-brand', 'akira-onion-leak-site')
        Platform    = 'Windows'
        Language    = 'C++'
        Traits      = @(
            'ChaCha-family stream cipher for file data, RSA-wrapped key blob appended to each file',
            'Shadow copies removed with an embedded PowerShell one-liner (Get-WmiObject Win32_Shadowcopy | Remove-WmiObject)',
            'Note dropped in every encrypted directory as akira_readme.txt'
        )
        Notes       = 'The long-running Windows encryptor. Still the most commonly observed on Windows endpoints and file servers.'
    }
    [pscustomobject]@{
        Variant     = 'Megazord (Rust / Windows)'
        FirstSeen   = '2023-08'
        Extensions  = @('.powerranges')
        NoteNames   = @('powerranges.txt', 'megazord_readme.txt')
        NoteMarkers = @('megazord-brand')
        Platform    = 'Windows'
        Language    = 'Rust'
        Traits      = @(
            'Rust rewrite operated alongside the C++ line for part of 2023-2024',
            'Appends .powerranges and drops powerranges.txt',
            'Different note branding, same negotiation infrastructure'
        )
        Notes       = 'If you see .powerranges the host was hit by the Megazord/Rust branch, not the C++ encryptor.'
    }
    [pscustomobject]@{
        Variant     = 'Akira_v2 / Rust line (ESXi-focused, Windows builds seen)'
        FirstSeen   = '2024-01'
        Extensions  = @('.akira')
        NoteNames   = @('akira_readme.txt')
        NoteMarkers = @('akira-brand')
        Platform    = 'ESXi / Linux (Windows builds reported)'
        Language    = 'Rust'
        Traits      = @(
            'Rust codebase reintroduced with .akira extension - extension alone cannot separate it from the C++ line',
            'ESXi builds shut down guests and encrypt VMDK/VMEM/VSWP files on datastores',
            'Separation from the C++ line requires binary analysis of the recovered encryptor'
        )
        Notes       = 'Report this as a candidate whenever .akira is present and no encryptor sample has been examined.'
    }
    [pscustomobject]@{
        Variant     = 'Akira ESXi / Linux encryptor'
        FirstSeen   = '2023-06'
        Extensions  = @('.akira')
        NoteNames   = @('akira_readme.txt')
        NoteMarkers = @('akira-brand')
        Platform    = 'VMware ESXi / Linux'
        Language    = 'C++ / Rust builds'
        Traits      = @(
            'Runs on the hypervisor, not the guest - kills VMs with esxcli then encrypts datastore files',
            'On a Windows host you would only see the result: whole VMs unusable, not per-file notes inside guests'
        )
        Notes       = 'Relevant when the Windows machine is a guest whose virtual disks were encrypted from below. Check the hypervisor separately.'
    }
)

# Host-side behaviours attributed to Akira intrusions. Used for the behaviour
# score in the variant assessment and for the "what did they do" narrative.
$script:AkiraBehaviours = @(
    [pscustomobject]@{ Id = 'vss-wipe';        Description = 'Volume Shadow Copies deleted';                      Mitre = 'T1490' }
    [pscustomobject]@{ Id = 'defender-off';    Description = 'Microsoft Defender disabled or neutered';           Mitre = 'T1562.001' }
    [pscustomobject]@{ Id = 'defender-excl';   Description = 'Broad Defender exclusions added';                   Mitre = 'T1562.001' }
    [pscustomobject]@{ Id = 'byovd';           Description = 'Vulnerable driver dropped to kill security tooling'; Mitre = 'T1562.001' }
    [pscustomobject]@{ Id = 'rmm-abuse';       Description = 'Remote-access/RMM tooling installed by the actor';  Mitre = 'T1219' }
    [pscustomobject]@{ Id = 'tunnel';          Description = 'Tunnelling utility (ngrok/cloudflared/chisel)';     Mitre = 'T1572' }
    [pscustomobject]@{ Id = 'exfil-tool';      Description = 'Bulk copy/exfil tooling (rclone, WinSCP, FileZilla, MEGA)'; Mitre = 'T1567' }
    [pscustomobject]@{ Id = 'cred-dump';       Description = 'Credential access tooling present';                 Mitre = 'T1003' }
    [pscustomobject]@{ Id = 'discovery';       Description = 'Network discovery tooling present';                 Mitre = 'T1046' }
    [pscustomobject]@{ Id = 'account-create';  Description = 'New local/domain account created by the actor';     Mitre = 'T1136' }
    [pscustomobject]@{ Id = 'log-clear';       Description = 'Event logs cleared';                                Mitre = 'T1070.001' }
    [pscustomobject]@{ Id = 'rdp-lateral';     Description = 'RDP used for lateral movement';                     Mitre = 'T1021.001' }
    [pscustomobject]@{ Id = 'wdigest';         Description = 'WDigest re-enabled to expose plaintext credentials'; Mitre = 'T1112' }
    [pscustomobject]@{ Id = 'recovery-off';    Description = 'Windows recovery environment disabled';             Mitre = 'T1490' }
)

# Tooling commonly abused in Akira intrusions. Matched against process names,
# service names, installed programs, prefetch entries and on-disk file names.
$script:ActorTooling = @(
    [pscustomobject]@{ Name = 'AnyDesk';                Category = 'Remote access';  Match = 'anydesk'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'RustDesk';               Category = 'Remote access';  Match = 'rustdesk'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'TeamViewer';             Category = 'Remote access';  Match = 'teamviewer'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'ScreenConnect/ConnectWise'; Category = 'Remote access'; Match = 'screenconnect|connectwisecontrol|connectwise\.control'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'Atera';                  Category = 'Remote access';  Match = 'ateraagent|atera'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'Splashtop';              Category = 'Remote access';  Match = 'splashtop'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'LogMeIn';                Category = 'Remote access';  Match = 'logmein'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'Radmin';                 Category = 'Remote access';  Match = 'radmin|rserver3'; Behaviour = 'rmm-abuse' }
    [pscustomobject]@{ Name = 'Ngrok';                  Category = 'Tunnelling';     Match = 'ngrok'; Behaviour = 'tunnel' }
    [pscustomobject]@{ Name = 'Cloudflared';            Category = 'Tunnelling';     Match = 'cloudflared'; Behaviour = 'tunnel' }
    [pscustomobject]@{ Name = 'Chisel';                 Category = 'Tunnelling';     Match = '\bchisel'; Behaviour = 'tunnel' }
    [pscustomobject]@{ Name = 'Tailscale/ZeroTier';     Category = 'Tunnelling';     Match = 'tailscale|zerotier'; Behaviour = 'tunnel' }
    [pscustomobject]@{ Name = 'Plink / PuTTY';          Category = 'Tunnelling';     Match = '\bplink\b|\bputty\b|\bpscp\b'; Behaviour = 'tunnel' }
    [pscustomobject]@{ Name = 'Rclone';                 Category = 'Exfiltration';   Match = 'rclone'; Behaviour = 'exfil-tool' }
    [pscustomobject]@{ Name = 'WinSCP';                 Category = 'Exfiltration';   Match = 'winscp'; Behaviour = 'exfil-tool' }
    [pscustomobject]@{ Name = 'FileZilla';              Category = 'Exfiltration';   Match = 'filezilla'; Behaviour = 'exfil-tool' }
    [pscustomobject]@{ Name = 'MEGA client/MEGAsync';   Category = 'Exfiltration';   Match = 'megasync|megacmd'; Behaviour = 'exfil-tool' }
    [pscustomobject]@{ Name = 'Advanced IP Scanner';    Category = 'Discovery';      Match = 'advanced_ip_scanner|advanced ip scanner'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'Advanced Port Scanner';  Category = 'Discovery';      Match = 'advanced_port_scanner'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'SoftPerfect NetScan';    Category = 'Discovery';      Match = 'netscan'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'Nmap / masscan';         Category = 'Discovery';      Match = '\bnmap\b|masscan'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'AdFind';                 Category = 'Discovery';      Match = 'adfind'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'SharpHound / BloodHound'; Category = 'Discovery';     Match = 'sharphound|bloodhound'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'Mimikatz';               Category = 'Credential access'; Match = 'mimikatz|mimilib|mimidrv'; Behaviour = 'cred-dump' }
    [pscustomobject]@{ Name = 'LaZagne';                Category = 'Credential access'; Match = 'lazagne'; Behaviour = 'cred-dump' }
    [pscustomobject]@{ Name = 'ProcDump (LSASS dump)';  Category = 'Credential access'; Match = 'procdump'; Behaviour = 'cred-dump' }
    [pscustomobject]@{ Name = 'Veeam credential extractor'; Category = 'Credential access'; Match = 'veeam.*(dump|extract|creds)'; Behaviour = 'cred-dump' }
    [pscustomobject]@{ Name = 'PsExec';                 Category = 'Lateral movement'; Match = 'psexec|psexesvc'; Behaviour = 'rdp-lateral' }
    [pscustomobject]@{ Name = 'PCHunter';               Category = 'Defence evasion'; Match = 'pchunter|pc hunter'; Behaviour = 'byovd' }
    [pscustomobject]@{ Name = 'GMER';                   Category = 'Defence evasion'; Match = '\bgmer'; Behaviour = 'byovd' }
    [pscustomobject]@{ Name = 'Process Hacker / System Informer'; Category = 'Defence evasion'; Match = 'processhacker|kprocesshacker|systeminformer'; Behaviour = 'byovd' }
    [pscustomobject]@{ Name = 'Defender Control / killav'; Category = 'Defence evasion'; Match = 'defendercontrol|dcontrol|killav|av_?kill'; Behaviour = 'defender-off' }
    [pscustomobject]@{ Name = 'Terminator / Zemana driver'; Category = 'Defence evasion'; Match = 'zam64|zam32|terminator'; Behaviour = 'byovd' }
    [pscustomobject]@{ Name = 'TDSSKiller';             Category = 'Defence evasion'; Match = 'tdsskiller'; Behaviour = 'byovd' }
    [pscustomobject]@{ Name = 'Everything (voidtools)'; Category = 'Discovery';      Match = 'everything\.exe|everything64'; Behaviour = 'discovery' }
    [pscustomobject]@{ Name = 'WinRAR / 7-Zip staging'; Category = 'Collection';     Match = 'winrar|\brar\.exe|7z(a|g|fm)?\.exe'; Behaviour = 'exfil-tool' }
)

# Drivers repeatedly abused to disable endpoint protection (BYOVD).
$script:VulnerableDrivers = @(
    'zam64.sys', 'zam32.sys', 'zamguard64.sys', 'aswarpot.sys', 'gmer64.sys',
    'truesight.sys', 'dbutil_2_3.sys', 'dbutildrv2.sys', 'kprocesshacker.sys',
    'procexp152.sys', 'rentdrv2.sys', 'iqvw64e.sys', 'viragt64.sys', 'mhyprot2.sys',
    'pchunter.sys', 'amsdk.sys'
)

# Registry autostart locations swept by the persistence module.
$script:RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)

$script:UserRunKeySuffixes = @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'Environment'
)

# Event IDs pulled during log triage.
$script:EventTriage = @(
    [pscustomobject]@{ Log = 'Security';    Id = 1102; Meaning = 'Security event log cleared';                 Severity = 'High' }
    [pscustomobject]@{ Log = 'System';      Id = 104;  Meaning = 'Event log cleared';                          Severity = 'High' }
    [pscustomobject]@{ Log = 'Security';    Id = 4720; Meaning = 'User account created';                       Severity = 'High' }
    [pscustomobject]@{ Log = 'Security';    Id = 4726; Meaning = 'User account deleted';                       Severity = 'Medium' }
    [pscustomobject]@{ Log = 'Security';    Id = 4732; Meaning = 'Member added to a security-enabled local group'; Severity = 'High' }
    [pscustomobject]@{ Log = 'Security';    Id = 4728; Meaning = 'Member added to a security-enabled global group'; Severity = 'High' }
    [pscustomobject]@{ Log = 'Security';    Id = 4724; Meaning = 'Password reset attempt on an account';       Severity = 'Medium' }
    [pscustomobject]@{ Log = 'Security';    Id = 4698; Meaning = 'Scheduled task created';                     Severity = 'Medium' }
    [pscustomobject]@{ Log = 'Security';    Id = 4702; Meaning = 'Scheduled task updated';                     Severity = 'Low' }
    [pscustomobject]@{ Log = 'Security';    Id = 4648; Meaning = 'Logon using explicit credentials';           Severity = 'Low' }
    [pscustomobject]@{ Log = 'System';      Id = 7045; Meaning = 'New service installed';                      Severity = 'Medium' }
    [pscustomobject]@{ Log = 'System';      Id = 7040; Meaning = 'Service start type changed';                 Severity = 'Low' }
    [pscustomobject]@{ Log = 'System';      Id = 8224; Meaning = 'VSS service shutting down (shadow copy activity)'; Severity = 'Medium' }
)

# -------------------------------------------------------------------------
#  MODULE 1 - HOST PROFILE
# -------------------------------------------------------------------------
function Invoke-HostProfile {
    $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios= Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

    $roleMap = @{
        0 = 'Standalone Workstation'; 1 = 'Member Workstation'; 2 = 'Standalone Server'
        3 = 'Member Server'; 4 = 'Backup Domain Controller'; 5 = 'Primary Domain Controller'
    }
    $role = if ($cs) { $roleMap[[int]$cs.DomainRole] } else { $null }
    if (-not $role) { $role = 'Unknown' }

    $boot   = $null
    $uptime = $null
    if ($os) {
        $boot = $os.LastBootUpTime
        try { $uptime = (New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)) } catch { }
    }

    $virt = 'Physical / unknown'
    if ($cs) {
        switch -Regex ("$($cs.Manufacturer) $($cs.Model)") {
            'VMware'            { $virt = 'VMware virtual machine' }
            'Virtual Machine|Hyper-V|Microsoft Corporation.*Virtual' { $virt = 'Hyper-V virtual machine' }
            'KVM|QEMU'          { $virt = 'KVM/QEMU virtual machine' }
            'VirtualBox'        { $virt = 'VirtualBox virtual machine' }
            'Xen'               { $virt = 'Xen virtual machine' }
        }
    }

    $disks = @()
    foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $disks += [pscustomobject]@{
            Drive      = $d.DeviceID
            Label      = $d.VolumeName
            FileSystem = $d.FileSystem
            SizeGB     = [math]::Round($d.Size / 1GB, 1)
            FreeGB     = [math]::Round($d.FreeSpace / 1GB, 1)
            FreePct    = $(if ($d.Size) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 })
        }
    }

    $nics = @()
    foreach ($n in (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
        $nics += [pscustomobject]@{
            Description = $n.Description
            MAC         = $n.MACAddress
            IPAddress   = ($n.IPAddress -join ', ')
            Gateway     = ($n.DefaultIPGateway -join ', ')
            DNS         = ($n.DNSServerSearchOrder -join ', ')
            DHCP        = $n.DHCPEnabled
            DHCPServer  = $n.DHCPServer
        }
    }

    $hyperv = $null
    try {
        $hyperv = (Get-Service -Name vmms -ErrorAction SilentlyContinue)
    } catch { }

    $profile = [ordered]@{
        Hostname          = $env:COMPUTERNAME
        FQDN              = $(try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $env:COMPUTERNAME })
        Domain            = $(if ($cs) { $cs.Domain } else { '' })
        DomainRole        = $role
        DomainJoined      = $(if ($cs) { [bool]$cs.PartOfDomain } else { $false })
        OperatingSystem   = $(if ($os) { $os.Caption } else { '' })
        OSVersion         = $(if ($os) { $os.Version } else { '' })
        OSBuild           = $(if ($os) { $os.BuildNumber } else { '' })
        InstallDate       = $(if ($os) { $os.InstallDate } else { $null })
        LastBoot          = $boot
        UptimeDays        = $(if ($uptime) { [math]::Round($uptime.TotalDays, 2) } else { $null })
        Manufacturer      = $(if ($cs) { $cs.Manufacturer } else { '' })
        Model             = $(if ($cs) { $cs.Model } else { '' })
        SerialNumber      = $(if ($bios) { $bios.SerialNumber } else { '' })
        Virtualisation    = $virt
        HyperVHost        = [bool]($hyperv -and $hyperv.Status -eq 'Running')
        LogicalProcessors = $(if ($cs) { $cs.NumberOfLogicalProcessors } else { $null })
        MemoryGB          = $(if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null })
        TimeZone          = (Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue).Caption
        LocalTime         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K')
        UtcTime           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
        RunningAsAdmin    = (Test-Administrator)
        RunningUser       = "$env:USERDOMAIN\$env:USERNAME"
        Disks             = $disks
        NetworkAdapters   = $nics
    }

    Write-Kv 'Hostname'      $profile.Hostname
    Write-Kv 'Domain / role' ("{0} / {1}" -f $profile.Domain, $profile.DomainRole)
    Write-Kv 'OS'            ("{0} (build {1})" -f $profile.OperatingSystem, $profile.OSBuild)
    Write-Kv 'Platform'      $profile.Virtualisation
    Write-Kv 'Last boot'     ("{0}  ({1} days up)" -f $profile.LastBoot, $profile.UptimeDays)
    Write-Kv 'Local time'    $profile.LocalTime
    foreach ($d in $disks) { Write-Kv ("Disk " + $d.Drive) ("{0} GB total, {1} GB free ({2}%)" -f $d.SizeGB, $d.FreeGB, $d.FreePct) }
    foreach ($n in $nics)  { Write-Kv 'IP address' ("{0}  [{1}]" -f $n.IPAddress, $n.Description) }

    if ($profile.DomainRole -match 'Domain Controller') {
        New-Finding -Severity 'Info' -Category 'Host' -Title 'Host is a domain controller' `
            -Detail 'Domain-wide credential reset (including krbtgt, twice) is required before this environment goes back online.' `
            -Recommendation 'Treat every domain credential as compromised. Reset krbtgt twice with the standard interval between resets.'
    }
    if ($profile.HyperVHost) {
        New-Finding -Severity 'Info' -Category 'Host' -Title 'Host runs the Hyper-V role' `
            -Detail 'Virtual disks on this host may have been encrypted from the hypervisor rather than inside the guests.' `
            -Recommendation 'Check VM storage paths and guest state separately from in-guest triage.'
    }

    Add-Section 'HostProfile' $profile
    Invoke-Capture -FileName 'systeminfo.txt' -Command 'systeminfo' -Description 'systeminfo output' | Out-Null
}

# -------------------------------------------------------------------------
#  MODULE 2 - SECURITY POSTURE
# -------------------------------------------------------------------------
function Invoke-SecurityPosture {
    $posture = [ordered]@{}

    # --- Microsoft Defender ---------------------------------------------
    Write-Sub 'Microsoft Defender'
    $mp = $null; $pref = $null
    try { $mp   = Get-MpComputerStatus -ErrorAction Stop } catch { }
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { }

    if ($mp) {
        $sigAge = $null
        try { $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).TotalDays } catch { }
        $defender = [ordered]@{
            AMServiceEnabled        = $mp.AMServiceEnabled
            RealTimeProtection      = $mp.RealTimeProtectionEnabled
            BehaviorMonitor         = $mp.BehaviorMonitorEnabled
            IoavProtection          = $mp.IoavProtectionEnabled
            OnAccessProtection      = $mp.OnAccessProtectionEnabled
            AntispywareEnabled      = $mp.AntispywareEnabled
            TamperProtection        = $mp.IsTamperProtected
            SignatureVersion        = $mp.AntivirusSignatureVersion
            SignatureLastUpdated    = $mp.AntivirusSignatureLastUpdated
            SignatureAgeDays        = $(if ($null -ne $sigAge) { [math]::Round($sigAge, 1) } else { $null })
            EngineVersion           = $mp.AMEngineVersion
            LastFullScan            = $mp.FullScanEndTime
            LastQuickScan           = $mp.QuickScanEndTime
        }
        $posture['Defender'] = $defender
        Write-Kv 'Real-time protection' $mp.RealTimeProtectionEnabled
        Write-Kv 'Tamper protection'    $mp.IsTamperProtected
        Write-Kv 'Signature age (days)' $defender.SignatureAgeDays

        if (-not $mp.RealTimeProtectionEnabled) {
            New-Finding -Severity 'High' -Category 'Security posture' -Title 'Defender real-time protection is disabled' `
                -Detail 'Akira intrusions routinely disable Defender before deploying the encryptor. This may be attacker action or a leftover of it.' `
                -Recommendation 'Re-enable real-time protection and tamper protection, then confirm the setting was not re-disabled by policy or a scheduled task.' `
                -Mitre @('T1562.001')
            $script:BehaviourHits['defender-off'] = $true
        }
        if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected' -and -not $mp.IsTamperProtected) {
            New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'Defender tamper protection is off' `
                -Detail 'Without tamper protection, Defender settings can be changed by any process running as SYSTEM.' `
                -Recommendation 'Turn tamper protection on before the host returns to production.'
        }
        if ($null -ne $sigAge -and $sigAge -gt 3) {
            New-Finding -Severity 'Medium' -Category 'Security posture' -Title ('Defender signatures are {0:N0} days old' -f $sigAge) `
                -Detail 'Stale signatures usually mean the update path was blocked or the machine has been offline since the incident.' `
                -Recommendation 'Update signatures before reconnecting, and confirm updates continue to apply afterwards.'
        }
    } else {
        Write-Warn 'Defender status not available (Defender may be removed, replaced by third-party AV, or the service is stopped).'
        $posture['Defender'] = @{ Available = $false }
        New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'Microsoft Defender status could not be read' `
            -Detail 'Get-MpComputerStatus failed. Defender may be uninstalled/disabled, or a third-party product has taken over.' `
            -Recommendation 'Confirm which endpoint protection product is active and that it is healthy.'
    }

    if ($pref) {
        $excl = [ordered]@{
            Paths      = @($pref.ExclusionPath)
            Extensions = @($pref.ExclusionExtension)
            Processes  = @($pref.ExclusionProcess)
            IpAddress  = @($pref.ExclusionIpAddress)
        }
        $posture['DefenderExclusions'] = $excl
        $posture['DefenderPolicy'] = [ordered]@{
            DisableRealtimeMonitoring   = $pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring   = $pref.DisableBehaviorMonitoring
            DisableScriptScanning       = $pref.DisableScriptScanning
            DisableArchiveScanning      = $pref.DisableArchiveScanning
            DisableIOAVProtection       = $pref.DisableIOAVProtection
            SubmitSamplesConsent        = $pref.SubmitSamplesConsent
            MAPSReporting               = $pref.MAPSReporting
        }
        $total = @($pref.ExclusionPath).Count + @($pref.ExclusionExtension).Count + @($pref.ExclusionProcess).Count
        Write-Kv 'Defender exclusions' $total

        $broad = @()
        foreach ($p in @($pref.ExclusionPath)) {
            if (-not $p) { continue }
            if ($p -match '^[A-Za-z]:\\?$' -or $p -match '^[A-Za-z]:\\(users|programdata|windows|temp)\\?$' -or $p -eq '*') { $broad += $p }
        }
        foreach ($e in @($pref.ExclusionExtension)) {
            if ($e -match '^\.?(exe|dll|ps1|bat|cmd|sys|scr)$') { $broad += "extension: $e" }
        }
        if ($broad.Count -gt 0) {
            New-Finding -Severity 'High' -Category 'Security posture' -Title 'Dangerously broad Defender exclusions are configured' `
                -Detail 'Whole-drive or executable-extension exclusions are a standard pre-encryption step and also a way to keep a backdoor invisible.' `
                -Evidence $broad `
                -Recommendation 'Remove these exclusions, then re-scan the excluded paths with an up-to-date engine before the host goes back into service.' `
                -Mitre @('T1562.001')
            $script:BehaviourHits['defender-excl'] = $true
        } elseif ($total -gt 0) {
            New-Finding -Severity 'Low' -Category 'Security posture' -Title ('{0} Defender exclusions configured' -f $total) `
                -Detail 'Exclusions are listed in the report. Confirm each one against the client change record - actors add exclusions that look plausible.' `
                -Evidence (@($pref.ExclusionPath) + @($pref.ExclusionProcess) | Where-Object { $_ })
        }
    }

    # --- Third-party AV registration ------------------------------------
    $avProducts = @()
    try {
        foreach ($av in (Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $avProducts += [pscustomobject]@{
                Name         = $av.displayName
                State        = ('0x{0:X}' -f $av.productState)
                PathToSignedProductExe = $av.pathToSignedProductExe
                Timestamp    = $av.timestamp
            }
        }
    } catch { }
    if ($avProducts.Count -gt 0) {
        $posture['RegisteredAntivirus'] = $avProducts
        foreach ($a in $avProducts) { Write-Kv 'Registered AV' $a.Name }
    }

    # --- EDR / security agent services ----------------------------------
    $edrPatterns = 'sentinel|crowdstrike|csagent|carbonblack|cbdefense|cylance|sophos|eset|bitdefender|trendmicro|mcafee|symantec|sepmaster|huntress|arcticwolf|s1agent|defender atp|sense'
    $edr = @()
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if ("$($svc.Name) $($svc.DisplayName)" -imatch $edrPatterns) {
            $edr += [pscustomobject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; State = $svc.State; StartMode = $svc.StartMode }
        }
    }
    $posture['SecurityAgents'] = $edr
    if ($edr.Count -gt 0) {
        foreach ($e in $edr) {
            Write-Kv 'Security agent' ("{0} [{1}/{2}]" -f $e.DisplayName, $e.State, $e.StartMode)
            if ($e.State -ne 'Running') {
                New-Finding -Severity 'High' -Category 'Security posture' -Title ("Security agent '{0}' is not running" -f $e.DisplayName) `
                    -Detail 'A stopped or disabled EDR service is one of the clearest signs of hands-on-keyboard defence evasion.' `
                    -Evidence @("Service: $($e.Name)", "State: $($e.State)", "Start mode: $($e.StartMode)") `
                    -Recommendation 'Determine when and by what the service was stopped (System log 7036/7040), then restore and verify agent health.' `
                    -Mitre @('T1562.001')
            }
        }
    } else {
        New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'No third-party EDR agent detected on this host' `
            -Detail 'Only built-in protection was found. Akira intrusions are typically caught, if at all, at the EDR layer.' `
            -Recommendation 'Deploy monitored EDR to every host before the environment returns to normal operation.'
    }

    # --- Firewall --------------------------------------------------------
    Write-Sub 'Firewall, RDP and hardening settings'
    $fw = @()
    try {
        foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
            $fw += [pscustomobject]@{ Profile = $p.Name; Enabled = $p.Enabled; InboundDefault = $p.DefaultInboundAction; LogAllowed = $p.LogAllowed }
        }
    } catch {
        $out = (netsh advfirewall show allprofiles state 2>&1 | Out-String)
        $fw += [pscustomobject]@{ Profile = 'raw'; Enabled = $out; InboundDefault = ''; LogAllowed = '' }
    }
    $posture['Firewall'] = $fw
    foreach ($p in $fw) {
        Write-Kv ("Firewall " + $p.Profile) $p.Enabled
        if ("$($p.Enabled)" -eq 'False') {
            New-Finding -Severity 'High' -Category 'Security posture' -Title ("Windows Firewall is off for the {0} profile" -f $p.Profile) `
                -Detail 'Disabled host firewall profiles are common after an intrusion and remove a barrier to re-infection and lateral movement.' `
                -Recommendation 'Re-enable the firewall on all profiles before reconnecting the host.'
        }
    }

    # --- RDP -------------------------------------------------------------
    $tsKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpDeny = Get-RegValue $tsKey 'fDenyTSConnections'
    $nla     = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $rdpPort = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
    $rdp = [ordered]@{
        RdpEnabled = ($rdpDeny -eq 0)
        NlaEnabled = ($nla -eq 1)
        Port       = $rdpPort
    }
    $posture['RDP'] = $rdp
    Write-Kv 'RDP enabled' $rdp.RdpEnabled
    Write-Kv 'RDP NLA'     $rdp.NlaEnabled
    if ($rdp.RdpEnabled -and -not $rdp.NlaEnabled) {
        New-Finding -Severity 'High' -Category 'Security posture' -Title 'RDP is enabled without Network Level Authentication' `
            -Detail 'RDP without NLA is a standing invitation for credential-based access, and RDP is Akira''s usual lateral movement path.' `
            -Recommendation 'Enable NLA, restrict RDP to jump hosts, and require MFA on any remote access path.' `
            -Mitre @('T1021.001')
    }

    # --- Credential exposure / lateral movement settings -----------------
    $wdigest   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $runAsPPL  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $tokenPol  = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
    $enableLua = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    $restrictedAdmin = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableRestrictedAdmin'

    $hard = [ordered]@{
        WDigestUseLogonCredential   = $wdigest
        LsaRunAsPPL                 = $runAsPPL
        LocalAccountTokenFilterPolicy = $tokenPol
        EnableLUA                   = $enableLua
        DisableRestrictedAdmin      = $restrictedAdmin
    }
    $posture['Hardening'] = $hard

    if ($wdigest -eq 1) {
        New-Finding -Severity 'High' -Category 'Security posture' -Title 'WDigest credential caching has been re-enabled' `
            -Detail 'UseLogonCredential=1 forces Windows to keep plaintext credentials in LSASS. This is set by attackers, never by accident.' `
            -Evidence @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1') `
            -Recommendation 'Set the value back to 0, reboot, and treat every credential used on this host as compromised.' `
            -Mitre @('T1112', 'T1003.001')
        $script:BehaviourHits['wdigest'] = $true
    }
    if ($tokenPol -eq 1) {
        New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'LocalAccountTokenFilterPolicy is enabled' `
            -Detail 'This allows local accounts full admin rights over the network - frequently set to ease lateral movement with a shared local admin password.' `
            -Recommendation 'Remove the value unless the client can document a business need.' -Mitre @('T1112')
    }
    if ($enableLua -eq 0) {
        New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'UAC is disabled (EnableLUA = 0)' `
            -Recommendation 'Re-enable UAC.' -Mitre @('T1112')
    }

    # --- PowerShell / audit logging -------------------------------------
    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $ml  = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
    $tr  = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
    $posture['Logging'] = [ordered]@{
        ScriptBlockLogging = ($sbl -eq 1)
        ModuleLogging      = ($ml -eq 1)
        Transcription      = ($tr -eq 1)
        SysmonInstalled    = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    }
    if ($sbl -ne 1) {
        New-Finding -Severity 'Low' -Category 'Visibility' -Title 'PowerShell script block logging is not enabled' `
            -Detail 'Without 4104 events, most of what an intruder did in PowerShell leaves no record.' `
            -Recommendation 'Enable script block logging fleet-wide as part of the return-to-service hardening.'
    }

    # --- Patch level ------------------------------------------------------
    $hotfix = @()
    try {
        $hotfix = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 15 |
                  ForEach-Object { [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $_.InstalledOn } }
    } catch { }
    $posture['RecentHotfixes'] = $hotfix
    if ($hotfix.Count -gt 0 -and $hotfix[0].InstalledOn) {
        $age = (New-TimeSpan -Start $hotfix[0].InstalledOn -End (Get-Date)).TotalDays
        Write-Kv 'Last patch installed' ("{0} ({1:N0} days ago)" -f $hotfix[0].InstalledOn.ToString('yyyy-MM-dd'), $age)
        if ($age -gt 60) {
            New-Finding -Severity 'Medium' -Category 'Security posture' -Title ('Host has not been patched in {0:N0} days' -f $age) `
                -Detail 'Patch gaps of this size usually extend to the perimeter devices that Akira uses for initial access.' `
                -Recommendation 'Patch the host and, more importantly, the VPN/firewall appliances before reconnecting.'
        }
    }

    # --- SMBv1 / BitLocker ------------------------------------------------
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $posture['SMB'] = [ordered]@{ SMB1Enabled = $smb.EnableSMB1Protocol; SMB2Enabled = $smb.EnableSMB2Protocol; SigningRequired = $smb.RequireSecuritySignature }
        if ($smb.EnableSMB1Protocol) {
            New-Finding -Severity 'Medium' -Category 'Security posture' -Title 'SMBv1 is enabled on this host' `
                -Recommendation 'Disable SMBv1 before returning to production.'
        }
    } catch { }
    try {
        $bl = Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Mount = $_.MountPoint; Protection = $_.ProtectionStatus; Status = $_.VolumeStatus }
        }
        $posture['BitLocker'] = @($bl)
    } catch { }

    # --- Pending reboot ---------------------------------------------------
    $pending = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
    $posture['PendingReboot'] = $pending

    Add-Section 'SecurityPosture' $posture
    Invoke-Capture -FileName 'auditpol.txt' -Command 'auditpol /get /category:*' -Description 'Audit policy configuration' | Out-Null
    Invoke-Capture -FileName 'firewall-rules.txt' -Command 'netsh advfirewall firewall show rule name=all' -Description 'All firewall rules' | Out-Null
}

# -------------------------------------------------------------------------
#  MODULE 3 - ACCOUNTS AND SESSIONS
# -------------------------------------------------------------------------
function Invoke-AccountSurvey {
    $users = @()
    $useCim = $true
    try { $null = Get-Command Get-LocalUser -ErrorAction Stop; $useCim = $false } catch { }

    if (-not $useCim) {
        foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
            $users += [pscustomobject]@{
                Name            = $u.Name
                Enabled         = $u.Enabled
                SID             = $u.SID.Value
                Description     = $u.Description
                LastLogon       = $u.LastLogon
                PasswordLastSet = $u.PasswordLastSet
                PasswordExpires = $u.PasswordExpires
                PasswordRequired= $u.PasswordRequired
                Source          = 'Get-LocalUser'
            }
        }
    } else {
        foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
            $users += [pscustomobject]@{
                Name            = $u.Name
                Enabled         = (-not $u.Disabled)
                SID             = $u.SID
                Description     = $u.Description
                LastLogon       = $null
                PasswordLastSet = $null
                PasswordExpires = $null
                PasswordRequired= $u.PasswordRequired
                Source          = 'Win32_UserAccount'
            }
        }
    }

    # Local administrators
    $admins = @()
    try {
        foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)) {
            $admins += [pscustomobject]@{ Member = $m.Name; Class = $m.ObjectClass; Source = $m.PrincipalSource }
        }
    } catch {
        $raw = (net localgroup administrators 2>&1 | Out-String)
        foreach ($line in ($raw -split "`r?`n")) {
            $t = $line.Trim()
            if ($t -and $t -notmatch '^(Alias name|Comment|Members|-+|The command completed)' ) {
                $admins += [pscustomobject]@{ Member = $t; Class = 'unknown'; Source = 'net localgroup' }
            }
        }
    }

    $rdpUsers = @()
    try {
        foreach ($m in (Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop)) {
            $rdpUsers += [pscustomobject]@{ Member = $m.Name; Class = $m.ObjectClass; Source = $m.PrincipalSource }
        }
    } catch { }

    Write-Kv 'Local accounts'      $users.Count
    Write-Kv 'Local administrators' $admins.Count
    foreach ($a in $admins) { Write-Note ("admin: " + $a.Member) }

    foreach ($u in $users) {
        # Accounts created or repasswarded inside the incident window
        if ($u.PasswordLastSet -and (Test-InIncidentWindow $u.PasswordLastSet)) {
            New-Finding -Severity 'High' -Category 'Accounts' -Title ("Local account '{0}' had its password set during the incident window" -f $u.Name) `
                -Detail 'Either the actor created/reset this account, or the account was legitimately reset during response. Confirm against the client change log.' `
                -Evidence @("PasswordLastSet: $($u.PasswordLastSet)", "Enabled: $($u.Enabled)", "SID: $($u.SID)") `
                -Recommendation 'Verify with the client. If unexplained, disable the account and treat it as attacker-controlled.' `
                -Mitre @('T1136.001')
            $script:BehaviourHits['account-create'] = $true
        }
        if ($u.Name -match '\$$' -and $u.Enabled) {
            New-Finding -Severity 'High' -Category 'Accounts' -Title ("Hidden-style account name detected: '{0}'" -f $u.Name) `
                -Detail 'A trailing $ hides the account from some enumeration tools - a known persistence trick.' `
                -Recommendation 'Confirm the account is legitimate; disable and investigate if not.' -Mitre @('T1564')
        }
        if ($u.Enabled -and $u.PasswordRequired -eq $false) {
            New-Finding -Severity 'High' -Category 'Accounts' -Title ("Enabled account '{0}' does not require a password" -f $u.Name) `
                -Recommendation 'Require a password or disable the account.'
        }
    }

    $guest = $users | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled }
    if ($guest) {
        New-Finding -Severity 'Medium' -Category 'Accounts' -Title 'The Guest account is enabled' `
            -Recommendation 'Disable the Guest account.'
    }

    # Sessions and profiles
    $sessions = @()
    try {
        $q = (quser 2>&1 | Out-String) -split "`r?`n" | Where-Object { $_.Trim() }
        $sessions = $q
    } catch { }

    $profiles = @()
    foreach ($p in (Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue)) {
        if ($p.Special) { continue }
        $profiles += [pscustomobject]@{
            Path        = $p.LocalPath
            SID         = $p.SID
            LastUseTime = $p.LastUseTime
            Loaded      = $p.Loaded
            CreatedInIncident = (Test-InIncidentWindow $p.LastUseTime)
        }
    }

    # Domain view when the module is present (DC or RSAT installed)
    $domainAdmins = @()
    $krbtgt = $null
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.SamAccountName; Class = $_.objectClass } }
        $k = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet -ErrorAction Stop
        $krbtgt = $k.PasswordLastSet
        Write-Kv 'krbtgt password set' $krbtgt
        if ($krbtgt -and -not (Test-InIncidentWindow $krbtgt)) {
            New-Finding -Severity 'High' -Category 'Accounts' -Title 'krbtgt password has not been reset since the incident' `
                -Detail ("krbtgt PasswordLastSet = {0}. Golden Ticket persistence survives everything else until krbtgt is reset twice." -f $krbtgt) `
                -Recommendation 'Reset krbtgt twice, allowing full replication between resets, before the domain is trusted again.' `
                -Mitre @('T1558.001')
        }
    } catch { }

    $data = [ordered]@{
        LocalUsers          = $users
        LocalAdministrators = $admins
        RemoteDesktopUsers  = $rdpUsers
        UserProfiles        = $profiles
        ActiveSessions      = $sessions
        DomainAdmins        = $domainAdmins
        KrbtgtPasswordLastSet = $krbtgt
    }
    Add-Section 'Accounts' $data
    Invoke-Capture -FileName 'net-accounts.txt' -Command 'net accounts' -Description 'Password policy' | Out-Null
    Invoke-Capture -FileName 'local-admins.txt' -Command 'net localgroup administrators' -Description 'Local administrators group' | Out-Null
}

# -------------------------------------------------------------------------
#  MODULE 4 - ENCRYPTION SURVEY
# -------------------------------------------------------------------------
$script:CommonDataExtensions = @(
    '.doc', '.docx', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pdf', '.txt', '.rtf',
    '.csv', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.psd', '.dwg',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.sql', '.bak', '.bkf', '.mdf', '.ldf', '.ndf',
    '.vhd', '.vhdx', '.vmdk', '.vmx', '.vmem', '.vswp', '.pst', '.ost', '.eml', '.msg',
    '.dbf', '.accdb', '.mdb', '.xml', '.json', '.config', '.ini', '.log', '.cs', '.js'
)

function Get-ChunkBytes {
    param([string]$Path, [long]$Offset, [int]$Length)
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                                              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    } catch { return $null }
    try {
        if ($Offset -ge $fs.Length) { return $null }
        [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $take = [int][math]::Min([long]$Length, $fs.Length - $Offset)
        $buf  = New-Object byte[] $take
        $read = $fs.Read($buf, 0, $take)
        if ($read -lt $take) { $buf = $buf[0..([math]::Max(0, $read - 1))] }
        return $buf
    } catch { return $null }
    finally { $fs.Dispose() }
}

function Get-ByteEntropy {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return $null }
    $hist = New-Object 'int[]' 256
    foreach ($b in $Bytes) { $hist[$b]++ }
    $len = $Bytes.Length
    $e   = 0.0
    foreach ($c in $hist) {
        if ($c -gt 0) {
            $p = $c / $len
            $e -= $p * [math]::Log($p, 2)
        }
    }
    return [math]::Round($e, 3)
}

function Format-HexDump {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Bytes.Length; $i += 16) {
        $take  = [math]::Min(16, $Bytes.Length - $i)
        $slice = $Bytes[$i..($i + $take - 1)]
        $hex   = ($slice | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
        $asc   = -join ($slice | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
        [void]$sb.AppendLine(('{0:X8}  {1,-47}  {2}' -f $i, $hex, $asc))
    }
    return $sb.ToString()
}

function Get-ScanRoots {
    if ($ScanPath -and $ScanPath.Count -gt 0) { return @($ScanPath) }
    $fixed = @()
    foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $fixed += ($d.DeviceID + '\')
    }
    if ($fixed.Count -eq 0) { $fixed = @('C:\') }

    switch ($Scope) {
        'Quick' {
            $roots = @("$env:SystemDrive\Users", "$env:SystemDrive\ProgramData", "$env:PUBLIC")
            foreach ($f in $fixed) { if ($f -ne "$env:SystemDrive\") { $roots += $f } }
            return ($roots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
        }
        'Deep' { return $fixed }
        default {
            $roots = @("$env:SystemDrive\Users", "$env:SystemDrive\ProgramData", "$env:SystemDrive\inetpub",
                       "$env:SystemDrive\Shares", "$env:SystemDrive\Data", "$env:SystemDrive\Backup")
            foreach ($f in $fixed) { if ($f -ne "$env:SystemDrive\") { $roots += $f } }
            $roots += "$env:SystemDrive\"    # top of C: is walked, WinSxS-style noise is excluded by the walker
            return ($roots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
        }
    }
}

function Invoke-EncryptionSurvey {
    $script:EncCount        = 0
    $script:EncBytes        = [long]0
    $script:EncFirst        = $null
    $script:EncLast         = $null
    $script:EncExtTally     = @{}
    $script:EncDirTally     = @{}
    $script:EncSamplePaths  = New-Object System.Collections.ArrayList
    $script:NotePaths       = New-Object System.Collections.ArrayList
    $script:NoteCount       = 0
    $script:SuspectExtTally = @{}
    $script:InnerExtTally   = @{}

    $roots = Get-ScanRoots
    Write-Note ("Scan roots: " + ($roots -join ', '))
    Write-Note ("Time budget: $ScanTimeoutMinutes minute(s). The scan stops cleanly when it is spent.")

    $onFile = {
        param($p)
        $name  = [System.IO.Path]::GetFileName($p)
        $lname = $name.ToLower()
        $ext   = [System.IO.Path]::GetExtension($lname)

        if ($ext -and ($script:KnownEncryptedExtensions -contains $ext)) {
            $script:EncCount++
            if ($script:EncExtTally.ContainsKey($ext)) { $script:EncExtTally[$ext]++ } else { $script:EncExtTally[$ext] = 1 }
            $dir = [System.IO.Path]::GetDirectoryName($p)
            if ($script:EncDirTally.ContainsKey($dir)) { $script:EncDirTally[$dir]++ } else { $script:EncDirTally[$dir] = 1 }
            $inner = [System.IO.Path]::GetExtension([System.IO.Path]::GetFileNameWithoutExtension($lname))
            if ($inner) {
                if ($script:InnerExtTally.ContainsKey($inner)) { $script:InnerExtTally[$inner]++ } else { $script:InnerExtTally[$inner] = 1 }
            }
            try {
                $fi = New-Object System.IO.FileInfo($p)
                $script:EncBytes += $fi.Length
                $w = $fi.LastWriteTimeUtc
                if (-not $script:EncFirst -or $w -lt $script:EncFirst) { $script:EncFirst = $w }
                if (-not $script:EncLast  -or $w -gt $script:EncLast)  { $script:EncLast  = $w }
            } catch { }
            if ($script:EncSamplePaths.Count -lt ($MaxEncryptedSamples * 4)) { [void]$script:EncSamplePaths.Add($p) }
            return
        }

        # unknown appended extension: something.docx.<junk>
        if ($ext -and $ext.Length -ge 3 -and $ext.Length -le 12 -and ($script:CommonDataExtensions -notcontains $ext)) {
            $inner = [System.IO.Path]::GetExtension([System.IO.Path]::GetFileNameWithoutExtension($lname))
            if ($inner -and ($script:CommonDataExtensions -contains $inner)) {
                if ($script:SuspectExtTally.ContainsKey($ext)) { $script:SuspectExtTally[$ext]++ } else { $script:SuspectExtTally[$ext] = 1 }
            }
        }

        if (($script:NoteFileNames -contains $lname) -or ($lname -match $script:NoteNameRegex)) {
            $script:NoteCount++
            if ($script:NotePaths.Count -lt 2000) { [void]$script:NotePaths.Add($p) }
        }
    }

    $walk = Invoke-FileWalk -Roots $roots -OnFile $onFile -TimeoutSeconds ($ScanTimeoutMinutes * 60)
    Write-Kv 'Files examined'   ('{0:N0}' -f $walk.FilesSeen)
    Write-Kv 'Folders examined' ('{0:N0}' -f $walk.FoldersSeen)
    Write-Kv 'Scan time'        ('{0} seconds' -f $walk.Seconds)
    if ($walk.Truncated) {
        Write-Warn ("Scan stopped early ({0}). Counts below are a floor, not a total." -f $walk.TruncateReason)
    }

    Write-Kv 'Encrypted files found' ('{0:N0}' -f $script:EncCount)
    Write-Kv 'Ransom notes found'    ('{0:N0}' -f $script:NoteCount)

    # ---- incident window ------------------------------------------------
    $windowSource = 'not established'
    if ($IncidentStart) {
        try {
            $script:IncidentStartTime = [datetime]::Parse($IncidentStart)
            $windowSource = 'supplied by operator'
        } catch { Write-Warn "Could not parse -IncidentStart '$IncidentStart'." }
    }
    if (-not $script:IncidentStartTime) {
        if ($script:EncFirst) {
            $script:IncidentStartTime = $script:EncFirst.ToLocalTime().AddDays(-14)
            $windowSource = 'estimated: 14 days before the earliest encrypted file (assumed dwell time)'
        } else {
            $script:IncidentStartTime = (Get-Date).AddDays(-$DaysBack)
            $windowSource = "fallback: $DaysBack days before this run"
        }
    }
    Write-Kv 'Incident window start' ("{0}  ({1})" -f $script:IncidentStartTime, $windowSource)

    # ---- ransom notes ---------------------------------------------------
    $noteRecords = @()
    $noteGroups  = @{}
    $collected   = 0
    foreach ($np in $script:NotePaths) {
        $text = ''
        try { $text = [System.IO.File]::ReadAllText($np) } catch { }
        if ($text.Length -gt 20000) { $text = $text.Substring(0, 20000) }
        $hash = Get-Sha256 $np
        $fi   = $null
        try { $fi = New-Object System.IO.FileInfo($np) } catch { }

        $markers = @()
        foreach ($m in $script:NoteMarkers) {
            if ($text -match $m.Pattern) { $markers += $m.Name }
        }
        $onions = @()
        foreach ($mm in [regex]::Matches($text, '[a-z2-7]{16,56}\.onion')) { $onions += $mm.Value }
        $onions = $onions | Select-Object -Unique

        $rec = [pscustomobject]@{
            Path        = $np
            FileName    = [System.IO.Path]::GetFileName($np)
            SHA256      = $hash
            SizeBytes   = $(if ($fi) { $fi.Length } else { $null })
            LastWrite   = $(if ($fi) { $fi.LastWriteTime } else { $null })
            Created     = $(if ($fi) { $fi.CreationTime } else { $null })
            Markers     = $markers
            OnionAddresses = @($onions)
            Preview     = ($text.Substring(0, [math]::Min(1200, $text.Length)))
        }
        $noteRecords += $rec

        $key = "$hash"
        if (-not $noteGroups.ContainsKey($key)) {
            $noteGroups[$key] = [pscustomobject]@{
                SHA256 = $hash; FileName = $rec.FileName; Count = 0
                Markers = $markers; OnionAddresses = @($onions)
                FirstSeenPath = $np; EarliestWrite = $rec.LastWrite; Text = $text
            }
        }
        $noteGroups[$key].Count++
        if ($rec.LastWrite -and $noteGroups[$key].EarliestWrite -and $rec.LastWrite -lt $noteGroups[$key].EarliestWrite) {
            $noteGroups[$key].EarliestWrite = $rec.LastWrite
        }

        if ($collected -lt $MaxNoteSamples) {
            $safe = ('note_{0:D3}_{1}' -f ($collected + 1), (ConvertTo-SafeName ([System.IO.Path]::GetFileName($np))))
            Copy-Artifact -Path $np -SubFolder 'notes' -NewName $safe -Category 'ransom-note' -Description "Ransom note from $np" | Out-Null
            $collected++
        }
    }

    if ($noteGroups.Count -gt 0) {
        Write-Sub 'Ransom notes'
        foreach ($g in ($noteGroups.Values | Sort-Object Count -Descending)) {
            Write-Kv $g.FileName ("{0} copies, SHA-256 {1}" -f $g.Count, $g.SHA256)
            if ($g.OnionAddresses.Count) { Write-Kv '  onion addresses' ($g.OnionAddresses -join ', ') }
        }
        $ev = @()
        foreach ($g in $noteGroups.Values) {
            $ev += ("{0}  x{1}  SHA-256 {2}" -f $g.FileName, $g.Count, $g.SHA256)
            if ($g.OnionAddresses.Count) { $ev += ("  onion: " + ($g.OnionAddresses -join ', ')) }
            if ($g.Markers.Count)        { $ev += ("  markers: " + ($g.Markers -join ', ')) }
        }
        New-Finding -Severity 'Critical' -Category 'Encryption' -Title ("{0:N0} ransom note file(s) present on this host" -f $script:NoteCount) `
            -Detail 'Notes are dropped per directory by the encryptor. Their names and contents are the primary variant fingerprint.' `
            -Evidence $ev `
            -Recommendation 'Preserve the notes (collected in artifacts\notes) and pass one to the negotiator/insurer intact - do not edit them.' `
            -Mitre @('T1486')
    }

    # ---- encrypted file samples -----------------------------------------
    $samples = @()
    $take = @($script:EncSamplePaths) | Select-Object -First $MaxEncryptedSamples
    foreach ($sp in $take) {
        $fi = $null
        try { $fi = New-Object System.IO.FileInfo($sp) } catch { continue }
        $head = Get-ChunkBytes -Path $sp -Offset 0 -Length 4096
        $tail = $null
        $mid  = $null
        if ($fi.Length -gt 8192) {
            $tail = Get-ChunkBytes -Path $sp -Offset ([math]::Max(0, $fi.Length - 4096)) -Length 4096
            $mid  = Get-ChunkBytes -Path $sp -Offset ([long]($fi.Length / 2)) -Length 4096
        }
        $samples += [pscustomobject]@{
            Path          = $sp
            OriginalName  = [System.IO.Path]::GetFileNameWithoutExtension($sp)
            SizeBytes     = $fi.Length
            LastWrite     = $fi.LastWriteTime
            Created       = $fi.CreationTime
            HeadEntropy   = (Get-ByteEntropy $head)
            MiddleEntropy = (Get-ByteEntropy $mid)
            TailEntropy   = (Get-ByteEntropy $tail)
            HeadHex       = (Format-HexDump ($(if ($head) { $head[0..([math]::Min(63, $head.Length - 1))] } else { $null })))
            TailHex       = (Format-HexDump ($(if ($tail) { $tail[($(if ($tail.Length -gt 64) { $tail.Length - 64 } else { 0 }))..($tail.Length - 1)] } else { $null })))
        }
    }

    if ($samples.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Encrypted file structure samples - $script:ToolName $script:ToolVersion")
        [void]$sb.AppendLine("Only the first and last 64 bytes of each file are recorded. No client data is copied.")
        [void]$sb.AppendLine('')
        foreach ($s in $samples) {
            [void]$sb.AppendLine(('-' * 70))
            [void]$sb.AppendLine("Path        : $($s.Path)")
            [void]$sb.AppendLine("Size        : $($s.SizeBytes) bytes")
            [void]$sb.AppendLine("Last write  : $($s.LastWrite)")
            [void]$sb.AppendLine("Entropy     : head $($s.HeadEntropy) / middle $($s.MiddleEntropy) / tail $($s.TailEntropy)  (8.0 = fully random)")
            [void]$sb.AppendLine("Header (first 64 bytes):")
            [void]$sb.AppendLine($s.HeadHex)
            [void]$sb.AppendLine("Footer (last 64 bytes):")
            [void]$sb.AppendLine($s.TailHex)
        }
        Save-Artifact -Content $sb.ToString() -SubFolder 'samples' -FileName 'encrypted-file-structure.txt' `
                      -Category 'encrypted-sample' -Description 'Header/footer and entropy of sampled encrypted files' | Out-Null

        $partial = @($samples | Where-Object { $_.MiddleEntropy -ne $null -and $_.HeadEntropy -ne $null -and $_.MiddleEntropy -lt 6.5 -and $_.HeadEntropy -gt 7.5 })
        if ($partial.Count -gt 0) {
            New-Finding -Severity 'Info' -Category 'Encryption' -Title 'Sampled files show partial (spot) encryption' `
                -Detail 'High entropy at the start and end with lower-entropy regions in between is the signature of a speed-optimised encryptor that only encrypts portions of large files. Akira builds do this by file size.' `
                -Evidence (@($partial | ForEach-Object { "{0}: head {1} / mid {2} / tail {3}" -f $_.Path, $_.HeadEntropy, $_.MiddleEntropy, $_.TailEntropy })) `
                -Recommendation 'Note it for the decryption/negotiation track: partially encrypted large files sometimes yield partial recovery of embedded data.'
        }
    }

    # ---- unknown appended extensions ------------------------------------
    $suspect = @()
    foreach ($k in $script:SuspectExtTally.Keys) {
        if ($script:SuspectExtTally[$k] -ge 5) {
            $suspect += [pscustomobject]@{ Extension = $k; FileCount = $script:SuspectExtTally[$k] }
        }
    }
    $suspect = @($suspect | Sort-Object FileCount -Descending | Select-Object -First 10)
    if ($suspect.Count -gt 0) {
        New-Finding -Severity 'Medium' -Category 'Encryption' -Title 'Unrecognised appended file extensions found' `
            -Detail 'These extensions sit after a normal document extension on many files, which is how a ransomware rename looks. They are not in the Akira extension list, so they may be a new variant, a second actor, or a benign application.' `
            -Evidence (@($suspect | ForEach-Object { "{0}  ({1:N0} files)" -f $_.Extension, $_.FileCount })) `
            -Recommendation 'Sample one of these files and compare with the known-good original before assuming it is ransomware.'
    }

    # ---- top-level findings ---------------------------------------------
    $topDirs = @()
    foreach ($k in ($script:EncDirTally.Keys | Sort-Object { -$script:EncDirTally[$_] } | Select-Object -First 20)) {
        $topDirs += [pscustomobject]@{ Directory = $k; EncryptedFiles = $script:EncDirTally[$k] }
    }
    $extBreak = @()
    foreach ($k in $script:EncExtTally.Keys) { $extBreak += [pscustomobject]@{ Extension = $k; FileCount = $script:EncExtTally[$k] } }
    $innerBreak = @()
    foreach ($k in ($script:InnerExtTally.Keys | Sort-Object { -$script:InnerExtTally[$_] } | Select-Object -First 15)) {
        $innerBreak += [pscustomobject]@{ OriginalExtension = $k; FileCount = $script:InnerExtTally[$k] }
    }

    if ($script:EncCount -gt 0) {
        $window = ''
        if ($script:EncFirst -and $script:EncLast) {
            $span = New-TimeSpan -Start $script:EncFirst -End $script:EncLast
            $window = "{0} to {1} UTC ({2:N1} hours)" -f $script:EncFirst, $script:EncLast, $span.TotalHours
        }
        New-Finding -Severity 'Critical' -Category 'Encryption' -Title ("{0:N0} encrypted files on this host ({1})" -f $script:EncCount, (($extBreak | ForEach-Object { $_.Extension }) -join ', ')) `
            -Detail ("Approximately {0:N1} GB of encrypted data. Encryption window: {1}" -f ($script:EncBytes / 1GB), $window) `
            -Evidence (@($extBreak | ForEach-Object { "{0}: {1:N0} files" -f $_.Extension, $_.FileCount }) + @("Encryption window: $window")) `
            -Recommendation 'Do not delete encrypted files until the recovery path (backup restore vs decryptor) is agreed with the client and insurer.' `
            -Mitre @('T1486')

        if ($window) {
            New-Finding -Severity 'Info' -Category 'Encryption' -Title ('Encryption ran between ' + $window) `
                -Detail 'This is derived from file last-write times, which the encryptor sets as it rewrites each file. Use it to anchor the event log review.'
        }
    } else {
        New-Finding -Severity 'Info' -Category 'Encryption' -Title 'No encrypted files found in the scanned scope' `
            -Detail ("Scanned: " + ($roots -join ', ')) `
            -Recommendation 'If this host was expected to be encrypted, widen the scan with -ScanPath or -Scope Deep before concluding it was untouched.'
    }

    $data = [ordered]@{
        ScanRoots            = @($roots)
        ScanSummary          = $walk
        EncryptedFileCount   = $script:EncCount
        EncryptedBytes       = $script:EncBytes
        EncryptedGB          = [math]::Round($script:EncBytes / 1GB, 2)
        EarliestEncryptedUtc = $script:EncFirst
        LatestEncryptedUtc   = $script:EncLast
        IncidentWindowStart  = $script:IncidentStartTime
        IncidentWindowSource = $windowSource
        ExtensionBreakdown   = $extBreak
        OriginalFileTypes    = $innerBreak
        TopEncryptedFolders  = $topDirs
        RansomNoteCount      = $script:NoteCount
        RansomNoteVariants   = @($noteGroups.Values | ForEach-Object {
                                  [pscustomobject]@{ FileName = $_.FileName; SHA256 = $_.SHA256; Copies = $_.Count
                                                     Markers = $_.Markers; OnionAddresses = $_.OnionAddresses
                                                     EarliestWrite = $_.EarliestWrite; Text = $_.Text } })
        RansomNoteSamples    = @($noteRecords | Select-Object -First 25)
        EncryptedSamples     = $samples
        UnknownAppendedExtensions = $suspect
    }
    Add-Section 'Encryption' $data
}

# -------------------------------------------------------------------------
#  MODULE 5 - VARIANT ASSESSMENT
# -------------------------------------------------------------------------
function Invoke-VariantAssessment {
    $enc = $script:Sections['Encryption']
    if (-not $enc) {
        Write-Warn 'Encryption survey did not run - variant assessment skipped.'
        return
    }

    $seenExt     = @($enc.ExtensionBreakdown | ForEach-Object { $_.Extension })
    $seenNotes   = @($enc.RansomNoteVariants | ForEach-Object { $_.FileName.ToLower() })
    $seenMarkers = @()
    foreach ($v in $enc.RansomNoteVariants) { $seenMarkers += @($v.Markers) }
    $seenMarkers = @($seenMarkers | Select-Object -Unique)
    $innerTypes  = @($enc.OriginalFileTypes | ForEach-Object { $_.OriginalExtension })

    $results = @()
    foreach ($variant in $script:AkiraVariants) {
        $score  = 0
        $why    = @()
        $against= @()

        foreach ($e in $variant.Extensions) {
            if ($seenExt -contains $e) { $score += 40; $why += "Extension $e observed on this host" }
        }
        foreach ($n in $variant.NoteNames) {
            if ($seenNotes -contains $n.ToLower()) { $score += 35; $why += "Ransom note '$n' present" }
        }
        foreach ($m in $variant.NoteMarkers) {
            if ($seenMarkers -contains $m) {
                $meaning = ($script:NoteMarkers | Where-Object { $_.Name -eq $m } | Select-Object -First 1).Meaning
                $score += 10; $why += "Note marker '$m' matched ($meaning)"
            }
        }

        # Extension present but belonging to a different branch counts against.
        foreach ($e in $script:KnownEncryptedExtensions) {
            if (($seenExt -contains $e) -and ($variant.Extensions -notcontains $e)) {
                $score -= 25; $against += "Extension $e is not used by this variant"
            }
        }

        # Hypervisor-level encryption hints
        if ($variant.Platform -match 'ESXi|Linux') {
            $vmHits = @($innerTypes | Where-Object { $_ -in @('.vmdk', '.vmx', '.vmem', '.vswp', '.nvram') })
            if ($vmHits.Count -gt 0) { $score += 25; $why += ("Virtual machine files were encrypted (" + ($vmHits -join ', ') + ") - consistent with a hypervisor-level encryptor") }
            else { $score -= 15; $against += 'No encrypted virtual machine disk files were seen on this host' }
        }

        if ($score -lt 0) { $score = 0 }
        $confidence = [math]::Min(95, $score)   # never claim certainty without sample analysis

        $results += [pscustomobject]@{
            Variant     = $variant.Variant
            Confidence  = $confidence
            FirstSeen   = $variant.FirstSeen
            Platform    = $variant.Platform
            Language    = $variant.Language
            Supporting  = $why
            Contradicting = $against
            Traits      = $variant.Traits
            Notes       = $variant.Notes
        }
    }

    $ranked = @($results | Sort-Object Confidence -Descending)
    $top    = $ranked | Select-Object -First 1

    Write-Sub 'Variant ranking (heuristic - based on notes, extensions and host behaviour)'
    foreach ($r in $ranked) {
        if ($r.Confidence -le 0) { continue }
        Write-Kv $r.Variant ("confidence {0}%" -f $r.Confidence)
        foreach ($w in $r.Supporting) { Write-Host "          + $w" -ForegroundColor DarkGray }
    }

    $behaviourList = @()
    foreach ($b in $script:AkiraBehaviours) {
        if ($script:BehaviourHits[$b.Id]) { $behaviourList += ("{0} ({1})" -f $b.Description, $b.Mitre) }
    }

    if ($top -and $top.Confidence -ge 40) {
        New-Finding -Severity 'High' -Category 'Attribution' -Title ("Most likely variant: {0} ({1}% confidence)" -f $top.Variant, $top.Confidence) `
            -Detail ($top.Notes) `
            -Evidence (@($top.Supporting) + @('') + @('Contradicting indicators:') + @($top.Contradicting)) `
            -Recommendation 'Confirm by submitting a recovered encryptor binary for analysis. Extension and note names alone cannot separate the C++ and Rust code lines.'
    } elseif ($script:NoteCount -gt 0 -or $script:EncCount -gt 0) {
        New-Finding -Severity 'Medium' -Category 'Attribution' -Title 'Ransomware activity present but the family could not be confidently matched' `
            -Detail 'Encryption artefacts were found that do not line up with the Akira fingerprints in this tool.' `
            -Recommendation 'Collect a note and a sample encrypted file and submit them for identification before assuming this is Akira.'
    } else {
        Write-Note 'No encryption artefacts on this host - nothing to attribute.'
    }

    Add-Section 'VariantAssessment' ([ordered]@{
        Ranked            = $ranked
        ObservedExtensions= $seenExt
        ObservedNoteNames = $seenNotes
        ObservedMarkers   = $seenMarkers
        ObservedBehaviours= $behaviourList
        Caveat            = 'Classification is heuristic. Extension and note names distinguish the Megazord branch reliably, but the C++ and Rust Akira lines both use .akira / akira_readme.txt and can only be separated by analysing the encryptor binary.'
    })
}

# -------------------------------------------------------------------------
#  MODULE 6 - PERSISTENCE SWEEP
# -------------------------------------------------------------------------
function Add-Autostart {
    <# Records one autostart mechanism and grades it. #>
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Context = '',
        [string]$MitreId = 'T1547'
    )

    $exe  = Resolve-ImagePath $Command
    $sig  = Get-SignatureState $exe
    $susPath = Test-SuspiciousPath $exe
    $susCmd  = Test-SuspiciousCommand $Command

    $created = $null
    $modified = $null
    $inWindow = $false
    if ($exe -and (Test-Path -LiteralPath $exe.Trim('"'))) {
        try {
            $fi = Get-Item -LiteralPath $exe.Trim('"') -Force -ErrorAction Stop
            $created  = $fi.CreationTime
            $modified = $fi.LastWriteTime
            $inWindow = (Test-InIncidentWindow $created) -or (Test-InIncidentWindow $modified)
        } catch { }
    }

    $score = 0
    $why   = @()
    if ($susPath)  { $score += 3; $why += 'binary sits in a directory autostart entries rarely use' }
    if ($susCmd)   { $score += 3; $why += 'command line uses a pattern associated with malicious execution' }
    if ($inWindow) { $score += 3; $why += 'binary was created or modified inside the incident window' }
    if ($sig -notlike 'Valid*' -and $sig -ne 'FileMissing') { $score += 2; $why += "binary signature state is '$sig'" }
    if ($sig -eq 'FileMissing') { $score += 1; $why += 'the referenced file no longer exists (stale or cleaned up)' }

    $severity = 'Info'
    if ($score -ge 6) { $severity = 'High' }
    elseif ($score -ge 3) { $severity = 'Medium' }
    elseif ($score -ge 1) { $severity = 'Low' }

    $entry = [pscustomobject]@{
        Type        = $Type
        Location    = $Location
        Name        = $Name
        Command     = $Command
        Executable  = $exe
        Signature   = $sig
        FileCreated = $created
        FileModified= $modified
        InIncidentWindow = $inWindow
        Suspicion   = $severity
        Reasons     = $why
        Context     = $Context
    }
    [void]$script:Autostarts.Add($entry)

    if ($severity -in @('High', 'Medium')) {
        New-Finding -Severity $severity -Category 'Persistence' -Title ("{0}: {1}" -f $Type, $(if ($Name) { $Name } else { $Command })) `
            -Detail (($why -join '; ')) `
            -Evidence @("Location: $Location", "Command: $Command", "Executable: $exe", "Signature: $sig",
                        "File created: $created", "File modified: $modified", "Context: $Context") `
            -Recommendation 'Verify against the client software inventory. If unexplained, capture the binary, then remove the autostart entry and the file as part of remediation.' `
            -Mitre @($MitreId)
    }
    return $entry
}

function Invoke-PersistenceSweep {
    $script:Autostarts = New-Object System.Collections.ArrayList

    # --- 1. Run / RunOnce style keys (machine) ---------------------------
    Write-Sub 'Registry autostart keys'
    foreach ($path in $script:RunKeyPaths) {
        foreach ($v in (Get-RegValues $path)) {
            if ($path -like '*Winlogon*' -and $v.Name -notin @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'GinaDLL')) { continue }
            if ($path -like '*Session Manager*' -and $v.Name -notin @('BootExecute', 'SetupExecute', 'AppCertDlls')) { continue }
            if ($path -like '*CurrentVersion\Windows*' -and $v.Name -notin @('Run', 'Load', 'AppInit_DLLs', 'IconServiceLib')) { continue }
            if ([string]::IsNullOrWhiteSpace($v.Value)) { continue }
            if ($path -like '*Winlogon*' -and $v.Name -eq 'Shell' -and $v.Value -eq 'explorer.exe') { continue }
            if ($path -like '*Winlogon*' -and $v.Name -eq 'Userinit' -and $v.Value -match '^C:\\Windows\\system32\\userinit\.exe,?$') { continue }
            if ($path -like '*Session Manager*' -and $v.Name -eq 'BootExecute' -and $v.Value -match '^autocheck autochk') { continue }
            Add-Autostart -Type 'Registry autostart' -Location $v.Key -Name $v.Name -Command $v.Value -Context 'machine-wide' -MitreId 'T1547.001' | Out-Null
        }
    }

    # --- 2. Per-user autostart keys (loaded hives) -----------------------
    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = Split-Path $hive.Name -Leaf
        if ($sid -match '_Classes$' -or $sid -in @('.DEFAULT', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20')) { continue }
        $account = $sid
        try { $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        foreach ($suffix in $script:UserRunKeySuffixes) {
            $p = "Registry::HKEY_USERS\$sid\$suffix"
            foreach ($v in (Get-RegValues $p)) {
                if ($suffix -eq 'Environment' -and $v.Name -notin @('UserInitMprLogonScript')) { continue }
                if ([string]::IsNullOrWhiteSpace($v.Value)) { continue }
                Add-Autostart -Type 'User autostart' -Location $p -Name $v.Name -Command $v.Value -Context "user: $account" -MitreId 'T1547.001' | Out-Null
            }
        }
    }

    # --- 3. Startup folders ----------------------------------------------
    Write-Sub 'Startup folders'
    $startupDirs = @(
        [Environment]::GetFolderPath('CommonStartup'),
        [Environment]::GetFolderPath('Startup')
    )
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        $startupDirs += (Join-Path $profileDir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
    }
    foreach ($dir in ($startupDirs | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($item.Name -eq 'desktop.ini') { continue }
            $target = $item.FullName
            if ($item.Extension -eq '.lnk') {
                try {
                    $sh = New-Object -ComObject WScript.Shell
                    $lnk = $sh.CreateShortcut($item.FullName)
                    $target = ($lnk.TargetPath + ' ' + $lnk.Arguments).Trim()
                } catch { }
            }
            Add-Autostart -Type 'Startup folder' -Location $dir -Name $item.Name -Command $target -Context 'startup item' -MitreId 'T1547.001' | Out-Null
        }
    }

    # --- 4. Image File Execution Options / accessibility hijacks ---------
    Write-Sub 'Image File Execution Options and accessibility binaries'
    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($k in (Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue)) {
        $dbg = Get-RegValue ("Registry::" + $k.Name) 'Debugger'
        if ($dbg) {
            New-Finding -Severity 'High' -Category 'Persistence' -Title ("IFEO Debugger set for {0}" -f (Split-Path $k.Name -Leaf)) `
                -Detail 'A Debugger value launches an arbitrary program whenever the target executable starts. Used both for persistence and for sticky-key style backdoors.' `
                -Evidence @("Key: $($k.Name)", "Debugger: $dbg") `
                -Recommendation 'Unless a debugging tool set this deliberately, remove the value and investigate the referenced binary.' `
                -Mitre @('T1546.012')
            Add-Autostart -Type 'IFEO debugger' -Location $k.Name -Name 'Debugger' -Command $dbg -Context 'image hijack' -MitreId 'T1546.012' | Out-Null
        }
        $mon = Get-RegValue ("Registry::" + $k.Name + "\SilentProcessExit") 'MonitorProcess'
        if ($mon) {
            New-Finding -Severity 'High' -Category 'Persistence' -Title ("SilentProcessExit MonitorProcess set for {0}" -f (Split-Path $k.Name -Leaf)) `
                -Evidence @("Key: $($k.Name)\SilentProcessExit", "MonitorProcess: $mon") `
                -Recommendation 'Remove unless documented.' -Mitre @('T1546.012')
        }
    }

    foreach ($acc in @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')) {
        $p = Join-Path $env:SystemRoot "System32\$acc"
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $sig = Get-SignatureState $p
        if ($sig -notlike 'Valid (Microsoft)*') {
            New-Finding -Severity 'High' -Category 'Persistence' -Title ("Accessibility binary {0} is not Microsoft-signed" -f $acc) `
                -Detail 'Replacing an accessibility binary with cmd.exe gives SYSTEM access from the logon screen without credentials.' `
                -Evidence @("Path: $p", "Signature: $sig", "Modified: $((Get-Item -LiteralPath $p -Force).LastWriteTime)") `
                -Recommendation 'Restore the original binary from a known-good source and check who replaced it.' `
                -Mitre @('T1546.008')
        }
    }

    # --- 5. LSA / netsh / print monitors / network providers -------------
    Write-Sub 'LSA, netsh, print monitor and provider DLLs'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    foreach ($name in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
        $val = Get-RegValue $lsa $name
        if ($val) {
            $known = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'scecli', 'rassfm', '""', '')
            foreach ($pkg in @($val)) {
                if ($pkg -and ($known -notcontains $pkg.ToLower())) {
                    New-Finding -Severity 'High' -Category 'Persistence' -Title ("Unexpected LSA package registered: {0}" -f $pkg) `
                        -Detail 'LSA packages load into lsass.exe at boot - a durable and stealthy persistence and credential-theft location.' `
                        -Evidence @("Key: $lsa", "Value: $name", "Package: $pkg") `
                        -Recommendation 'Locate the DLL in System32, capture it, and remove the registration if it is not a documented product.' `
                        -Mitre @('T1547.005')
                }
            }
        }
    }
    foreach ($v in (Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Netsh')) {
        Add-Autostart -Type 'Netsh helper DLL' -Location 'HKLM:\SOFTWARE\Microsoft\Netsh' -Name $v.Name -Command $v.Value -Context 'loads into netsh.exe' -MitreId 'T1546.007' | Out-Null
    }
    foreach ($mon in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue)) {
        $drv = Get-RegValue ("Registry::" + $mon.Name) 'Driver'
        $known = @('localspl.dll', 'tcpmon.dll', 'usbmon.dll', 'wsnmp32.dll', 'win32spl.dll', 'inetpp.dll', 'apmon.dll', 'mdmon.dll')
        if ($drv -and ($known -notcontains $drv.ToLower())) {
            Add-Autostart -Type 'Print monitor DLL' -Location $mon.Name -Name (Split-Path $mon.Name -Leaf) -Command $drv -Context 'loads into spoolsv.exe as SYSTEM' -MitreId 'T1547.010' | Out-Null
        }
    }
    $providerOrder = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' 'ProviderOrder'
    if ($providerOrder) {
        foreach ($prov in ($providerOrder -split ',')) {
            $dll = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$prov\NetworkProvider" 'ProviderPath'
            if ($dll -and ($dll -notmatch '(?i)\\system32\\(ntlanman|davclnt|drprov)\.dll')) {
                Add-Autostart -Type 'Network provider DLL' -Location "HKLM:\SYSTEM\CurrentControlSet\Services\$prov\NetworkProvider" -Name $prov -Command $dll -Context 'credential-visible provider' -MitreId 'T1556' | Out-Null
            }
        }
    }
    foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -ErrorAction SilentlyContinue)) {
        $stub = Get-RegValue ("Registry::" + $k.Name) 'StubPath'
        if ($stub) {
            Add-Autostart -Type 'Active Setup StubPath' -Location $k.Name -Name (Split-Path $k.Name -Leaf) -Command $stub -Context 'runs at first logon of every user' -MitreId 'T1547.014' | Out-Null
        }
    }

    # --- 6. Command hijacks used for UAC bypass / persistence ------------
    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = Split-Path $hive.Name -Leaf
        if ($sid -match '_Classes$') { continue }
        foreach ($cls in @('ms-settings', 'mscfile', 'exefile', 'Folder')) {
            $p = "Registry::HKEY_USERS\$sid\SOFTWARE\Classes\$cls\shell\open\command"
            $v = Get-RegValue $p '(default)'
            if ($v) {
                New-Finding -Severity 'High' -Category 'Persistence' -Title ("Shell command hijack under HKU\{0}: {1}" -f $sid, $cls) `
                    -Detail 'A user-hive handler for this class overrides the machine default and is a classic UAC-bypass / execution hijack.' `
                    -Evidence @("Key: $p", "Command: $v") `
                    -Recommendation 'Delete the key unless a legitimate application owns it.' -Mitre @('T1548.002')
            }
        }
    }

    # --- 7. Scheduled tasks ----------------------------------------------
    Write-Sub 'Scheduled tasks'
    $tasks = @()
    $taskCmd = $null
    try { $taskCmd = Get-Command Get-ScheduledTask -ErrorAction Stop } catch { }
    if ($taskCmd) {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }
            $actions = @()
            foreach ($a in @($t.Actions)) {
                $line = ''
                if ($a.PSObject.Properties.Name -contains 'Execute') { $line = ("{0} {1}" -f $a.Execute, $a.Arguments).Trim() }
                elseif ($a.PSObject.Properties.Name -contains 'ClassId') { $line = "COM handler $($a.ClassId)" }
                if ($line) { $actions += $line }
            }
            $principal = ''
            try { $principal = "$($t.Principal.UserId) ($($t.Principal.RunLevel))" } catch { }

            $rec = [pscustomobject]@{
                TaskName   = $t.TaskName
                TaskPath   = $t.TaskPath
                State      = "$($t.State)"
                Author     = $t.Author
                Principal  = $principal
                Actions    = $actions
                LastRun    = $(if ($info) { $info.LastRunTime } else { $null })
                NextRun    = $(if ($info) { $info.NextRunTime } else { $null })
                Hidden     = $(if ($t.Settings) { -not $t.Settings.Enabled } else { $null })
            }
            $tasks += $rec

            $isMicrosoft = ($t.TaskPath -like '\Microsoft\*') -and ("$($t.Author)" -match 'Microsoft|\$\(@%')
            foreach ($act in $actions) {
                if ($isMicrosoft -and -not (Test-SuspiciousCommand $act)) { continue }
                $exe = Resolve-ImagePath $act
                if ($isMicrosoft -and -not (Test-SuspiciousPath $exe)) { continue }
                Add-Autostart -Type 'Scheduled task' -Location ($t.TaskPath + $t.TaskName) -Name $t.TaskName -Command $act `
                              -Context ("author: $($t.Author); runs as: $principal; state: $($t.State)") -MitreId 'T1053.005' | Out-Null
            }

            # Task XML files created during the incident window are worth a look
            $xmlPath = Join-Path $env:SystemRoot ('System32\Tasks' + $t.TaskPath.TrimEnd('\') + '\' + $t.TaskName)
            if (Test-Path -LiteralPath $xmlPath) {
                try {
                    $fi = Get-Item -LiteralPath $xmlPath -Force
                    if ((Test-InIncidentWindow $fi.CreationTime) -or (Test-InIncidentWindow $fi.LastWriteTime)) {
                        New-Finding -Severity 'Medium' -Category 'Persistence' -Title ("Scheduled task '{0}' was created or modified during the incident window" -f $t.TaskName) `
                            -Evidence @("Task: $($t.TaskPath)$($t.TaskName)", "Created: $($fi.CreationTime)", "Modified: $($fi.LastWriteTime)",
                                        "Actions: " + ($actions -join ' | '), "Runs as: $principal") `
                            -Recommendation 'Confirm the task against the client change record; capture the task XML (collected in artifacts\tasks) before removing anything.' `
                            -Mitre @('T1053.005')
                        Copy-Artifact -Path $xmlPath -SubFolder 'tasks' -NewName (ConvertTo-SafeName ($t.TaskName + '.xml')) -Category 'scheduled-task' -Description "Task definition for $($t.TaskPath)$($t.TaskName)" | Out-Null
                    }
                } catch { }
            }
        }
    } else {
        $raw = (schtasks /query /fo LIST /v 2>&1 | Out-String)
        Save-Artifact -Content $raw -SubFolder 'tasks' -FileName 'schtasks-verbose.txt' -Category 'scheduled-task' -Description 'schtasks /query /fo LIST /v' | Out-Null
    }

    # --- 8. Services and drivers -----------------------------------------
    Write-Sub 'Services and drivers'
    $services = @()
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $exe  = Resolve-ImagePath $svc.PathName
        $sig  = Get-SignatureState $exe
        $created = $null
        if ($exe -and (Test-Path -LiteralPath $exe.Trim('"'))) {
            try { $created = (Get-Item -LiteralPath $exe.Trim('"') -Force).CreationTime } catch { }
        }
        $rec = [pscustomobject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            State       = $svc.State
            StartMode   = $svc.StartMode
            Account     = $svc.StartName
            PathName    = $svc.PathName
            Executable  = $exe
            Signature   = $sig
            FileCreated = $created
        }
        $services += $rec

        $suspicious = (Test-SuspiciousPath $exe) -or (Test-SuspiciousCommand $svc.PathName) -or
                      ($created -and (Test-InIncidentWindow $created))
        if ($suspicious -and $sig -notlike 'Valid (Microsoft)*') {
            Add-Autostart -Type 'Service' -Location "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name $svc.Name `
                          -Command $svc.PathName -Context ("display name: $($svc.DisplayName); account: $($svc.StartName); start: $($svc.StartMode)") `
                          -MitreId 'T1543.003' | Out-Null
        }
    }

    $drivers = @()
    foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $exe = Resolve-ImagePath $d.PathName
        $leaf = ''
        if ($exe) { $leaf = (Split-Path $exe -Leaf).ToLower() }
        $isVuln = $script:VulnerableDrivers -contains $leaf
        $rec = [pscustomobject]@{
            Name = $d.Name; DisplayName = $d.DisplayName; State = $d.State; StartMode = $d.StartMode
            PathName = $d.PathName; KnownVulnerable = $isVuln
        }
        $drivers += $rec
        if ($isVuln) {
            New-Finding -Severity 'Critical' -Category 'Persistence' -Title ("Known-abusable driver registered: {0}" -f $leaf) `
                -Detail 'This driver appears on public bring-your-own-vulnerable-driver lists and is used to terminate endpoint protection from kernel mode. Its presence is a strong indicator of hands-on-keyboard defence evasion.' `
                -Evidence @("Service: $($d.Name)", "Path: $($d.PathName)", "State: $($d.State)", "Start mode: $($d.StartMode)") `
                -Recommendation 'Capture the driver file, remove the service, and confirm Microsoft vulnerable driver blocklist enforcement is enabled.' `
                -Mitre @('T1562.001', 'T1068')
            $script:BehaviourHits['byovd'] = $true
        }
    }

    # --- 9. WMI event subscriptions --------------------------------------
    Write-Sub 'WMI event subscriptions'
    $wmi = @()
    try {
        $filters   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)
        $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)
        $bindings  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)

        foreach ($f in $filters) {
            $wmi += [pscustomobject]@{ Kind = 'Filter'; Name = $f.Name; Detail = $f.Query }
            if ($f.Name -notmatch '^(SCM Event Log Filter|BVTFilter)$') {
                New-Finding -Severity 'High' -Category 'Persistence' -Title ("Non-default WMI event filter: {0}" -f $f.Name) `
                    -Detail 'WMI event subscriptions survive reboots and are invisible to most autostart tooling.' `
                    -Evidence @("Name: $($f.Name)", "Query: $($f.Query)") `
                    -Recommendation 'Pair it with its consumer and binding, capture the payload, then delete all three during remediation.' `
                    -Mitre @('T1546.003')
            }
        }
        foreach ($c in $consumers) {
            $payload = ''
            if ($c.PSObject.Properties.Name -contains 'CommandLineTemplate') { $payload = $c.CommandLineTemplate }
            elseif ($c.PSObject.Properties.Name -contains 'ScriptText') { $payload = $c.ScriptText }
            $wmi += [pscustomobject]@{ Kind = "Consumer ($($c.CimClass.CimClassName))"; Name = $c.Name; Detail = $payload }
            if ($c.Name -notmatch '^(SCM Event Log Consumer)$') {
                New-Finding -Severity 'High' -Category 'Persistence' -Title ("Non-default WMI event consumer: {0}" -f $c.Name) `
                    -Evidence @("Class: $($c.CimClass.CimClassName)", "Name: $($c.Name)", "Payload: $payload") `
                    -Recommendation 'Treat the payload as attacker-controlled code until proven otherwise.' -Mitre @('T1546.003')
            }
        }
        foreach ($b in $bindings) {
            $wmi += [pscustomobject]@{ Kind = 'Binding'; Name = "$($b.Filter)"; Detail = "$($b.Consumer)" }
        }
    } catch {
        Write-Note 'WMI subscription namespace could not be queried.'
    }

    # --- 10. BITS jobs and logon scripts ---------------------------------
    try {
        $bits = @(Get-BitsTransfer -AllUsers -ErrorAction Stop)
        foreach ($j in $bits) {
            New-Finding -Severity 'Medium' -Category 'Persistence' -Title ("BITS transfer job present: {0}" -f $j.DisplayName) `
                -Detail 'Long-lived BITS jobs are used both to pull payloads and to re-establish access after cleanup.' `
                -Evidence @("Job: $($j.DisplayName)", "State: $($j.JobState)", "Owner: $($j.OwnerAccount)", "Created: $($j.CreationTime)") `
                -Recommendation 'Inspect the job URL and destination, then remove it if it is not a legitimate update job.' `
                -Mitre @('T1197')
        }
    } catch { }

    $gpoScripts = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts'
    if (Test-Path -LiteralPath $gpoScripts) {
        foreach ($f in (Get-ChildItem -LiteralPath $gpoScripts -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Extension -in @('.bat', '.cmd', '.ps1', '.vbs', '.exe')) {
                Add-Autostart -Type 'Local GPO script' -Location $f.DirectoryName -Name $f.Name -Command $f.FullName -Context 'machine startup/shutdown script' -MitreId 'T1037' | Out-Null
            }
        }
    }

    $high = @($script:Autostarts | Where-Object { $_.Suspicion -in @('High', 'Medium') })
    Write-Kv 'Autostart entries reviewed' $script:Autostarts.Count
    Write-Kv 'Entries needing follow-up'  $high.Count
    if ($high.Count -eq 0) {
        Write-Ok 'No suspicious autostart entries were identified by the built-in heuristics.'
    }

    Add-Section 'Persistence' ([ordered]@{
        AutostartEntries   = @($script:Autostarts)
        SuspiciousEntries  = $high
        Services           = $services
        Drivers            = $drivers
        WmiSubscriptions   = $wmi
        Caveat             = 'A clean result here means no persistence was found in the locations this tool checks. It is not proof that the host is clean - only rebuild-from-known-good gives that.'
    })

    Invoke-Capture -FileName 'services.txt' -Command 'sc query type= service state= all' -Description 'All services' | Out-Null
    Invoke-Capture -FileName 'scheduled-tasks.txt' -Command 'schtasks /query /fo LIST /v' -Description 'All scheduled tasks (verbose)' | Out-Null
}

# -------------------------------------------------------------------------
#  MODULE 7 - ACTOR TOOLING HUNT
# -------------------------------------------------------------------------
function Invoke-ToolingHunt {
    $hits = @{}

    function Add-ToolHit {
        param($Tool, [string]$Where, [string]$Evidence)
        if (-not $hits.ContainsKey($Tool.Name)) {
            $hits[$Tool.Name] = [pscustomobject]@{
                Tool = $Tool.Name; Category = $Tool.Category; Behaviour = $Tool.Behaviour
                Sightings = New-Object System.Collections.ArrayList
            }
        }
        [void]$hits[$Tool.Name].Sightings.Add("[$Where] $Evidence")
    }

    # --- running processes -----------------------------------------------
    Write-Sub 'Running processes'
    $procs = @()
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $owner = ''
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($o) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
        $sig = ''
        if ($p.ExecutablePath) { $sig = Get-SignatureState $p.ExecutablePath }
        $rec = [pscustomobject]@{
            ProcessId   = $p.ProcessId
            Name        = $p.Name
            ExecutablePath = $p.ExecutablePath
            CommandLine = $p.CommandLine
            ParentPid   = $p.ParentProcessId
            Owner       = $owner
            Started     = $p.CreationDate
            Signature   = $sig
        }
        $procs += $rec

        $probe = "$($p.Name) $($p.ExecutablePath) $($p.CommandLine)"
        foreach ($tool in $script:ActorTooling) {
            if ($probe -imatch $tool.Match) { Add-ToolHit -Tool $tool -Where 'running process' -Evidence ("PID $($p.ProcessId) $($p.ExecutablePath)") }
        }
        if ($p.ExecutablePath -and (Test-SuspiciousPath $p.ExecutablePath) -and $sig -notlike 'Valid*') {
            New-Finding -Severity 'High' -Category 'Live activity' -Title ("Unsigned process running from an unusual location: {0}" -f $p.Name) `
                -Evidence @("PID: $($p.ProcessId)", "Path: $($p.ExecutablePath)", "Command line: $($p.CommandLine)", "Owner: $owner", "Signature: $sig", "Started: $($p.CreationDate)") `
                -Recommendation 'Capture the binary and the process memory before terminating anything. This may be live attacker tooling.' `
                -Mitre @('T1204')
        }
        if ((Test-SuspiciousCommand $p.CommandLine) -and $p.Name -imatch 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32') {
            New-Finding -Severity 'Medium' -Category 'Live activity' -Title ("Suspicious command line on a live process: {0}" -f $p.Name) `
                -Evidence @("PID: $($p.ProcessId)", "Command line: $($p.CommandLine)", "Owner: $owner") `
                -Recommendation 'Review the full command line; it matches patterns used for staging and defence evasion.' `
                -Mitre @('T1059.001')
        }
    }

    # --- services, installed programs, prefetch, hot directories ---------
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $probe = "$($svc.Name) $($svc.DisplayName) $($svc.PathName)"
        foreach ($tool in $script:ActorTooling) {
            if ($probe -imatch $tool.Match) { Add-ToolHit -Tool $tool -Where 'service' -Evidence ("$($svc.Name) -> $($svc.PathName)") }
        }
    }

    $installed = @()
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $name = Get-RegValue ("Registry::" + $k.Name) 'DisplayName'
            if (-not $name) { continue }
            $rec = [pscustomobject]@{
                Name        = $name
                Version     = (Get-RegValue ("Registry::" + $k.Name) 'DisplayVersion')
                Publisher   = (Get-RegValue ("Registry::" + $k.Name) 'Publisher')
                InstallDate = (Get-RegValue ("Registry::" + $k.Name) 'InstallDate')
                Location    = (Get-RegValue ("Registry::" + $k.Name) 'InstallLocation')
            }
            $installed += $rec
            foreach ($tool in $script:ActorTooling) {
                if ("$name $($rec.Location)" -imatch $tool.Match) { Add-ToolHit -Tool $tool -Where 'installed program' -Evidence ("$name $($rec.Version) (installed $($rec.InstallDate))") }
            }
        }
    }

    $prefetchDir = Join-Path $env:SystemRoot 'Prefetch'
    $prefetch = @()
    if (Test-Path -LiteralPath $prefetchDir) {
        foreach ($pf in (Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue)) {
            $prefetch += [pscustomobject]@{ Name = $pf.Name; LastWrite = $pf.LastWriteTime; Created = $pf.CreationTime }
            foreach ($tool in $script:ActorTooling) {
                if ($pf.Name -imatch $tool.Match) { Add-ToolHit -Tool $tool -Where 'prefetch' -Evidence ("$($pf.Name) last run $($pf.LastWriteTime)") }
            }
        }
    }

    Write-Sub 'Staging directories'
    $hotDirs = @("$env:SystemDrive\Users\Public", "$env:SystemDrive\ProgramData", "$env:SystemRoot\Temp",
                 "$env:SystemDrive\PerfLogs", "$env:SystemDrive\Temp", "$env:SystemDrive\Intel", "$env:SystemDrive\")
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        $hotDirs += (Join-Path $profileDir.FullName 'Downloads')
        $hotDirs += (Join-Path $profileDir.FullName 'Desktop')
        $hotDirs += (Join-Path $profileDir.FullName 'AppData\Local\Temp')
        $hotDirs += (Join-Path $profileDir.FullName 'Documents')
    }
    $stagedFiles = @()
    foreach ($dir in ($hotDirs | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -imatch '^\.(exe|dll|sys|ps1|bat|cmd|vbs|js|7z|zip|rar|msi|scr)$' })) {
            $rec = [pscustomobject]@{
                Path = $f.FullName; SizeBytes = $f.Length; Created = $f.CreationTime
                Modified = $f.LastWriteTime; Signature = (Get-SignatureState $f.FullName)
                InIncidentWindow = ((Test-InIncidentWindow $f.CreationTime) -or (Test-InIncidentWindow $f.LastWriteTime))
            }
            $stagedFiles += $rec
            foreach ($tool in $script:ActorTooling) {
                if ($f.Name -imatch $tool.Match) { Add-ToolHit -Tool $tool -Where 'file on disk' -Evidence ("$($f.FullName) created $($f.CreationTime)") }
            }
            if ($script:VulnerableDrivers -contains $f.Name.ToLower()) {
                New-Finding -Severity 'Critical' -Category 'Actor tooling' -Title ("Known-abusable driver file on disk: {0}" -f $f.Name) `
                    -Evidence @("Path: $($f.FullName)", "Created: $($f.CreationTime)", "SHA-256: $(Get-Sha256 $f.FullName)") `
                    -Recommendation 'Collect the file, then remove it. Confirm the vulnerable driver blocklist is enforced.' `
                    -Mitre @('T1562.001')
                $script:BehaviourHits['byovd'] = $true
            }
        }
    }
    $recentStaged = @($stagedFiles | Where-Object { $_.InIncidentWindow -and $_.Signature -notlike 'Valid (Microsoft)*' })
    if ($recentStaged.Count -gt 0) {
        New-Finding -Severity 'Medium' -Category 'Actor tooling' -Title ("{0} executable file(s) appeared in staging directories during the incident window" -f $recentStaged.Count) `
            -Detail 'Public, ProgramData, Temp and Downloads are the usual drop points for intrusion tooling and for the encryptor itself.' `
            -Evidence (@($recentStaged | Select-Object -First 25 | ForEach-Object { "{0}  created {1}  [{2}]" -f $_.Path, $_.Created, $_.Signature })) `
            -Recommendation 'Hash each file and check it against the client software inventory before dismissing it.'
    }

    # --- exfiltration configuration files ---------------------------------
    $exfilConfigs = @()
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        $candidates = @(
            (Join-Path $profileDir.FullName 'AppData\Roaming\rclone\rclone.conf'),
            (Join-Path $profileDir.FullName '.config\rclone\rclone.conf'),
            (Join-Path $profileDir.FullName 'AppData\Roaming\FileZilla\recentservers.xml'),
            (Join-Path $profileDir.FullName 'AppData\Roaming\FileZilla\sitemanager.xml'),
            (Join-Path $profileDir.FullName 'AppData\Roaming\WinSCP.ini'),
            (Join-Path $profileDir.FullName 'AppData\Local\MEGAsync\MEGAsync.cfg')
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) {
                $fi = Get-Item -LiteralPath $c -Force
                $exfilConfigs += [pscustomobject]@{ Path = $c; Modified = $fi.LastWriteTime; SizeBytes = $fi.Length }
                Copy-Artifact -Path $c -SubFolder 'system' -NewName (ConvertTo-SafeName ("exfilcfg_" + $profileDir.Name + "_" + (Split-Path $c -Leaf))) -Category 'exfil-config' -Description 'Transfer tool configuration' | Out-Null
                New-Finding -Severity 'High' -Category 'Exfiltration' -Title ("Data transfer tool configuration found: {0}" -f (Split-Path $c -Leaf)) `
                    -Detail 'Configuration files for rclone / WinSCP / FileZilla / MEGA name the destination the data went to. Akira exfiltrates before encrypting, so this is central to the breach-notification question.' `
                    -Evidence @("Path: $c", "Modified: $($fi.LastWriteTime)") `
                    -Recommendation 'Parse the configuration for remote endpoints and hand it to the legal/notification track. The file has been collected.' `
                    -Mitre @('T1567.002')
                $script:BehaviourHits['exfil-tool'] = $true
            }
        }
    }

    # --- report tool hits --------------------------------------------------
    foreach ($h in $hits.Values) {
        $tool = $script:ActorTooling | Where-Object { $_.Name -eq $h.Tool } | Select-Object -First 1
        if ($tool -and $tool.Behaviour) { $script:BehaviourHits[$tool.Behaviour] = $true }
        $sev = 'Medium'
        if ($h.Category -in @('Credential access', 'Defence evasion')) { $sev = 'Critical' }
        elseif ($h.Category -in @('Exfiltration', 'Tunnelling', 'Remote access')) { $sev = 'High' }
        New-Finding -Severity $sev -Category 'Actor tooling' -Title ("{0} present on this host ({1})" -f $h.Tool, $h.Category) `
            -Detail 'This utility is repeatedly abused in Akira intrusions. It may also be legitimate on this host - the client software inventory decides.' `
            -Evidence @($h.Sightings) `
            -Recommendation 'Confirm with the client whether this tool is authorised here. If not, treat every sighting as attacker activity and pivot on the timestamps.' `
            -Mitre @('T1219')
    }
    if ($hits.Count -eq 0) { Write-Ok 'No known intrusion tooling matched on this host.' }

    Add-Section 'ActorTooling' ([ordered]@{
        ToolHits          = @($hits.Values | ForEach-Object { [pscustomobject]@{ Tool = $_.Tool; Category = $_.Category; Sightings = @($_.Sightings) } })
        StagedExecutables = @($stagedFiles | Sort-Object Created -Descending | Select-Object -First 200)
        ExfilConfigFiles  = $exfilConfigs
        InstalledPrograms = @($installed | Sort-Object Name)
        PrefetchEntries   = @($prefetch | Sort-Object LastWrite -Descending | Select-Object -First 200)
        Processes         = $procs
    })

    Invoke-Capture -FileName 'processes.txt' -Command 'wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:list' -Description 'Process list with command lines' | Out-Null
}

# -------------------------------------------------------------------------
#  MODULE 8 - BACKUP AND RECOVERY STATE
# -------------------------------------------------------------------------
function Invoke-BackupState {
    $shadows = @()
    try {
        foreach ($s in (Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)) {
            $shadows += [pscustomobject]@{ Id = $s.ID; VolumeName = $s.VolumeName; InstallDate = $s.InstallDate; DeviceObject = $s.DeviceObject }
        }
    } catch { }
    Write-Kv 'Shadow copies present' $shadows.Count

    $vssList    = Invoke-Capture -FileName 'vssadmin-shadows.txt' -Command 'vssadmin list shadows' -Description 'vssadmin list shadows'
    $vssStorage = Invoke-Capture -FileName 'vssadmin-shadowstorage.txt' -Command 'vssadmin list shadowstorage' -Description 'vssadmin list shadowstorage'
    $bcd        = Invoke-Capture -FileName 'bcdedit.txt' -Command 'bcdedit /enum' -Description 'Boot configuration'

    if ($shadows.Count -eq 0) {
        New-Finding -Severity 'High' -Category 'Recovery' -Title 'No Volume Shadow Copies exist on this host' `
            -Detail 'Akira deletes shadow copies before encrypting, typically through an embedded PowerShell WMI call. Absence is expected after an Akira run but should still be recorded - it removes the cheapest recovery option.' `
            -Evidence @('Win32_ShadowCopy returned no instances') `
            -Recommendation 'Recover from offline/immutable backup. Once rebuilt, re-enable shadow copies and confirm backups are isolated from domain credentials.' `
            -Mitre @('T1490')
        $script:BehaviourHits['vss-wipe'] = $true
    } else {
        Write-Ok ("{0} shadow copies still present - check whether any predate the encryption window." -f $shadows.Count)
    }

    if ($bcd -match '(?i)recoveryenabled\s+No') {
        New-Finding -Severity 'High' -Category 'Recovery' -Title 'Windows recovery environment has been disabled (bcdedit recoveryenabled No)' `
            -Detail 'Disabling the recovery environment is a standard pre-encryption step to stop the victim rolling back.' `
            -Evidence @('bcdedit /enum shows recoveryenabled No') `
            -Recommendation 'Re-enable recovery after rebuild: bcdedit /set {default} recoveryenabled Yes' `
            -Mitre @('T1490')
        $script:BehaviourHits['recovery-off'] = $true
    }
    if ($bcd -match '(?i)bootstatuspolicy\s+ignoreallfailures') {
        New-Finding -Severity 'Medium' -Category 'Recovery' -Title 'Boot status policy set to ignoreallfailures' `
            -Detail 'Commonly set alongside recovery disablement so the machine does not offer repair options after the encryptor runs.' `
            -Recommendation 'Restore the default boot status policy after rebuild.' -Mitre @('T1490')
    }

    # Backup products present on the host
    $backupPatterns = 'veeam|acronis|backupexec|datto|commvault|networker|arcserve|nakivo|altaro|macrium|shadowprotect|cohesity|rubrik|synology active backup'
    $backupSvc = @()
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if ("$($svc.Name) $($svc.DisplayName)" -imatch $backupPatterns) {
            $backupSvc += [pscustomobject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; State = $svc.State; StartMode = $svc.StartMode }
        }
    }
    foreach ($b in $backupSvc) {
        Write-Kv 'Backup service' ("{0} [{1}]" -f $b.DisplayName, $b.State)
        if ($b.State -ne 'Running') {
            New-Finding -Severity 'High' -Category 'Recovery' -Title ("Backup service '{0}' is not running" -f $b.DisplayName) `
                -Detail 'Backup services are stopped deliberately before encryption, and Veeam in particular is targeted for stored credentials.' `
                -Evidence @("Service: $($b.Name)", "State: $($b.State)", "Start mode: $($b.StartMode)") `
                -Recommendation 'Treat backup server credentials as compromised, verify backup integrity offline, and restore only after the environment is known clean.' `
                -Mitre @('T1490')
        }
    }
    if ($backupSvc.Count -gt 0) {
        New-Finding -Severity 'Info' -Category 'Recovery' -Title 'Backup software is installed on this host' `
            -Detail 'Akira intrusions specifically hunt backup infrastructure and its stored credentials before encrypting.' `
            -Evidence (@($backupSvc | ForEach-Object { "{0} [{1}]" -f $_.DisplayName, $_.State })) `
            -Recommendation 'Rotate all credentials stored by the backup product and verify restore media offline before reconnecting.'
    }

    Add-Section 'Recovery' ([ordered]@{
        ShadowCopies      = $shadows
        ShadowCopyCount   = $shadows.Count
        BackupServices    = $backupSvc
        RecoveryDisabled  = [bool]($bcd -match '(?i)recoveryenabled\s+No')
        VssShadowsRaw     = ($vssList -split "`r?`n" | Select-Object -First 60)
        VssStorageRaw     = ($vssStorage -split "`r?`n" | Select-Object -First 40)
    })
}

# -------------------------------------------------------------------------
#  MODULE 9 - EVENT LOG TRIAGE
# -------------------------------------------------------------------------
function Get-EventDataValue {
    param($Event, [string]$Name)
    try {
        $xml = [xml]$Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($node) { return $node.'#text' }
    } catch { }
    return $null
}

function Get-EventsSafe {
    param([string]$LogName, [int[]]$Id, [datetime]$StartTime, [int]$MaxEvents = 500)
    try {
        $filter = @{ LogName = $LogName; StartTime = $StartTime }
        if ($Id) { $filter['Id'] = $Id }
        return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch { return @() }
}

function Invoke-EventLogTriage {
    $start = (Get-Date).AddDays(-$DaysBack)
    Write-Note ("Reviewing the last {0} days of event logs (from {1})." -f $DaysBack, $start.ToString('yyyy-MM-dd'))

    $summary = @()
    $details = [ordered]@{}

    # --- generic ID sweep -------------------------------------------------
    foreach ($check in $script:EventTriage) {
        $events = Get-EventsSafe -LogName $check.Log -Id @($check.Id) -StartTime $start -MaxEvents 300
        $summary += [pscustomobject]@{
            Log = $check.Log; EventId = $check.Id; Meaning = $check.Meaning
            Count = $events.Count
            First = $(if ($events.Count) { ($events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated } else { $null })
            Last  = $(if ($events.Count) { ($events | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated } else { $null })
        }
        if ($events.Count -eq 0) { continue }
        Write-Kv ("{0}/{1}" -f $check.Log, $check.Id) ("{0}  x{1}" -f $check.Meaning, $events.Count)

        switch ($check.Id) {
            1102 {
                New-Finding -Severity 'High' -Category 'Anti-forensics' -Title ('Security event log was cleared {0} time(s)' -f $events.Count) `
                    -Detail 'Clearing the Security log is a deliberate act. Everything before the clear is gone from this host and can only be recovered from a SIEM or backup.' `
                    -Evidence (@($events | Select-Object -First 5 | ForEach-Object { "Cleared at $($_.TimeCreated) by $($_.UserId)" })) `
                    -Recommendation 'Pull the equivalent window from the SIEM or from log forwarding. Record the gap in the incident timeline.' `
                    -Mitre @('T1070.001')
                $script:BehaviourHits['log-clear'] = $true
            }
            104 {
                New-Finding -Severity 'High' -Category 'Anti-forensics' -Title ('An event log was cleared {0} time(s) (System 104)' -f $events.Count) `
                    -Evidence (@($events | Select-Object -First 5 | ForEach-Object { "$($_.TimeCreated): $(($_.Message -split "`r?`n")[0])" })) `
                    -Recommendation 'Treat missing log coverage as a visibility gap in the report.' -Mitre @('T1070.001')
                $script:BehaviourHits['log-clear'] = $true
            }
            4720 {
                $names = @($events | ForEach-Object { Get-EventDataValue $_ 'TargetUserName' } | Where-Object { $_ } | Select-Object -Unique)
                New-Finding -Severity 'High' -Category 'Accounts' -Title ('{0} account(s) were created in the review window' -f $names.Count) `
                    -Detail ('Accounts created: ' + ($names -join ', ')) `
                    -Evidence (@($events | Select-Object -First 20 | ForEach-Object { "{0}: {1} created by {2}" -f $_.TimeCreated, (Get-EventDataValue $_ 'TargetUserName'), (Get-EventDataValue $_ 'SubjectUserName') })) `
                    -Recommendation 'Match every account against the client change record. Unexplained accounts are attacker persistence until proven otherwise.' `
                    -Mitre @('T1136.001')
                $script:BehaviourHits['account-create'] = $true
            }
            4732 {
                $rows = @($events | Select-Object -First 20 | ForEach-Object {
                    "{0}: {1} added to {2} by {3}" -f $_.TimeCreated, (Get-EventDataValue $_ 'MemberSid'), (Get-EventDataValue $_ 'TargetUserName'), (Get-EventDataValue $_ 'SubjectUserName') })
                New-Finding -Severity 'High' -Category 'Accounts' -Title ('{0} local group membership addition(s) in the review window' -f $events.Count) `
                    -Evidence $rows `
                    -Recommendation 'Focus on additions to Administrators, Remote Desktop Users and Backup Operators.' -Mitre @('T1098')
            }
            7045 {
                $rows = @($events | Select-Object -First 30 | ForEach-Object {
                    "{0}: {1} -> {2}" -f $_.TimeCreated, (Get-EventDataValue $_ 'ServiceName'), (Get-EventDataValue $_ 'ImagePath') })
                $suspect = @($rows | Where-Object { (Test-SuspiciousCommand $_) -or ($_ -imatch '\\users\\|\\temp\\|\\programdata\\|\\public\\') })
                $sev = 'Low'
                if ($suspect.Count -gt 0) { $sev = 'High' }
                New-Finding -Severity $sev -Category 'Persistence' -Title ('{0} service(s) installed in the review window' -f $events.Count) `
                    -Detail 'Service installation is how PsExec, Impacket and most kernel-mode evasion drivers land on a host.' `
                    -Evidence $rows `
                    -Recommendation 'Cross-check each service name against the software inventory; the suspicious paths are listed first.' `
                    -Mitre @('T1543.003')
                $details['ServiceInstallEvents'] = $rows
            }
        }
    }

    # --- RDP activity ------------------------------------------------------
    Write-Sub 'Remote access activity'
    $rdpLogons = @()
    foreach ($e in (Get-EventsSafe -LogName 'Security' -Id @(4624) -StartTime $start -MaxEvents 4000)) {
        $type = Get-EventDataValue $e 'LogonType'
        if ($type -ne '10' -and $type -ne '3') { continue }
        $rdpLogons += [pscustomobject]@{
            Time      = $e.TimeCreated
            LogonType = $type
            User      = Get-EventDataValue $e 'TargetUserName'
            Domain    = Get-EventDataValue $e 'TargetDomainName'
            SourceIp  = Get-EventDataValue $e 'IpAddress'
            Workstation = Get-EventDataValue $e 'WorkstationName'
            Process   = Get-EventDataValue $e 'ProcessName'
        }
    }
    $interactiveRemote = @($rdpLogons | Where-Object { $_.LogonType -eq '10' })
    if ($interactiveRemote.Count -gt 0) {
        $byUser = $interactiveRemote | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
        $bySrc  = $interactiveRemote | Group-Object SourceIp | Sort-Object Count -Descending | Select-Object -First 10
        New-Finding -Severity 'Medium' -Category 'Remote access' -Title ('{0} interactive RDP logon(s) recorded in the review window' -f $interactiveRemote.Count) `
            -Detail 'RDP is Akira''s standard lateral movement path once domain credentials are in hand. Compare these accounts and sources against expected admin activity.' `
            -Evidence (@('Top accounts:') + @($byUser | ForEach-Object { "  $($_.Name): $($_.Count)" }) +
                       @('Top sources:')  + @($bySrc  | ForEach-Object { "  $($_.Name): $($_.Count)" })) `
            -Recommendation 'Any RDP source outside the admin jump-host range belongs in the intrusion timeline.' `
            -Mitre @('T1021.001')
        $script:BehaviourHits['rdp-lateral'] = $true
    }

    $failed = Get-EventsSafe -LogName 'Security' -Id @(4625) -StartTime $start -MaxEvents 3000
    if ($failed.Count -ge 100) {
        $srcs = $failed | ForEach-Object { Get-EventDataValue $_ 'IpAddress' } | Where-Object { $_ -and $_ -ne '-' } |
                Group-Object | Sort-Object Count -Descending | Select-Object -First 10
        New-Finding -Severity 'Medium' -Category 'Remote access' -Title ('{0} failed logons in the review window' -f $failed.Count) `
            -Detail 'A high failed-logon volume points at password spraying or brute force against this host.' `
            -Evidence (@($srcs | ForEach-Object { "$($_.Name): $($_.Count) failures" })) `
            -Recommendation 'Confirm whether the sources are internal (spread from another compromised host) or external (exposed service).' `
            -Mitre @('T1110')
    }

    # --- PowerShell script block logging ------------------------------------
    $psSuspicious = @()
    foreach ($e in (Get-EventsSafe -LogName 'Microsoft-Windows-PowerShell/Operational' -Id @(4104) -StartTime $start -MaxEvents 2000)) {
        if (Test-SuspiciousCommand $e.Message) {
            $text = ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 4) -join ' '
            $psSuspicious += [pscustomobject]@{ Time = $e.TimeCreated; Excerpt = $text.Substring(0, [math]::Min(400, $text.Length)) }
        }
    }
    if ($psSuspicious.Count -gt 0) {
        New-Finding -Severity 'High' -Category 'Execution' -Title ('{0} suspicious PowerShell script block(s) recorded' -f $psSuspicious.Count) `
            -Detail 'Script block logging captured PowerShell matching encoded-command, download, shadow-copy-deletion or defence-evasion patterns.' `
            -Evidence (@($psSuspicious | Select-Object -First 15 | ForEach-Object { "{0}: {1}" -f $_.Time, $_.Excerpt })) `
            -Recommendation 'Read the full 4104 events around these timestamps - they usually contain the intrusion''s own tooling verbatim.' `
            -Mitre @('T1059.001')
        $details['SuspiciousPowerShell'] = $psSuspicious
        if (($psSuspicious | Where-Object { $_.Excerpt -imatch 'shadowcopy|vssadmin' }).Count -gt 0) { $script:BehaviourHits['vss-wipe'] = $true }
    }

    # --- Defender events ----------------------------------------------------
    $defEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Windows Defender/Operational' -Id @(1116, 1117, 5001, 5007, 5010, 5012) -StartTime $start -MaxEvents 500
    if ($defEvents.Count -gt 0) {
        $detections = @($defEvents | Where-Object { $_.Id -in @(1116, 1117) })
        $configs    = @($defEvents | Where-Object { $_.Id -in @(5001, 5007, 5010, 5012) })
        if ($detections.Count -gt 0) {
            New-Finding -Severity 'High' -Category 'Detection history' -Title ('{0} Defender detection event(s) in the review window' -f $detections.Count) `
                -Detail 'These are the malware Defender did see. The names and paths are the fastest route to the intrusion timeline.' `
                -Evidence (@($detections | Select-Object -First 20 | ForEach-Object { "{0}: {1}" -f $_.TimeCreated, (($_.Message -split "`r?`n" | Where-Object { $_ -match 'Name:|Path:' }) -join ' ') })) `
                -Recommendation 'Pivot on each detection path and time; check whether the detection was actioned or merely logged.'
        }
        if ($configs.Count -gt 0) {
            New-Finding -Severity 'High' -Category 'Detection history' -Title ('{0} Defender configuration/state change event(s) in the review window' -f $configs.Count) `
                -Detail 'Defender recorded its own protection being turned off or reconfigured.' `
                -Evidence (@($configs | Select-Object -First 15 | ForEach-Object { "{0} (id {1}): {2}" -f $_.TimeCreated, $_.Id, (($_.Message -split "`r?`n")[0]) })) `
                -Recommendation 'Correlate the change times with logon and process events to identify who disabled protection.' `
                -Mitre @('T1562.001')
            $script:BehaviourHits['defender-off'] = $true
        }
    }

    # --- log coverage -------------------------------------------------------
    $coverage = @()
    foreach ($ln in @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
                      'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                      'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-Sysmon/Operational')) {
        try {
            $log = Get-WinEvent -ListLog $ln -ErrorAction Stop
            $oldest = $null
            try { $oldest = (Get-WinEvent -LogName $ln -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
            $coverage += [pscustomobject]@{
                Log = $ln; RecordCount = $log.RecordCount; MaxSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                Enabled = $log.IsEnabled; OldestRecord = $oldest
                CoversIncidentStart = $(if ($oldest -and $script:IncidentStartTime) { $oldest -le $script:IncidentStartTime } else { $null })
            }
        } catch { }
    }
    foreach ($c in $coverage) {
        if ($c.CoversIncidentStart -eq $false) {
            New-Finding -Severity 'Medium' -Category 'Visibility' -Title ("The {0} log does not reach back to the start of the incident window" -f $c.Log) `
                -Detail ("Oldest record: {0}. Incident window starts: {1}. Either the log rolled over or it was cleared." -f $c.OldestRecord, $script:IncidentStartTime) `
                -Recommendation 'Note the gap in the report and source the missing window from SIEM/backup if available.'
        }
    }

    Add-Section 'EventLogTriage' ([ordered]@{
        ReviewWindowStart = $start
        Summary           = $summary
        RdpLogons         = @($rdpLogons | Sort-Object Time -Descending | Select-Object -First 200)
        FailedLogonCount  = $failed.Count
        LogCoverage       = $coverage
        Details           = $details
    })
}

# -------------------------------------------------------------------------
#  MODULE 10 - NETWORK SNAPSHOT
# -------------------------------------------------------------------------
function Invoke-NetworkSnapshot {
    $listening = @()
    $established = @()
    try {
        foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
            $procName = ''
            try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            $rec = [pscustomobject]@{
                LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
                RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort
                State = "$($c.State)"; ProcessId = $c.OwningProcess; Process = $procName
            }
            if ($c.State -eq 'Listen') { $listening += $rec }
            elseif ($c.State -eq 'Established') { $established += $rec }
        }
    } catch { }

    $netstat = Invoke-Capture -FileName 'netstat.txt' -Command 'netstat -anob' -Description 'Connections with owning processes'
    Invoke-Capture -FileName 'arp.txt' -Command 'arp -a' -Description 'ARP cache' | Out-Null
    Invoke-Capture -FileName 'route.txt' -Command 'route print' -Description 'Routing table' | Out-Null
    Invoke-Capture -FileName 'dnscache.txt' -Command 'ipconfig /displaydns' -Description 'DNS resolver cache' | Out-Null
    Invoke-Capture -FileName 'shares.txt' -Command 'net share' -Description 'Shared folders' | Out-Null
    Invoke-Capture -FileName 'sessions.txt' -Command 'net session' -Description 'Inbound SMB sessions' | Out-Null

    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hosts) {
        Copy-Artifact -Path $hosts -SubFolder 'system' -NewName 'hosts' -Category 'system-config' -Description 'hosts file' | Out-Null
        $hostLines = @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
        if ($hostLines.Count -gt 0) {
            New-Finding -Severity 'Low' -Category 'Network' -Title ('The hosts file contains {0} active entry/entries' -f $hostLines.Count) `
                -Detail 'Entries here can redirect update or security traffic. Confirm each one is expected.' `
                -Evidence $hostLines -Recommendation 'Remove anything the client cannot account for.' -Mitre @('T1565.001')
        }
    }

    $rdpListening = @($listening | Where-Object { $_.LocalPort -eq 3389 -and $_.LocalAddress -in @('0.0.0.0', '::') })
    if ($rdpListening.Count -gt 0) {
        New-Finding -Severity 'Medium' -Category 'Network' -Title 'RDP is listening on all interfaces' `
            -Detail 'Port 3389 bound to 0.0.0.0 means anything that can route to this host can attempt RDP.' `
            -Recommendation 'Restrict RDP by firewall rule to management ranges before the host returns to the network.' `
            -Mitre @('T1021.001')
    }

    $dcom = @($listening | Where-Object { $_.LocalPort -in @(4444, 5555, 8080, 8443, 1080, 9001) })
    if ($dcom.Count -gt 0) {
        New-Finding -Severity 'Medium' -Category 'Network' -Title 'Uncommon service ports are listening on this host' `
            -Evidence (@($dcom | ForEach-Object { "{0}:{1} ({2}, pid {3})" -f $_.LocalAddress, $_.LocalPort, $_.Process, $_.ProcessId })) `
            -Recommendation 'Identify the owning process for each port; these ranges are common for tunnels and remote shells.' `
            -Mitre @('T1571')
    }

    Add-Section 'Network' ([ordered]@{
        Listening   = $listening
        Established = $established
        NetstatRaw  = ($netstat -split "`r?`n" | Select-Object -First 200)
    })
}

# -------------------------------------------------------------------------
#  MODULE 11 - ARTIFACT COLLECTION
# -------------------------------------------------------------------------
function Invoke-ArtifactCollection {
    if ($script:SkipCollectionMode) {
        Write-Note 'Collection skipped (-SkipCollection).'
        return
    }

    $wantLogs   = ($CollectEventLogs -or $Scope -in @('Standard', 'Deep'))
    $wantHives  = ($CollectRegistryHives -or $Scope -eq 'Deep')
    $wantDeep   = ($Scope -eq 'Deep')

    # --- event logs --------------------------------------------------------
    if ($wantLogs) {
        Write-Sub 'Exporting event logs'
        $logs = @('Security', 'System', 'Application',
                  'Microsoft-Windows-PowerShell/Operational',
                  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
                  'Microsoft-Windows-TaskScheduler/Operational',
                  'Microsoft-Windows-Windows Defender/Operational',
                  'Microsoft-Windows-Sysmon/Operational',
                  'Microsoft-Windows-WinRM/Operational',
                  'Microsoft-Windows-Bits-Client/Operational')
        foreach ($l in $logs) {
            $safe = (ConvertTo-SafeName ($l -replace '[\\/]', '-')) + '.evtx'
            $dest = Join-Path (Join-Path $script:ArtifactDir 'eventlogs') $safe
            try {
                $null = & wevtutil.exe epl "$l" "$dest" /ow:true 2>&1
                if (Test-Path -LiteralPath $dest) {
                    Add-ManifestEntry -LocalPath $dest -SourcePath "eventlog:$l" -Category 'eventlog' -Description "Exported event log $l"
                    Write-Ok "exported $l"
                }
            } catch { Write-Note "could not export $l" }
        }
    }

    # --- registry hives ----------------------------------------------------
    if ($wantHives) {
        Write-Sub 'Exporting registry hives'
        $regDir = Join-Path $script:ArtifactDir 'registry'
        foreach ($pair in @(@('HKLM\SYSTEM', 'SYSTEM'), @('HKLM\SOFTWARE', 'SOFTWARE'),
                            @('HKLM\SAM', 'SAM'), @('HKLM\SECURITY', 'SECURITY'))) {
            $dest = Join-Path $regDir ($pair[1] + '.hiv')
            try {
                $null = & reg.exe save $pair[0] "$dest" /y 2>&1
                if (Test-Path -LiteralPath $dest) {
                    Add-ManifestEntry -LocalPath $dest -SourcePath $pair[0] -Category 'registry-hive' -Description "Registry hive $($pair[1])"
                    Write-Ok "saved $($pair[1]) hive"
                }
            } catch { Write-Note "could not save $($pair[1])" }
        }
        # NTUSER.DAT for each profile (copied, not loaded)
        foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
            $nt = Join-Path $profileDir.FullName 'NTUSER.DAT'
            Copy-Artifact -Path $nt -SubFolder 'registry' -NewName ("NTUSER_" + (ConvertTo-SafeName $profileDir.Name) + ".DAT") `
                          -Category 'registry-hive' -Description "User hive for $($profileDir.Name)" | Out-Null
        }
    }

    # --- execution evidence ------------------------------------------------
    if ($wantDeep) {
        Write-Sub 'Collecting execution evidence'
        $pfDir = Join-Path $env:SystemRoot 'Prefetch'
        if (Test-Path -LiteralPath $pfDir) {
            $count = 0
            foreach ($pf in (Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue |
                             Sort-Object LastWriteTime -Descending | Select-Object -First 400)) {
                Copy-Artifact -Path $pf.FullName -SubFolder 'prefetch' -Category 'prefetch' -Description 'Prefetch execution evidence' | Out-Null
                $count++
            }
            Write-Ok "collected $count prefetch files"
        }
        Copy-Artifact -Path (Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve') -SubFolder 'registry' `
                      -Category 'amcache' -Description 'Amcache - program execution/installation evidence' | Out-Null
        Copy-Artifact -Path (Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat') -SubFolder 'system' `
                      -Category 'srum' -Description 'SRUM database - per-process network usage (useful for exfiltration volume)' | Out-Null
    }

    # --- PowerShell console history ---------------------------------------
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        $hist = Join-Path $profileDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path -LiteralPath $hist) {
            Copy-Artifact -Path $hist -SubFolder 'system' -NewName ("pshistory_" + (ConvertTo-SafeName $profileDir.Name) + ".txt") `
                          -Category 'command-history' -Description "PowerShell console history for $($profileDir.Name)" | Out-Null
            $lines = @(Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue)
            $sus = @($lines | Where-Object { Test-SuspiciousCommand $_ })
            if ($sus.Count -gt 0) {
                New-Finding -Severity 'High' -Category 'Execution' -Title ("Suspicious PowerShell console history for user {0}" -f $profileDir.Name) `
                    -Detail 'PSReadLine keeps a plaintext history of everything typed at a PowerShell prompt by this user, including the intruder if they used this profile.' `
                    -Evidence (@($sus | Select-Object -First 20)) `
                    -Recommendation 'Read the full history file (collected) and add the commands to the intrusion timeline.' `
                    -Mitre @('T1059.001')
            }
        }
    }

    # --- misc system config -------------------------------------------------
    Invoke-Capture -FileName 'quser.txt' -Command 'quser' -Description 'Logged-on users' | Out-Null
    Invoke-Capture -FileName 'ipconfig-all.txt' -Command 'ipconfig /all' -Description 'IP configuration' | Out-Null
    Invoke-Capture -FileName 'driverquery.txt' -Command 'driverquery /v /fo list' -Description 'Installed drivers' | Out-Null
    Invoke-Capture -FileName 'wmic-startup.txt' -Command 'wmic startup get Caption,Command,Location,User /format:list' -Description 'Startup entries per WMI' | Out-Null

    Write-Kv 'Artifacts collected' $script:Manifest.Count
}

# -------------------------------------------------------------------------
#  MODULE 12 - RETURN-TO-SERVICE READINESS
# -------------------------------------------------------------------------
function Add-Check {
    param(
        [string]$Id, [string]$Item,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Manual', 'Unknown')][string]$Status,
        [string]$Detail = '', [string]$Action = '', [string]$Why = ''
    )
    [void]$script:Readiness.Add([pscustomobject]@{
        Id = $Id; Item = $Item; Status = $Status; Detail = $Detail; Action = $Action; Why = $Why
    })
    switch ($Status) {
        'Pass'   { Write-Ok   ("{0}: {1}" -f $Item, $Detail) }
        'Warn'   { Write-Warn ("{0}: {1}" -f $Item, $Detail) }
        'Fail'   { Write-Bad  ("{0}: {1}" -f $Item, $Detail) }
        default  { Write-Note ("{0}: {1}" -f $Item, $Detail) }
    }
}

function Invoke-ReadinessAssessment {
    $f = @($script:Findings)

    # 1 - persistence
    $persist = @($f | Where-Object { $_.Category -eq 'Persistence' -and $_.Severity -in @('Critical', 'High') })
    if ($persist.Count -gt 0) {
        Add-Check -Id 'R01' -Item 'No unexplained persistence on this host' -Status 'Fail' `
            -Detail ("{0} high-severity persistence finding(s) still open" -f $persist.Count) `
            -Action 'Resolve or explain every persistence finding, or rebuild the host from known-good media.' `
            -Why 'A single surviving autostart entry lets the actor back in the moment the host is reconnected.'
    } else {
        Add-Check -Id 'R01' -Item 'No unexplained persistence on this host' -Status 'Pass' `
            -Detail 'Nothing suspicious in the autostart locations checked' `
            -Why 'Checked registry run keys, startup folders, services, drivers, scheduled tasks, WMI subscriptions, LSA/netsh/print/provider DLLs, IFEO and accessibility binaries.'
    }

    # 2 - actor tooling
    $tooling = @($f | Where-Object { $_.Category -in @('Actor tooling', 'Live activity') -and $_.Severity -in @('Critical', 'High') })
    if ($tooling.Count -gt 0) {
        Add-Check -Id 'R02' -Item 'No intrusion tooling left on the host' -Status 'Fail' `
            -Detail ("{0} tooling finding(s) require a decision" -f $tooling.Count) `
            -Action 'Confirm each tool with the client; remove anything unauthorised and re-check after removal.' `
            -Why 'Remote-access and tunnelling tools are re-entry paths that survive credential resets.'
    } else {
        Add-Check -Id 'R02' -Item 'No intrusion tooling left on the host' -Status 'Pass' -Detail 'No known intrusion utilities matched'
    }

    # 3 - endpoint protection
    $posture = $script:Sections['SecurityPosture']
    $epOk = $false
    $epDetail = 'Endpoint protection state unknown'
    if ($posture -and $posture['Defender'] -and $posture['Defender'].RealTimeProtection) {
        $epOk = $true
        $epDetail = 'Defender real-time protection is on'
        if ($posture['Defender'].SignatureAgeDays -gt 3) { $epOk = $false; $epDetail = ("Defender signatures are {0} days old" -f $posture['Defender'].SignatureAgeDays) }
    }
    $agents = @()
    if ($posture -and $posture['SecurityAgents']) { $agents = @($posture['SecurityAgents'] | Where-Object { $_.State -eq 'Running' }) }
    if ($agents.Count -gt 0) { $epOk = $true; $epDetail += ("; {0} third-party agent(s) running" -f $agents.Count) }
    Add-Check -Id 'R03' -Item 'Endpoint protection is healthy and current' -Status $(if ($epOk) { 'Pass' } else { 'Fail' }) `
        -Detail $epDetail `
        -Action 'Enable real-time protection and tamper protection, update signatures, and confirm the EDR agent reports into the console.' `
        -Why 'The host will be reconnected to a network that may still contain the actor.'

    # 4 - firewall
    $fwOff = @()
    if ($posture -and $posture['Firewall']) { $fwOff = @($posture['Firewall'] | Where-Object { "$($_.Enabled)" -eq 'False' }) }
    Add-Check -Id 'R04' -Item 'Host firewall enabled on all profiles' -Status $(if ($fwOff.Count -eq 0) { 'Pass' } else { 'Fail' }) `
        -Detail $(if ($fwOff.Count -eq 0) { 'All profiles enabled' } else { ("Disabled profiles: " + (($fwOff | ForEach-Object { $_.Profile }) -join ', ')) }) `
        -Action 'Re-enable the firewall on every profile.'

    # 5 - accounts
    $acct = @($f | Where-Object { $_.Category -eq 'Accounts' -and $_.Severity -in @('Critical', 'High') })
    Add-Check -Id 'R05' -Item 'Local accounts and administrators reconciled' -Status $(if ($acct.Count -gt 0) { 'Fail' } else { 'Manual' }) `
        -Detail $(if ($acct.Count -gt 0) { ("{0} account finding(s) open" -f $acct.Count) } else { 'No automated account red flags - still needs client sign-off' }) `
        -Action 'Walk the local user and administrator list with the client and confirm every entry is expected.' `
        -Why 'Account creation is the cheapest persistence there is and looks like normal administration in logs.'

    # 6 - credential rotation
    $krb = $null
    if ($script:Sections['Accounts']) { $krb = $script:Sections['Accounts'].KrbtgtPasswordLastSet }
    $krbStatus = 'Manual'
    $krbDetail = 'Credential rotation must be confirmed by the client'
    if ($krb) {
        if (Test-InIncidentWindow $krb) { $krbStatus = 'Pass'; $krbDetail = "krbtgt password reset on $krb" }
        else { $krbStatus = 'Fail'; $krbDetail = "krbtgt password last set $krb - before the incident window" }
    }
    Add-Check -Id 'R06' -Item 'Credentials rotated (local, domain, service, krbtgt x2)' -Status $krbStatus -Detail $krbDetail `
        -Action 'Reset every credential used in this environment, including service accounts and krbtgt twice with replication between resets.' `
        -Why 'Akira harvests credentials before encrypting; unrotated credentials make everything else pointless.'

    # 7 - recovery position
    $rec = $script:Sections['Recovery']
    $shadowCount = 0
    if ($rec) { $shadowCount = [int]$rec.ShadowCopyCount }
    Add-Check -Id 'R07' -Item 'Recovery position understood and backups verified' -Status 'Manual' `
        -Detail ("{0} shadow copies on this host" -f $shadowCount) `
        -Action 'Verify backups restore cleanly from offline/immutable copies, and that the backup system credentials have been rotated.' `
        -Why 'Backup infrastructure is targeted before encryption in most Akira cases.'

    # 8 - encrypted data still present
    $encCount = 0
    if ($script:Sections['Encryption']) { $encCount = [int]$script:Sections['Encryption'].EncryptedFileCount }
    if ($encCount -gt 0) {
        Add-Check -Id 'R08' -Item 'Encrypted data removed or restored on this host' -Status 'Warn' `
            -Detail ("{0:N0} encrypted files still on disk" -f $encCount) `
            -Action 'Decide per system: restore from backup, keep encrypted files for a possible decryptor, or rebuild. Record the decision.' `
            -Why 'Leaving encrypted data in production paths confuses users and future investigations.'
    } else {
        Add-Check -Id 'R08' -Item 'Encrypted data removed or restored on this host' -Status 'Pass' -Detail 'No encrypted files found in the scanned scope'
    }

    # 9 - visibility
    $vis = @($f | Where-Object { $_.Category -in @('Visibility', 'Anti-forensics') })
    Add-Check -Id 'R09' -Item 'Logging and visibility restored' -Status $(if ($vis.Count -gt 0) { 'Warn' } else { 'Pass' }) `
        -Detail $(if ($vis.Count -gt 0) { ("{0} visibility gap(s) recorded" -f $vis.Count) } else { 'No log gaps detected in the review window' }) `
        -Action 'Enable PowerShell script block logging, raise Security log size, and forward logs off-host before reconnecting.' `
        -Why 'If it happens again, the client needs the evidence this incident did not have.'

    # 10 - remote access exposure
    $rdp = $null
    if ($posture) { $rdp = $posture['RDP'] }
    $rdpStatus = 'Pass'
    $rdpDetail = 'RDP disabled'
    if ($rdp -and $rdp.RdpEnabled) {
        if ($rdp.NlaEnabled) { $rdpStatus = 'Warn'; $rdpDetail = 'RDP enabled with NLA' }
        else { $rdpStatus = 'Fail'; $rdpDetail = 'RDP enabled without NLA' }
    }
    Add-Check -Id 'R10' -Item 'Remote access surface minimised' -Status $rdpStatus -Detail $rdpDetail `
        -Action 'Restrict RDP to jump hosts, require NLA and MFA, and remove any actor-installed remote access tooling.' `
        -Why 'Remote access without MFA is the most common Akira entry point.'

    # 11 - hardening regressions
    $hardIssues = @()
    if ($posture -and $posture['Hardening']) {
        if ($posture['Hardening'].WDigestUseLogonCredential -eq 1) { $hardIssues += 'WDigest plaintext credentials enabled' }
        if ($posture['Hardening'].LocalAccountTokenFilterPolicy -eq 1) { $hardIssues += 'LocalAccountTokenFilterPolicy enabled' }
        if ($posture['Hardening'].EnableLUA -eq 0) { $hardIssues += 'UAC disabled' }
    }
    if ($posture -and $posture['SMB'] -and $posture['SMB'].SMB1Enabled) { $hardIssues += 'SMBv1 enabled' }
    Add-Check -Id 'R11' -Item 'Attacker-friendly settings reverted' -Status $(if ($hardIssues.Count -gt 0) { 'Fail' } else { 'Pass' }) `
        -Detail $(if ($hardIssues.Count -gt 0) { ($hardIssues -join '; ') } else { 'No credential-exposure or lateral-movement settings found' }) `
        -Action 'Revert each setting and confirm it is enforced by policy, not left to the local machine.'

    # 12 - patching
    $patchStatus = 'Manual'
    $patchDetail = 'Patch level not established'
    if ($posture -and $posture['RecentHotfixes'] -and @($posture['RecentHotfixes']).Count -gt 0) {
        $last = @($posture['RecentHotfixes'])[0].InstalledOn
        if ($last) {
            $age = (New-TimeSpan -Start $last -End (Get-Date)).TotalDays
            $patchDetail = ("Last hotfix {0:yyyy-MM-dd} ({1:N0} days ago)" -f $last, $age)
            $patchStatus = $(if ($age -le 45) { 'Pass' } else { 'Warn' })
        }
    }
    Add-Check -Id 'R12' -Item 'Operating system patched' -Status $patchStatus -Detail $patchDetail `
        -Action 'Patch the host, and treat perimeter VPN/firewall firmware as the higher priority.'

    # 13 - pending reboot
    if ($posture -and $posture['PendingReboot']) {
        Add-Check -Id 'R13' -Item 'No pending reboot' -Status 'Warn' -Detail 'A reboot is pending; some changes are not yet in effect' `
            -Action 'Reboot before final verification so protection and policy changes are actually applied.'
    } else {
        Add-Check -Id 'R13' -Item 'No pending reboot' -Status 'Pass' -Detail 'No reboot pending'
    }

    # 14+ - environment-level items this tool cannot see from one host
    Add-Check -Id 'R14' -Item 'Initial access vector identified and closed' -Status 'Manual' `
        -Detail 'Not determinable from a single host' `
        -Action 'Confirm the perimeter device (VPN/firewall) firmware is current, MFA is enforced on every remote path, and any exposed service is patched.' `
        -Why 'Akira intrusions typically start at an unpatched or MFA-less VPN; reconnecting before that is closed invites a repeat.'
    Add-Check -Id 'R15' -Item 'Whole-environment sweep completed' -Status 'Manual' `
        -Detail 'This report covers one host only' `
        -Action 'Run this tool on every reachable server and a representative sample of workstations, and reconcile the results.' `
        -Why 'Akira usually touches domain controllers, backup servers and hypervisors before the endpoints.'
    Add-Check -Id 'R16' -Item 'Data exfiltration assessed for notification obligations' -Status 'Manual' `
        -Detail $(if ($script:BehaviourHits['exfil-tool']) { 'Transfer tooling or configuration was found on this host' } else { 'No exfiltration tooling found on this host' }) `
        -Action 'Review firewall/proxy egress logs for the incident window and confirm with legal whether notification thresholds are met.' `
        -Why 'Akira operates double extortion - encryption is the second half of the incident.'
    Add-Check -Id 'R17' -Item 'Monitoring in place for re-entry' -Status 'Manual' `
        -Detail 'Post-incident monitoring is an environment-level control' `
        -Action 'Keep heightened monitoring and alerting on the entry vector, admin accounts and the tooling names in this report for at least 30 days after go-live.'

    $fail = @($script:Readiness | Where-Object { $_.Status -eq 'Fail' })
    $warn = @($script:Readiness | Where-Object { $_.Status -eq 'Warn' })
    $manual = @($script:Readiness | Where-Object { $_.Status -eq 'Manual' })

    $verdict = 'READY WITH CONDITIONS'
    $verdictClass = 'warn'
    $verdictText = 'No blocking host-level issues were found. The manual items below must be signed off before this host is reconnected.'
    if ($fail.Count -gt 0) {
        $verdict = 'NOT READY'
        $verdictClass = 'fail'
        $verdictText = ("{0} blocking issue(s) must be resolved before this host is reconnected." -f $fail.Count)
    } elseif ($warn.Count -eq 0 -and $manual.Count -eq 0) {
        $verdict = 'READY'
        $verdictClass = 'pass'
        $verdictText = 'All host-level checks passed.'
    }

    Write-Head ("READINESS: {0}" -f $verdict)
    Write-Kv 'Blocking issues'  $fail.Count
    Write-Kv 'Warnings'         $warn.Count
    Write-Kv 'Manual sign-offs' $manual.Count

    Add-Section 'Readiness' ([ordered]@{
        Verdict      = $verdict
        VerdictClass = $verdictClass
        VerdictText  = $verdictText
        Blocking     = $fail.Count
        Warnings     = $warn.Count
        ManualItems  = $manual.Count
        Checklist    = @($script:Readiness)
        Scope        = 'Single host. This is a host-level readiness opinion, not a certification that the environment is free of the actor.'
    })
}

# -------------------------------------------------------------------------
#  REPORTING
# -------------------------------------------------------------------------
function HtmlEnc {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HtmlTable {
    param($Rows, [string[]]$Columns, [string]$EmptyText = 'Nothing recorded.')
    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return "<p class='muted'>$(HtmlEnc $EmptyText)</p>" }
    if (-not $Columns -or $Columns.Count -eq 0) {
        $Columns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tablewrap'><table><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(HtmlEnc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $null
            try { $v = $r.$c } catch { }
            if ($v -is [System.Array]) { $v = ($v -join ' | ') }
            [void]$sb.Append("<td>$(HtmlEnc $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-HtmlKv {
    param($Data, [string[]]$Keys)
    if (-not $Data) { return "<p class='muted'>Not available.</p>" }
    if (-not $Keys) { $Keys = @($Data.Keys) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<dl class='kv'>")
    foreach ($k in $Keys) {
        $v = $Data[$k]
        if ($v -is [System.Array]) { continue }
        if ($null -eq $v -or "$v" -eq '') { $v = '-' }
        [void]$sb.Append("<div><dt>$(HtmlEnc $k)</dt><dd>$(HtmlEnc $v)</dd></div>")
    }
    [void]$sb.Append('</dl>')
    return $sb.ToString()
}

function Get-SeverityCounts {
    $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $script:Findings) { $counts[$f.Severity] = [int]$counts[$f.Severity] + 1 }
    return $counts
}

function Write-HtmlReport {
    param([string]$Path, $Meta)

    $counts    = Get-SeverityCounts
    $readiness = $script:Sections['Readiness']
    $enc       = $script:Sections['Encryption']
    $variant   = $script:Sections['VariantAssessment']
    $hostInfo  = $script:Sections['HostProfile']
    $persist   = $script:Sections['Persistence']
    $tooling   = $script:Sections['ActorTooling']
    $recovery  = $script:Sections['Recovery']
    $events    = $script:Sections['EventLogTriage']

    $css = @'
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#14161a;--muted:#5c636e;--line:#e3e6ea;
--crit:#b3121f;--high:#d1481b;--med:#a8760a;--low:#4a6b8a;--info:#5c636e;
--pass:#1f7a4d;--warn:#a8760a;--fail:#b3121f;--accent:#1f3d5c;}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1c1f25;--ink:#e8eaed;--muted:#9aa2ad;--line:#2b2f37;
--crit:#ff6b6b;--high:#ff9f5a;--med:#e8c05a;--low:#8ab4d8;--info:#9aa2ad;
--pass:#5cc98d;--warn:#e8c05a;--fail:#ff6b6b;--accent:#8ab4d8;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1140px;margin:0 auto;padding:32px 20px 80px}
header.top{border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:26px}
h1{font-size:27px;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:20px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
p{margin:8px 0}
.muted{color:var(--muted)}
.sub{color:var(--muted);font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.verdict{border-radius:12px;padding:20px 22px;margin:18px 0 6px;border:1px solid var(--line);background:var(--card);
border-left:8px solid var(--info)}
.verdict.pass{border-left-color:var(--pass)}
.verdict.warn{border-left-color:var(--warn)}
.verdict.fail{border-left-color:var(--fail)}
.verdict h2{border:0;margin:0 0 6px;font-size:24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile .n{font-size:24px;font-weight:650;letter-spacing:-.02em}
.tile .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;padding:10px 12px;background:rgba(127,127,127,.08);font-weight:600;white-space:nowrap}
td{padding:9px 12px;border-top:1px solid var(--line);vertical-align:top}
td:first-child{white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:650;letter-spacing:.03em;
text-transform:uppercase;border:1px solid currentColor}
.s-critical{color:var(--crit)}.s-high{color:var(--high)}.s-medium{color:var(--med)}.s-low{color:var(--low)}.s-info{color:var(--info)}
.s-pass{color:var(--pass)}.s-warn{color:var(--warn)}.s-fail{color:var(--fail)}.s-manual{color:var(--low)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:0}
details>summary{cursor:pointer;padding:12px 16px;font-weight:600;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
details>summary::-webkit-details-marker{display:none}
details>summary:before{content:"\25B8";color:var(--muted);font-size:12px}
details[open]>summary:before{content:"\25BE"}
details .body{padding:0 16px 14px 16px;border-top:1px solid var(--line)}
pre{background:rgba(127,127,127,.09);padding:10px 12px;border-radius:8px;overflow-x:auto;font-size:12.5px;
font-family:ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
dl.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2px 18px;margin:6px 0}
dl.kv>div{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid var(--line)}
dl.kv dt{color:var(--muted);font-size:13px}
dl.kv dd{margin:0;font-size:13px;text-align:right;word-break:break-word}
.bar{height:7px;border-radius:4px;background:rgba(127,127,127,.2);overflow:hidden;margin-top:5px}
.bar span{display:block;height:100%;background:var(--accent)}
ul.tight{margin:6px 0;padding-left:20px}
ul.tight li{margin:3px 0}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
@media print{body{background:#fff}.card,.tablewrap,details{break-inside:avoid}details{border:0}details>.body{display:block!important}}
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>Akira Escape Report - $(HtmlEnc $Meta.Hostname)</title>")
    [void]$sb.AppendLine("<style>$css</style>")
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine("<div class='wrap'>")

    # header
    [void]$sb.AppendLine("<header class='top'>")
    [void]$sb.AppendLine("<h1>Akira Escape Tool - incident triage report</h1>")
    [void]$sb.AppendLine("<p class='sub'>$(HtmlEnc $Meta.Hostname) &middot; case $(HtmlEnc $Meta.CaseId) &middot; collected $(HtmlEnc $Meta.Started) &middot; operator $(HtmlEnc $Meta.Operator)</p>")
    [void]$sb.AppendLine("<p class='sub'>Read-only triage. No files were removed, no processes stopped, no configuration changed on this host.</p>")
    [void]$sb.AppendLine("</header>")

    # verdict
    if ($readiness) {
        [void]$sb.AppendLine("<div class='verdict $(HtmlEnc $readiness.VerdictClass)'>")
        [void]$sb.AppendLine("<h2>Return to service: $(HtmlEnc $readiness.Verdict)</h2>")
        [void]$sb.AppendLine("<p>$(HtmlEnc $readiness.VerdictText)</p>")
        [void]$sb.AppendLine("<p class='sub'>$(HtmlEnc $readiness.Scope)</p>")
        [void]$sb.AppendLine("</div>")
    }

    # tiles
    $encCount = 0; $noteCount = 0
    if ($enc) { $encCount = [int]$enc.EncryptedFileCount; $noteCount = [int]$enc.RansomNoteCount }
    [void]$sb.AppendLine("<div class='tiles'>")
    foreach ($t in @(
        @{ n = ('{0:N0}' -f $encCount);        l = 'Encrypted files' },
        @{ n = ('{0:N0}' -f $noteCount);       l = 'Ransom notes' },
        @{ n = $counts.Critical;               l = 'Critical findings' },
        @{ n = $counts.High;                   l = 'High findings' },
        @{ n = $counts.Medium;                 l = 'Medium findings' },
        @{ n = $script:Manifest.Count;         l = 'Artifacts collected' })) {
        [void]$sb.AppendLine("<div class='tile'><div class='n'>$(HtmlEnc $t.n)</div><div class='l'>$(HtmlEnc $t.l)</div></div>")
    }
    [void]$sb.AppendLine("</div>")

    # variant
    [void]$sb.AppendLine("<h2>Which Akira is this?</h2>")
    if ($variant -and @($variant.Ranked).Count -gt 0) {
        foreach ($r in (@($variant.Ranked) | Where-Object { $_.Confidence -gt 0 })) {
            [void]$sb.AppendLine("<div class='card'>")
            [void]$sb.AppendLine("<strong>$(HtmlEnc $r.Variant)</strong> <span class='sub'>&middot; $(HtmlEnc $r.Platform) &middot; $(HtmlEnc $r.Language) &middot; first seen $(HtmlEnc $r.FirstSeen)</span>")
            [void]$sb.AppendLine("<div class='bar'><span style='width:$([int]$r.Confidence)%'></span></div>")
            [void]$sb.AppendLine("<p class='sub'>Confidence $(HtmlEnc $r.Confidence)%</p>")
            if (@($r.Supporting).Count) {
                [void]$sb.AppendLine("<ul class='tight'>")
                foreach ($s in @($r.Supporting)) { [void]$sb.AppendLine("<li>$(HtmlEnc $s)</li>") }
                [void]$sb.AppendLine("</ul>")
            }
            [void]$sb.AppendLine("<p class='sub'>$(HtmlEnc $r.Notes)</p>")
            [void]$sb.AppendLine("</div>")
        }
        [void]$sb.AppendLine("<p class='sub'>$(HtmlEnc $variant.Caveat)</p>")
    } else {
        [void]$sb.AppendLine("<p class='muted'>No encryption artefacts were found on this host, so no variant assessment was made.</p>")
    }

    # findings
    [void]$sb.AppendLine("<h2>Findings</h2>")
    $ordered = @($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Category)
    if ($ordered.Count -eq 0) {
        [void]$sb.AppendLine("<p class='muted'>No findings were recorded.</p>")
    }
    foreach ($f in $ordered) {
        $cls = 's-' + $f.Severity.ToLower()
        $openAttr = ''
        if ($f.Severity -in @('Critical', 'High')) { $openAttr = ' open' }
        [void]$sb.AppendLine("<details$openAttr><summary><span class='pill $cls'>$(HtmlEnc $f.Severity)</span> <span>$(HtmlEnc $f.Title)</span> <span class='sub'>$(HtmlEnc $f.Category) &middot; $(HtmlEnc $f.Id)</span></summary><div class='body'>")
        if ($f.Detail)  { [void]$sb.AppendLine("<p>$(HtmlEnc $f.Detail)</p>") }
        if (@($f.Evidence).Count) {
            [void]$sb.AppendLine("<h3>Evidence</h3><pre>$(HtmlEnc ((@($f.Evidence)) -join [Environment]::NewLine))</pre>")
        }
        if ($f.Recommendation) { [void]$sb.AppendLine("<h3>What to do</h3><p>$(HtmlEnc $f.Recommendation)</p>") }
        if (@($f.Mitre).Count)  { [void]$sb.AppendLine("<p class='sub'>ATT&amp;CK: $(HtmlEnc ((@($f.Mitre)) -join ', '))</p>") }
        [void]$sb.AppendLine("</div></details>")
    }

    # readiness checklist
    [void]$sb.AppendLine("<h2>Return-to-service checklist</h2>")
    if ($readiness) {
        [void]$sb.AppendLine("<div class='tablewrap'><table><thead><tr><th>#</th><th>Status</th><th>Item</th><th>Detail</th><th>Action</th></tr></thead><tbody>")
        foreach ($c in @($readiness.Checklist)) {
            $cls = 's-' + $c.Status.ToLower()
            [void]$sb.AppendLine("<tr><td>$(HtmlEnc $c.Id)</td><td><span class='pill $cls'>$(HtmlEnc $c.Status)</span></td><td>$(HtmlEnc $c.Item)</td><td>$(HtmlEnc $c.Detail)</td><td>$(HtmlEnc $c.Action)</td></tr>")
        }
        [void]$sb.AppendLine("</tbody></table></div>")
    }

    # encryption detail
    if ($enc) {
        [void]$sb.AppendLine("<h2>Encryption footprint</h2>")
        [void]$sb.AppendLine((New-HtmlKv -Data $enc -Keys @('EncryptedFileCount', 'EncryptedGB', 'RansomNoteCount',
                              'EarliestEncryptedUtc', 'LatestEncryptedUtc', 'IncidentWindowStart', 'IncidentWindowSource')))
        [void]$sb.AppendLine("<h3>Extensions observed</h3>")
        [void]$sb.AppendLine((New-HtmlTable -Rows $enc.ExtensionBreakdown -EmptyText 'No encrypted files were found in the scanned scope.'))
        [void]$sb.AppendLine("<h3>Worst-hit folders</h3>")
        [void]$sb.AppendLine((New-HtmlTable -Rows $enc.TopEncryptedFolders -EmptyText 'None.'))
        [void]$sb.AppendLine("<h3>Ransom notes</h3>")
        [void]$sb.AppendLine((New-HtmlTable -Rows (@($enc.RansomNoteVariants | ForEach-Object {
            [pscustomobject]@{ FileName = $_.FileName; Copies = $_.Copies; SHA256 = $_.SHA256
                               Markers = (@($_.Markers) -join ', '); Onion = (@($_.OnionAddresses) -join ', ') } })) -EmptyText 'No ransom notes were found.'))
        $firstNote = @($enc.RansomNoteVariants) | Select-Object -First 1
        if ($firstNote -and $firstNote.Text) {
            [void]$sb.AppendLine("<h3>Note text (as recovered)</h3><pre>$(HtmlEnc ($firstNote.Text.Substring(0, [math]::Min(3000, $firstNote.Text.Length))))</pre>")
        }
    }

    # persistence
    if ($persist) {
        [void]$sb.AppendLine("<h2>Persistence sweep</h2>")
        [void]$sb.AppendLine("<p class='sub'>$(HtmlEnc $persist.Caveat)</p>")
        [void]$sb.AppendLine((New-HtmlTable -Rows (@($persist.SuspiciousEntries | ForEach-Object {
            [pscustomobject]@{ Suspicion = $_.Suspicion; Type = $_.Type; Name = $_.Name; Command = $_.Command
                               Signature = $_.Signature; Created = $_.FileCreated; Why = (@($_.Reasons) -join '; ') } })) `
            -EmptyText 'No suspicious autostart entries were identified.'))
        $vuln = @($persist.Drivers | Where-Object { $_.KnownVulnerable })
        if ($vuln.Count -gt 0) {
            [void]$sb.AppendLine("<h3>Known-abusable drivers</h3>")
            [void]$sb.AppendLine((New-HtmlTable -Rows $vuln))
        }
        if (@($persist.WmiSubscriptions).Count -gt 0) {
            [void]$sb.AppendLine("<h3>WMI subscriptions</h3>")
            [void]$sb.AppendLine((New-HtmlTable -Rows $persist.WmiSubscriptions))
        }
    }

    # tooling
    if ($tooling) {
        [void]$sb.AppendLine("<h2>Intrusion tooling</h2>")
        [void]$sb.AppendLine((New-HtmlTable -Rows (@($tooling.ToolHits | ForEach-Object {
            [pscustomobject]@{ Tool = $_.Tool; Category = $_.Category; Sightings = (@($_.Sightings) -join ' | ') } })) `
            -EmptyText 'No known intrusion tooling matched on this host.'))
        if (@($tooling.ExfilConfigFiles).Count -gt 0) {
            [void]$sb.AppendLine("<h3>Transfer tool configuration files</h3>")
            [void]$sb.AppendLine((New-HtmlTable -Rows $tooling.ExfilConfigFiles))
        }
    }

    # recovery + events
    if ($recovery) {
        [void]$sb.AppendLine("<h2>Recovery position</h2>")
        [void]$sb.AppendLine((New-HtmlKv -Data $recovery -Keys @('ShadowCopyCount', 'RecoveryDisabled')))
        [void]$sb.AppendLine((New-HtmlTable -Rows $recovery.BackupServices -EmptyText 'No backup software services found on this host.'))
    }
    if ($events) {
        [void]$sb.AppendLine("<h2>Event log triage</h2>")
        [void]$sb.AppendLine((New-HtmlTable -Rows (@($events.Summary | Where-Object { $_.Count -gt 0 })) -EmptyText 'No triaged events in the review window.'))
        [void]$sb.AppendLine("<h3>Log coverage</h3>")
        [void]$sb.AppendLine((New-HtmlTable -Rows $events.LogCoverage))
    }

    # host + artifacts
    [void]$sb.AppendLine("<h2>Host</h2>")
    [void]$sb.AppendLine((New-HtmlKv -Data $hostInfo -Keys @('Hostname', 'FQDN', 'Domain', 'DomainRole', 'OperatingSystem',
                          'OSBuild', 'Virtualisation', 'LastBoot', 'UptimeDays', 'TimeZone', 'LocalTime', 'UtcTime', 'RunningUser')))
    [void]$sb.AppendLine("<h2>Evidence collected</h2>")
    [void]$sb.AppendLine("<p class='sub'>Every file below was hashed at collection time. The manifest is also written as collection-manifest.csv.</p>")
    [void]$sb.AppendLine((New-HtmlTable -Rows (@($script:Manifest | Select-Object Category, File, SizeBytes, SHA256)) -EmptyText 'Collection was skipped for this run.'))

    # methodology
    [void]$sb.AppendLine("<h2>Method and limits</h2>")
    [void]$sb.AppendLine("<div class='card'><ul class='tight'>")
    foreach ($line in @(
        'The tool reads; it never writes to the host under examination. Nothing was quarantined, deleted or reconfigured.',
        'Variant identification is heuristic, from ransom note names and contents, appended extensions and host behaviour. The C++ and Rust Akira lines both use .akira and akira_readme.txt and can only be separated by analysing the encryptor binary.',
        'A clean persistence result means nothing was found in the locations checked. It is not proof the host is clean - only a rebuild from known-good media gives that.',
        'File system results are bounded by the scan scope and time budget recorded above. Where a scan was truncated, counts are a floor.',
        'This is a single-host assessment. Environment-wide readiness depends on the manual items in the checklist.')) {
        [void]$sb.AppendLine("<li>$(HtmlEnc $line)</li>")
    }
    [void]$sb.AppendLine("</ul></div>")
    [void]$sb.AppendLine("<h3>Modules run</h3>")
    [void]$sb.AppendLine((New-HtmlTable -Rows $script:ModuleStatus))

    [void]$sb.AppendLine("<footer>Generated by $(HtmlEnc $script:ToolName) $(HtmlEnc $script:ToolVersion) on $(HtmlEnc $Meta.Finished). Tool SHA-256: $(HtmlEnc $Meta.ToolSha256).</footer>")
    [void]$sb.AppendLine('</div></body></html>')

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 -Force
}

function Write-MarkdownReport {
    param([string]$Path, $Meta)
    $counts    = Get-SeverityCounts
    $readiness = $script:Sections['Readiness']
    $enc       = $script:Sections['Encryption']
    $variant   = $script:Sections['VariantAssessment']

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# Akira Escape Tool - triage report")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Host:** $($Meta.Hostname)  ")
    [void]$sb.AppendLine("**Case:** $($Meta.CaseId)  ")
    [void]$sb.AppendLine("**Operator:** $($Meta.Operator)  ")
    [void]$sb.AppendLine("**Collected:** $($Meta.Started) to $($Meta.Finished)  ")
    [void]$sb.AppendLine("**Scope:** $($Meta.Scope)  ")
    [void]$sb.AppendLine('')
    if ($readiness) {
        [void]$sb.AppendLine("## Verdict: $($readiness.Verdict)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine($readiness.VerdictText)
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("Blocking: $($readiness.Blocking) | Warnings: $($readiness.Warnings) | Manual sign-offs: $($readiness.ManualItems)")
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Metric | Value |")
    [void]$sb.AppendLine("|---|---|")
    if ($enc) {
        [void]$sb.AppendLine("| Encrypted files | $('{0:N0}' -f [int]$enc.EncryptedFileCount) |")
        [void]$sb.AppendLine("| Encrypted data | $($enc.EncryptedGB) GB |")
        [void]$sb.AppendLine("| Ransom notes | $('{0:N0}' -f [int]$enc.RansomNoteCount) |")
        [void]$sb.AppendLine("| Encryption window | $($enc.EarliestEncryptedUtc) to $($enc.LatestEncryptedUtc) UTC |")
    }
    foreach ($k in $counts.Keys) { [void]$sb.AppendLine("| $k findings | $($counts[$k]) |") }
    [void]$sb.AppendLine("| Artifacts collected | $($script:Manifest.Count) |")
    [void]$sb.AppendLine('')

    if ($variant -and @($variant.Ranked).Count -gt 0) {
        [void]$sb.AppendLine("## Variant assessment")
        [void]$sb.AppendLine('')
        foreach ($r in (@($variant.Ranked) | Where-Object { $_.Confidence -gt 0 })) {
            [void]$sb.AppendLine("### $($r.Variant) - $($r.Confidence)% confidence")
            [void]$sb.AppendLine('')
            foreach ($s in @($r.Supporting)) { [void]$sb.AppendLine("- $s") }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("$($r.Notes)")
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine("> $($variant.Caveat)")
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine("## Findings")
    [void]$sb.AppendLine('')
    foreach ($f in (@($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Category))) {
        [void]$sb.AppendLine("### [$($f.Severity)] $($f.Title)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("*$($f.Category) - $($f.Id)*")
        [void]$sb.AppendLine('')
        if ($f.Detail) { [void]$sb.AppendLine("$($f.Detail)"); [void]$sb.AppendLine('') }
        if (@($f.Evidence).Count) {
            [void]$sb.AppendLine('```')
            foreach ($e in @($f.Evidence)) { [void]$sb.AppendLine("$e") }
            [void]$sb.AppendLine('```')
            [void]$sb.AppendLine('')
        }
        if ($f.Recommendation) { [void]$sb.AppendLine("**What to do:** $($f.Recommendation)"); [void]$sb.AppendLine('') }
    }

    if ($readiness) {
        [void]$sb.AppendLine("## Return-to-service checklist")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("| # | Status | Item | Detail | Action |")
        [void]$sb.AppendLine("|---|---|---|---|---|")
        foreach ($c in @($readiness.Checklist)) {
            [void]$sb.AppendLine("| $($c.Id) | $($c.Status) | $($c.Item) | $($c.Detail) | $($c.Action) |")
        }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine("## Evidence manifest")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Category | File | SHA-256 |")
    [void]$sb.AppendLine("|---|---|---|")
    foreach ($m in $script:Manifest) { [void]$sb.AppendLine("| $($m.Category) | $($m.File) | $($m.SHA256) |") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("Generated by $script:ToolName $script:ToolVersion. Read-only triage: nothing on the host was changed.")

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 -Force
}

function Write-AiHandoff {
    param([string]$Path, $Meta, [string]$JsonPath)

    $counts    = Get-SeverityCounts
    $readiness = $script:Sections['Readiness']
    $enc       = $script:Sections['Encryption']
    $variant   = $script:Sections['VariantAssessment']

    $hp = $script:Sections['HostProfile']
    $compact = [ordered]@{
        case = [ordered]@{
            caseId = $Meta.CaseId; operator = $Meta.Operator; hostname = $Meta.Hostname
            domain = $(if ($hp) { $hp.Domain } else { '' }); role = $(if ($hp) { $hp.DomainRole } else { '' })
            os = $(if ($hp) { $hp.OperatingSystem } else { '' })
            collectedFrom = $Meta.Started; collectedTo = $Meta.Finished; scope = $Meta.Scope
        }
        verdict = $(if ($readiness) { [ordered]@{ verdict = $readiness.Verdict; text = $readiness.VerdictText
                     blocking = $readiness.Blocking; warnings = $readiness.Warnings; manual = $readiness.ManualItems } } else { $null })
        encryption = $(if ($enc) { [ordered]@{
                     encryptedFiles = $enc.EncryptedFileCount; encryptedGB = $enc.EncryptedGB
                     ransomNotes = $enc.RansomNoteCount; extensions = $enc.ExtensionBreakdown
                     earliestUtc = $enc.EarliestEncryptedUtc; latestUtc = $enc.LatestEncryptedUtc
                     noteVariants = @($enc.RansomNoteVariants | ForEach-Object {
                         [ordered]@{ fileName = $_.FileName; sha256 = $_.SHA256; copies = $_.Copies
                                     markers = @($_.Markers); onion = @($_.OnionAddresses) } })
                     topFolders = @($enc.TopEncryptedFolders | Select-Object -First 10) } } else { $null })
        variant = $(if ($variant) { [ordered]@{
                     ranked = @($variant.Ranked | Where-Object { $_.Confidence -gt 0 } | Select-Object -First 3 |
                               ForEach-Object { [ordered]@{ variant = $_.Variant; confidence = $_.Confidence
                                                            platform = $_.Platform; language = $_.Language
                                                            supporting = @($_.Supporting) } })
                     observedBehaviours = @($variant.ObservedBehaviours)
                     caveat = $variant.Caveat } } else { $null })
        findingCounts = $counts
        findings = @($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] } | ForEach-Object {
                        [ordered]@{ id = $_.Id; severity = $_.Severity; category = $_.Category; title = $_.Title
                                    detail = $_.Detail; recommendation = $_.Recommendation
                                    evidence = @($_.Evidence | Select-Object -First 12); mitre = @($_.Mitre) } })
        readinessChecklist = $(if ($readiness) { @($readiness.Checklist) } else { @() })
        artifactsCollected = $script:Manifest.Count
        modulesRun = @($script:ModuleStatus)
    }

    $json = $compact | ConvertTo-Json -Depth 8

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Akira Escape Tool - AI handoff')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Paste this whole file into Claude to turn the triage data into a written report.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Prompt')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> You are helping an incident responder write up a single-host triage from an Akira ransomware engagement.')
    [void]$sb.AppendLine('> The JSON below is the tool output. Write a client-facing report with these sections:')
    [void]$sb.AppendLine('>')
    [void]$sb.AppendLine('> 1. **Executive summary** - three short paragraphs, no jargon: what happened to this host, what was found, whether it can go back online.')
    [void]$sb.AppendLine('> 2. **What we found** - the encryption footprint, the ransomware variant assessment (state the confidence and the caveat), and the intrusion behaviours evidenced.')
    [void]$sb.AppendLine('> 3. **Timeline** - build it from the encryption window, event log findings and file timestamps present in the data. Say plainly where the data does not support a timeline.')
    [void]$sb.AppendLine('> 4. **Persistence and remaining risk** - what is still on the host, ranked, each with the concrete action.')
    [void]$sb.AppendLine('> 5. **Return-to-service assessment** - reproduce the checklist as a table, keep the Pass/Warn/Fail/Manual status, and state the verdict prominently.')
    [void]$sb.AppendLine('> 6. **Recommendations** - split into "before this host reconnects" and "before the environment is considered recovered".')
    [void]$sb.AppendLine('> 7. **Evidence and method** - what was collected, that the tool was read-only, and the stated limits.')
    [void]$sb.AppendLine('>')
    [void]$sb.AppendLine('> Rules: do not invent findings that are not in the JSON; keep every stated confidence level and caveat; where the data is inconclusive, say so; write for a client executive with a technical appendix.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Data')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('```json')
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Full detail, including every collected artifact and its hash, is in findings.json next to this file.")

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 -Force
}

function Write-Reports {
    $finished = Get-Date
    $toolSha = $null
    if ($PSCommandPath) { $toolSha = Get-Sha256 $PSCommandPath }

    $meta = [ordered]@{
        Tool        = $script:ToolName
        Version     = $script:ToolVersion
        ToolSha256  = $toolSha
        CaseId      = $script:CaseIdValue
        Operator    = $script:OperatorValue
        Hostname    = $env:COMPUTERNAME
        Scope       = $Scope
        Started     = $script:RunStart.ToString('yyyy-MM-dd HH:mm:ss K')
        Finished    = $finished.ToString('yyyy-MM-dd HH:mm:ss K')
        DurationMin = [math]::Round((New-TimeSpan -Start $script:RunStart -End $finished).TotalMinutes, 1)
        ReadOnly    = $true
        CommandLine = $script:CommandLine
    }

    $jsonPath = Join-Path $script:CaseDir 'findings.json'
    $payload = [ordered]@{
        meta       = $meta
        verdict    = $script:Sections['Readiness']
        severityCounts = (Get-SeverityCounts)
        findings   = @($script:Findings)
        sections   = $script:Sections
        manifest   = @($script:Manifest)
        modules    = @($script:ModuleStatus)
    }
    try {
        ($payload | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -Force
        Write-Ok "findings.json"
    } catch {
        Write-Bad "findings.json could not be written: $($_.Exception.Message)"
    }

    $htmlPath = Join-Path $script:CaseDir 'report.html'
    try { Write-HtmlReport -Path $htmlPath -Meta $meta; Write-Ok 'report.html' }
    catch { Write-Bad "report.html failed: $($_.Exception.Message)" }

    $mdPath = Join-Path $script:CaseDir 'report.md'
    try { Write-MarkdownReport -Path $mdPath -Meta $meta; Write-Ok 'report.md' }
    catch { Write-Bad "report.md failed: $($_.Exception.Message)" }

    $aiPath = Join-Path $script:CaseDir 'AI-HANDOFF.md'
    try { Write-AiHandoff -Path $aiPath -Meta $meta -JsonPath $jsonPath; Write-Ok 'AI-HANDOFF.md' }
    catch { Write-Bad "AI-HANDOFF.md failed: $($_.Exception.Message)" }

    $csvPath = Join-Path $script:CaseDir 'collection-manifest.csv'
    try {
        if ($script:Manifest.Count -gt 0) { $script:Manifest | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 }
        Write-Ok 'collection-manifest.csv'
    } catch { }

    # short console-style summary
    $counts = Get-SeverityCounts
    $readiness = $script:Sections['Readiness']
    $sum = New-Object System.Text.StringBuilder
    [void]$sum.AppendLine("$script:ToolName $script:ToolVersion")
    [void]$sum.AppendLine("Host      : $($meta.Hostname)")
    [void]$sum.AppendLine("Case      : $($meta.CaseId)")
    [void]$sum.AppendLine("Operator  : $($meta.Operator)")
    [void]$sum.AppendLine("Window    : $($meta.Started) -> $($meta.Finished) ($($meta.DurationMin) min)")
    if ($readiness) { [void]$sum.AppendLine("Verdict   : $($readiness.Verdict) - $($readiness.VerdictText)") }
    [void]$sum.AppendLine("Findings  : Critical $($counts.Critical), High $($counts.High), Medium $($counts.Medium), Low $($counts.Low), Info $($counts.Info)")
    if ($script:Sections['Encryption']) {
        [void]$sum.AppendLine("Encrypted : $('{0:N0}' -f [int]$script:Sections['Encryption'].EncryptedFileCount) files, $($script:Sections['Encryption'].EncryptedGB) GB")
        [void]$sum.AppendLine("Notes     : $($script:Sections['Encryption'].RansomNoteCount)")
    }
    [void]$sum.AppendLine("Artifacts : $($script:Manifest.Count)")
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine('Top findings:')
    foreach ($f in (@($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] } | Select-Object -First 15))) {
        [void]$sum.AppendLine("  [$($f.Severity)] $($f.Title)")
    }
    Set-Content -LiteralPath (Join-Path $script:CaseDir 'summary.txt') -Value $sum.ToString() -Encoding UTF8 -Force
    Write-Ok 'summary.txt'

    if (-not $NoZip) {
        $zip = $script:CaseDir + '.zip'
        try {
            Write-Note 'Compressing the case folder...'
            Compress-Archive -Path (Join-Path $script:CaseDir '*') -DestinationPath $zip -Force -ErrorAction Stop
            $zipHash = Get-Sha256 $zip
            Write-Ok  ("archive: {0}" -f $zip)
            Write-Kv  'Archive SHA-256' $zipHash
            Set-Content -LiteralPath ($zip + '.sha256') -Value "$zipHash  $(Split-Path $zip -Leaf)" -Encoding ASCII -Force
        } catch {
            Write-Warn "Could not compress the case folder: $($_.Exception.Message)"
        }
    }
}

# -------------------------------------------------------------------------
#  ORCHESTRATION
# -------------------------------------------------------------------------
function Show-Banner {
    Write-Host ''
    Write-Host '  +--------------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '  |                      A K I R A   E S C A P E                       |' -ForegroundColor Cyan
    Write-Host '  |         offline triage, artifact capture and readiness report       |' -ForegroundColor Cyan
    Write-Host '  +--------------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ("   version $script:ToolVersion   -   read-only: this tool never changes the host") -ForegroundColor DarkGray
    Write-Host ''
    if (-not (Test-Administrator)) {
        Write-Warn 'Not running as Administrator. Registry, service, event log and collection checks will be incomplete.'
        Write-Warn 'Re-run from an elevated PowerShell prompt for a usable report.'
        Write-Host ''
    }
    Write-Note 'Best practice: image the disk before running any live triage if the host may become evidence in litigation.'
}

function Set-EnabledModules {
    param([string[]]$Modules)
    $script:Enabled = @{}
    foreach ($m in $Modules) { $script:Enabled[$m] = $true }
}

function Initialize-Run {
    $script:SkipCollectionMode = [bool]$SkipCollection
    $script:BehaviourHits      = @{}
    $script:Autostarts         = New-Object System.Collections.ArrayList

    if (-not $script:CaseIdValue)   { $script:CaseIdValue   = $(if ($CaseId) { $CaseId } else { 'CASE-' + (Get-Date).ToString('yyyyMMdd-HHmm') }) }
    if (-not $script:OperatorValue) { $script:OperatorValue = $(if ($Operator) { $Operator } else { "$env:USERDOMAIN\$env:USERNAME" }) }

    $root = $OutputRoot
    if (-not $root) {
        $root = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
    }
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
    }

    $script:CaseDir     = New-CaseFolder -Root $root -Case $script:CaseIdValue
    $script:ArtifactDir = Join-Path $script:CaseDir 'artifacts'
    $script:LogFile     = Join-Path $script:CaseDir 'logs\akira-escape.log'
    Write-Log "$script:ToolName $script:ToolVersion starting. Scope=$Scope Case=$script:CaseIdValue Operator=$script:OperatorValue"

    Write-Host ''
    Write-Kv 'Case'        $script:CaseIdValue
    Write-Kv 'Operator'    $script:OperatorValue
    Write-Kv 'Scope'       $Scope
    Write-Kv 'Output'      $script:CaseDir
    Write-Kv 'Collection'  $(if ($script:SkipCollectionMode) { 'disabled (-SkipCollection)' } else { 'enabled' })
}

function Invoke-Triage {
    Initialize-Run

    Invoke-Module -Name 'Host'        -Title '1. HOST PROFILE'                     -Body { Invoke-HostProfile }
    Invoke-Module -Name 'Encryption'  -Title '2. ENCRYPTION SURVEY'                -Body { Invoke-EncryptionSurvey }
    Invoke-Module -Name 'Posture'     -Title '3. SECURITY POSTURE'                 -Body { Invoke-SecurityPosture }
    Invoke-Module -Name 'Accounts'    -Title '4. ACCOUNTS AND SESSIONS'            -Body { Invoke-AccountSurvey }
    Invoke-Module -Name 'Persistence' -Title '5. PERSISTENCE SWEEP'                -Body { Invoke-PersistenceSweep }
    Invoke-Module -Name 'Tooling'     -Title '6. INTRUSION TOOLING HUNT'           -Body { Invoke-ToolingHunt }
    Invoke-Module -Name 'Recovery'    -Title '7. BACKUP AND RECOVERY STATE'        -Body { Invoke-BackupState }
    Invoke-Module -Name 'Events'      -Title '8. EVENT LOG TRIAGE'                 -Body { Invoke-EventLogTriage }
    Invoke-Module -Name 'Network'     -Title '9. NETWORK SNAPSHOT'                 -Body { Invoke-NetworkSnapshot }
    Invoke-Module -Name 'Variant'     -Title '10. AKIRA VARIANT ASSESSMENT'        -Body { Invoke-VariantAssessment }
    Invoke-Module -Name 'Collection'  -Title '11. ARTIFACT COLLECTION'             -Body { Invoke-ArtifactCollection }
    Invoke-Module -Name 'Readiness'   -Title '12. RETURN-TO-SERVICE ASSESSMENT'    -Body { Invoke-ReadinessAssessment }

    Write-Head 'REPORTS'
    Write-Reports

    $readiness = $script:Sections['Readiness']
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor Cyan
    if ($readiness) {
        $colour = 'Yellow'
        if ($readiness.VerdictClass -eq 'pass') { $colour = 'Green' }
        if ($readiness.VerdictClass -eq 'fail') { $colour = 'Red' }
        Write-Host ("  RETURN TO SERVICE: {0}" -f $readiness.Verdict) -ForegroundColor $colour
        Write-Host ("  {0}" -f $readiness.VerdictText) -ForegroundColor Gray
    }
    Write-Host ("  Case folder : {0}" -f $script:CaseDir) -ForegroundColor White
    Write-Host  '  Open report.html for the client-facing view.' -ForegroundColor Gray
    Write-Host  '  Paste AI-HANDOFF.md into Claude to have the full report written up.' -ForegroundColor Gray
    Write-Host ('=' * 74) -ForegroundColor Cyan
    Write-Host ''

    # reset run state so a second menu selection starts clean
    $script:Findings     = New-Object System.Collections.ArrayList
    $script:Sections     = [ordered]@{}
    $script:Manifest     = New-Object System.Collections.ArrayList
    $script:ModuleStatus = New-Object System.Collections.ArrayList
    $script:Readiness    = New-Object System.Collections.ArrayList
    $script:RunStart     = Get-Date
    $script:IncidentStartTime = $null
}

$AllModules = @('Host', 'Encryption', 'Posture', 'Accounts', 'Persistence', 'Tooling',
                'Recovery', 'Events', 'Network', 'Variant', 'Collection', 'Readiness')

function Show-Menu {
    Write-Host ''
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host '     Akira Escape Tool' -ForegroundColor Cyan
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host '   1. Full triage            (standard scope, event logs, full report)'
    Write-Host '   2. Quick look             (fast scan, no event log export)'
    Write-Host '   3. Deep collection        (whole disk, hives, prefetch, Amcache)'
    Write-Host '   4. Persistence check only (is anything still holding on?)'
    Write-Host '   5. Encryption and variant (what hit this host, and which build?)'
    Write-Host '   6. Readiness check only   (can this host go back online?)'
    Write-Host '   7. Set case ID and operator'
    Write-Host '   Q. Quit'
    Write-Host ''
}

function Read-CaseDetails {
    $c = Read-Host '  Case ID (blank for auto)'
    if ($c.Trim()) { $script:CaseIdValue = $c.Trim() }
    $o = Read-Host '  Operator name/initials'
    if ($o.Trim()) { $script:OperatorValue = $o.Trim() }
    Write-Ok ("case {0}, operator {1}" -f $script:CaseIdValue, $script:OperatorValue)
}

function Start-Interactive {
    do {
        Show-Menu
        $choice = (Read-Host '  Select an option').Trim().ToUpper()
        switch ($choice) {
            '1' { $script:Scope = 'Standard'; Set-EnabledModules $AllModules; Invoke-Triage }
            '2' { $script:Scope = 'Quick'; $script:ScanTimeoutMinutes = [math]::Min($ScanTimeoutMinutes, 5)
                  Set-EnabledModules @('Host', 'Encryption', 'Posture', 'Persistence', 'Tooling', 'Recovery', 'Variant', 'Readiness')
                  Invoke-Triage }
            '3' { $script:Scope = 'Deep'; $script:CollectEventLogs = $true; $script:CollectRegistryHives = $true
                  $script:ScanTimeoutMinutes = [math]::Max($ScanTimeoutMinutes, 45)
                  Set-EnabledModules $AllModules; Invoke-Triage }
            '4' { Set-EnabledModules @('Host', 'Persistence', 'Tooling', 'Readiness'); Invoke-Triage }
            '5' { Set-EnabledModules @('Host', 'Encryption', 'Variant'); Invoke-Triage }
            '6' { $script:Scope = 'Quick'
                  Set-EnabledModules @('Host', 'Encryption', 'Posture', 'Accounts', 'Persistence', 'Recovery', 'Readiness')
                  Invoke-Triage }
            '7' { Read-CaseDetails }
            'Q' { Write-Host '  Done.' -ForegroundColor Cyan }
            default { Write-Host '  Invalid selection.' -ForegroundColor Red }
        }
    } while ($choice -ne 'Q')
}

# -------------------------------------------------------------------------
#  ENTRY POINT
# -------------------------------------------------------------------------
Show-Banner

$interactive = $Menu -or ($PSBoundParameters.Count -eq 0 -and [Environment]::UserInteractive)
if ($interactive) {
    Start-Interactive
} else {
    Set-EnabledModules $AllModules
    Invoke-Triage
}
