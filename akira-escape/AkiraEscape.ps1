#Requires -Version 5.1
<#
.SYNOPSIS
    Akira Escape Tool - offline triage, artifact collection and readiness reporting
    for Windows hosts involved in an Akira ransomware incident.

.DESCRIPTION
    Read-only incident response triage. The tool does not remediate, quarantine,
    delete or decrypt anything. It inspects the host, collects evidence into a
    case folder, and produces:

        Report.html        - human readable report for the client
        findings.json      - structured data (feed this to Claude for a write-up)
        Summary.txt        - console-style summary
        Timeline.csv       - merged event timeline
        Manifest.csv       - SHA256 of every collected artifact
        ClaudePrompt.md    - ready-made prompt for generating a client report
        Artifacts\         - collected evidence

    Run from an elevated PowerShell session. Intended for an isolated / offline
    host that has already been contained.

.PARAMETER OutputPath
    Root folder for the case output. Default: <SystemDrive>\AkiraEscape

.PARAMETER CaseName
    Optional case reference printed on the report (e.g. "ACME-IR-2026-014").

.PARAMETER ScanPath
    Volumes or folders to search for ransom notes and encrypted files.
    Default: all fixed drives.

.PARAMETER DaysBack
    Event log lookback window in days. Default 45.

.PARAMETER MaxScanDepth
    Directory recursion depth for the file scan. Default 5.

.PARAMETER SamplePath
    Path to a recovered encryptor binary to fingerprint (optional).

.PARAMETER RunAll
    Run every module non-interactively and write the report. Without this the
    tool starts in menu mode.

.PARAMETER SkipEventLogs
    Do not query or export Windows event logs (much faster).

.PARAMETER SkipHives
    Do not export registry hives / Amcache / SRUM.

.PARAMETER SkipFileScan
    Do not walk the file system for notes and encrypted files.

.EXAMPLE
    .\AkiraEscape.ps1 -RunAll -CaseName "ACME-IR-2026-014"

.EXAMPLE
    .\AkiraEscape.ps1 -RunAll -ScanPath C:\,D:\ -DaysBack 90 -SamplePath C:\evidence\w.exe

.NOTES
    Read-only by design. Nothing is written outside the case folder.
#>

[CmdletBinding()]
param(
    [string]   $OutputPath   = (Join-Path $env:SystemDrive 'AkiraEscape'),
    [string]   $CaseName     = '',
    [string[]] $ScanPath     = @(),
    [int]      $DaysBack     = 45,
    [int]      $MaxScanDepth = 5,
    [string]   $SamplePath   = '',
    [switch]   $RunAll,
    [switch]   $SkipEventLogs,
    [switch]   $SkipHives,
    [switch]   $SkipFileScan
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:ToolName    = 'Akira Escape Tool'
$script:ToolVersion = '1.0.0'

# -------------------------------------------------------
#  KNOWN AKIRA INDICATORS
#  Evidence-driven: everything below is a *lead*, not a verdict.
# -------------------------------------------------------

# Ransom note filenames seen across Akira lineages.
$script:NoteNames = @(
    'akira_readme.txt',
    'powerranges.txt',
    'akira_readme.hta',
    'megazord_readme.txt',
    'how_to_decrypt.txt',
    'readme.txt'          # only counted when the content matches
)

# Extensions appended to encrypted files, mapped to the lineage that used them.
$script:EncryptedExtensions = [ordered]@{
    '.akira'       = 'Akira (C++ or Rust lineage - note content decides)'
    '.powerranges' = 'Megazord (Rust)'
    '.akiranew'    = 'Akira Rust lineage (reported)'
    '.aki'         = 'Akira variant (reported)'
}

# Strings that identify the note / lineage.
$script:NoteSignatures = @(
    @{ Pattern = 'akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad\.onion'
       Label   = 'Akira leak-site .onion (long-running Akira infrastructure)'
       Weight  = 40; Lineage = 'Akira' },
    @{ Pattern = 'Whatever who you are and what your title is'
       Label   = 'Classic Akira note body ("Hi friends" letter)'
       Weight  = 30; Lineage = 'Akira-C++' },
    @{ Pattern = 'Hi friends'
       Label   = 'Akira note greeting'
       Weight  = 10; Lineage = 'Akira' },
    @{ Pattern = '[Mm]egazord'
       Label   = 'Megazord branding in note'
       Weight  = 40; Lineage = 'Megazord' },
    @{ Pattern = 'powerranges'
       Label   = 'Megazord note filename/branding'
       Weight  = 35; Lineage = 'Megazord' },
    @{ Pattern = '\.onion'
       Label   = 'Tor negotiation address present'
       Weight  = 5;  Lineage = '' },
    @{ Pattern = 'akira'
       Label   = 'Akira named in note'
       Weight  = 15; Lineage = 'Akira' }
)

# Tooling repeatedly observed in Akira intrusions (discovery, exfil, remote access).
$script:AdversaryTooling = @(
    @{ Name = 'netscan.exe';        Desc = 'SoftPerfect NetScan - network discovery'; Sev = 'High' },
    @{ Name = 'advanced_ip_scanner.exe'; Desc = 'Advanced IP Scanner - network discovery'; Sev = 'High' },
    @{ Name = 'advanced_port_scanner.exe'; Desc = 'Advanced Port Scanner - discovery'; Sev = 'High' },
    @{ Name = 'rclone.exe';         Desc = 'Rclone - bulk data exfiltration'; Sev = 'Critical' },
    @{ Name = 'winscp.exe';         Desc = 'WinSCP - data exfiltration'; Sev = 'High' },
    @{ Name = 'filezilla.exe';      Desc = 'FileZilla - data exfiltration'; Sev = 'High' },
    @{ Name = 'megasync.exe';       Desc = 'MEGAsync - cloud exfiltration'; Sev = 'Critical' },
    @{ Name = 'mimikatz.exe';       Desc = 'Mimikatz - credential theft'; Sev = 'Critical' },
    @{ Name = 'lazagne.exe';        Desc = 'LaZagne - credential theft'; Sev = 'Critical' },
    @{ Name = 'psexec.exe';         Desc = 'PsExec - lateral movement'; Sev = 'High' },
    @{ Name = 'psexesvc.exe';       Desc = 'PsExec service stub - remote execution occurred'; Sev = 'Critical' },
    @{ Name = 'pchunter64.exe';     Desc = 'PCHunter - EDR/AV tampering'; Sev = 'Critical' },
    @{ Name = 'processhacker.exe';  Desc = 'Process Hacker - EDR/AV tampering'; Sev = 'High' },
    @{ Name = 'ngrok.exe';          Desc = 'Ngrok - tunnelling / C2'; Sev = 'Critical' },
    @{ Name = 'cloudflared.exe';    Desc = 'Cloudflared tunnel - C2'; Sev = 'Critical' },
    @{ Name = 'plink.exe';          Desc = 'Plink - SSH tunnelling'; Sev = 'High' },
    @{ Name = 'anydesk.exe';        Desc = 'AnyDesk - remote access (Akira favourite)'; Sev = 'High' },
    @{ Name = 'rustdesk.exe';       Desc = 'RustDesk - remote access'; Sev = 'High' },
    @{ Name = 'radmin.exe';         Desc = 'Radmin - remote access'; Sev = 'High' },
    @{ Name = 'atera_agent.exe';    Desc = 'Atera RMM - persistence via RMM'; Sev = 'High' },
    @{ Name = 'ateraagent.exe';     Desc = 'Atera RMM - persistence via RMM'; Sev = 'High' },
    @{ Name = 'screenconnect.clientservice.exe'; Desc = 'ScreenConnect - remote access'; Sev = 'High' },
    @{ Name = 'splashtop.exe';      Desc = 'Splashtop - remote access'; Sev = 'High' },
    @{ Name = 'megazord.exe';       Desc = 'Megazord encryptor binary'; Sev = 'Critical' },
    @{ Name = 'akira.exe';          Desc = 'Akira encryptor binary'; Sev = 'Critical' },
    @{ Name = 'w.exe';              Desc = 'Filename repeatedly used for the Akira encryptor'; Sev = 'Critical' },
    @{ Name = 'locker.exe';         Desc = 'Generic encryptor filename'; Sev = 'Critical' },
    @{ Name = 'veeam-get-creds.ps1';Desc = 'Veeam credential dumper'; Sev = 'Critical' },
    @{ Name = 'zerologon.exe';      Desc = 'Zerologon exploit tool'; Sev = 'Critical' }
)

# Vulnerable / abused drivers (BYOVD). Akira has used ThrottleStop (rwdrv.sys)
# and a paired helper driver to disable endpoint protection.
$script:BadDrivers = @(
    @{ Name = 'rwdrv.sys';    Desc = 'ThrottleStop RW driver - BYOVD used by Akira to kill AV' },
    @{ Name = 'hlpdrv.sys';   Desc = 'Helper driver deployed alongside rwdrv.sys by Akira' },
    @{ Name = 'zam64.sys';    Desc = 'Zemana AntiMalware driver - common BYOVD' },
    @{ Name = 'zamguard64.sys'; Desc = 'Zemana driver variant - common BYOVD' },
    @{ Name = 'aswarpot.sys'; Desc = 'Avast driver abused to terminate protected processes' },
    @{ Name = 'gdrv.sys';     Desc = 'Gigabyte driver - classic BYOVD' },
    @{ Name = 'iqvw64e.sys';  Desc = 'Intel network driver - BYOVD' },
    @{ Name = 'dbutil_2_3.sys'; Desc = 'Dell driver - BYOVD' },
    @{ Name = 'truesight.sys';Desc = 'RogueKiller driver - BYOVD used to disable EDR' },
    @{ Name = 'viragt64.sys'; Desc = 'TG Soft driver - BYOVD' },
    @{ Name = 'pcdsrvc.sys';  Desc = 'PC-Doctor driver - BYOVD' },
    @{ Name = 'throttlestop.sys'; Desc = 'ThrottleStop driver - BYOVD' }
)

# Remote access / RMM products worth flagging wherever they appear.
$script:RemoteAccessProducts = @(
    @{ Name = 'AnyDesk';      Paths = @('C:\Program Files (x86)\AnyDesk','C:\Program Files\AnyDesk','C:\ProgramData\AnyDesk') },
    @{ Name = 'RustDesk';     Paths = @('C:\Program Files\RustDesk','C:\ProgramData\RustDesk') },
    @{ Name = 'TeamViewer';   Paths = @('C:\Program Files (x86)\TeamViewer','C:\Program Files\TeamViewer') },
    @{ Name = 'ScreenConnect';Paths = @('C:\Program Files (x86)\ScreenConnect Client','C:\ProgramData\ScreenConnect') },
    @{ Name = 'Atera';        Paths = @('C:\Program Files\ATERA Networks','C:\Program Files (x86)\ATERA Networks') },
    @{ Name = 'Splashtop';    Paths = @('C:\Program Files (x86)\Splashtop','C:\Program Files\Splashtop') },
    @{ Name = 'LogMeIn';      Paths = @('C:\Program Files (x86)\LogMeIn','C:\Program Files\LogMeIn') },
    @{ Name = 'Radmin';       Paths = @('C:\Program Files (x86)\Radmin','C:\Program Files\Radmin') },
    @{ Name = 'Level.io';     Paths = @('C:\Program Files\Level','C:\ProgramData\Level') },
    @{ Name = 'Action1';      Paths = @('C:\Program Files\Action1','C:\Program Files (x86)\Action1') },
    @{ Name = 'Tailscale';    Paths = @('C:\Program Files\Tailscale') },
    @{ Name = 'Netbird';      Paths = @('C:\Program Files\Netbird','C:\Program Files (x86)\Netbird') },
    @{ Name = 'Ngrok';        Paths = @('C:\ProgramData\ngrok') },
    @{ Name = 'Cloudflared';  Paths = @('C:\Program Files\cloudflared','C:\ProgramData\cloudflared') },
    @{ Name = 'Datto RMM';    Paths = @('C:\Program Files (x86)\CentraStage') },
    @{ Name = 'Syncro';       Paths = @('C:\Program Files\RepairTech\Syncro') }
)

# Folders that are never worth walking during the file scan.
$script:ScanExcludes = @(
    '\Windows\WinSxS', '\Windows\servicing', '\Windows\SoftwareDistribution',
    '\Windows\assembly', '\Windows\Installer', '\$Recycle.Bin',
    '\System Volume Information', '\Windows\Microsoft.NET'
)

# -------------------------------------------------------
#  STATE
# -------------------------------------------------------
$script:Findings = New-Object System.Collections.ArrayList
$script:Timeline = New-Object System.Collections.ArrayList
$script:Manifest = New-Object System.Collections.ArrayList
$script:RunLog   = New-Object System.Collections.ArrayList
$script:Report   = [ordered]@{}
$script:CaseDir  = $null
$script:ArtDir   = $null
$script:StartUtc = (Get-Date).ToUniversalTime()

$script:SeverityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

# -------------------------------------------------------
#  CONSOLE HELPERS
# -------------------------------------------------------
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 62) -ForegroundColor Cyan
}

function Write-Result {
    param([string]$Message, [bool]$Success = $true)
    if ($Success) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $Message" -ForegroundColor Yellow
    }
}

function Write-Bad {
    param([string]$Message)
    Write-Host "  [XX] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Label, $Value)
    if ($null -eq $Value -or "$Value" -eq '') { $Value = '(none)' }
    Write-Host ("  {0,-26}: {1}" -f $Label, $Value) -ForegroundColor White
}

function Write-Step {
    param([string]$Message)
    Write-Host "  -> $Message" -ForegroundColor Gray
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0}  [{1}]  {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    [void]$script:RunLog.Add($line)
    if ($script:CaseDir) {
        Add-Content -Path (Join-Path $script:CaseDir 'Log.txt') -Value $line -ErrorAction SilentlyContinue
    }
}

# -------------------------------------------------------
#  FINDINGS AND TIMELINE
# -------------------------------------------------------
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        $Evidence = $null,
        [string]$Recommendation = ''
    )
    $f = [pscustomobject]@{
        Id             = 'F{0:D3}' -f ($script:Findings.Count + 1)
        Category       = $Category
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
    [void]$script:Findings.Add($f)
    Write-Log "FINDING [$Severity] $Category :: $Title" 'FIND'

    switch ($Severity) {
        'Critical' { Write-Bad "$Title" }
        'High'     { Write-Bad "$Title" }
        'Medium'   { Write-Result $Title $false }
        'Low'      { Write-Result $Title $false }
        default    { }
    }
    # Deliberately no return value - callers are statements, and emitting the
    # object here would dump raw findings onto the console.
}

function Add-Timeline {
    param(
        $Time,
        [string]$Source,
        [string]$Event,
        [string]$Detail = ''
    )
    if (-not $Time) { return }
    try { $Time = [datetime]$Time } catch { return }
    [void]$script:Timeline.Add([pscustomobject]@{
        Time   = $Time
        Source = $Source
        Event  = $Event
        Detail = $Detail
    })
}

# -------------------------------------------------------
#  UTILITY
# -------------------------------------------------------
function Test-Administrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function ConvertTo-SafeString {
    param($Value, [int]$MaxLength = 32000)
    if ($null -eq $Value) { return '' }
    $s = "$Value"
    # Strip control characters that would break CSV/HTML/JSON rendering.
    $s = ($s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' ')
    if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength) + '...[truncated]' }
    return $s
}

function Get-FileHashSafe {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return '(hash failed)'
    }
}

function Get-FileMeta {
    <#
      Returns a consistent evidence record for a file: size, timestamps,
      SHA256 and Authenticode signature state.
    #>
    param([string]$Path, [switch]$NoHash)

    $r = [ordered]@{
        Path           = $Path
        Exists         = $false
        SizeBytes      = 0
        CreatedUtc     = $null
        ModifiedUtc    = $null
        AccessedUtc    = $null
        Sha256         = ''
        Signature      = ''
        Signer         = ''
        CompanyName    = ''
        FileVersion    = ''
    }
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $r.Exists      = $true
        $r.SizeBytes   = [int64]$fi.Length
        $r.CreatedUtc  = $fi.CreationTimeUtc
        $r.ModifiedUtc = $fi.LastWriteTimeUtc
        $r.AccessedUtc = $fi.LastAccessTimeUtc

        if (-not $NoHash -and $fi.Length -lt 200MB) {
            $r.Sha256 = Get-FileHashSafe -Path $Path
        }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r.Signature = "$($sig.Status)"
            if ($sig.SignerCertificate) { $r.Signer = $sig.SignerCertificate.Subject }
        } catch { $r.Signature = 'Unknown' }

        if ($fi.VersionInfo) {
            $r.CompanyName = ConvertTo-SafeString $fi.VersionInfo.CompanyName
            $r.FileVersion = ConvertTo-SafeString $fi.VersionInfo.FileVersion
        }
    } catch { }
    return [pscustomobject]$r
}

function Get-BoundedFiles {
    <#
      Breadth-first file walk with a depth cap, a result cap and reparse-point
      skipping. Get-ChildItem -Recurse dies on a single ACL error and can run for
      hours on a file server; this keeps the scan predictable.
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$IncludeNames = @(),
        [string[]]$IncludeExtensions = @(),
        [int]$MaxDepth = 5,
        [int]$MaxResults = 5000,
        [int]$TimeoutSeconds = 900
    )

    $results = New-Object System.Collections.ArrayList
    $sw      = [System.Diagnostics.Stopwatch]::StartNew()

    $nameSet = @{}
    foreach ($n in $IncludeNames)      { $nameSet[$n.ToLowerInvariant()] = $true }
    $extSet  = @{}
    foreach ($e in $IncludeExtensions) { $extSet[$e.ToLowerInvariant()]  = $true }

    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue([pscustomobject]@{ Path = $Root; Depth = 0 })

    while ($queue.Count -gt 0) {
        if ($results.Count -ge $MaxResults)       { break }
        if ($sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            Write-Log "File scan timeout after $TimeoutSeconds s under $Root" 'WARN'
            break
        }

        $node = $queue.Dequeue()

        $skip = $false
        foreach ($ex in $script:ScanExcludes) {
            if ($node.Path -like "*$ex*") { $skip = $true; break }
        }
        if ($skip) { continue }

        try {
            foreach ($file in [System.IO.Directory]::EnumerateFiles($node.Path)) {
                $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                $ext  = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
                if ($nameSet.ContainsKey($leaf) -or $extSet.ContainsKey($ext)) {
                    [void]$results.Add($file)
                    if ($results.Count -ge $MaxResults) { break }
                }
            }
        } catch { }

        if ($node.Depth -lt $MaxDepth) {
            try {
                foreach ($dir in [System.IO.Directory]::EnumerateDirectories($node.Path)) {
                    try {
                        $di = New-Object System.IO.DirectoryInfo($dir)
                        if ($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                    } catch { continue }
                    $queue.Enqueue([pscustomobject]@{ Path = $dir; Depth = $node.Depth + 1 })
                }
            } catch { }
        }
    }
    $sw.Stop()
    return $results
}

function Copy-Evidence {
    <#
      Copies a file into the case Artifacts folder, hashing the source so the
      manifest records what was on the host, not what landed in the case folder.
    #>
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SubFolder,
        [string]$NewName = '',
        [string]$Note = ''
    )
    if (-not $script:ArtDir) { return $null }
    if (-not (Test-Path -LiteralPath $Source)) { return $null }

    $destDir = Join-Path $script:ArtDir $SubFolder
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    if (-not $NewName) { $NewName = Split-Path $Source -Leaf }
    $dest = Join-Path $destDir $NewName

    # Never overwrite one piece of evidence with another.
    $i = 1
    while (Test-Path -LiteralPath $dest) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($NewName)
        $ext  = [System.IO.Path]::GetExtension($NewName)
        $dest = Join-Path $destDir ("{0}_{1}{2}" -f $base, $i, $ext)
        $i++
    }

    $copied = $false
    try {
        Copy-Item -LiteralPath $Source -Destination $dest -Force -ErrorAction Stop
        $copied = $true
    } catch {
        # Locked file (hives, SRUM, Amcache) - esentutl can read the shadow.
        try {
            $null = & esentutl.exe /y "$Source" /vss /d "$dest" 2>&1
            if (Test-Path -LiteralPath $dest) { $copied = $true }
        } catch { }
    }

    if (-not $copied) {
        Write-Log "Could not collect $Source" 'WARN'
        return $null
    }

    $hash = Get-FileHashSafe -Path $dest
    $size = 0
    try { $size = (Get-Item -LiteralPath $dest -Force).Length } catch { }

    [void]$script:Manifest.Add([pscustomobject]@{
        SourcePath  = $Source
        CollectedAs = $dest.Replace($script:CaseDir, '.')
        SizeBytes   = $size
        Sha256      = $hash
        CollectedUtc= (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Note        = $Note
    })
    return $dest
}

function Save-TextEvidence {
    param([string]$Name, [string]$SubFolder, $Content, [string]$Note = '')
    if (-not $script:ArtDir) { return }
    $destDir = Join-Path $script:ArtDir $SubFolder
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    $dest = Join-Path $destDir $Name
    try {
        $Content | Out-File -FilePath $dest -Encoding utf8 -Force -ErrorAction Stop
        [void]$script:Manifest.Add([pscustomobject]@{
            SourcePath  = '(generated by tool)'
            CollectedAs = $dest.Replace($script:CaseDir, '.')
            SizeBytes   = (Get-Item -LiteralPath $dest).Length
            Sha256      = Get-FileHashSafe -Path $dest
            CollectedUtc= (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            Note        = $Note
        })
    } catch {
        Write-Log "Failed writing $dest : $_" 'WARN'
    }
}

function New-CaseFolder {
    if ($script:CaseDir) { return $script:CaseDir }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $name  = "AkiraEscape_{0}_{1}" -f $env:COMPUTERNAME, $stamp
    $script:CaseDir = Join-Path $OutputPath $name
    $script:ArtDir  = Join-Path $script:CaseDir 'Artifacts'
    New-Item -ItemType Directory -Path $script:ArtDir -Force | Out-Null
    Write-Log "Case folder: $script:CaseDir"
    return $script:CaseDir
}

# -------------------------------------------------------
#  MODULE 1 - SYSTEM PROFILE
# -------------------------------------------------------
function Invoke-SystemProfile {
    Write-Header "1. Host Profile"

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $bi = Get-CimInstance Win32_BIOS            -ErrorAction SilentlyContinue

    $roleMap = @{ 0='Standalone Workstation'; 1='Member Workstation'; 2='Standalone Server';
                  3='Member Server'; 4='Backup Domain Controller'; 5='Primary Domain Controller' }
    $role = '(unknown)'
    if ($cs -and $roleMap.ContainsKey([int]$cs.DomainRole)) { $role = $roleMap[[int]$cs.DomainRole] }

    $ips = @()
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.IPAddress -notmatch '^127\.' } |
               ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength) ($($_.InterfaceAlias))" }
    } catch {
        $ips = @(ipconfig | Select-String 'IPv4' | ForEach-Object { $_.ToString().Trim() })
    }

    $disks = @()
    try {
        $disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                 ForEach-Object {
                     [pscustomobject]@{
                         Drive       = $_.DeviceID
                         FileSystem  = $_.FileSystem
                         SizeGB      = [math]::Round($_.Size / 1GB, 1)
                         FreeGB      = [math]::Round($_.FreeSpace / 1GB, 1)
                         VolumeName  = $_.VolumeName
                     }
                 }
    } catch { }

    $hotfix = @()
    try {
        $hotfix = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending |
                  Select-Object -First 15 |
                  ForEach-Object { [pscustomobject]@{ HotFixID = $_.HotFixID; InstalledOn = $_.InstalledOn } }
    } catch { }

    $lastPatch = $null
    if ($hotfix.Count -gt 0) { $lastPatch = ($hotfix | Select-Object -First 1).InstalledOn }

    $hostProfile = [ordered]@{
        Hostname        = $env:COMPUTERNAME
        FQDN            = ''
        Domain          = if ($cs) { $cs.Domain } else { '' }
        DomainRole      = $role
        PartOfDomain    = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
        OperatingSystem = if ($os) { $os.Caption } else { '' }
        OSVersion       = if ($os) { $os.Version } else { '' }
        OSBuild         = if ($os) { $os.BuildNumber } else { '' }
        Architecture    = if ($os) { $os.OSArchitecture } else { '' }
        InstallDateUtc  = if ($os -and $os.InstallDate) { $os.InstallDate.ToUniversalTime() } else { $null }
        LastBootUtc     = if ($os -and $os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime() } else { $null }
        UptimeHours     = if ($os -and $os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } else { $null }
        TimeZone        = (Get-TimeZone -ErrorAction SilentlyContinue).Id
        Manufacturer    = if ($cs) { $cs.Manufacturer } else { '' }
        Model           = if ($cs) { $cs.Model } else { '' }
        SerialNumber    = if ($bi) { $bi.SerialNumber } else { '' }
        MemoryGB        = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null }
        IPv4Addresses   = $ips
        Disks           = $disks
        RecentHotfixes  = $hotfix
        LastPatchDate   = $lastPatch
        SecureBoot      = $null
        BitLocker       = @()
    }

    try { $hostProfile.FQDN = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
    try { $hostProfile.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $hostProfile.SecureBoot = $null }
    try {
        $hostProfile.BitLocker = Get-BitLockerVolume -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Mount = $_.MountPoint; Status = "$($_.ProtectionStatus)"; Method = "$($_.EncryptionMethod)" } }
    } catch { }

    Write-Info 'Hostname'      $hostProfile.Hostname
    Write-Info 'Domain / Role' ("{0} / {1}" -f $hostProfile.Domain, $hostProfile.DomainRole)
    Write-Info 'OS'            ("{0} (build {1})" -f $hostProfile.OperatingSystem, $hostProfile.OSBuild)
    Write-Info 'Last boot UTC' $hostProfile.LastBootUtc
    Write-Info 'Uptime (hrs)'  $hostProfile.UptimeHours
    Write-Info 'IPv4'          ($hostProfile.IPv4Addresses -join ', ')
    Write-Info 'Last patch'    $hostProfile.LastPatchDate

    # A host rebooted since encryption loses volatile evidence - worth stating.
    if ($null -ne $hostProfile.UptimeHours -and $hostProfile.UptimeHours -lt 24) {
        Add-Finding -Category 'Host' -Severity 'Info' `
            -Title "Host booted within the last 24 hours (uptime $($hostProfile.UptimeHours) h)" `
            -Detail 'Volatile evidence (running processes, network connections, memory) from the intrusion is gone. Disk-based artefacts below are still valid.' `
            -Recommendation 'Rely on on-disk artefacts and event logs for this host.'
    }

    if ($hostProfile.LastPatchDate -and ((Get-Date) - $hostProfile.LastPatchDate).TotalDays -gt 90) {
        Add-Finding -Category 'Host' -Severity 'Medium' `
            -Title "No OS patches installed for $([math]::Round(((Get-Date) - $hostProfile.LastPatchDate).TotalDays)) days" `
            -Detail "Most recent hotfix: $($hostProfile.LastPatchDate)" `
            -Recommendation 'Fully patch before returning the host to the production network.'
    }

    if ($hostProfile.LastBootUtc) { Add-Timeline $hostProfile.LastBootUtc 'System' 'Last boot' '' }

    $script:Report['System'] = $hostProfile
    Write-Log 'System profile complete'
}

# -------------------------------------------------------
#  MODULE 2 - AKIRA ARTIFACT HUNT
# -------------------------------------------------------
function Invoke-AkiraArtefactHunt {
    Write-Header "2. Akira Artefacts (notes, encrypted files, tooling)"

    $result = [ordered]@{
        Scanned            = @()
        Skipped            = $SkipFileScan.IsPresent
        RansomNotes        = @()
        NoteContentSample  = ''
        EncryptedFileStats = @()
        EncryptionWindow   = [ordered]@{ FirstUtc = $null; LastUtc = $null }
        SuspectTooling     = @()
        SampleAnalysis     = $null
    }

    if ($SkipFileScan) {
        Write-Step 'File scan skipped (-SkipFileScan).'
        $script:Report['Artefacts'] = $result
        return
    }

    $roots = @()
    if ($ScanPath.Count -gt 0) {
        $roots = $ScanPath | Where-Object { Test-Path $_ }
    } else {
        try {
            $roots = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                     ForEach-Object { "$($_.DeviceID)\" }
        } catch { $roots = @("$env:SystemDrive\") }
    }
    $result.Scanned = $roots
    Write-Step ("Scanning: {0} (depth {1})" -f ($roots -join ', '), $MaxScanDepth)

    $noteHits = New-Object System.Collections.ArrayList
    $encHits  = @{}
    $encTimes = New-Object System.Collections.ArrayList

    foreach ($root in $roots) {
        Write-Step "Walking $root ..."
        $hits = Get-BoundedFiles -Root $root `
                                 -IncludeNames $script:NoteNames `
                                 -IncludeExtensions ($script:EncryptedExtensions.Keys) `
                                 -MaxDepth $MaxScanDepth -MaxResults 20000

        foreach ($h in $hits) {
            $ext  = [System.IO.Path]::GetExtension($h).ToLowerInvariant()
            $leaf = [System.IO.Path]::GetFileName($h).ToLowerInvariant()

            if ($script:EncryptedExtensions.Contains($ext)) {
                if (-not $encHits.ContainsKey($ext)) {
                    $encHits[$ext] = [pscustomobject]@{
                        Extension   = $ext
                        Lineage     = $script:EncryptedExtensions[$ext]
                        Count       = 0
                        SamplePaths = New-Object System.Collections.ArrayList
                    }
                }
                $encHits[$ext].Count++
                if ($encHits[$ext].SamplePaths.Count -lt 5) { [void]$encHits[$ext].SamplePaths.Add($h) }
                try {
                    $wt = (Get-Item -LiteralPath $h -Force -ErrorAction Stop).LastWriteTimeUtc
                    [void]$encTimes.Add($wt)
                } catch { }
            }
            elseif ($script:NoteNames -contains $leaf) {
                [void]$noteHits.Add($h)
            }
        }
    }

    # --- Ransom notes -------------------------------------------------
    Write-Host ""
    Write-Host "  Ransom notes" -ForegroundColor White
    $noteRecords = New-Object System.Collections.ArrayList
    $collected   = 0

    foreach ($n in ($noteHits | Sort-Object)) {
        $meta = Get-FileMeta -Path $n
        $body = ''
        try { $body = Get-Content -LiteralPath $n -Raw -ErrorAction Stop } catch { }

        # readme.txt is only a ransom note if it reads like one.
        $leaf = [System.IO.Path]::GetFileName($n).ToLowerInvariant()
        if ($leaf -eq 'readme.txt') {
            if ($body -notmatch '(?i)(\.onion|encrypt|akira|megazord|ransom)') { continue }
        }

        $rec = [pscustomobject]@{
            Path        = $n
            SizeBytes   = $meta.SizeBytes
            CreatedUtc  = $meta.CreatedUtc
            ModifiedUtc = $meta.ModifiedUtc
            Sha256      = $meta.Sha256
            Preview     = ConvertTo-SafeString $body 4000
        }
        [void]$noteRecords.Add($rec)

        if ($result.NoteContentSample -eq '' -and $body) { $result.NoteContentSample = ConvertTo-SafeString $body 8000 }
        if ($meta.CreatedUtc) { Add-Timeline $meta.CreatedUtc 'Filesystem' 'Ransom note written' $n }

        if ($collected -lt 25) {
            $flat = ($n -replace '[:\\/]', '_')
            Copy-Evidence -Source $n -SubFolder 'RansomNotes' -NewName $flat -Note 'Ransom note' | Out-Null
            $collected++
        }
    }
    $result.RansomNotes = $noteRecords

    if ($noteRecords.Count -gt 0) {
        Add-Finding -Category 'Ransomware' -Severity 'Critical' `
            -Title "$($noteRecords.Count) ransom note(s) found on this host" `
            -Detail ("Earliest note written: {0}" -f (($noteRecords | Sort-Object CreatedUtc | Select-Object -First 1).CreatedUtc)) `
            -Evidence ($noteRecords | Select-Object -First 10 Path, CreatedUtc, Sha256) `
            -Recommendation 'Preserve notes for law enforcement / insurer. Do not contact the actor without legal and IR guidance.'
    } else {
        Write-Result 'No ransom notes found in the scanned paths.'
    }

    # --- Encrypted files ----------------------------------------------
    Write-Host ""
    Write-Host "  Encrypted files" -ForegroundColor White
    $result.EncryptedFileStats = @($encHits.Values | Sort-Object Count -Descending)

    if ($encTimes.Count -gt 0) {
        $sorted = $encTimes | Sort-Object
        $result.EncryptionWindow.FirstUtc = $sorted | Select-Object -First 1
        $result.EncryptionWindow.LastUtc  = $sorted | Select-Object -Last 1
        Add-Timeline $result.EncryptionWindow.FirstUtc 'Filesystem' 'First encrypted file (by mtime)' ''
        Add-Timeline $result.EncryptionWindow.LastUtc  'Filesystem' 'Last encrypted file (by mtime)'  ''
    }

    $totalEnc = 0
    foreach ($e in $result.EncryptedFileStats) {
        $totalEnc += $e.Count
        Write-Info "  $($e.Extension)" "$($e.Count) file(s) - $($e.Lineage)"
    }

    if ($totalEnc -gt 0) {
        $capped = if ($totalEnc -ge 20000) { ' (scan cap reached - true count is higher)' } else { '' }
        Add-Finding -Category 'Ransomware' -Severity 'Critical' `
            -Title "$totalEnc encrypted file(s) observed$capped" `
            -Detail ("Encryption window (file mtimes): {0} to {1} UTC" -f $result.EncryptionWindow.FirstUtc, $result.EncryptionWindow.LastUtc) `
            -Evidence $result.EncryptedFileStats `
            -Recommendation 'Restore from known-good offline backup. There is no free decryptor for current Akira builds.'
    } else {
        Write-Result 'No encrypted files with known Akira extensions found.'
    }

    # --- Adversary tooling on disk ------------------------------------
    Write-Host ""
    Write-Host "  Adversary tooling" -ForegroundColor White
    $toolRoots = @(
        "$env:SystemDrive\", "$env:SystemDrive\Users", "$env:SystemDrive\ProgramData",
        "$env:SystemDrive\Temp", "$env:windir\Temp", "$env:SystemDrive\Perflogs",
        "$env:SystemDrive\Intel", "$env:SystemDrive\Recovery"
    ) | Where-Object { Test-Path $_ } | Select-Object -Unique

    $toolNames = $script:AdversaryTooling | ForEach-Object { $_.Name }
    $toolFound = New-Object System.Collections.ArrayList
    $seen      = @{}

    foreach ($tr in $toolRoots) {
        $hits = Get-BoundedFiles -Root $tr -IncludeNames $toolNames -MaxDepth 4 -MaxResults 500 -TimeoutSeconds 240
        foreach ($h in $hits) {
            if ($seen.ContainsKey($h.ToLowerInvariant())) { continue }
            $seen[$h.ToLowerInvariant()] = $true

            $leaf = [System.IO.Path]::GetFileName($h).ToLowerInvariant()
            $def  = $script:AdversaryTooling | Where-Object { $_.Name -eq $leaf } | Select-Object -First 1
            $meta = Get-FileMeta -Path $h

            [void]$toolFound.Add([pscustomobject]@{
                Tool        = $leaf
                Description = $def.Desc
                Path        = $h
                Sha256      = $meta.Sha256
                CreatedUtc  = $meta.CreatedUtc
                ModifiedUtc = $meta.ModifiedUtc
                Signature   = $meta.Signature
                Signer      = $meta.Signer
            })
            if ($meta.CreatedUtc) { Add-Timeline $meta.CreatedUtc 'Filesystem' "Tool dropped: $leaf" $h }
        }
    }
    $result.SuspectTooling = $toolFound

    foreach ($t in $toolFound) {
        $def = $script:AdversaryTooling | Where-Object { $_.Name -eq $t.Tool } | Select-Object -First 1
        $sev = if ($def) { $def.Sev } else { 'High' }
        Add-Finding -Category 'Tooling' -Severity $sev `
            -Title "Adversary-associated tool present: $($t.Tool)" `
            -Detail "$($t.Description) - $($t.Path)" `
            -Evidence $t `
            -Recommendation 'Confirm whether this is sanctioned IT tooling. If not, treat as attacker-deployed and rebuild the host.'
    }
    if ($toolFound.Count -eq 0) { Write-Result 'No known adversary tooling found on disk.' }

    # --- Optional sample fingerprint ----------------------------------
    if ($SamplePath -and (Test-Path -LiteralPath $SamplePath)) {
        $result.SampleAnalysis = Get-SampleFingerprint -Path $SamplePath
    }

    $script:Report['Artefacts'] = $result
    Write-Log 'Artefact hunt complete'
}

# -------------------------------------------------------
#  MODULE 3 - SAMPLE FINGERPRINT AND VARIANT ASSESSMENT
# -------------------------------------------------------
function Get-SampleFingerprint {
    <#
      Static, read-only look at a recovered encryptor. The binary is never run.
      Language markers separate the C++ lineage from the Rust lineage
      (Megazord / Akira_v2), which is the main version discriminator when a
      sample survives.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Write-Step "Fingerprinting sample: $Path"
    $meta = Get-FileMeta -Path $Path

    $fp = [ordered]@{
        Path         = $Path
        Sha256       = $meta.Sha256
        SizeBytes    = $meta.SizeBytes
        CreatedUtc   = $meta.CreatedUtc
        ModifiedUtc  = $meta.ModifiedUtc
        Signature    = $meta.Signature
        CompileStamp = $null
        Language     = 'Unknown'
        Strings      = @()
        Indicators   = @()
    }

    # PE compile timestamp from the COFF header.
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            $fs.Seek(0x3C, 'Begin') | Out-Null
            $peOffset = $br.ReadInt32()
            if ($peOffset -gt 0 -and $peOffset -lt $fs.Length - 8) {
                $fs.Seek($peOffset, 'Begin') | Out-Null
                $sig = $br.ReadUInt32()
                if ($sig -eq 0x00004550) {            # "PE\0\0"
                    $null = $br.ReadUInt16()          # Machine
                    $null = $br.ReadUInt16()          # NumberOfSections
                    $ts   = $br.ReadUInt32()          # TimeDateStamp
                    $fp.CompileStamp = ([datetime]'1970-01-01Z').AddSeconds($ts).ToUniversalTime()
                }
            }
        } finally { $fs.Close() }
    } catch { }

    # ASCII string sweep (bounded - we only need language and note markers).
    $found = New-Object System.Collections.ArrayList
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $max   = [math]::Min($bytes.Length, 12MB)
        $sb    = New-Object System.Text.StringBuilder
        $all   = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $max; $i++) {
            $b = $bytes[$i]
            if ($b -ge 32 -and $b -le 126) {
                [void]$sb.Append([char]$b)
            } else {
                if ($sb.Length -ge 6) { [void]$all.Append($sb.ToString()).Append("`n") }
                [void]$sb.Clear()
            }
        }
        if ($sb.Length -ge 6) { [void]$all.Append($sb.ToString()) }
        $blob = $all.ToString()

        $markers = @(
            @{ Pattern = 'rust_begin_unwind|rustc|cargo|core::panicking|library\\std\\src'; Label = 'Rust runtime strings'; Lang = 'Rust' },
            @{ Pattern = 'Megazord|megazord';                        Label = 'Megazord branding'; Lang = '' },
            @{ Pattern = 'powerranges';                              Label = 'powerranges note/extension string'; Lang = '' },
            @{ Pattern = 'akira_readme';                             Label = 'akira_readme note filename'; Lang = '' },
            @{ Pattern = 'akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad'; Label = 'Akira leak-site .onion'; Lang = '' },
            @{ Pattern = 'encryption_percent|--encryption_path|-–encryption'; Label = 'Akira_v2 style command-line switches'; Lang = 'Rust' },
            @{ Pattern = 'ChaCha|chacha';                            Label = 'ChaCha stream cipher reference'; Lang = '' },
            @{ Pattern = 'Win32_Shadowcopy|Remove-WmiObject';        Label = 'Shadow copy deletion routine'; Lang = '' },
            @{ Pattern = 'MSVCP\d+\.dll|MSVCR\d+\.dll';              Label = 'MSVC C++ runtime imports'; Lang = 'C++' },
            @{ Pattern = 'Boost|boost::';                            Label = 'Boost library strings (Akira C++ lineage)'; Lang = 'C++' }
        )

        foreach ($m in $markers) {
            if ($blob -match $m.Pattern) {
                [void]$found.Add($m.Label)
                if ($m.Lang -and $fp.Language -eq 'Unknown') { $fp.Language = $m.Lang }
                elseif ($m.Lang -eq 'Rust') { $fp.Language = 'Rust' }
            }
        }
        $fp.Strings = @($found)
    } catch {
        Write-Log "String scan failed on sample: $_" 'WARN'
    }

    $fp.Indicators = @($found)
    Copy-Evidence -Source $Path -SubFolder 'Sample' -Note 'Operator-supplied encryptor sample' | Out-Null

    Add-Finding -Category 'Ransomware' -Severity 'Critical' `
        -Title "Encryptor sample fingerprinted: $(Split-Path $Path -Leaf)" `
        -Detail ("SHA256 {0}; language {1}; markers: {2}" -f $fp.Sha256, $fp.Language, (($found | Select-Object -First 6) -join ', ')) `
        -Evidence ([pscustomobject]$fp) `
        -Recommendation 'Submit the hash to your threat intel provider and law enforcement. Do not execute the sample outside a lab.'

    return [pscustomobject]$fp
}

function Resolve-AkiraVariant {
    <#
      Weighted assessment rather than a single verdict: the artefacts on disk
      vote, and the report shows which signals produced the answer.
    #>
    Write-Header "3. Variant Assessment"

    $art = $script:Report['Artefacts']
    $assessment = [ordered]@{
        Assessed      = 'Not determined'
        Lineage       = 'Unknown'
        Confidence    = 'None'
        Score         = 0
        Signals       = @()
        Notes         = ''
        Encryptor     = 'Unknown'
    }

    if (-not $art) {
        $script:Report['Variant'] = $assessment
        Write-Result 'No artefact data - run the artefact hunt first.' $false
        return
    }

    $signals = New-Object System.Collections.ArrayList
    $score   = @{ 'Akira' = 0; 'Akira-C++' = 0; 'Megazord' = 0 }

    # 1. Encrypted file extensions.
    foreach ($e in $art.EncryptedFileStats) {
        switch ($e.Extension) {
            '.powerranges' {
                $score['Megazord'] += 45
                [void]$signals.Add("Encrypted files use '.powerranges' ($($e.Count) files) - Megazord lineage")
            }
            '.akira' {
                $score['Akira'] += 35
                [void]$signals.Add("Encrypted files use '.akira' ($($e.Count) files) - Akira lineage")
            }
            '.akiranew' {
                $score['Akira'] += 25
                [void]$signals.Add("Encrypted files use '.akiranew' ($($e.Count) files) - reported for the Rust rewrite")
            }
            '.aki' {
                $score['Akira'] += 15
                [void]$signals.Add("Encrypted files use '.aki' ($($e.Count) files)")
            }
        }
    }

    # 2. Ransom note filenames.
    foreach ($n in $art.RansomNotes) {
        $leaf = [System.IO.Path]::GetFileName($n.Path).ToLowerInvariant()
        switch ($leaf) {
            'akira_readme.txt'    { $score['Akira'] += 35; [void]$signals.Add("Ransom note named 'akira_readme.txt'") }
            'powerranges.txt'     { $score['Megazord'] += 45; [void]$signals.Add("Ransom note named 'powerranges.txt' - Megazord") }
            'megazord_readme.txt' { $score['Megazord'] += 40; [void]$signals.Add("Ransom note named 'megazord_readme.txt'") }
        }
    }

    # 3. Ransom note content.
    $body = $art.NoteContentSample
    if ($body) {
        foreach ($sig in $script:NoteSignatures) {
            if ($body -match $sig.Pattern) {
                [void]$signals.Add("Note content: $($sig.Label)")
                if ($sig.Lineage -and $score.ContainsKey($sig.Lineage)) {
                    $score[$sig.Lineage] += $sig.Weight
                }
            }
        }
    }

    # 4. Sample language, when a binary was supplied.
    if ($art.SampleAnalysis) {
        $lang = $art.SampleAnalysis.Language
        if ($lang -eq 'Rust') {
            $score['Megazord'] += 15
            $score['Akira']    += 15
            [void]$signals.Add('Encryptor sample is Rust-built (Megazord / Akira_v2 generation)')
            $assessment.Encryptor = 'Rust'
        } elseif ($lang -eq 'C++') {
            $score['Akira-C++'] += 30
            [void]$signals.Add('Encryptor sample is C++/MSVC-built (original 2023 Akira generation)')
            $assessment.Encryptor = 'C++'
        }
        foreach ($m in $art.SampleAnalysis.Indicators) { [void]$signals.Add("Sample string: $m") }
    }

    # Pick the winner.
    $best     = ($score.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
    $bestName = $best.Key
    $bestVal  = [int]$best.Value

    if ($bestVal -le 0) {
        $assessment.Assessed   = 'No Akira artefacts identified on this host'
        $assessment.Confidence = 'None'
        $assessment.Notes      = 'This host shows no ransom notes or Akira-extension files in the paths scanned. It may be unaffected, already rebuilt, or the scan paths/depth may have missed them.'
    } else {
        switch ($bestName) {
            'Megazord' {
                $assessment.Assessed = 'Megazord (Rust-based Akira variant, first seen Aug 2023)'
                $assessment.Lineage  = 'Megazord'
                if ($assessment.Encryptor -eq 'Unknown') { $assessment.Encryptor = 'Rust (inferred)' }
            }
            'Akira-C++' {
                $assessment.Assessed = 'Akira - original C++ encryptor lineage (2023)'
                $assessment.Lineage  = 'Akira (C++)'
                if ($assessment.Encryptor -eq 'Unknown') { $assessment.Encryptor = 'C++ (inferred)' }
            }
            default {
                $assessment.Assessed = 'Akira - .akira encryptor lineage (C++ 2023 build or the Rust Akira_v2 rewrite)'
                $assessment.Lineage  = 'Akira'
            }
        }

        $assessment.Score = $bestVal
        $assessment.Confidence = if     ($bestVal -ge 70) { 'High' }
                                 elseif ($bestVal -ge 40) { 'Medium' }
                                 else                     { 'Low' }

        if ($assessment.Lineage -eq 'Akira' -and $assessment.Encryptor -eq 'Unknown') {
            $assessment.Notes = 'Both the 2023 C++ build and the Rust Akira_v2 rewrite append ".akira" and drop "akira_readme.txt", so on-disk artefacts alone cannot separate them. Recover the encryptor binary and re-run with -SamplePath to resolve the generation.'
        }
    }

    $assessment.Signals = @($signals)

    Write-Info 'Assessed variant' $assessment.Assessed
    Write-Info 'Lineage'          $assessment.Lineage
    Write-Info 'Encryptor build'  $assessment.Encryptor
    Write-Info 'Confidence'       ("{0} (score {1})" -f $assessment.Confidence, $assessment.Score)
    Write-Host ""
    foreach ($s in $signals) { Write-Host "    - $s" -ForegroundColor Gray }
    if ($assessment.Notes) {
        Write-Host ""
        Write-Host "  Note: $($assessment.Notes)" -ForegroundColor Yellow
    }

    if ($bestVal -gt 0) {
        Add-Finding -Category 'Ransomware' -Severity 'Critical' `
            -Title "Variant assessed as: $($assessment.Assessed)" `
            -Detail "Confidence $($assessment.Confidence) (score $($assessment.Score)). $($assessment.Notes)" `
            -Evidence ([pscustomobject]@{ Signals = $assessment.Signals }) `
            -Recommendation 'Record the variant for the insurer and law enforcement report. No free decryptor exists for current Akira builds - plan on restore from backup.'
    }

    $script:Report['Variant'] = $assessment
    Write-Log "Variant assessed: $($assessment.Assessed) [$($assessment.Confidence)]"
}

# -------------------------------------------------------
#  MODULE 4 - PERSISTENCE
# -------------------------------------------------------
function Test-SuspiciousCommand {
    <#
      Shared heuristics for anything that runs a command line at boot/logon.
      Returns the list of reasons the command line looks wrong, empty if clean.
    #>
    param([string]$Command)
    $reasons = New-Object System.Collections.ArrayList
    if (-not $Command) { return $reasons }
    $c = $Command.ToLowerInvariant()

    if ($c -match 'powershell|pwsh')                     { [void]$reasons.Add('launches PowerShell') }
    if ($c -match '-enc\b|-encodedcommand|frombase64')   { [void]$reasons.Add('base64-encoded command') }
    if ($c -match '-w\s+hidden|-windowstyle\s+hidden')   { [void]$reasons.Add('hidden window') }
    if ($c -match '-nop\b|-noprofile')                   { [void]$reasons.Add('-noprofile') }
    if ($c -match 'bypass')                              { [void]$reasons.Add('execution policy bypass') }
    if ($c -match 'downloadstring|downloadfile|invoke-webrequest|curl |wget |certutil|bitsadmin') { [void]$reasons.Add('network download') }
    if ($c -match 'iex |invoke-expression')              { [void]$reasons.Add('Invoke-Expression') }
    if ($c -match 'rundll32|regsvr32|mshta|wscript|cscript') { [void]$reasons.Add('LOLBin execution') }
    if ($c -match '\\temp\\|\\appdata\\|\\programdata\\|\\public\\|\\perflogs\\|\\users\\public') { [void]$reasons.Add('runs from a user-writable path') }
    if ($c -match '\\recycle')                           { [void]$reasons.Add('runs from the recycle bin') }
    if ($c -match 'vssadmin|wbadmin|bcdedit|wmic shadowcopy') { [void]$reasons.Add('backup/shadow-copy tampering command') }
    if ($c -match 'net user |net localgroup')            { [void]$reasons.Add('account manipulation') }
    if ($c -match 'anydesk|rustdesk|ngrok|cloudflared|screenconnect|atera') { [void]$reasons.Add('remote-access tooling') }

    # Comma stops PowerShell unrolling the list - callers append to it.
    return ,$reasons
}

function Get-RegistryValues {
    param([string]$Key)
    $out = New-Object System.Collections.ArrayList
    try {
        if (-not (Test-Path $Key)) { return $out }
        $item = Get-ItemProperty -Path $Key -ErrorAction Stop
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            [void]$out.Add([pscustomobject]@{
                Key   = $Key
                Name  = $p.Name
                Value = ConvertTo-SafeString $p.Value 2000
            })
        }
    } catch { }
    return ,$out
}

function Invoke-PersistenceAudit {
    Write-Header "4. Persistence"

    $p = [ordered]@{
        RunKeys           = @()
        StartupFolders    = @()
        ScheduledTasks    = @()
        Services          = @()
        WmiSubscriptions  = @()
        WinlogonKeys      = @()
        ImageFileExecution= @()
        AppInitDlls       = @()
        LsaPackages       = @()
        PrintMonitors     = @()
        NetshHelpers      = @()
        BitsJobs          = @()
        AccessibilityBins = @()
        RogueRootCerts    = @()
    }

    # --- 4.1 Run keys -------------------------------------------------
    Write-Host ""
    Write-Host "  Autorun registry keys" -ForegroundColor White

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    # Every loaded user hive, not just the analyst's own.
    try {
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop | Out-Null
        }
        foreach ($sid in (Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
                          Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' })) {
            $runKeys += "HKU:\$($sid.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            $runKeys += "HKU:\$($sid.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        }
    } catch { Write-Log "HKU enumeration failed: $_" 'WARN' }

    $runEntries = New-Object System.Collections.ArrayList
    foreach ($k in ($runKeys | Select-Object -Unique)) {
        foreach ($v in (Get-RegistryValues -Key $k)) {
            $reasons = Test-SuspiciousCommand -Command $v.Value
            $rec = [pscustomobject]@{
                Key        = $v.Key
                Name       = $v.Name
                Command    = $v.Value
                Suspicious = ($reasons.Count -gt 0)
                Reasons    = @($reasons)
            }
            [void]$runEntries.Add($rec)
            if ($reasons.Count -gt 0) {
                Add-Finding -Category 'Persistence' -Severity 'High' `
                    -Title "Suspicious autorun entry: $($v.Name)" `
                    -Detail "$($v.Key) -> $($v.Value) [$($reasons -join '; ')]" `
                    -Evidence $rec `
                    -Recommendation 'Validate against the client change record. Remove if unrecognised, then re-scan.'
            }
        }
    }
    $p.RunKeys = $runEntries
    Write-Info 'Autorun values found' $runEntries.Count

    # --- 4.2 Startup folders -----------------------------------------
    Write-Host ""
    Write-Host "  Startup folders" -ForegroundColor White
    $startupDirs = New-Object System.Collections.ArrayList
    [void]$startupDirs.Add([Environment]::GetFolderPath('CommonStartup'))
    try {
        foreach ($u in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction Stop)) {
            [void]$startupDirs.Add((Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        }
    } catch { }

    $startupItems = New-Object System.Collections.ArrayList
    foreach ($d in ($startupDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
        foreach ($f in (Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $target = ''
            if ($f.Extension -eq '.lnk') {
                try {
                    $sh = New-Object -ComObject WScript.Shell
                    $lnk = $sh.CreateShortcut($f.FullName)
                    $target = "$($lnk.TargetPath) $($lnk.Arguments)"
                } catch { }
            }
            $reasons = Test-SuspiciousCommand -Command "$($f.FullName) $target"
            $rec = [pscustomobject]@{
                Path        = $f.FullName
                Target      = $target
                CreatedUtc  = $f.CreationTimeUtc
                ModifiedUtc = $f.LastWriteTimeUtc
                Suspicious  = ($reasons.Count -gt 0)
                Reasons     = @($reasons)
            }
            [void]$startupItems.Add($rec)
            if ($reasons.Count -gt 0) {
                Add-Finding -Category 'Persistence' -Severity 'High' `
                    -Title "Suspicious startup-folder item: $($f.Name)" `
                    -Detail "$($f.FullName) -> $target [$($reasons -join '; ')]" `
                    -Evidence $rec `
                    -Recommendation 'Validate with the client. Remove if unrecognised.'
                Copy-Evidence -Source $f.FullName -SubFolder 'Persistence\Startup' | Out-Null
            }
        }
    }
    $p.StartupFolders = $startupItems
    Write-Info 'Startup items' $startupItems.Count

    # --- 4.3 Scheduled tasks -----------------------------------------
    Write-Host ""
    Write-Host "  Scheduled tasks" -ForegroundColor White
    $taskRecs = New-Object System.Collections.ArrayList

    if (Test-CommandExists 'Get-ScheduledTask') {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($t.TaskPath -like '\Microsoft\*') { continue }

            $actions = @()
            foreach ($a in $t.Actions) {
                $line = ''
                if ($a.PSObject.Properties['Execute']) { $line = "$($a.Execute) $($a.Arguments)" }
                elseif ($a.PSObject.Properties['ClassId']) { $line = "COM:$($a.ClassId)" }
                $actions += $line.Trim()
            }
            $cmd = ($actions -join ' | ')

            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }

            $runAs = ''
            try { $runAs = $t.Principal.UserId } catch { }

            $reasons = Test-SuspiciousCommand -Command $cmd
            if ($runAs -match '(?i)system' -and $cmd -match '(?i)\\users\\|\\temp\\') {
                [void]$reasons.Add('SYSTEM task running a binary from a user-writable path')
            }

            $rec = [pscustomobject]@{
                TaskPath    = $t.TaskPath
                TaskName    = $t.TaskName
                State       = "$($t.State)"
                RunAs       = $runAs
                Author      = $t.Author
                Command     = $cmd
                LastRunUtc  = if ($info) { $info.LastRunTime } else { $null }
                NextRunUtc  = if ($info) { $info.NextRunTime } else { $null }
                Suspicious  = ($reasons.Count -gt 0)
                Reasons     = @($reasons)
            }
            [void]$taskRecs.Add($rec)

            if ($reasons.Count -gt 0) {
                Add-Finding -Category 'Persistence' -Severity 'High' `
                    -Title "Suspicious scheduled task: $($t.TaskPath)$($t.TaskName)" `
                    -Detail "Runs as '$runAs': $cmd [$($reasons -join '; ')]" `
                    -Evidence $rec `
                    -Recommendation 'Confirm the task is sanctioned. If not, export the task XML as evidence and remove it.'
            }
        }
    } else {
        # Older hosts: fall back to schtasks output.
        try {
            $raw = & schtasks.exe /query /fo CSV /v 2>$null | ConvertFrom-Csv
            foreach ($t in $raw) {
                if ($t.TaskName -like '\Microsoft\*') { continue }
                $reasons = Test-SuspiciousCommand -Command $t.'Task To Run'
                [void]$taskRecs.Add([pscustomobject]@{
                    TaskPath = $t.TaskName; TaskName = $t.TaskName; State = $t.Status
                    RunAs = $t.'Run As User'; Author = $t.Author; Command = $t.'Task To Run'
                    LastRunUtc = $t.'Last Run Time'; NextRunUtc = $t.'Next Run Time'
                    Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
                })
            }
        } catch { }
    }

    # Recently written task definitions are a strong lead regardless of content.
    $taskDir = Join-Path $env:windir 'System32\Tasks'
    if (Test-Path $taskDir) {
        $cutoff = (Get-Date).AddDays(-$DaysBack)
        foreach ($tf in (Get-ChildItem $taskDir -Recurse -File -Force -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notlike '*\Tasks\Microsoft\*' })) {
            Add-Timeline $tf.LastWriteTimeUtc 'Filesystem' 'Scheduled task definition written' $tf.FullName
            Copy-Evidence -Source $tf.FullName -SubFolder 'Persistence\Tasks' -NewName ($tf.Name + '.xml') | Out-Null
        }
    }
    $p.ScheduledTasks = $taskRecs
    Write-Info 'Non-Microsoft tasks' $taskRecs.Count

    # --- 4.4 Services -------------------------------------------------
    Write-Host ""
    Write-Host "  Services" -ForegroundColor White
    $svcRecs = New-Object System.Collections.ArrayList
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $path = $s.PathName
        if (-not $path) { continue }

        $reasons = Test-SuspiciousCommand -Command $path

        # Unquoted path containing spaces is a privilege-escalation foothold.
        if ($path -notmatch '^\s*"' -and $path -match '^[A-Za-z]:\\[^"]*\s[^"]*\.exe') {
            [void]$reasons.Add('unquoted service path with spaces')
        }

        # Binary outside the normal install locations. Quoted paths keep their
        # spaces; an unquoted path with spaces truncates, which is the case we
        # already flag above.
        $binOnly = ''
        if     ($path -match '^\s*"([^"]+)"') { $binOnly = $Matches[1] }
        elseif ($path -match '^\s*(\S+)')     { $binOnly = $Matches[1] }

        if ($binOnly -match '^[A-Za-z]:\\' -and
            $binOnly -notmatch '(?i)\\windows\\|\\program files|\\programdata\\microsoft') {
            [void]$reasons.Add('binary outside Windows/Program Files')
        }

        $meta = $null
        if ($binOnly -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $binOnly -ErrorAction SilentlyContinue)) {
            $meta = Get-FileMeta -Path $binOnly
            if ($meta.Signature -eq 'NotSigned' -and $reasons.Count -gt 0) {
                [void]$reasons.Add('unsigned binary')
            }
        }

        $rec = [pscustomobject]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
            RunAs       = $s.StartName
            PathName    = ConvertTo-SafeString $path 1000
            BinarySha256= if ($meta) { $meta.Sha256 } else { '' }
            BinaryCreatedUtc = if ($meta) { $meta.CreatedUtc } else { $null }
            Signature   = if ($meta) { $meta.Signature } else { '' }
            Suspicious  = ($reasons.Count -gt 0)
            Reasons     = @($reasons)
        }

        if ($reasons.Count -gt 0) {
            [void]$svcRecs.Add($rec)
            $sev = if ($reasons -contains 'unquoted service path with spaces' -and $reasons.Count -eq 1) { 'Low' } else { 'High' }
            Add-Finding -Category 'Persistence' -Severity $sev `
                -Title "Service worth reviewing: $($s.Name)" `
                -Detail "$path [$($reasons -join '; ')]" `
                -Evidence $rec `
                -Recommendation 'Confirm the service is a sanctioned application. Attacker-installed services are usually recent and unsigned.'
        }
    }
    $p.Services = $svcRecs
    Write-Info 'Services flagged' $svcRecs.Count

    # --- 4.5 WMI event subscriptions ---------------------------------
    Write-Host ""
    Write-Host "  WMI event subscriptions" -ForegroundColor White
    $wmiRecs = New-Object System.Collections.ArrayList
    foreach ($cls in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
        try {
            foreach ($o in (Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop)) {
                $detail = switch ($cls) {
                    '__EventFilter'              { "Query: $($o.Query)" }
                    'CommandLineEventConsumer'   { "Executes: $($o.CommandLineTemplate)" }
                    'ActiveScriptEventConsumer'  { "Script: $(ConvertTo-SafeString $o.ScriptText 1500)" }
                    default                      { "Filter: $($o.Filter) Consumer: $($o.Consumer)" }
                }
                $rec = [pscustomobject]@{ Class = $cls; Name = $o.Name; Detail = ConvertTo-SafeString $detail 2000 }
                [void]$wmiRecs.Add($rec)

                if ($cls -in @('CommandLineEventConsumer','ActiveScriptEventConsumer')) {
                    Add-Finding -Category 'Persistence' -Severity 'High' `
                        -Title "WMI event consumer present: $($o.Name)" `
                        -Detail $rec.Detail `
                        -Evidence $rec `
                        -Recommendation 'WMI event consumers are rare in normal estates and are a favoured stealth persistence mechanism. Validate or remove.'
                }
            }
        } catch { }
    }
    $p.WmiSubscriptions = $wmiRecs
    Write-Info 'WMI subscription objects' $wmiRecs.Count

    # --- 4.6 Winlogon, IFEO, AppInit, LSA ----------------------------
    Write-Host ""
    Write-Host "  Logon and loader hijacks" -ForegroundColor White

    $wl = Get-RegistryValues -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $p.WinlogonKeys = @($wl | Where-Object { $_.Name -in @('Shell','Userinit','Taskman','AppSetup','GinaDLL','VmApplet') })
    foreach ($v in $p.WinlogonKeys) {
        $expected = switch ($v.Name) {
            'Shell'    { 'explorer.exe' }
            'Userinit' { 'C:\Windows\system32\userinit.exe,' }
            default    { $null }
        }
        if ($expected -and ($v.Value.Trim().TrimEnd(',') -ne $expected.Trim().TrimEnd(','))) {
            Add-Finding -Category 'Persistence' -Severity 'Critical' `
                -Title "Winlogon $($v.Name) has been modified" `
                -Detail "Value: '$($v.Value)' (expected '$expected')" `
                -Evidence $v `
                -Recommendation 'Winlogon Shell/Userinit hijacks run at every logon. Treat the host as compromised and rebuild.'
        }
        if ($v.Name -in @('Taskman','GinaDLL','VmApplet','AppSetup') -and $v.Value) {
            Add-Finding -Category 'Persistence' -Severity 'High' `
                -Title "Uncommon Winlogon value set: $($v.Name)" `
                -Detail "Value: $($v.Value)" -Evidence $v `
                -Recommendation 'These values are normally absent. Validate or remove.'
        }
    }

    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $ifeoRecs = New-Object System.Collections.ArrayList
    try {
        foreach ($k in (Get-ChildItem $ifeoRoot -ErrorAction Stop)) {
            $dbg = (Get-ItemProperty -Path $k.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                $rec = [pscustomobject]@{ Image = $k.PSChildName; Debugger = ConvertTo-SafeString $dbg 500 }
                [void]$ifeoRecs.Add($rec)
                Add-Finding -Category 'Persistence' -Severity 'High' `
                    -Title "IFEO debugger set on $($k.PSChildName)" `
                    -Detail "Debugger: $dbg" -Evidence $rec `
                    -Recommendation 'IFEO debuggers hijack execution of the named program. Validate or remove.'
            }
        }
    } catch { }
    $p.ImageFileExecution = $ifeoRecs

    $wopt = Get-RegistryValues -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $p.AppInitDlls = @($wopt | Where-Object { $_.Name -in @('AppInit_DLLs','LoadAppInit_DLLs') })
    $appInit = $p.AppInitDlls | Where-Object { $_.Name -eq 'AppInit_DLLs' -and $_.Value }
    if ($appInit) {
        Add-Finding -Category 'Persistence' -Severity 'High' `
            -Title 'AppInit_DLLs is populated' `
            -Detail "Value: $($appInit.Value)" -Evidence $appInit `
            -Recommendation 'AppInit_DLLs loads the named DLL into most processes. Validate or clear.'
    }

    $lsa = Get-RegistryValues -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $p.LsaPackages = @($lsa | Where-Object { $_.Name -in @('Security Packages','Authentication Packages','Notification Packages','RunAsPPL','LimitBlankPasswordUse') })
    foreach ($v in ($p.LsaPackages | Where-Object { $_.Name -like '*Packages' })) {
        if ($v.Value -match '(?i)mimilib|ssp|dummy') {
            Add-Finding -Category 'Persistence' -Severity 'Critical' `
                -Title "Unexpected LSA package registered: $($v.Name)" `
                -Detail "Value: $($v.Value)" -Evidence $v `
                -Recommendation 'A rogue LSA/SSP package captures credentials at every logon. Rebuild the host and reset all credentials used on it.'
        }
    }

    $pm = Get-RegistryValues -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $p.PrintMonitors = @($pm)
    $nh = Get-RegistryValues -Key 'HKLM:\SOFTWARE\Microsoft\NetSh'
    $p.NetshHelpers = @($nh)

    # --- 4.7 BITS jobs -----------------------------------------------
    $bits = New-Object System.Collections.ArrayList
    try {
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        foreach ($j in (Get-BitsTransfer -AllUsers -ErrorAction Stop)) {
            $rec = [pscustomobject]@{
                JobId = "$($j.JobId)"; DisplayName = $j.DisplayName; State = "$($j.JobState)"
                Owner = $j.OwnerAccount; Created = $j.CreationTime
                Files = (($j.FileList | ForEach-Object { "$($_.RemoteName) -> $($_.LocalName)" }) -join '; ')
            }
            [void]$bits.Add($rec)
            Add-Finding -Category 'Persistence' -Severity 'Medium' `
                -Title "BITS transfer job present: $($j.DisplayName)" `
                -Detail $rec.Files -Evidence $rec `
                -Recommendation 'Long-lived BITS jobs are used for stealthy download persistence. Validate or remove.'
        }
    } catch { }
    $p.BitsJobs = $bits

    # --- 4.8 Accessibility binary tampering --------------------------
    Write-Host ""
    Write-Host "  Accessibility / sticky-key backdoors" -ForegroundColor White
    $accRecs = New-Object System.Collections.ArrayList
    foreach ($b in @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe')) {
        $path = Join-Path $env:windir "System32\$b"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $meta = Get-FileMeta -Path $path
        # Only treat a populated non-Microsoft company as suspicious; an empty
        # VersionInfo on its own is too noisy to act on.
        $bad  = ($meta.Signature -ne 'Valid') -or ($meta.CompanyName -and $meta.CompanyName -notmatch '(?i)microsoft')
        $rec = [pscustomobject]@{
            Binary = $b; Path = $path; Sha256 = $meta.Sha256
            ModifiedUtc = $meta.ModifiedUtc; Signature = $meta.Signature
            Company = $meta.CompanyName; Suspicious = $bad
        }
        [void]$accRecs.Add($rec)
        if ($bad) {
            Add-Finding -Category 'Persistence' -Severity 'Critical' `
                -Title "Accessibility binary replaced or unsigned: $b" `
                -Detail "Signature '$($meta.Signature)', company '$($meta.CompanyName)', modified $($meta.ModifiedUtc)" `
                -Evidence $rec `
                -Recommendation 'Classic pre-logon backdoor reachable from the RDP logon screen. Rebuild the host.'
        }
    }
    $p.AccessibilityBins = $accRecs

    # --- 4.9 Recently added root certificates ------------------------
    $certRecs = New-Object System.Collections.ArrayList
    try {
        $cutoff = (Get-Date).AddDays(-$DaysBack)
        foreach ($c in (Get-ChildItem 'Cert:\LocalMachine\Root','Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue)) {
            if ($c.NotBefore -gt $cutoff) {
                $rec = [pscustomobject]@{
                    Subject = $c.Subject; Issuer = $c.Issuer; Thumbprint = $c.Thumbprint
                    NotBefore = $c.NotBefore; NotAfter = $c.NotAfter
                }
                [void]$certRecs.Add($rec)
                Add-Finding -Category 'Persistence' -Severity 'Medium' `
                    -Title "Root/CA certificate issued within the incident window: $($c.Subject)" `
                    -Detail "Thumbprint $($c.Thumbprint), valid from $($c.NotBefore)" -Evidence $rec `
                    -Recommendation 'Verify the certificate is expected. Attacker-installed roots enable TLS interception and signed-payload trust.'
            }
        }
    } catch { }
    $p.RogueRootCerts = $certRecs

    $script:Report['Persistence'] = $p

    $persistFindings = @($script:Findings | Where-Object { $_.Category -eq 'Persistence' })
    Write-Host ""
    if ($persistFindings.Count -eq 0) {
        Write-Result 'No persistence mechanisms flagged on this host.'
    } else {
        Write-Bad "$($persistFindings.Count) persistence item(s) need review."
    }
    Write-Log 'Persistence audit complete'
}

# -------------------------------------------------------
#  MODULE 5 - REMOTE ACCESS AND RMM
# -------------------------------------------------------
function Invoke-RemoteAccessAudit {
    Write-Header "5. Remote Access / RMM Footprint"

    $r = [ordered]@{
        InstalledProducts = @()
        AnyDeskTraces     = @()
        RdpSettings       = [ordered]@{}
        RdpUsers          = @()
    }

    $found = New-Object System.Collections.ArrayList
    foreach ($prod in $script:RemoteAccessProducts) {
        foreach ($path in $prod.Paths) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $di = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            $rec = [pscustomobject]@{
                Product     = $prod.Name
                Path        = $path
                CreatedUtc  = if ($di) { $di.CreationTimeUtc } else { $null }
                ModifiedUtc = if ($di) { $di.LastWriteTimeUtc } else { $null }
                Service     = ''
            }
            try {
                $svc = Get-CimInstance Win32_Service -ErrorAction Stop |
                       Where-Object { $_.PathName -like "*$($prod.Name)*" } | Select-Object -First 1
                if ($svc) { $rec.Service = "$($svc.Name) [$($svc.State)/$($svc.StartMode)]" }
            } catch { }

            [void]$found.Add($rec)
            if ($rec.CreatedUtc) { Add-Timeline $rec.CreatedUtc 'Filesystem' "Remote access product installed: $($prod.Name)" $path }

            Add-Finding -Category 'RemoteAccess' -Severity 'High' `
                -Title "Remote access / RMM product installed: $($prod.Name)" `
                -Detail "$path (installed $($rec.CreatedUtc) UTC)$(if ($rec.Service) { "; service $($rec.Service)" })" `
                -Evidence $rec `
                -Recommendation 'Akira routinely installs legitimate remote-access tools for persistence. Confirm each product against the client asset register; remove anything unsanctioned before reconnecting.'
        }
    }
    $r.InstalledProducts = $found
    if ($found.Count -eq 0) { Write-Result 'No known remote access / RMM products found.' }

    # AnyDesk trace files record incoming connection IDs - high value evidence.
    $adPaths = @(
        "$env:ProgramData\AnyDesk\ad.trace",
        "$env:ProgramData\AnyDesk\connection_trace.txt",
        "$env:ProgramData\AnyDesk\ad_svc.trace"
    )
    try {
        foreach ($u in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction Stop)) {
            $adPaths += (Join-Path $u.FullName 'AppData\Roaming\AnyDesk\ad.trace')
            $adPaths += (Join-Path $u.FullName 'AppData\Roaming\AnyDesk\connection_trace.txt')
        }
    } catch { }

    $adRecs = New-Object System.Collections.ArrayList
    foreach ($ap in ($adPaths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $ap)) { continue }
        $dest = Copy-Evidence -Source $ap -SubFolder 'RemoteAccess\AnyDesk' -NewName (($ap -replace '[:\\/]', '_')) -Note 'AnyDesk trace'
        $ids = @()
        try {
            $ids = Get-Content -LiteralPath $ap -ErrorAction Stop |
                   Select-String -Pattern 'Incoming session|External address|Logged in from' |
                   Select-Object -First 40 | ForEach-Object { ConvertTo-SafeString $_.Line 400 }
        } catch { }
        $rec = [pscustomobject]@{ Path = $ap; Collected = [bool]$dest; ConnectionLines = @($ids) }
        [void]$adRecs.Add($rec)

        if ($ids.Count -gt 0) {
            Add-Finding -Category 'RemoteAccess' -Severity 'High' `
                -Title 'AnyDesk connection history recovered' `
                -Detail "$($ids.Count) connection line(s) in $ap - contains remote AnyDesk IDs and source addresses." `
                -Evidence $rec `
                -Recommendation 'Extract the remote AnyDesk IDs and source IPs for the intrusion timeline and law enforcement report.'
        }
    }
    $r.AnyDeskTraces = $adRecs

    # RDP posture.
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpDeny  = (Get-ItemProperty -Path $ts -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpPort  = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber
    $nlaVal   = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
    $shadow   = (Get-ItemProperty -Path $ts -Name 'Shadow' -ErrorAction SilentlyContinue).Shadow

    $r.RdpSettings = [ordered]@{
        RdpEnabled          = ($rdpDeny -eq 0)
        ListeningPort       = if ($null -ne $rdpPort) { $rdpPort } else { 3389 }
        NetworkLevelAuth    = ($nlaVal -eq 1)
        ShadowPolicy        = $shadow
    }
    Write-Info 'RDP enabled'    $r.RdpSettings.RdpEnabled
    Write-Info 'RDP port'       $r.RdpSettings.ListeningPort
    Write-Info 'NLA enabled'    $r.RdpSettings.NetworkLevelAuth

    if ($r.RdpSettings.RdpEnabled -and -not $r.RdpSettings.NetworkLevelAuth) {
        Add-Finding -Category 'RemoteAccess' -Severity 'Medium' `
            -Title 'RDP is enabled with Network Level Authentication off' `
            -Detail 'NLA off exposes the logon screen pre-authentication.' `
            -Recommendation 'Enable NLA, or disable RDP if it is not required, before reconnecting.'
    }
    if ($null -ne $rdpPort -and $rdpPort -ne 3389) {
        Add-Finding -Category 'RemoteAccess' -Severity 'Medium' `
            -Title "RDP is listening on a non-default port ($rdpPort)" `
            -Detail 'Port changes are sometimes made by attackers to evade detection, and sometimes by IT for the same reason.' `
            -Recommendation 'Confirm the port change is a documented client configuration.'
    }

    try {
        $r.RdpUsers = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop |
                        ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" })
    } catch {
        try { $r.RdpUsers = @(& net localgroup "Remote Desktop Users" 2>$null) } catch { }
    }
    if ($r.RdpUsers.Count -gt 0) { Write-Info 'RDP users group' ($r.RdpUsers -join ', ') }

    $script:Report['RemoteAccess'] = $r
    Write-Log 'Remote access audit complete'
}

# -------------------------------------------------------
#  MODULE 6 - DEFENCES AND ANTI-FORENSICS
# -------------------------------------------------------
function Invoke-DefenceAudit {
    Write-Header "6. Endpoint Defences and Anti-Forensics"

    $d = [ordered]@{
        Defender        = [ordered]@{}
        DefenderExclusions = [ordered]@{}
        InstalledAV     = @()
        Firewall        = @()
        ShadowCopies    = @()
        VssService      = ''
        BootConfig      = [ordered]@{}
        SecurityLogState= [ordered]@{}
        Sysmon          = $false
        BadDrivers      = @()
    }

    # --- Defender -----------------------------------------------------
    Write-Host ""
    Write-Host "  Microsoft Defender" -ForegroundColor White
    if (Test-CommandExists 'Get-MpComputerStatus') {
        try {
            $st = Get-MpComputerStatus -ErrorAction Stop
            $d.Defender = [ordered]@{
                AMServiceEnabled       = $st.AMServiceEnabled
                AntivirusEnabled       = $st.AntivirusEnabled
                RealTimeProtection     = $st.RealTimeProtectionEnabled
                BehaviorMonitor        = $st.BehaviorMonitorEnabled
                TamperProtection       = $st.IsTamperProtected
                SignatureAge           = $st.AntivirusSignatureAge
                SignatureVersion       = $st.AntivirusSignatureVersion
                LastFullScan           = $st.FullScanEndTime
                LastQuickScan          = $st.QuickScanEndTime
            }
            Write-Info 'Real-time protection' $st.RealTimeProtectionEnabled
            Write-Info 'Tamper protection'    $st.IsTamperProtected
            Write-Info 'Signature age (days)' $st.AntivirusSignatureAge

            if (-not $st.RealTimeProtectionEnabled) {
                Add-Finding -Category 'Defences' -Severity 'Critical' `
                    -Title 'Defender real-time protection is disabled' `
                    -Detail 'Akira disables endpoint protection before deploying the encryptor.' `
                    -Recommendation 'Re-enable real-time protection and tamper protection, and confirm no policy is forcing it off, before reconnecting.'
            }
            if ($st.PSObject.Properties['IsTamperProtected'] -and -not $st.IsTamperProtected) {
                Add-Finding -Category 'Defences' -Severity 'High' `
                    -Title 'Defender tamper protection is off' -Detail '' `
                    -Recommendation 'Enable tamper protection (ideally enforced from Intune/Defender portal, not locally).'
            }
            if ($st.AntivirusSignatureAge -gt 7) {
                Add-Finding -Category 'Defences' -Severity 'Medium' `
                    -Title "Defender signatures are $($st.AntivirusSignatureAge) days old" `
                    -Detail 'Expected on an isolated host, but must be resolved before reconnection.' `
                    -Recommendation 'Update signatures and run a full scan before returning the host to service.'
            }
        } catch { Write-Log "Get-MpComputerStatus failed: $_" 'WARN' }

        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $d.DefenderExclusions = [ordered]@{
                Paths      = @($pref.ExclusionPath)
                Extensions = @($pref.ExclusionExtension)
                Processes  = @($pref.ExclusionProcess)
                IpAddresses= @($pref.ExclusionIpAddress)
                DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
                DisableScriptScanning     = $pref.DisableScriptScanning
                DisableIOAVProtection     = $pref.DisableIOAVProtection
                MAPSReporting             = "$($pref.MAPSReporting)"
                SubmitSamplesConsent      = "$($pref.SubmitSamplesConsent)"
            }
            $excl = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension)
            $excl = $excl | Where-Object { $_ }
            if ($excl.Count -gt 0) {
                # Broad exclusions (drive roots, whole user tree) are the ones that matter.
                $broad = $excl | Where-Object { $_ -match '^[A-Za-z]:\\?$|\\users\\?$|\\programdata\\?$|\\temp\\?$|^\.\w+$' }
                $sev = if ($broad) { 'Critical' } else { 'High' }
                Add-Finding -Category 'Defences' -Severity $sev `
                    -Title "$($excl.Count) Defender exclusion(s) configured" `
                    -Detail ("Exclusions: " + (($excl | Select-Object -First 20) -join '; ')) `
                    -Evidence $d.DefenderExclusions `
                    -Recommendation 'Attackers add exclusions to stage payloads safely. Verify every exclusion against the client change record and remove anything unrecognised.'
            } else {
                Write-Result 'No Defender exclusions configured.'
            }
        } catch { }
    } else {
        Write-Result 'Defender cmdlets unavailable (third-party AV or server core).' $false
    }

    # Policy-level Defender kill switches.
    foreach ($pol in @(
        @{ Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name='DisableAntiSpyware'; Label='DisableAntiSpyware policy' },
        @{ Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableRealtimeMonitoring'; Label='DisableRealtimeMonitoring policy' },
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'; Name='TamperProtection'; Label='TamperProtection value' }
    )) {
        $v = (Get-ItemProperty -Path $pol.Key -Name $pol.Name -ErrorAction SilentlyContinue).($pol.Name)
        if ($null -ne $v) {
            $d.Defender[$pol.Label] = $v
            if ($pol.Name -ne 'TamperProtection' -and $v -eq 1) {
                Add-Finding -Category 'Defences' -Severity 'Critical' `
                    -Title "Defender disabled by policy: $($pol.Label) = 1" `
                    -Detail "$($pol.Key)\$($pol.Name)" `
                    -Recommendation 'Remove the policy value and confirm it is not being re-applied by GPO. Attackers push this via Group Policy across the estate.'
            }
        }
    }

    # --- Registered AV products --------------------------------------
    try {
        $d.InstalledAV = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.displayName; State = $_.productState; Path = $_.pathToSignedProductExe } })
    } catch { }

    # --- Firewall ----------------------------------------------------
    Write-Host ""
    Write-Host "  Firewall" -ForegroundColor White
    try {
        $d.Firewall = @(Get-NetFirewallProfile -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Profile = $_.Name; Enabled = [bool]$_.Enabled; Inbound = "$($_.DefaultInboundAction)"; Outbound = "$($_.DefaultOutboundAction)" } })
        foreach ($fp in $d.Firewall) {
            Write-Info "  $($fp.Profile)" ("Enabled={0} Inbound={1}" -f $fp.Enabled, $fp.Inbound)
            if (-not $fp.Enabled) {
                Add-Finding -Category 'Defences' -Severity 'High' `
                    -Title "Windows Firewall is disabled for the $($fp.Profile) profile" -Detail '' -Evidence $fp `
                    -Recommendation 'Re-enable the firewall profile before reconnecting.'
            }
        }
    } catch { }

    # --- Shadow copies / backup destruction --------------------------
    Write-Host ""
    Write-Host "  Volume Shadow Copies" -ForegroundColor White
    try {
        $d.ShadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Id = $_.ID; Volume = $_.VolumeName; InstallDate = $_.InstallDate } })
    } catch { }
    try { $d.VssService = (Get-Service -Name VSS -ErrorAction Stop).Status.ToString() } catch { }

    Write-Info 'Shadow copies present' $d.ShadowCopies.Count
    Write-Info 'VSS service'           $d.VssService

    if ($d.ShadowCopies.Count -eq 0) {
        Add-Finding -Category 'Defences' -Severity 'High' `
            -Title 'No volume shadow copies exist on this host' `
            -Detail 'Akira deletes shadow copies (typically via WMI or vssadmin) immediately before encryption. Their absence is consistent with that, though some hosts never had VSS configured.' `
            -Recommendation 'Confirm against the client backup policy. Recovery will depend on offline/immutable backups.'
    }

    # Boot recovery settings are commonly disabled by ransomware.
    try {
        $bcd = & bcdedit.exe /enum 2>$null | Out-String
        $d.BootConfig = [ordered]@{
            RecoveryEnabled     = ($bcd -match '(?im)^recoveryenabled\s+Yes')
            BootStatusPolicy    = if ($bcd -match '(?im)^bootstatuspolicy\s+(\S+)') { $Matches[1] } else { '' }
            Raw                 = ConvertTo-SafeString $bcd 6000
        }
        if ($bcd -match '(?im)^bootstatuspolicy\s+ignoreallfailures') {
            Add-Finding -Category 'Defences' -Severity 'High' `
                -Title 'Boot status policy set to ignoreallfailures' `
                -Detail 'Ransomware sets this (with bcdedit) to stop Windows Recovery Environment from launching after failed boots.' `
                -Recommendation 'Restore the default boot policy: bcdedit /set {default} bootstatuspolicy displayallfailures'
        }
    } catch { }

    # --- Sysmon ------------------------------------------------------
    try { $d.Sysmon = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) } catch { }

    # --- Vulnerable / BYOVD drivers ----------------------------------
    Write-Host ""
    Write-Host "  Kernel drivers (BYOVD)" -ForegroundColor White
    $drvRecs = New-Object System.Collections.ArrayList
    $drvDirs = @("$env:windir\System32\drivers", "$env:windir\Temp", "$env:SystemDrive\ProgramData", "$env:SystemDrive\Users") |
               Where-Object { Test-Path $_ }
    $badNames = $script:BadDrivers | ForEach-Object { $_.Name }

    foreach ($dd in $drvDirs) {
        foreach ($hit in (Get-BoundedFiles -Root $dd -IncludeNames $badNames -MaxDepth 3 -MaxResults 100 -TimeoutSeconds 120)) {
            $leaf = [System.IO.Path]::GetFileName($hit).ToLowerInvariant()
            $def  = $script:BadDrivers | Where-Object { $_.Name -eq $leaf } | Select-Object -First 1
            $meta = Get-FileMeta -Path $hit
            $rec = [pscustomobject]@{
                Driver = $leaf; Description = $def.Desc; Path = $hit
                Sha256 = $meta.Sha256; CreatedUtc = $meta.CreatedUtc; Signature = $meta.Signature
            }
            [void]$drvRecs.Add($rec)
            if ($meta.CreatedUtc) { Add-Timeline $meta.CreatedUtc 'Filesystem' "Vulnerable driver dropped: $leaf" $hit }
            Add-Finding -Category 'Defences' -Severity 'Critical' `
                -Title "Known-abused kernel driver present: $leaf" `
                -Detail "$($def.Desc) - $hit" -Evidence $rec `
                -Recommendation 'Bring-your-own-vulnerable-driver activity means kernel-level AV/EDR tampering. Rebuild the host and enable the Microsoft vulnerable driver blocklist.'
        }
    }

    # Anything registered as a service driver but living outside drivers\ is odd.
    try {
        foreach ($drv in (Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' })) {
            $pn = $drv.PathName
            if ($pn -and $pn -match '(?i)\\users\\|\\temp\\|\\programdata\\|\\perflogs\\') {
                $rec = [pscustomobject]@{ Driver = $drv.Name; Path = $pn; State = $drv.State; StartMode = $drv.StartMode }
                [void]$drvRecs.Add($rec)
                Add-Finding -Category 'Defences' -Severity 'Critical' `
                    -Title "Running kernel driver loaded from a user-writable path: $($drv.Name)" `
                    -Detail $pn -Evidence $rec `
                    -Recommendation 'Legitimate drivers do not load from Temp/Users/ProgramData. Treat as BYOVD and rebuild.'
            }
        }
    } catch { }
    $d.BadDrivers = $drvRecs
    if ($drvRecs.Count -eq 0) { Write-Result 'No known-abused drivers found.' }

    $script:Report['Defences'] = $d
    Write-Log 'Defence audit complete'
}

# -------------------------------------------------------
#  MODULE 7 - ACCOUNTS
# -------------------------------------------------------
function Invoke-AccountAudit {
    Write-Header "7. Accounts and Credential Exposure"

    $a = [ordered]@{
        LocalUsers        = @()
        LocalAdmins       = @()
        RecentlyCreated   = (New-Object System.Collections.ArrayList)
        Profiles          = @()
        CredentialDumps   = @()
        DomainRole        = if ($script:Report['System']) { $script:Report['System'].DomainRole } else { '' }
    }

    $cutoff = (Get-Date).AddDays(-$DaysBack)

    # --- Local users --------------------------------------------------
    $users = @()
    if (Test-CommandExists 'Get-LocalUser') {
        try {
            $users = Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    Enabled           = $_.Enabled
                    SID               = "$($_.SID)"
                    Description       = $_.Description
                    LastLogon         = $_.LastLogon
                    PasswordLastSet   = $_.PasswordLastSet
                    PasswordExpires   = $_.PasswordExpires
                    PasswordRequired  = $_.PasswordRequired
                }
            }
        } catch { }
    }
    if ($users.Count -eq 0) {
        try {
            $users = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name; Enabled = (-not $_.Disabled); SID = $_.SID
                    Description = $_.Description; LastLogon = $null
                    PasswordLastSet = $null; PasswordExpires = $null
                    PasswordRequired = $_.PasswordRequired
                }
            }
        } catch { }
    }
    $a.LocalUsers = $users
    Write-Info 'Local accounts' $users.Count

    foreach ($u in $users) {
        if ($u.PasswordLastSet -and $u.PasswordLastSet -gt $cutoff) {
            [void]$a.RecentlyCreated.Add($u)
            Add-Finding -Category 'Accounts' -Severity 'High' `
                -Title "Local account password set during the incident window: $($u.Name)" `
                -Detail "Password last set $($u.PasswordLastSet); account enabled = $($u.Enabled)" `
                -Evidence $u `
                -Recommendation 'Confirm the change with the client. Attackers create or reset local accounts to keep access after remediation.'
        }
        if ($u.Enabled -and $u.PasswordRequired -eq $false) {
            Add-Finding -Category 'Accounts' -Severity 'Medium' `
                -Title "Enabled local account with no password requirement: $($u.Name)" -Detail '' -Evidence $u `
                -Recommendation 'Set a password or disable the account.'
        }
    }

    # Profile directories give a creation date even when the account is gone.
    try {
        $a.Profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | ForEach-Object {
            $lp = $_.LocalPath
            $created = $null
            try { if (Test-Path -LiteralPath $lp) { $created = (Get-Item -LiteralPath $lp -Force).CreationTimeUtc } } catch { }
            [pscustomobject]@{
                LocalPath = $lp; SID = $_.SID; Special = $_.Special
                LastUseUtc = $_.LastUseTime; CreatedUtc = $created
            }
        })
        foreach ($pr in ($a.Profiles | Where-Object { -not $_.Special -and $_.CreatedUtc -and $_.CreatedUtc -gt $cutoff })) {
            Add-Finding -Category 'Accounts' -Severity 'High' `
                -Title "User profile created during the incident window: $(Split-Path $pr.LocalPath -Leaf)" `
                -Detail "$($pr.LocalPath) created $($pr.CreatedUtc) UTC (SID $($pr.SID))" -Evidence $pr `
                -Recommendation 'A new profile means that account logged on interactively during the incident. Confirm it is legitimate.'
            Add-Timeline $pr.CreatedUtc 'Filesystem' 'User profile created' $pr.LocalPath
        }
    } catch { }

    # --- Local administrators ----------------------------------------
    Write-Host ""
    Write-Host "  Local Administrators group" -ForegroundColor White
    $admins = @()
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Class = "$($_.ObjectClass)"; Source = "$($_.PrincipalSource)"; SID = "$($_.SID)" } })
    } catch {
        try {
            $raw = & net localgroup Administrators 2>$null
            $admins = @($raw | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' } |
                        ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); Class = ''; Source = ''; SID = '' } })
        } catch { }
    }
    $a.LocalAdmins = $admins
    foreach ($ad in $admins) { Write-Host "    - $($ad.Name)" -ForegroundColor Gray }

    # Cross-reference: a local admin whose password was set inside the window.
    foreach ($ad in $admins) {
        $leaf = ($ad.Name -split '\\')[-1]
        $match = $users | Where-Object { $_.Name -eq $leaf -and $_.PasswordLastSet -and $_.PasswordLastSet -gt $cutoff }
        if ($match) {
            Add-Finding -Category 'Accounts' -Severity 'Critical' `
                -Title "Local administrator changed during the incident window: $($ad.Name)" `
                -Detail "Member of Administrators; password last set $($match.PasswordLastSet)" -Evidence $ad `
                -Recommendation 'Treat as an attacker-controlled backdoor account until the client proves otherwise.'
        }
    }

    # --- Credential theft artefacts ----------------------------------
    Write-Host ""
    Write-Host "  Credential theft artefacts" -ForegroundColor White
    $dumpNames = @('lsass.dmp','lsass.dump','lsass_dump.dmp','ntds.dit','ntds.jfm','SAM','SYSTEM','SECURITY','procdump.exe','procdump64.exe','nanodump.exe')
    $dumpRoots = @("$env:windir\Temp", "$env:SystemDrive\Temp", "$env:SystemDrive\ProgramData", "$env:SystemDrive\Users", "$env:SystemDrive\Perflogs", "$env:SystemDrive\Windows\NTDS") |
                 Where-Object { Test-Path $_ }

    $dumps = New-Object System.Collections.ArrayList
    foreach ($dr in $dumpRoots) {
        foreach ($hit in (Get-BoundedFiles -Root $dr -IncludeNames $dumpNames -MaxDepth 4 -MaxResults 200 -TimeoutSeconds 180)) {
            # SAM/SYSTEM/SECURITY in their normal home are just the live hives.
            if ($hit -match '(?i)\\Windows\\System32\\config\\') { continue }
            if ($hit -match '(?i)\\Windows\\NTDS\\ntds\.dit$')    { continue }

            $meta = Get-FileMeta -Path $hit -NoHash
            $rec = [pscustomobject]@{
                Path = $hit; SizeBytes = $meta.SizeBytes
                CreatedUtc = $meta.CreatedUtc; ModifiedUtc = $meta.ModifiedUtc
            }
            [void]$dumps.Add($rec)
            if ($meta.CreatedUtc) { Add-Timeline $meta.CreatedUtc 'Filesystem' 'Credential dump artefact created' $hit }
            Add-Finding -Category 'Accounts' -Severity 'Critical' `
                -Title "Credential theft artefact on disk: $(Split-Path $hit -Leaf)" `
                -Detail "$hit ($([math]::Round($meta.SizeBytes/1MB,1)) MB, created $($meta.CreatedUtc) UTC)" -Evidence $rec `
                -Recommendation 'Assume every credential used on this host is compromised. Force a domain-wide password reset and reset krbtgt twice if this is a domain environment.'
        }
    }
    $a.CredentialDumps = $dumps
    if ($dumps.Count -eq 0) { Write-Result 'No credential-dump artefacts found in the usual staging paths.' }

    if ($a.DomainRole -match 'Domain Controller') {
        Add-Finding -Category 'Accounts' -Severity 'High' `
            -Title 'This host is a Domain Controller' `
            -Detail 'Any compromise here is a full-domain compromise.' `
            -Recommendation 'Plan a domain-wide credential reset including two krbtgt resets, and rebuild rather than clean this host.'
    }

    $script:Report['Accounts'] = $a
    Write-Log 'Account audit complete'
}

# -------------------------------------------------------
#  MODULE 8 - NETWORK POSTURE
# -------------------------------------------------------
function Invoke-NetworkAudit {
    Write-Header "8. Network Posture"

    $n = [ordered]@{
        Listeners        = @()
        Established      = @()
        Shares           = @()
        HostsFileEntries = @()
        DnsServers       = @()
        ProxySettings    = [ordered]@{}
        SmbV1Enabled     = $null
        MappedDrives     = @()
    }

    # --- Listening and established -----------------------------------
    if (Test-CommandExists 'Get-NetTCPConnection') {
        try {
            $conns = Get-NetTCPConnection -ErrorAction Stop
            $procs = @{}
            foreach ($pr in (Get-Process -ErrorAction SilentlyContinue)) { $procs[$pr.Id] = $pr.ProcessName }

            $n.Listeners = @($conns | Where-Object { $_.State -eq 'Listen' } | ForEach-Object {
                [pscustomobject]@{
                    LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                    Pid = $_.OwningProcess; Process = $procs[[int]$_.OwningProcess]
                }
            } | Sort-Object LocalPort -Unique)

            $n.Established = @($conns | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
                [pscustomobject]@{
                    LocalPort = $_.LocalPort; RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort
                    Pid = $_.OwningProcess; Process = $procs[[int]$_.OwningProcess]
                }
            })
        } catch { }
    } else {
        try { $n.Listeners = @(& netstat.exe -ano 2>$null | Select-String 'LISTENING' | ForEach-Object { ConvertTo-SafeString $_.Line 300 }) } catch { }
    }

    # Anything talking to a routable address on an "offline" host is a red flag.
    foreach ($c in $n.Established) {
        $ra = "$($c.RemoteAddress)"
        if ($ra -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80:|0\.0\.0\.0)') { continue }
        Add-Finding -Category 'Network' -Severity 'High' `
            -Title "Active connection to a public address: $ra`:$($c.RemotePort)" `
            -Detail "Process $($c.Process) (PID $($c.Pid))" -Evidence $c `
            -Recommendation 'This host is supposed to be isolated. Identify the process and confirm the destination before reconnecting.'
    }
    Write-Info 'Listening ports'      $n.Listeners.Count
    Write-Info 'Established sessions' $n.Established.Count

    # --- Shares -------------------------------------------------------
    try {
        $n.Shares = @(Get-CimInstance Win32_Share -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.Path; Type = $_.Type; Description = $_.Description } })
        foreach ($sh in ($n.Shares | Where-Object { $_.Name -notmatch '^\w\$$|^(ADMIN|IPC)\$$' })) {
            Write-Host "    - $($sh.Name) -> $($sh.Path)" -ForegroundColor Gray
        }
    } catch { }

    # --- Hosts file ---------------------------------------------------
    $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    if (Test-Path $hostsPath) {
        try {
            $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop |
                     Where-Object { $_ -and $_.Trim() -notmatch '^#' -and $_.Trim() -ne '' }
            $n.HostsFileEntries = @($lines | ForEach-Object { ConvertTo-SafeString $_ 300 })
            if ($n.HostsFileEntries.Count -gt 0) {
                Add-Finding -Category 'Network' -Severity 'Medium' `
                    -Title "$($n.HostsFileEntries.Count) active entr(ies) in the hosts file" `
                    -Detail ($n.HostsFileEntries -join ' | ') -Evidence $n.HostsFileEntries `
                    -Recommendation 'Ransomware operators add hosts entries to block AV/telemetry endpoints. Verify each entry.'
            }
            Copy-Evidence -Source $hostsPath -SubFolder 'Network' -Note 'hosts file' | Out-Null
        } catch { }
    }

    # --- DNS, proxy, SMBv1 -------------------------------------------
    try {
        $n.DnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses } |
            ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Servers = ($_.ServerAddresses -join ', ') } })
    } catch { }

    try {
        $ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $n.ProxySettings = [ordered]@{ ProxyEnable = $ie.ProxyEnable; ProxyServer = $ie.ProxyServer; AutoConfigURL = $ie.AutoConfigURL }
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
            Add-Finding -Category 'Network' -Severity 'Low' `
                -Title "A proxy is configured for the current user: $($ie.ProxyServer)" -Detail '' `
                -Recommendation 'Confirm the proxy is a client standard.'
        }
    } catch { }

    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $n.SmbV1Enabled = [bool]$smb.EnableSMB1Protocol
        if ($n.SmbV1Enabled) {
            Add-Finding -Category 'Network' -Severity 'Medium' `
                -Title 'SMBv1 is enabled on this host' -Detail '' `
                -Recommendation 'Disable SMBv1 before reconnecting.'
        }
    } catch { }

    # --- Command-line captures for the case file ---------------------
    foreach ($cmd in @(
        @{ File='ipconfig_all.txt';  Exe='ipconfig.exe';  Args=@('/all') },
        @{ File='netstat_ano.txt';   Exe='netstat.exe';   Args=@('-ano') },
        @{ File='arp_a.txt';         Exe='arp.exe';       Args=@('-a') },
        @{ File='route_print.txt';   Exe='route.exe';     Args=@('print') },
        @{ File='net_share.txt';     Exe='net.exe';       Args=@('share') },
        @{ File='net_session.txt';   Exe='net.exe';       Args=@('session') },
        @{ File='tasklist_v.txt';    Exe='tasklist.exe';  Args=@('/v') },
        @{ File='tasklist_svc.txt';  Exe='tasklist.exe';  Args=@('/svc') },
        @{ File='whoami_all.txt';    Exe='whoami.exe';    Args=@('/all') },
        @{ File='systeminfo.txt';    Exe='systeminfo.exe';Args=@() },
        @{ File='qwinsta.txt';       Exe='qwinsta.exe';   Args=@() }
    )) {
        try {
            $argList = @($cmd.Args)
            $out = if ($argList.Count -gt 0) { & $cmd.Exe @argList 2>&1 | Out-String }
                   else                      { & $cmd.Exe 2>&1 | Out-String }
            Save-TextEvidence -Name $cmd.File -SubFolder 'Commands' -Content $out -Note "Output of $($cmd.Exe) $($argList -join ' ')"
        } catch { }
    }

    $script:Report['Network'] = $n
    Write-Log 'Network audit complete'
}

# -------------------------------------------------------
#  MODULE 9 - EVENT LOGS
# -------------------------------------------------------
function Invoke-EventLogAudit {
    Write-Header "9. Event Log Analysis (last $DaysBack days)"

    $e = [ordered]@{
        Skipped          = $SkipEventLogs.IsPresent
        WindowDays       = $DaysBack
        LogSizes         = @()
        Counts           = [ordered]@{}
        ClearedLogs      = @()
        ServiceInstalls  = @()
        AccountEvents    = @()
        RdpLogons        = @()
        DefenderAlerts   = @()
        PowerShellHits   = @()
        ShadowCopyEvents = @()
    }

    if ($SkipEventLogs) {
        Write-Step 'Event log analysis skipped (-SkipEventLogs).'
        $script:Report['Events'] = $e
        return
    }

    $start = (Get-Date).AddDays(-$DaysBack)

    function Get-Events {
        param([string]$LogName, [int[]]$Ids, [int]$Max = 400)
        try {
            $filter = @{ LogName = $LogName; StartTime = $start }
            if ($Ids -and $Ids.Count -gt 0) { $filter['Id'] = $Ids }
            return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop)
        } catch {
            return @()
        }
    }

    # Log sizes tell you how far back the evidence actually reaches.
    try {
        $e.LogSizes = @(Get-WinEvent -ListLog 'Security','System','Application','Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject]@{
                    Log = $_.LogName; RecordCount = $_.RecordCount
                    MaxSizeMB = [math]::Round($_.MaximumSizeInBytes / 1MB, 0)
                    OldestRecordUtc = $null
                }
            })
    } catch { }

    # --- Log clearing (anti-forensics) --------------------------------
    Write-Host ""
    Write-Host "  Log clearing" -ForegroundColor White
    foreach ($pair in @(@{L='Security'; I=@(1102)}, @{L='System'; I=@(104)})) {
        foreach ($ev in (Get-Events -LogName $pair.L -Ids $pair.I -Max 100)) {
            $rec = [pscustomobject]@{
                TimeUtc = $ev.TimeCreated.ToUniversalTime(); Log = $pair.L; Id = $ev.Id
                Message = ConvertTo-SafeString $ev.Message 1000
            }
            $e.ClearedLogs += $rec
            Add-Timeline $rec.TimeUtc 'EventLog' "Event log cleared ($($pair.L) ID $($ev.Id))" $rec.Message
            Add-Finding -Category 'AntiForensics' -Severity 'High' `
                -Title "Event log cleared: $($pair.L) (Event ID $($ev.Id))" `
                -Detail "Cleared at $($rec.TimeUtc) UTC. $($rec.Message)" -Evidence $rec `
                -Recommendation 'Deliberate log clearing means the on-host timeline is incomplete. Pivot to network, backup and EDR telemetry for the missing window.'
        }
    }
    if ($e.ClearedLogs.Count -eq 0) { Write-Result 'No log-clearing events in the window.' }

    # --- Service installs ---------------------------------------------
    Write-Host ""
    Write-Host "  Service installations (System 7045)" -ForegroundColor White
    foreach ($ev in (Get-Events -LogName 'System' -Ids @(7045) -Max 300)) {
        $msg = ConvertTo-SafeString $ev.Message 1200
        $rec = [pscustomobject]@{ TimeUtc = $ev.TimeCreated.ToUniversalTime(); Message = $msg }
        $e.ServiceInstalls += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' 'Service installed (7045)' $msg

        if ($msg -match '(?i)psexesvc|paexec|remcom|powershell|cmd\.exe /c|\\temp\\|\\users\\|\\programdata\\') {
            Add-Finding -Category 'LateralMovement' -Severity 'Critical' `
                -Title 'Suspicious service installation recorded (Event 7045)' `
                -Detail "$($rec.TimeUtc) UTC - $msg" -Evidence $rec `
                -Recommendation 'PsExec-style service installs indicate remote code execution on this host. Correlate the timestamp with logon events to identify the source.'
        }
    }
    Write-Info 'Service installs' $e.ServiceInstalls.Count

    # --- Account changes ----------------------------------------------
    Write-Host ""
    Write-Host "  Account and group changes (Security)" -ForegroundColor White
    $acctIds = @(4720, 4722, 4724, 4726, 4728, 4732, 4756, 4738, 4740)
    foreach ($ev in (Get-Events -LogName 'Security' -Ids $acctIds -Max 500)) {
        $msg = ConvertTo-SafeString $ev.Message 800
        $rec = [pscustomobject]@{ TimeUtc = $ev.TimeCreated.ToUniversalTime(); Id = $ev.Id; Message = $msg }
        $e.AccountEvents += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' "Account event $($ev.Id)" $msg

        if ($ev.Id -in @(4720, 4728, 4732, 4756)) {
            $label = switch ($ev.Id) {
                4720 { 'user account created' }
                4728 { 'member added to a global security group' }
                4732 { 'member added to a local security group' }
                4756 { 'member added to a universal security group' }
            }
            Add-Finding -Category 'Accounts' -Severity 'High' `
                -Title "Security event $($ev.Id): $label" `
                -Detail "$($rec.TimeUtc) UTC - $msg" -Evidence $rec `
                -Recommendation 'Confirm each account creation and privileged group change against client change control.'
        }
    }
    Write-Info 'Account events' $e.AccountEvents.Count

    # --- RDP logons ----------------------------------------------------
    Write-Host ""
    Write-Host "  Remote logons" -ForegroundColor White
    foreach ($ev in (Get-Events -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids @(21,22,25) -Max 400)) {
        $msg = ConvertTo-SafeString $ev.Message 600
        $rec = [pscustomobject]@{ TimeUtc = $ev.TimeCreated.ToUniversalTime(); Id = $ev.Id; Message = $msg }
        $e.RdpLogons += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' "RDP session event $($ev.Id)" $msg
    }
    foreach ($ev in (Get-Events -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Ids @(1149) -Max 400)) {
        $msg = ConvertTo-SafeString $ev.Message 600
        $rec = [pscustomobject]@{ TimeUtc = $ev.TimeCreated.ToUniversalTime(); Id = 1149; Message = $msg }
        $e.RdpLogons += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' 'RDP authentication succeeded (1149)' $msg
    }
    Write-Info 'RDP events' $e.RdpLogons.Count

    # Brute force / password spray signal.
    $failed = Get-Events -LogName 'Security' -Ids @(4625) -Max 1000
    if ($failed.Count -ge 100) {
        Add-Finding -Category 'Network' -Severity 'Medium' `
            -Title "$($failed.Count)+ failed logons in the window (Event 4625)" `
            -Detail 'Volume consistent with brute-force or password spraying against this host.' `
            -Recommendation 'Identify the source addresses from the 4625 events and confirm the exposure path is closed.'
    }
    $e.Counts['FailedLogons4625'] = $failed.Count

    # --- Defender detections -------------------------------------------
    Write-Host ""
    Write-Host "  Defender detections" -ForegroundColor White
    foreach ($ev in (Get-Events -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids @(1006,1015,1116,1117,5001,5007,5010,5012) -Max 300)) {
        $msg = ConvertTo-SafeString $ev.Message 1000
        $rec = [pscustomobject]@{ TimeUtc = $ev.TimeCreated.ToUniversalTime(); Id = $ev.Id; Message = $msg }
        $e.DefenderAlerts += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' "Defender event $($ev.Id)" $msg

        if ($ev.Id -in @(1116,1117)) {
            Add-Finding -Category 'Defences' -Severity 'High' `
                -Title 'Defender malware detection recorded' `
                -Detail "$($rec.TimeUtc) UTC - $msg" -Evidence $rec `
                -Recommendation 'Use the detection names and paths to scope the intrusion.'
        }
        if ($ev.Id -eq 5001) {
            Add-Finding -Category 'Defences' -Severity 'Critical' `
                -Title 'Defender real-time protection was disabled (Event 5001)' `
                -Detail "$($rec.TimeUtc) UTC" -Evidence $rec `
                -Recommendation 'This is a deliberate defence-evasion action. Correlate with the logon session active at that time.'
        }
    }
    Write-Info 'Defender events' $e.DefenderAlerts.Count

    # --- PowerShell script blocks --------------------------------------
    Write-Host ""
    Write-Host "  PowerShell script block logging" -ForegroundColor White
    foreach ($ev in (Get-Events -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4104) -Max 600)) {
        $msg = "$($ev.Message)"
        if ($msg -match '(?i)vssadmin|shadowcopy|Remove-WmiObject|wbadmin|bcdedit|-enc |FromBase64String|DownloadString|Invoke-Expression|Add-MpPreference|Set-MpPreference|net user |net localgroup|akira') {
            $rec = [pscustomobject]@{
                TimeUtc = $ev.TimeCreated.ToUniversalTime()
                Script  = ConvertTo-SafeString $msg 3000
            }
            $e.PowerShellHits += $rec
            Add-Timeline $rec.TimeUtc 'EventLog' 'Suspicious PowerShell script block (4104)' (ConvertTo-SafeString $msg 300)
            Add-Finding -Category 'Execution' -Severity 'High' `
                -Title 'Suspicious PowerShell activity recorded (Event 4104)' `
                -Detail "$($rec.TimeUtc) UTC - $(ConvertTo-SafeString $msg 600)" -Evidence $rec `
                -Recommendation 'Review the full script block in the collected event log. Akira uses PowerShell to delete shadow copies and disable defences.'
        }
    }
    Write-Info 'Suspicious script blocks' $e.PowerShellHits.Count

    # --- Shadow copy destruction ---------------------------------------
    foreach ($ev in (Get-Events -LogName 'Application' -Ids @(8193,8194,8224) -Max 200)) {
        $rec = [pscustomobject]@{
            TimeUtc = $ev.TimeCreated.ToUniversalTime(); Id = $ev.Id
            Message = ConvertTo-SafeString $ev.Message 800
        }
        $e.ShadowCopyEvents += $rec
        Add-Timeline $rec.TimeUtc 'EventLog' "VSS event $($ev.Id)" $rec.Message
    }
    if (($e.ShadowCopyEvents | Where-Object { $_.Id -eq 8224 }).Count -gt 0) {
        Add-Finding -Category 'AntiForensics' -Severity 'High' `
            -Title 'VSS service shutdown events recorded (Event 8224)' `
            -Detail 'Commonly logged when shadow copies are deleted en masse.' `
            -Recommendation 'Correlate the timestamps with the encryption window.'
    }

    $script:Report['Events'] = $e
    Write-Log 'Event log analysis complete'
}

# -------------------------------------------------------
#  MODULE 10 - ARTEFACT COLLECTION
# -------------------------------------------------------
function Invoke-ArtefactCollection {
    Write-Header "10. Artefact Collection"

    $c = [ordered]@{
        EventLogs      = @()
        RegistryHives  = @()
        Prefetch       = 0
        PowerShellHistory = @()
        RdpCache       = 0
        Other          = @()
    }

    # --- Event logs ----------------------------------------------------
    if (-not $SkipEventLogs) {
        Write-Host ""
        Write-Host "  Exporting event logs" -ForegroundColor White
        $logs = @(
            'Security', 'System', 'Application',
            'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-Sysmon/Operational',
            'Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-Bits-Client/Operational',
            'Microsoft-Windows-TerminalServices-RDPClient/Operational'
        )
        $dest = Join-Path $script:ArtDir 'EventLogs'
        New-Item -ItemType Directory -Path $dest -Force | Out-Null

        foreach ($l in $logs) {
            $file = Join-Path $dest (($l -replace '[\\/]', '-') + '.evtx')
            try {
                # wevtutil reads the live log properly; a file copy would be locked.
                $null = & wevtutil.exe epl "$l" "$file" /ow:true 2>&1
                if (Test-Path -LiteralPath $file) {
                    $size = (Get-Item -LiteralPath $file).Length
                    $c.EventLogs += [pscustomobject]@{ Log = $l; File = (Split-Path $file -Leaf); SizeBytes = $size }
                    [void]$script:Manifest.Add([pscustomobject]@{
                        SourcePath   = "EventLog:$l"
                        CollectedAs  = $file.Replace($script:CaseDir, '.')
                        SizeBytes    = $size
                        Sha256       = Get-FileHashSafe -Path $file
                        CollectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        Note         = 'Exported with wevtutil epl'
                    })
                    Write-Step "$l ($([math]::Round($size/1MB,1)) MB)"
                }
            } catch { Write-Log "Export failed for $l : $_" 'WARN' }
        }
    }

    # --- Registry hives, Amcache, SRUM ---------------------------------
    if (-not $SkipHives) {
        Write-Host ""
        Write-Host "  Exporting registry hives" -ForegroundColor White
        $hiveDir = Join-Path $script:ArtDir 'Registry'
        New-Item -ItemType Directory -Path $hiveDir -Force | Out-Null

        foreach ($h in @('SYSTEM','SOFTWARE','SAM','SECURITY')) {
            $out = Join-Path $hiveDir "$h.hiv"
            try {
                $null = & reg.exe save "HKLM\$h" "$out" /y 2>&1
                if (Test-Path -LiteralPath $out) {
                    $size = (Get-Item -LiteralPath $out).Length
                    $c.RegistryHives += [pscustomobject]@{ Hive = $h; SizeBytes = $size }
                    [void]$script:Manifest.Add([pscustomobject]@{
                        SourcePath   = "HKLM\$h"
                        CollectedAs  = $out.Replace($script:CaseDir, '.')
                        SizeBytes    = $size
                        Sha256       = Get-FileHashSafe -Path $out
                        CollectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        Note         = 'reg save'
                    })
                    Write-Step "HKLM\$h ($([math]::Round($size/1MB,1)) MB)"
                }
            } catch { Write-Log "reg save failed for $h : $_" 'WARN' }
        }

        foreach ($f in @(
            @{ P = "$env:windir\AppCompat\Programs\Amcache.hve"; N = 'Amcache (program execution)' },
            @{ P = "$env:windir\System32\sru\SRUDB.dat";         N = 'SRUM (per-process network usage)' },
            @{ P = "$env:windir\System32\config\SOFTWARE.LOG1";  N = 'SOFTWARE transaction log' },
            @{ P = "$env:windir\System32\config\SYSTEM.LOG1";    N = 'SYSTEM transaction log' }
        )) {
            if (Test-Path -LiteralPath $f.P) {
                $d = Copy-Evidence -Source $f.P -SubFolder 'Registry' -Note $f.N
                if ($d) { Write-Step "$($f.N)"; $c.Other += $f.N }
            }
        }
    }

    # --- Prefetch --------------------------------------------------------
    Write-Host ""
    Write-Host "  Prefetch" -ForegroundColor White
    $pfDir = Join-Path $env:windir 'Prefetch'
    if (Test-Path $pfDir) {
        $destPf = Join-Path $script:ArtDir 'Prefetch'
        New-Item -ItemType Directory -Path $destPf -Force | Out-Null
        $n = 0
        foreach ($pf in (Get-ChildItem $pfDir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue)) {
            try {
                Copy-Item -LiteralPath $pf.FullName -Destination $destPf -Force -ErrorAction Stop
                $n++
                # Prefetch mtime is the last execution time of that program.
                Add-Timeline $pf.LastWriteTimeUtc 'Prefetch' 'Program executed' $pf.Name
            } catch { }
        }
        $c.Prefetch = $n
        Write-Step "$n prefetch file(s) collected"
        if ($n -eq 0) {
            Add-Finding -Category 'AntiForensics' -Severity 'Medium' `
                -Title 'Prefetch directory is empty' `
                -Detail 'Prefetch is disabled on most servers by default, but attackers also clear it to destroy execution evidence.' `
                -Recommendation 'Confirm whether prefetch is disabled by policy on this host class.'
        }
    }

    # --- PowerShell console history ---------------------------------------
    Write-Host ""
    Write-Host "  PowerShell console history" -ForegroundColor White
    try {
        foreach ($u in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction Stop)) {
            $hist = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (Test-Path -LiteralPath $hist) {
                $d = Copy-Evidence -Source $hist -SubFolder 'PSHistory' -NewName "$($u.Name)_ConsoleHost_history.txt" -Note 'PSReadLine history'
                $lines = @()
                try { $lines = Get-Content -LiteralPath $hist -ErrorAction Stop } catch { }
                $c.PowerShellHistory += [pscustomobject]@{ User = $u.Name; Lines = $lines.Count }
                Write-Step "$($u.Name): $($lines.Count) line(s)"

                $bad = $lines | Where-Object { $_ -match '(?i)vssadmin|shadowcopy|net user |net localgroup|Add-MpPreference|Set-MpPreference|-enc |rclone|anydesk|mimikatz|Invoke-WebRequest|certutil' }
                if ($bad) {
                    Add-Finding -Category 'Execution' -Severity 'High' `
                        -Title "Suspicious commands in PowerShell history for user '$($u.Name)'" `
                        -Detail (($bad | Select-Object -First 15) -join ' | ') `
                        -Evidence @($bad | Select-Object -First 40) `
                        -Recommendation 'PSReadLine history is not timestamped but proves the commands were typed in that user context. Correlate with logon events.'
                }
            }
        }
    } catch { }

    # --- RDP bitmap cache --------------------------------------------------
    try {
        $n = 0
        foreach ($u in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction Stop)) {
            $cache = Join-Path $u.FullName 'AppData\Local\Microsoft\Terminal Server Client\Cache'
            if (Test-Path -LiteralPath $cache) {
                foreach ($f in (Get-ChildItem -LiteralPath $cache -File -Force -ErrorAction SilentlyContinue)) {
                    if (Copy-Evidence -Source $f.FullName -SubFolder "RdpCache\$($u.Name)" -Note 'RDP bitmap cache') { $n++ }
                }
            }
        }
        $c.RdpCache = $n
        if ($n -gt 0) { Write-Step "$n RDP bitmap cache file(s) collected" }
    } catch { }

    $script:Report['Collection'] = $c
    Write-Log 'Artefact collection complete'
}

# -------------------------------------------------------
#  MODULE 11 - READINESS ASSESSMENT
# -------------------------------------------------------
function Get-ReadinessAssessment {
    <#
      Turns the findings into a go / no-go checklist. Automated checks are
      answered from collected evidence; the rest are marked MANUAL because no
      host-local tool can answer them - they need the analyst and the client.
    #>
    Write-Header "11. Return-to-Service Readiness"

    $checks = New-Object System.Collections.ArrayList

    function Add-Check {
        param(
            [string]$Area,
            [string]$Check,
            [ValidateSet('PASS','FAIL','WARN','MANUAL')][string]$Status,
            [string]$Evidence = '',
            [string]$Action = ''
        )
        [void]$checks.Add([pscustomobject]@{
            Area = $Area; Check = $Check; Status = $Status; Evidence = $Evidence; Action = $Action
        })
    }

    $f    = $script:Findings
    $sys  = $script:Report['System']
    $art  = $script:Report['Artefacts']
    $def  = $script:Report['Defences']
    $net  = $script:Report['Network']
    $ev   = $script:Report['Events']

    $critical = @($f | Where-Object { $_.Severity -eq 'Critical' })
    $high     = @($f | Where-Object { $_.Severity -eq 'High' })

    # 1. Encryptor / ransomware artefacts still present
    $encCount = 0
    if ($art) { foreach ($x in $art.EncryptedFileStats) { $encCount += $x.Count } }
    if ($encCount -gt 0) {
        Add-Check 'Ransomware' 'Host is free of encrypted data' 'FAIL' `
            "$encCount encrypted file(s) still present on this host" `
            'Rebuild the host or restore the affected volumes from known-good backup.'
    } else {
        Add-Check 'Ransomware' 'Host is free of encrypted data' 'PASS' 'No files with known Akira extensions found in the scanned paths' ''
    }

    $noteCount = if ($art) { @($art.RansomNotes).Count } else { 0 }
    if ($noteCount -gt 0) {
        Add-Check 'Ransomware' 'Ransom notes removed' 'FAIL' "$noteCount ransom note(s) present" `
            'Preserve copies as evidence, then remove from production paths during rebuild/restore.'
    } else {
        Add-Check 'Ransomware' 'Ransom notes removed' 'PASS' 'None found' ''
    }

    $toolCount = if ($art) { @($art.SuspectTooling).Count } else { 0 }
    if ($toolCount -gt 0) {
        Add-Check 'Ransomware' 'No attacker tooling on disk' 'FAIL' "$toolCount known adversary tool(s) present" `
            'Remove unsanctioned tooling. If any is present, rebuilding is safer than cleaning.'
    } else {
        Add-Check 'Ransomware' 'No attacker tooling on disk' 'PASS' 'No known adversary tooling found' ''
    }

    # 2. Persistence
    $persist = @($f | Where-Object { $_.Category -eq 'Persistence' })
    if ($persist.Count -gt 0) {
        Add-Check 'Persistence' 'No unexplained persistence mechanisms' 'FAIL' `
            "$($persist.Count) persistence item(s) flagged (see findings $((($persist | Select-Object -First 6).Id) -join ', '))" `
            'Validate each entry against client change control. Remove or rebuild, then re-run this tool to confirm.'
    } else {
        Add-Check 'Persistence' 'No unexplained persistence mechanisms' 'PASS' 'Autoruns, tasks, services, WMI, logon hijacks and startup folders all clean' ''
    }

    # 3. Remote access
    $ra = @($f | Where-Object { $_.Category -eq 'RemoteAccess' -and $_.Severity -in @('Critical','High') })
    if ($ra.Count -gt 0) {
        Add-Check 'RemoteAccess' 'No unsanctioned remote access tooling' 'FAIL' `
            "$($ra.Count) remote-access finding(s): $((($ra | Select-Object -First 5).Title) -join '; ')" `
            'Uninstall unsanctioned remote access/RMM agents and block their outbound domains at the perimeter.'
    } else {
        Add-Check 'RemoteAccess' 'No unsanctioned remote access tooling' 'PASS' 'No remote access / RMM products flagged' ''
    }

    # 4. Endpoint protection health
    if ($def -and $def.Defender.Count -gt 0) {
        $rtp = $def.Defender['RealTimeProtection']
        if ($rtp -eq $true) {
            Add-Check 'Defences' 'Endpoint protection is running' 'PASS' 'Defender real-time protection enabled' ''
        } elseif ($null -eq $rtp) {
            Add-Check 'Defences' 'Endpoint protection is running' 'MANUAL' 'Defender state could not be read (third-party AV?)' `
                'Confirm the endpoint agent is installed, healthy and reporting to the console.'
        } else {
            Add-Check 'Defences' 'Endpoint protection is running' 'FAIL' 'Defender real-time protection is disabled' `
                'Re-enable real-time and tamper protection and confirm no GPO is forcing them off.'
        }

        $sigAge = $def.Defender['SignatureAge']
        if ($null -ne $sigAge -and $sigAge -gt 7) {
            Add-Check 'Defences' 'AV signatures current' 'WARN' "Signatures are $sigAge day(s) old" `
                'Update signatures and complete a full scan before reconnecting.'
        } elseif ($null -ne $sigAge) {
            Add-Check 'Defences' 'AV signatures current' 'PASS' "Signature age $sigAge day(s)" ''
        }

        $exCount = 0
        if ($def.DefenderExclusions.Count -gt 0) {
            $exCount = @($def.DefenderExclusions['Paths']).Count + @($def.DefenderExclusions['Processes']).Count + @($def.DefenderExclusions['Extensions']).Count
        }
        if ($exCount -gt 0) {
            Add-Check 'Defences' 'No unexplained AV exclusions' 'WARN' "$exCount exclusion(s) configured" `
                'Verify every exclusion against the client baseline; remove any the client cannot account for.'
        } else {
            Add-Check 'Defences' 'No unexplained AV exclusions' 'PASS' 'No exclusions configured' ''
        }
    } else {
        Add-Check 'Defences' 'Endpoint protection is running' 'MANUAL' 'Defender data unavailable' `
            'Verify the endpoint agent manually.'
    }

    $byovd = if ($def) { @($def.BadDrivers).Count } else { 0 }
    if ($byovd -gt 0) {
        Add-Check 'Defences' 'No known-abused kernel drivers' 'FAIL' "$byovd vulnerable/abused driver(s) present" `
            'Rebuild the host. Enable the Microsoft vulnerable driver blocklist and HVCI estate-wide.'
    } else {
        Add-Check 'Defences' 'No known-abused kernel drivers' 'PASS' 'None found' ''
    }

    $fwAll = if ($def) { @($def.Firewall) } else { @() }
    $fwOff = @($fwAll | Where-Object { -not $_.Enabled })
    if ($fwOff.Count -gt 0) {
        Add-Check 'Defences' 'Host firewall enabled' 'FAIL' "Disabled profiles: $(($fwOff.Profile) -join ', ')" 'Re-enable all firewall profiles.'
    } elseif ($fwAll.Count -gt 0) {
        Add-Check 'Defences' 'Host firewall enabled' 'PASS' 'All profiles enabled' ''
    }

    # 5. Credential exposure
    $credFindings = @($f | Where-Object { $_.Category -eq 'Accounts' -and $_.Severity -in @('Critical','High') })
    if ($credFindings.Count -gt 0) {
        Add-Check 'Credentials' 'No evidence of credential compromise on this host' 'FAIL' `
            "$($credFindings.Count) account/credential finding(s)" `
            'Force a password reset for every account that logged on to this host. In a domain, reset krbtgt twice (with the required interval between resets).'
    } else {
        Add-Check 'Credentials' 'No evidence of credential compromise on this host' 'PASS' 'No credential dumps or suspicious account changes found' ''
    }
    Add-Check 'Credentials' 'Domain-wide credential reset completed' 'MANUAL' 'Cannot be verified from a single host' `
        'Confirm with the client that all privileged, service and user passwords have been reset, and krbtgt rotated twice if a DC was in scope.'

    # 6. Anti-forensics
    $cleared = if ($ev) { @($ev.ClearedLogs).Count } else { 0 }
    if ($cleared -gt 0) {
        Add-Check 'Evidence' 'Event logs intact' 'WARN' "$cleared log-clearing event(s) recorded" `
            'Note in the report that the on-host timeline is incomplete for the cleared period; corroborate from network/EDR/backup logs.'
    } else {
        Add-Check 'Evidence' 'Event logs intact' 'PASS' 'No log-clearing events in the review window' ''
    }

    # 7. Recovery capability
    $shadows = if ($def) { @($def.ShadowCopies).Count } else { 0 }
    if ($shadows -eq 0) {
        Add-Check 'Recovery' 'Shadow copies available' 'WARN' 'No shadow copies present on this host' `
            'Recovery must come from offline/immutable backup. Re-establish VSS and backup schedules after rebuild.'
    } else {
        Add-Check 'Recovery' 'Shadow copies available' 'PASS' "$shadows shadow copy set(s) present" ''
    }
    Add-Check 'Recovery' 'Known-good backup restored and validated' 'MANUAL' 'Cannot be verified from this host' `
        'Confirm the restore source pre-dates the earliest attacker activity, and that a test restore has been validated.'

    # 8. Patching / entry vector
    if ($sys -and $sys.LastPatchDate) {
        $age = [math]::Round(((Get-Date) - $sys.LastPatchDate).TotalDays)
        if ($age -gt 60) {
            Add-Check 'Hardening' 'Operating system patched' 'FAIL' "Last hotfix $age day(s) ago ($($sys.LastPatchDate))" `
                'Fully patch the host before reconnecting.'
        } else {
            Add-Check 'Hardening' 'Operating system patched' 'PASS' "Last hotfix $age day(s) ago" ''
        }
    } else {
        Add-Check 'Hardening' 'Operating system patched' 'MANUAL' 'Patch history unavailable' 'Verify patch level manually.'
    }

    Add-Check 'Hardening' 'Initial access vector identified and closed' 'MANUAL' `
        'Akira intrusions commonly begin at internet-facing VPN/firewall appliances or unmanaged remote access, not at this host' `
        'Confirm perimeter appliances (VPN/SSL-VPN, firewall, backup servers) are patched, credentials rotated, and MFA enforced on all remote access before reconnecting.'

    Add-Check 'Hardening' 'MFA enforced on all remote access' 'MANUAL' 'Cannot be verified from this host' `
        'Confirm MFA on VPN, RDP gateways, and any RMM/remote support tooling.'

    # 9. Network isolation state at time of scan
    $pub = @($f | Where-Object { $_.Category -eq 'Network' -and $_.Title -like '*public address*' })
    if ($pub.Count -gt 0) {
        Add-Check 'Isolation' 'Host was isolated during examination' 'WARN' `
            "$($pub.Count) active connection(s) to public addresses observed during the scan" `
            'Verify the host is genuinely contained and identify the responsible processes.'
    } else {
        Add-Check 'Isolation' 'Host was isolated during examination' 'PASS' 'No connections to public addresses observed' ''
    }

    Add-Check 'Monitoring' 'Enhanced monitoring in place for return to service' 'MANUAL' 'Cannot be verified from this host' `
        'Confirm EDR is deployed and alerting, and that this host is under heightened monitoring for at least 30 days after reconnection.'

    # --- Score -----------------------------------------------------------
    $pass   = @($checks | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail   = @($checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn   = @($checks | Where-Object { $_.Status -eq 'WARN' }).Count
    $manual = @($checks | Where-Object { $_.Status -eq 'MANUAL' }).Count

    if ($fail -gt 0 -or $critical.Count -gt 0) {
        $verdict = 'NOT READY'
        $verdictDetail = "$fail automated check(s) failed and $($critical.Count) critical finding(s) are open. This host must not be returned to the production network in its current state."
    } elseif ($warn -gt 0 -or $high.Count -gt 0) {
        $verdict = 'READY WITH CONDITIONS'
        $verdictDetail = "No automated check failed, but $warn warning(s) and $($high.Count) high-severity finding(s) need an explicit decision before reconnection."
    } else {
        $verdict = 'READY (pending manual checks)'
        $verdictDetail = "All automated host checks passed. Reconnection still depends on the $manual manual check(s) below, which cannot be answered from this host alone."
    }

    $assessment = [ordered]@{
        Verdict        = $verdict
        VerdictDetail  = $verdictDetail
        Passed         = $pass
        Failed         = $fail
        Warnings       = $warn
        ManualRequired = $manual
        Checks         = @($checks)
        Disclaimer     = 'This is host-level triage evidence, not an eradication certificate. A return-to-service decision covers the whole environment - identity, perimeter, backups and monitoring - and remains the responsibility of the lead responder and the client.'
    }

    Write-Host ""
    switch -Wildcard ($verdict) {
        'NOT READY*'   { Write-Host "  VERDICT: $verdict" -ForegroundColor Red }
        'READY WITH*'  { Write-Host "  VERDICT: $verdict" -ForegroundColor Yellow }
        default        { Write-Host "  VERDICT: $verdict" -ForegroundColor Green }
    }
    Write-Host "  $verdictDetail" -ForegroundColor Gray
    Write-Host ""
    Write-Info 'Checks passed'   $pass
    Write-Info 'Checks failed'   $fail
    Write-Info 'Warnings'        $warn
    Write-Info 'Manual required' $manual

    Write-Host ""
    foreach ($chk in $checks) {
        $colour = switch ($chk.Status) {
            'PASS'   { 'Green' }
            'FAIL'   { 'Red' }
            'WARN'   { 'Yellow' }
            default  { 'Cyan' }
        }
        Write-Host ("    [{0,-6}] {1,-12} {2}" -f $chk.Status, $chk.Area, $chk.Check) -ForegroundColor $colour
    }

    $script:Report['Readiness'] = $assessment
    Write-Log "Readiness verdict: $verdict"
    return $assessment
}

# -------------------------------------------------------
#  MODULE 12 - OUTPUT
# -------------------------------------------------------
function ConvertTo-Html5 {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = "$Value"
    $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
    return $s
}

function Get-ReportMeta {
    return [ordered]@{
        Tool           = $script:ToolName
        ToolVersion    = $script:ToolVersion
        CaseName       = if ($CaseName) { $CaseName } else { '(not supplied)' }
        Hostname       = $env:COMPUTERNAME
        ExaminedBy     = "$env:USERDOMAIN\$env:USERNAME"
        StartedUtc     = $script:StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        CompletedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        LocalTimeZone  = (Get-TimeZone -ErrorAction SilentlyContinue).Id
        ReviewWindowDays = $DaysBack
        ScanPaths      = if ($ScanPath.Count -gt 0) { $ScanPath } else { @('(all fixed drives)') }
        CaseFolder     = $script:CaseDir
        Elevated       = (Test-Administrator)
        PSVersion      = "$($PSVersionTable.PSVersion)"
        ReadOnly       = $true
    }
}

function Export-CaseData {
    Write-Header "12. Writing Report"

    $script:Report['Meta']     = Get-ReportMeta
    $script:Report['Findings'] = @($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Category)
    $script:Report['Timeline'] = @($script:Timeline | Sort-Object Time)
    $script:Report['Manifest'] = @($script:Manifest)

    # --- JSON (the machine-readable deliverable) ------------------------
    $jsonPath = Join-Path $script:CaseDir 'findings.json'
    try {
        $script:Report | ConvertTo-Json -Depth 8 -ErrorAction Stop |
            Out-File -FilePath $jsonPath -Encoding utf8 -Force
        Write-Step "findings.json"
    } catch {
        Write-Log "JSON export failed: $_" 'ERROR'
        # Depth blow-ups are the usual cause - retry shallower rather than lose the file.
        try {
            $script:Report | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding utf8 -Force
            Write-Step "findings.json (reduced depth)"
        } catch { Write-Bad "Could not write findings.json: $_" }
    }

    # --- CSVs -----------------------------------------------------------
    try {
        $script:Report['Timeline'] |
            Select-Object @{N='TimeUtc';E={$_.Time.ToString('yyyy-MM-dd HH:mm:ss')}}, Source, Event, Detail |
            Export-Csv -Path (Join-Path $script:CaseDir 'Timeline.csv') -NoTypeInformation -Encoding UTF8
        Write-Step "Timeline.csv ($($script:Timeline.Count) events)"
    } catch { Write-Log "Timeline export failed: $_" 'WARN' }

    try {
        $script:Manifest | Export-Csv -Path (Join-Path $script:CaseDir 'Manifest.csv') -NoTypeInformation -Encoding UTF8
        Write-Step "Manifest.csv ($($script:Manifest.Count) artefacts)"
    } catch { Write-Log "Manifest export failed: $_" 'WARN' }

    try {
        $script:Findings |
            Select-Object Id, Severity, Category, Title, Detail, Recommendation |
            Export-Csv -Path (Join-Path $script:CaseDir 'Findings.csv') -NoTypeInformation -Encoding UTF8
        Write-Step "Findings.csv"
    } catch { }

    Export-SummaryText
    Export-HtmlReport
    Export-ClaudePrompt

    Write-Host ""
    Write-Host "  Case folder: $script:CaseDir" -ForegroundColor Cyan
}

function Export-SummaryText {
    $r   = $script:Report
    $sb  = New-Object System.Text.StringBuilder
    $rd  = $r['Readiness']

    [void]$sb.AppendLine("$($script:ToolName) v$($script:ToolVersion)")
    [void]$sb.AppendLine(('=' * 62))
    [void]$sb.AppendLine("Case         : $($r['Meta'].CaseName)")
    [void]$sb.AppendLine("Host         : $($r['Meta'].Hostname)")
    [void]$sb.AppendLine("Examined by  : $($r['Meta'].ExaminedBy)")
    [void]$sb.AppendLine("Started (UTC): $($r['Meta'].StartedUtc)")
    [void]$sb.AppendLine("Completed    : $($r['Meta'].CompletedUtc)")
    [void]$sb.AppendLine("Window       : last $($r['Meta'].ReviewWindowDays) days")
    [void]$sb.AppendLine('')

    if ($r['Variant']) {
        [void]$sb.AppendLine('VARIANT ASSESSMENT')
        [void]$sb.AppendLine(('-' * 62))
        [void]$sb.AppendLine("Assessed   : $($r['Variant'].Assessed)")
        [void]$sb.AppendLine("Confidence : $($r['Variant'].Confidence) (score $($r['Variant'].Score))")
        foreach ($s in $r['Variant'].Signals) { [void]$sb.AppendLine("  - $s") }
        if ($r['Variant'].Notes) { [void]$sb.AppendLine("Note: $($r['Variant'].Notes)") }
        [void]$sb.AppendLine('')
    }

    if ($rd) {
        [void]$sb.AppendLine('READINESS')
        [void]$sb.AppendLine(('-' * 62))
        [void]$sb.AppendLine("VERDICT: $($rd.Verdict)")
        [void]$sb.AppendLine($rd.VerdictDetail)
        [void]$sb.AppendLine("Pass $($rd.Passed) | Fail $($rd.Failed) | Warn $($rd.Warnings) | Manual $($rd.ManualRequired)")
        [void]$sb.AppendLine('')
        foreach ($c in $rd.Checks) {
            [void]$sb.AppendLine(("[{0,-6}] {1,-12} {2}" -f $c.Status, $c.Area, $c.Check))
            if ($c.Evidence) { [void]$sb.AppendLine("           evidence: $($c.Evidence)") }
            if ($c.Action)   { [void]$sb.AppendLine("           action  : $($c.Action)") }
        }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('FINDINGS')
    [void]$sb.AppendLine(('-' * 62))
    foreach ($f in $r['Findings']) {
        [void]$sb.AppendLine("[$($f.Severity.ToUpper())] $($f.Id) $($f.Category) - $($f.Title)")
        if ($f.Detail)         { [void]$sb.AppendLine("    $($f.Detail)") }
        if ($f.Recommendation) { [void]$sb.AppendLine("    ACTION: $($f.Recommendation)") }
    }
    if ($r['Findings'].Count -eq 0) { [void]$sb.AppendLine('No findings raised.') }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('DISCLAIMER')
    [void]$sb.AppendLine(('-' * 62))
    [void]$sb.AppendLine($rd.Disclaimer)

    $sb.ToString() | Out-File -FilePath (Join-Path $script:CaseDir 'Summary.txt') -Encoding utf8 -Force
    Write-Step 'Summary.txt'
}

function Export-ClaudePrompt {
    $r    = $script:Report
    $meta = $r['Meta']
    $rd   = $r['Readiness']

    $md = @"
# Client report request - $($meta.CaseName)

Attach ``findings.json`` from this case folder alongside this file.

## What I need

Write a client-facing incident report for the host below. The audience is a
non-technical business owner plus their IT provider. Keep it factual and
plain-spoken. Do not invent findings that are not in the JSON, and do not
soften a NOT READY verdict.

## Structure to follow

1. **Executive summary** - three or four sentences: what happened, what was
   found on this host, and whether it can go back online.
2. **What we found** - group the findings by theme (ransomware artefacts,
   persistence, remote access, credential exposure, defence tampering). Explain
   each in business terms with the technical detail in a sub-bullet.
3. **Which Akira variant** - state the assessed variant, the confidence level,
   and the evidence that supports it. Be explicit about what is not certain.
4. **Timeline** - a short table of the key dated events from ``Timeline`` in the
   JSON (first/last encrypted file, tool drops, log clearing, account changes).
5. **Readiness assessment** - reproduce the checklist as a table with a clear
   RAG status. List every MANUAL item as an outstanding action owned by a
   named party.
6. **Recommended actions before reconnection** - ordered by priority, using the
   ``Recommendation`` field on each finding.
7. **Evidence held** - summarise ``Manifest`` (how many artefacts, what types,
   that everything is SHA256 hashed).

## Facts already established (do not contradict these)

- Host: $($meta.Hostname)
- Examined: $($meta.StartedUtc) to $($meta.CompletedUtc) (UTC)
- Examiner: $($meta.ExaminedBy)
- Review window: last $($meta.ReviewWindowDays) days
- Assessed variant: $(if ($r['Variant']) { $r['Variant'].Assessed } else { 'not determined' })
- Variant confidence: $(if ($r['Variant']) { $r['Variant'].Confidence } else { 'n/a' })
- Readiness verdict: $(if ($rd) { $rd.Verdict } else { 'not assessed' })
- Findings: $(@($r['Findings'] | Where-Object { $_.Severity -eq 'Critical' }).Count) critical, $(@($r['Findings'] | Where-Object { $_.Severity -eq 'High' }).Count) high, $(@($r['Findings'] | Where-Object { $_.Severity -eq 'Medium' }).Count) medium
- Artefacts collected: $(@($r['Manifest']).Count)

## Required caveats

Include these verbatim in the report:

- This assessment covers a single host. It is not a statement about the wider
  environment.
- $(if ($rd) { $rd.Disclaimer } else { 'Host-level triage evidence only.' })
- There is no free decryptor for current Akira builds. Recovery depends on
  known-good backups.
"@

    $md | Out-File -FilePath (Join-Path $script:CaseDir 'ClaudePrompt.md') -Encoding utf8 -Force
    Write-Step 'ClaudePrompt.md'
}

function Export-HtmlReport {
    $r    = $script:Report
    $meta = $r['Meta']
    $rd   = $r['Readiness']
    $var  = $r['Variant']

    $css = @'
:root{
  --bg:#f5f6f8; --panel:#ffffff; --ink:#15181d; --muted:#5b6472; --line:#dfe3ea;
  --crit:#b3121f; --high:#c2410c; --med:#a16207; --low:#0f6f8f; --info:#4b5563;
  --pass:#0f7b3f; --fail:#b3121f; --warn:#a16207; --manual:#3f4fa1;
  --accent:#1f2a44;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#12151a; --panel:#191d24; --ink:#e8ebf0; --muted:#98a2b3; --line:#2a313c;
    --crit:#ff6b6b; --high:#ff9f5a; --med:#e8c46a; --low:#6cc7e8; --info:#9aa5b5;
    --pass:#5ed39a; --fail:#ff6b6b; --warn:#e8c46a; --manual:#9aa9ff;
    --accent:#c9d4ec;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
     font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:32px 24px 80px}
header{border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:26px}
h1{margin:0 0 4px;font-size:26px;letter-spacing:-.2px}
h2{margin:38px 0 12px;font-size:19px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{margin:22px 0 8px;font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.sub{color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.card .v{font-size:15px;margin-top:3px;word-break:break-word}
.verdict{border-radius:10px;padding:18px 20px;margin:18px 0;border:2px solid;background:var(--panel)}
.verdict .t{font-size:22px;font-weight:700;letter-spacing:-.2px}
.verdict .d{margin-top:6px;color:var(--muted);font-size:14px}
.v-fail{border-color:var(--fail)} .v-fail .t{color:var(--fail)}
.v-warn{border-color:var(--warn)} .v-warn .t{color:var(--warn)}
.v-pass{border-color:var(--pass)} .v-pass .t{color:var(--pass)}
.tally{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.tally span{font-size:12px;padding:3px 10px;border-radius:99px;border:1px solid var(--line);background:var(--bg)}
.tblwrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;padding:9px 12px;background:var(--bg);border-bottom:1px solid var(--line);
   font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;
      padding:2px 8px;border-radius:99px;border:1px solid currentColor;white-space:nowrap}
.s-Critical{color:var(--crit)} .s-High{color:var(--high)} .s-Medium{color:var(--med)}
.s-Low{color:var(--low)} .s-Info{color:var(--info)}
.st-PASS{color:var(--pass)} .st-FAIL{color:var(--fail)}
.st-WARN{color:var(--warn)} .st-MANUAL{color:var(--manual)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;
    overflow-x:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.note{background:var(--panel);border-left:4px solid var(--accent);padding:12px 16px;
      border-radius:0 8px 8px 0;margin:16px 0;font-size:13.5px;color:var(--muted)}
.empty{color:var(--muted);font-style:italic;padding:10px 0}
footer{margin-top:50px;padding-top:16px;border-top:1px solid var(--line);
       color:var(--muted);font-size:12px}
@media print{
  body{background:#fff}
  .wrap{max-width:none;padding:0}
  h2{page-break-after:avoid} tr{page-break-inside:avoid}
  .verdict{border-width:1px}
}
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine("<title>Akira Escape Report - $(ConvertTo-Html5 $meta.Hostname)</title>")
    [void]$sb.AppendLine("<style>$css</style></head><body><div class=""wrap"">")

    # --- Header ---------------------------------------------------------
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine("<h1>Akira Escape &mdash; Host Triage Report</h1>")
    [void]$sb.AppendLine("<div class=""sub"">$(ConvertTo-Html5 $meta.Hostname) &middot; case $(ConvertTo-Html5 $meta.CaseName) &middot; examined $(ConvertTo-Html5 $meta.StartedUtc) by $(ConvertTo-Html5 $meta.ExaminedBy)</div>")
    [void]$sb.AppendLine('</header>')

    # --- Verdict --------------------------------------------------------
    if ($rd) {
        $vclass = if ($rd.Verdict -like 'NOT READY*') { 'v-fail' }
                  elseif ($rd.Verdict -like 'READY WITH*') { 'v-warn' }
                  else { 'v-pass' }
        [void]$sb.AppendLine("<div class=""verdict $vclass"">")
        [void]$sb.AppendLine("<div class=""t"">$(ConvertTo-Html5 $rd.Verdict)</div>")
        [void]$sb.AppendLine("<div class=""d"">$(ConvertTo-Html5 $rd.VerdictDetail)</div>")
        [void]$sb.AppendLine("<div class=""tally""><span>$($rd.Passed) passed</span><span>$($rd.Failed) failed</span><span>$($rd.Warnings) warnings</span><span>$($rd.ManualRequired) manual</span></div>")
        [void]$sb.AppendLine('</div>')
    }

    # --- Key facts ------------------------------------------------------
    $sys = $r['System']
    $crit = @($r['Findings'] | Where-Object { $_.Severity -eq 'Critical' }).Count
    $hi   = @($r['Findings'] | Where-Object { $_.Severity -eq 'High' }).Count

    [void]$sb.AppendLine('<div class="grid">')
    $facts = [ordered]@{
        'Host'              = $meta.Hostname
        'Operating system'  = if ($sys) { "$($sys.OperatingSystem) (build $($sys.OSBuild))" } else { '' }
        'Role'              = if ($sys) { $sys.DomainRole } else { '' }
        'Domain'            = if ($sys) { $sys.Domain } else { '' }
        'Assessed variant'  = if ($var) { $var.Assessed } else { 'not determined' }
        'Variant confidence'= if ($var) { "$($var.Confidence) (score $($var.Score))" } else { 'n/a' }
        'Critical findings' = $crit
        'High findings'     = $hi
        'Artefacts held'    = @($r['Manifest']).Count
        'Timeline events'   = @($r['Timeline']).Count
        'Review window'     = "$($meta.ReviewWindowDays) days"
        'Examiner'          = $meta.ExaminedBy
    }
    foreach ($k in $facts.Keys) {
        [void]$sb.AppendLine("<div class=""card""><div class=""k"">$(ConvertTo-Html5 $k)</div><div class=""v"">$(ConvertTo-Html5 $facts[$k])</div></div>")
    }
    [void]$sb.AppendLine('</div>')

    # --- Variant --------------------------------------------------------
    [void]$sb.AppendLine('<h2>Variant assessment</h2>')
    if ($var -and @($var.Signals).Count -gt 0) {
        [void]$sb.AppendLine("<p><strong>$(ConvertTo-Html5 $var.Assessed)</strong> &mdash; confidence <strong>$(ConvertTo-Html5 $var.Confidence)</strong> (weighted score $($var.Score)). Encryptor build: $(ConvertTo-Html5 $var.Encryptor).</p>")
        [void]$sb.AppendLine('<h3>Signals that produced this assessment</h3><ul>')
        foreach ($s in $var.Signals) { [void]$sb.AppendLine("<li>$(ConvertTo-Html5 $s)</li>") }
        [void]$sb.AppendLine('</ul>')
        if ($var.Notes) { [void]$sb.AppendLine("<div class=""note"">$(ConvertTo-Html5 $var.Notes)</div>") }
    } else {
        [void]$sb.AppendLine('<p class="empty">No Akira artefacts were identified in the paths scanned on this host.</p>')
    }

    # --- Readiness checklist --------------------------------------------
    if ($rd) {
        [void]$sb.AppendLine('<h2>Return-to-service checklist</h2>')
        [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Status</th><th>Area</th><th>Check</th><th>Evidence</th><th>Action required</th></tr></thead><tbody>')
        foreach ($c in $rd.Checks) {
            [void]$sb.AppendLine(("<tr><td><span class=""pill st-{0}"">{0}</span></td><td>{1}</td><td>{2}</td><td class=""sub"">{3}</td><td class=""sub"">{4}</td></tr>" -f `
                $c.Status, (ConvertTo-Html5 $c.Area), (ConvertTo-Html5 $c.Check), (ConvertTo-Html5 $c.Evidence), (ConvertTo-Html5 $c.Action)))
        }
        [void]$sb.AppendLine('</tbody></table></div>')
        [void]$sb.AppendLine("<div class=""note""><strong>Scope limit.</strong> $(ConvertTo-Html5 $rd.Disclaimer)</div>")
    }

    # --- Findings --------------------------------------------------------
    [void]$sb.AppendLine('<h2>Findings</h2>')
    if (@($r['Findings']).Count -gt 0) {
        [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Recommended action</th></tr></thead><tbody>')
        foreach ($f in $r['Findings']) {
            [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td><span class=""pill s-{1}"">{1}</span></td><td>{2}</td><td><strong>{3}</strong></td><td class=""sub"">{4}</td><td class=""sub"">{5}</td></tr>" -f `
                $f.Id, $f.Severity, (ConvertTo-Html5 $f.Category), (ConvertTo-Html5 $f.Title),
                (ConvertTo-Html5 (ConvertTo-SafeString $f.Detail 1200)), (ConvertTo-Html5 $f.Recommendation)))
        }
        [void]$sb.AppendLine('</tbody></table></div>')
    } else {
        [void]$sb.AppendLine('<p class="empty">No findings were raised on this host.</p>')
    }

    # --- Encrypted files and notes ---------------------------------------
    $art = $r['Artefacts']
    if ($art) {
        [void]$sb.AppendLine('<h2>Ransomware artefacts</h2>')

        [void]$sb.AppendLine('<h3>Encrypted files</h3>')
        if (@($art.EncryptedFileStats).Count -gt 0) {
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Extension</th><th>Count</th><th>Associated lineage</th><th>Example path</th></tr></thead><tbody>')
            foreach ($e in $art.EncryptedFileStats) {
                $ex = if (@($e.SamplePaths).Count -gt 0) { @($e.SamplePaths)[0] } else { '' }
                [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td>{1}</td><td>{2}</td><td class=""mono sub"">{3}</td></tr>" -f `
                    (ConvertTo-Html5 $e.Extension), $e.Count, (ConvertTo-Html5 $e.Lineage), (ConvertTo-Html5 $ex)))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
            if ($art.EncryptionWindow.FirstUtc) {
                [void]$sb.AppendLine("<p class=""sub"">Encryption window from file modification times: <strong>$(ConvertTo-Html5 $art.EncryptionWindow.FirstUtc)</strong> to <strong>$(ConvertTo-Html5 $art.EncryptionWindow.LastUtc)</strong> (UTC).</p>")
            }
        } else {
            [void]$sb.AppendLine('<p class="empty">None found.</p>')
        }

        [void]$sb.AppendLine('<h3>Ransom notes</h3>')
        if (@($art.RansomNotes).Count -gt 0) {
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Path</th><th>Written (UTC)</th><th>SHA256</th></tr></thead><tbody>')
            foreach ($n in (@($art.RansomNotes) | Select-Object -First 40)) {
                [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td class=""sub"">{1}</td><td class=""mono sub"">{2}</td></tr>" -f `
                    (ConvertTo-Html5 $n.Path), (ConvertTo-Html5 $n.CreatedUtc), (ConvertTo-Html5 $n.Sha256)))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
            if ($art.NoteContentSample) {
                [void]$sb.AppendLine('<h3>Note contents (verbatim)</h3>')
                [void]$sb.AppendLine("<pre>$(ConvertTo-Html5 $art.NoteContentSample)</pre>")
            }
        } else {
            [void]$sb.AppendLine('<p class="empty">None found.</p>')
        }

        if (@($art.SuspectTooling).Count -gt 0) {
            [void]$sb.AppendLine('<h3>Adversary tooling on disk</h3>')
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Tool</th><th>Description</th><th>Path</th><th>Created (UTC)</th><th>SHA256</th></tr></thead><tbody>')
            foreach ($t in $art.SuspectTooling) {
                [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td>{1}</td><td class=""mono sub"">{2}</td><td class=""sub"">{3}</td><td class=""mono sub"">{4}</td></tr>" -f `
                    (ConvertTo-Html5 $t.Tool), (ConvertTo-Html5 $t.Description), (ConvertTo-Html5 $t.Path),
                    (ConvertTo-Html5 $t.CreatedUtc), (ConvertTo-Html5 $t.Sha256)))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
        }
    }

    # --- Timeline ---------------------------------------------------------
    [void]$sb.AppendLine('<h2>Timeline</h2>')
    $tl = @($r['Timeline'])
    if ($tl.Count -gt 0) {
        [void]$sb.AppendLine("<p class=""sub"">$($tl.Count) event(s) reconstructed. Full set in Timeline.csv; the 150 most recent are shown.</p>")
        [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Event</th><th>Detail</th></tr></thead><tbody>')
        foreach ($t in ($tl | Sort-Object Time -Descending | Select-Object -First 150)) {
            [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td>{1}</td><td>{2}</td><td class=""sub"">{3}</td></tr>" -f `
                $t.Time.ToString('yyyy-MM-dd HH:mm:ss'), (ConvertTo-Html5 $t.Source),
                (ConvertTo-Html5 $t.Event), (ConvertTo-Html5 (ConvertTo-SafeString $t.Detail 400))))
        }
        [void]$sb.AppendLine('</tbody></table></div>')
    } else {
        [void]$sb.AppendLine('<p class="empty">No timeline events were reconstructed.</p>')
    }

    # --- Persistence detail -------------------------------------------------
    $p = $r['Persistence']
    if ($p) {
        [void]$sb.AppendLine('<h2>Persistence detail</h2>')

        $flaggedRuns = @($p.RunKeys | Where-Object { $_.Suspicious })
        [void]$sb.AppendLine("<h3>Autorun entries flagged ($($flaggedRuns.Count) of $(@($p.RunKeys).Count) total)</h3>")
        if ($flaggedRuns.Count -gt 0) {
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Key</th><th>Name</th><th>Command</th><th>Why flagged</th></tr></thead><tbody>')
            foreach ($x in $flaggedRuns) {
                [void]$sb.AppendLine(("<tr><td class=""mono sub"">{0}</td><td>{1}</td><td class=""mono"">{2}</td><td class=""sub"">{3}</td></tr>" -f `
                    (ConvertTo-Html5 $x.Key), (ConvertTo-Html5 $x.Name),
                    (ConvertTo-Html5 (ConvertTo-SafeString $x.Command 400)), (ConvertTo-Html5 (($x.Reasons) -join ', '))))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
        } else {
            [void]$sb.AppendLine('<p class="empty">No autorun entries flagged.</p>')
        }

        $flaggedTasks = @($p.ScheduledTasks | Where-Object { $_.Suspicious })
        [void]$sb.AppendLine("<h3>Scheduled tasks flagged ($($flaggedTasks.Count) of $(@($p.ScheduledTasks).Count) non-Microsoft tasks)</h3>")
        if ($flaggedTasks.Count -gt 0) {
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Task</th><th>Runs as</th><th>Command</th><th>Why flagged</th></tr></thead><tbody>')
            foreach ($x in $flaggedTasks) {
                [void]$sb.AppendLine(("<tr><td class=""mono"">{0}{1}</td><td>{2}</td><td class=""mono sub"">{3}</td><td class=""sub"">{4}</td></tr>" -f `
                    (ConvertTo-Html5 $x.TaskPath), (ConvertTo-Html5 $x.TaskName), (ConvertTo-Html5 $x.RunAs),
                    (ConvertTo-Html5 (ConvertTo-SafeString $x.Command 400)), (ConvertTo-Html5 (($x.Reasons) -join ', '))))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
        } else {
            [void]$sb.AppendLine('<p class="empty">No scheduled tasks flagged.</p>')
        }

        [void]$sb.AppendLine("<h3>Services flagged ($(@($p.Services).Count))</h3>")
        if (@($p.Services).Count -gt 0) {
            [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Service</th><th>State</th><th>Runs as</th><th>Path</th><th>Why flagged</th></tr></thead><tbody>')
            foreach ($x in $p.Services) {
                [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td>{1}/{2}</td><td class=""sub"">{3}</td><td class=""mono sub"">{4}</td><td class=""sub"">{5}</td></tr>" -f `
                    (ConvertTo-Html5 $x.Name), (ConvertTo-Html5 $x.State), (ConvertTo-Html5 $x.StartMode),
                    (ConvertTo-Html5 $x.RunAs), (ConvertTo-Html5 $x.PathName), (ConvertTo-Html5 (($x.Reasons) -join ', '))))
            }
            [void]$sb.AppendLine('</tbody></table></div>')
        } else {
            [void]$sb.AppendLine('<p class="empty">No services flagged.</p>')
        }
    }

    # --- Evidence manifest ---------------------------------------------------
    [void]$sb.AppendLine('<h2>Evidence collected</h2>')
    $man = @($r['Manifest'])
    if ($man.Count -gt 0) {
        $totalMb = [math]::Round((($man | Measure-Object -Property SizeBytes -Sum).Sum) / 1MB, 1)
        [void]$sb.AppendLine("<p class=""sub"">$($man.Count) artefact(s), $totalMb MB, each SHA256 hashed. Full list in Manifest.csv.</p>")
        [void]$sb.AppendLine('<div class="tblwrap"><table><thead><tr><th>Source</th><th>Stored as</th><th>Size (KB)</th><th>SHA256</th></tr></thead><tbody>')
        foreach ($m in ($man | Select-Object -First 120)) {
            [void]$sb.AppendLine(("<tr><td class=""mono sub"">{0}</td><td class=""mono sub"">{1}</td><td>{2}</td><td class=""mono sub"">{3}</td></tr>" -f `
                (ConvertTo-Html5 $m.SourcePath), (ConvertTo-Html5 $m.CollectedAs),
                [math]::Round($m.SizeBytes / 1KB, 1), (ConvertTo-Html5 $m.Sha256)))
        }
        [void]$sb.AppendLine('</tbody></table></div>')
    } else {
        [void]$sb.AppendLine('<p class="empty">No artefacts were collected.</p>')
    }

    # --- Footer --------------------------------------------------------------
    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine("Generated by $(ConvertTo-Html5 $script:ToolName) v$($script:ToolVersion) &middot; started $(ConvertTo-Html5 $meta.StartedUtc) &middot; completed $(ConvertTo-Html5 $meta.CompletedUtc) &middot; PowerShell $(ConvertTo-Html5 $meta.PSVersion) &middot; elevated: $($meta.Elevated)<br>")
    [void]$sb.AppendLine('This tool performs read-only collection. No files were modified, quarantined or removed on the examined host.')
    [void]$sb.AppendLine('</footer></div></body></html>')

    $out = Join-Path $script:CaseDir 'Report.html'
    $sb.ToString() | Out-File -FilePath $out -Encoding utf8 -Force
    Write-Step 'Report.html'
}

# -------------------------------------------------------
#  ORCHESTRATION
# -------------------------------------------------------
function Show-Banner {
    Write-Host ""
    Write-Host "  ###############################################################" -ForegroundColor DarkCyan
    Write-Host "  #                                                             #" -ForegroundColor DarkCyan
    Write-Host "  #   A K I R A   E S C A P E   T O O L                         #" -ForegroundColor Cyan
    Write-Host "  #   Offline triage - persistence, variant, artefacts, report  #" -ForegroundColor DarkCyan
    Write-Host "  #                                                             #" -ForegroundColor DarkCyan
    Write-Host "  ###############################################################" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "   Version   : $script:ToolVersion" -ForegroundColor Gray
    Write-Host "   Host      : $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "   Examiner  : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
    Write-Host "   Started   : $($script:StartUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   READ-ONLY. This tool collects and reports. It does not clean," -ForegroundColor DarkYellow
    Write-Host "   quarantine, remediate or decrypt anything." -ForegroundColor DarkYellow
    Write-Host ""
}

function Invoke-FullTriage {
    Invoke-SystemProfile
    Invoke-AkiraArtefactHunt
    Resolve-AkiraVariant
    Invoke-PersistenceAudit
    Invoke-RemoteAccessAudit
    Invoke-DefenceAudit
    Invoke-AccountAudit
    Invoke-NetworkAudit
    Invoke-EventLogAudit
    Invoke-ArtefactCollection
    Get-ReadinessAssessment | Out-Null
    Export-CaseData
    Show-Closing
}

function Show-Closing {
    $rd = $script:Report['Readiness']
    Write-Header 'Done'
    Write-Host ""
    if ($rd) {
        $colour = if ($rd.Verdict -like 'NOT READY*') { 'Red' } elseif ($rd.Verdict -like 'READY WITH*') { 'Yellow' } else { 'Green' }
        Write-Host "  VERDICT: $($rd.Verdict)" -ForegroundColor $colour
        Write-Host ""
    }
    Write-Host "  Deliverables in $script:CaseDir" -ForegroundColor Cyan
    Write-Host "    Report.html      open this with the client" -ForegroundColor Gray
    Write-Host "    Summary.txt      console-style summary" -ForegroundColor Gray
    Write-Host "    findings.json    structured data - give this to Claude" -ForegroundColor Gray
    Write-Host "    ClaudePrompt.md  paste alongside findings.json for a written report" -ForegroundColor Gray
    Write-Host "    Timeline.csv     merged event timeline" -ForegroundColor Gray
    Write-Host "    Manifest.csv     SHA256 of every collected artefact" -ForegroundColor Gray
    Write-Host "    Findings.csv     findings in spreadsheet form" -ForegroundColor Gray
    Write-Host "    Artifacts\       collected evidence" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Copy the whole case folder off this host before it is rebuilt." -ForegroundColor Yellow
    Write-Host ""
}

function Show-Menu {
    while ($true) {
        Write-Host ""
        Write-Host ("=" * 62) -ForegroundColor Cyan
        Write-Host "  AKIRA ESCAPE - MENU" -ForegroundColor Cyan
        Write-Host ("=" * 62) -ForegroundColor Cyan
        Write-Host "   1.  Full triage (everything, then write the report)" -ForegroundColor White
        Write-Host ""
        Write-Host "   2.  Host profile" -ForegroundColor Gray
        Write-Host "   3.  Akira artefact hunt + variant assessment" -ForegroundColor Gray
        Write-Host "   4.  Persistence audit" -ForegroundColor Gray
        Write-Host "   5.  Remote access / RMM audit" -ForegroundColor Gray
        Write-Host "   6.  Endpoint defences and anti-forensics" -ForegroundColor Gray
        Write-Host "   7.  Accounts and credential exposure" -ForegroundColor Gray
        Write-Host "   8.  Network posture" -ForegroundColor Gray
        Write-Host "   9.  Event log analysis" -ForegroundColor Gray
        Write-Host "  10.  Collect artefacts (logs, hives, prefetch)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  11.  Readiness assessment + write the report" -ForegroundColor White
        Write-Host "  12.  Show current findings" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Q.  Quit" -ForegroundColor White
        Write-Host ""
        $choice = Read-Host "  Select"

        switch ($choice.Trim().ToUpper()) {
            '1'  { Invoke-FullTriage }
            '2'  { Invoke-SystemProfile }
            '3'  { Invoke-AkiraArtefactHunt; Resolve-AkiraVariant }
            '4'  { Invoke-PersistenceAudit }
            '5'  { Invoke-RemoteAccessAudit }
            '6'  { Invoke-DefenceAudit }
            '7'  { Invoke-AccountAudit }
            '8'  { Invoke-NetworkAudit }
            '9'  { Invoke-EventLogAudit }
            '10' { Invoke-ArtefactCollection }
            '11' {
                if (-not $script:Report['Artefacts']) {
                    Write-Result 'Run the artefact hunt (option 3) first for a complete assessment.' $false
                }
                Get-ReadinessAssessment | Out-Null
                Export-CaseData
                Show-Closing
            }
            '12' { Show-Findings }
            'Q'  { return }
            default { Write-Result 'Unrecognised selection.' $false }
        }
    }
}

function Show-Findings {
    Write-Header "Findings so far ($($script:Findings.Count))"
    if ($script:Findings.Count -eq 0) {
        Write-Result 'Nothing raised yet.'
        return
    }
    foreach ($f in ($script:Findings | Sort-Object { $script:SeverityRank[$_.Severity] })) {
        $colour = switch ($f.Severity) {
            'Critical' { 'Red' }
            'High'     { 'Red' }
            'Medium'   { 'Yellow' }
            'Low'      { 'DarkYellow' }
            default    { 'Gray' }
        }
        Write-Host ("  [{0,-8}] {1} {2,-14} {3}" -f $f.Severity, $f.Id, $f.Category, $f.Title) -ForegroundColor $colour
    }
}

# -------------------------------------------------------
#  ENTRY POINT
# -------------------------------------------------------
Show-Banner

if (-not (Test-Administrator)) {
    Write-Host "  [XX] Not running elevated." -ForegroundColor Red
    Write-Host "       Most checks (registry hives, event log export, service and" -ForegroundColor Yellow
    Write-Host "       driver enumeration) need administrator rights. Re-launch" -ForegroundColor Yellow
    Write-Host "       PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
    if (-not $RunAll) {
        $go = Read-Host "  Continue anyway with reduced coverage? (y/N)"
        if ($go.Trim().ToUpper() -ne 'Y') { return }
    }
}

New-CaseFolder | Out-Null
Write-Log "$script:ToolName v$script:ToolVersion started by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
Write-Host "  Case folder: $script:CaseDir" -ForegroundColor Cyan

if ($SamplePath -and -not (Test-Path -LiteralPath $SamplePath)) {
    Write-Result "Sample path not found: $SamplePath" $false
}

if ($RunAll) {
    Invoke-FullTriage
} else {
    Show-Menu
    Write-Host ""
    Write-Host "  Exited. Case folder: $script:CaseDir" -ForegroundColor Cyan
}
