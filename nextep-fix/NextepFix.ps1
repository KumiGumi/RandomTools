# NextepFix.ps1
# Paths - replace these with your actual values
$InactiveFilesFolder   = "C:\Path\To\InactiveFilesFolder"
$TmXmlPath             = "C:\Path\To\tm.xml"
$ShortcutName          = "Nextep.lnk"
$DesktopShortcutPath   = [System.IO.Path]::Combine([Environment]::GetFolderPath("CommonDesktopDirectory"), $ShortcutName)
$StartupShortcutPath   = [System.IO.Path]::Combine([Environment]::GetFolderPath("CommonStartup"), $ShortcutName)
$CorrectShortcutTarget = "C:\Path\To\Nextep\Nextep.exe"
$CorrectWorkingDir     = "C:\Path\To\Nextep"

# --- tm.xml template - fill in the fields you need ---
$TmXmlTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<TerminalManager>
  <Setting name="Server">SERVER_ADDRESS_HERE</Setting>
  <Setting name="Port">PORT_HERE</Setting>
  <Setting name="SiteName">SITE_NAME_HERE</Setting>
</TerminalManager>
"@

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Cyan
}

function Write-Result {
    param([string]$Message, [bool]$Success = $true)
    if ($Success) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $Message" -ForegroundColor Yellow
    }
}

# -------------------------------------------------------
#  CLIENT FIXES
# -------------------------------------------------------
function Invoke-ClientFixes {
    Write-Header "Client Fixes"

    # 1. Delete .inactive files
    Write-Host ""
    Write-Host "  Checking for .inactive files in:" -ForegroundColor White
    Write-Host "  $InactiveFilesFolder" -ForegroundColor Gray
    if (Test-Path $InactiveFilesFolder) {
        $inactiveFiles = Get-ChildItem -Path $InactiveFilesFolder -Filter "*.inactive" -File -ErrorAction SilentlyContinue
        if ($inactiveFiles.Count -eq 0) {
            Write-Result "No .inactive files found."
        } else {
            foreach ($file in $inactiveFiles) {
                Remove-Item $file.FullName -Force
                Write-Result "Deleted: $($file.Name)"
            }
        }
    } else {
        Write-Result "Folder not found: $InactiveFilesFolder" $false
    }

    # 2. Check / create tm.xml
    Write-Host ""
    Write-Host "  Checking for tm.xml..." -ForegroundColor White
    if (Test-Path $TmXmlPath) {
        Write-Result "tm.xml already exists at $TmXmlPath"
    } else {
        try {
            $tmDir = Split-Path $TmXmlPath -Parent
            if (-not (Test-Path $tmDir)) { New-Item -ItemType Directory -Path $tmDir -Force | Out-Null }
            $TmXmlTemplate | Out-File -FilePath $TmXmlPath -Encoding utf8 -Force
            Write-Result "Created tm.xml at $TmXmlPath"
        } catch {
            Write-Result "Failed to create tm.xml: $_" $false
        }
    }

    # 3. Fix desktop shortcut
    Write-Host ""
    Write-Host "  Checking desktop shortcut..." -ForegroundColor White
    Set-ShortcutTarget -ShortcutPath $DesktopShortcutPath -Label "Desktop"

    # 4. Fix startup shortcut
    Write-Host ""
    Write-Host "  Checking startup folder shortcut..." -ForegroundColor White
    Set-ShortcutTarget -ShortcutPath $StartupShortcutPath -Label "Startup"

    Write-Host ""
    Write-Host "  Client fixes complete." -ForegroundColor Cyan
}

function Set-ShortcutTarget {
    param([string]$ShortcutPath, [string]$Label)

    if (-not (Test-Path $ShortcutPath)) {
        Write-Result "$Label shortcut not found at $ShortcutPath" $false
        return
    }

    $shell    = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)

    if ($shortcut.TargetPath -eq $CorrectShortcutTarget) {
        Write-Result "$Label shortcut target is correct."
    } else {
        Write-Host "  Current target : $($shortcut.TargetPath)" -ForegroundColor Gray
        Write-Host "  Correct target : $CorrectShortcutTarget" -ForegroundColor Gray
        $shortcut.TargetPath       = $CorrectShortcutTarget
        $shortcut.WorkingDirectory = $CorrectWorkingDir
        $shortcut.Save()
        Write-Result "$Label shortcut target updated."
    }
}

# -------------------------------------------------------
#  SERVER FIXES  (placeholder)
# -------------------------------------------------------
function Invoke-ServerFixes {
    Write-Header "Server Fixes"
    Write-Host ""
    Write-Host "  Server fix checks will go here." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Server fixes complete." -ForegroundColor Cyan
}

# -------------------------------------------------------
#  MAIN MENU
# -------------------------------------------------------
function Show-Menu {
    Write-Host ""
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "   Nextep Fix Utility" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "  1. Client fixes"
    Write-Host "  2. Server fixes"
    Write-Host "  Q. Quit"
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "  Select an option"
    switch ($choice.Trim().ToUpper()) {
        "1" { Invoke-ClientFixes }
        "2" { Invoke-ServerFixes }
        "Q" { Write-Host "  Goodbye." -ForegroundColor Cyan; break }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
} while ($choice.Trim().ToUpper() -ne "Q")
