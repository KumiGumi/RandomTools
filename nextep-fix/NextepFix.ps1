# NextepFix.ps1
# Paths - replace these with your actual values
$InactiveFilesFolder   = "C:\Path\To\InactiveFilesFolder"
$TmXmlPath             = "C:\Path\To\tm.xml"
$ShortcutName          = "Nextep.lnk"
$DesktopShortcutPath   = [System.IO.Path]::Combine([Environment]::GetFolderPath("CommonDesktopDirectory"), $ShortcutName)
$StartupShortcutPath   = [System.IO.Path]::Combine([Environment]::GetFolderPath("CommonStartup"), $ShortcutName)
$CorrectShortcutTarget = "C:\Path\To\Nextep\Nextep.exe"
$CorrectWorkingDir     = "C:\Path\To\Nextep"

# Client info sources
$ClientHostnameFile    = "C:\Path\To\ClientHostnameFile"   # file that lists the expected client hostname
$ClientUiXmlPath       = "C:\Path\To\ClientUI.xml"         # XML file with client UI details

# Printer config XML (contains printers/Localbase check)
$PrinterConfigXmlPath  = "C:\Path\To\PrinterConfig.xml"    # XML file containing the printers section

# Kiosk movie autofix
$KioskXmlPath          = "C:\Path\To\KioskConfig.xml"      # XML file containing the kiosk-movie element
$KioskMoviePath        = "C:\Path\To\KioskMovie.mp4"        # correct value for the path attribute
$KioskDeviceType       = "DEVICE_TYPE_HERE"                 # correct value for the devicetype attribute

# --- tm.xml template - fill in the fields you need ---
$TmXmlTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<TerminalManager>
  <Setting name="Server">SERVER_ADDRESS_HERE</Setting>
  <Setting name="Port">PORT_HERE</Setting>
  <Setting name="SiteName">SITE_NAME_HERE</Setting>
</TerminalManager>
"@

# -------------------------------------------------------
#  HELPERS
# -------------------------------------------------------
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

function Write-Info {
    param([string]$Label, [string]$Value)
    Write-Host ("  {0,-22}: {1}" -f $Label, $Value) -ForegroundColor White
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
#  CLIENT INFO
# -------------------------------------------------------
function Show-ClientInfo {
    Write-Header "Client Info"

    # Hostname and IP
    Write-Host ""
    $hostname = $env:COMPUTERNAME
    Write-Info "This Machine Hostname" $hostname

    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notmatch "^127\." -and $_.PrefixOrigin -ne "WellKnown" } |
           Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = "(not found)" }
    Write-Info "IP Address" $ip

    # Expected client hostname from file
    Write-Host ""
    Write-Host "  Client Hostname (from file):" -ForegroundColor White
    if (Test-Path $ClientHostnameFile) {
        $fileHostname = (Get-Content $ClientHostnameFile -Raw).Trim()
        Write-Info "  Expected Hostname" $fileHostname
        if ($fileHostname -eq $hostname) {
            Write-Result "Hostname matches."
        } else {
            Write-Result "Hostname MISMATCH (this machine: $hostname)" $false
        }
    } else {
        Write-Result "Client hostname file not found: $ClientHostnameFile" $false
    }

    # Localbase printer check
    Write-Host ""
    Write-Host "  Printer Config - Localbase:" -ForegroundColor White
    if (Test-Path $PrinterConfigXmlPath) {
        try {
            [xml]$printerXml = Get-Content $PrinterConfigXmlPath -Raw
            $localbaseNode = $printerXml.SelectSingleNode("//printers/Localbase")
            if ($null -eq $localbaseNode) {
                Write-Result "No <Localbase> element found under <printers>." $false
            } else {
                $localbaseValue = $localbaseNode.InnerText.Trim()
                if ([string]::IsNullOrWhiteSpace($localbaseValue)) {
                    Write-Result "Localbase is present but has no value." $false
                } else {
                    Write-Info "  Localbase" $localbaseValue
                    Write-Result "Localbase value found."
                }
            }
        } catch {
            Write-Result "Failed to parse $PrinterConfigXmlPath : $_" $false
        }
    } else {
        Write-Result "Printer config XML not found: $PrinterConfigXmlPath" $false
    }

    # Client UI details from XML
    Write-Host ""
    Write-Host "  Client UI Details (from XML):" -ForegroundColor White
    if (Test-Path $ClientUiXmlPath) {
        try {
            [xml]$uiXml = Get-Content $ClientUiXmlPath -Raw
            # Walk every element and print attributes - works regardless of schema
            foreach ($node in $uiXml.SelectNodes("//*")) {
                if ($node.Attributes.Count -gt 0 -or $node.InnerText.Trim()) {
                    $label = $node.Name
                    foreach ($attr in $node.Attributes) {
                        Write-Info "  $label.$($attr.Name)" $attr.Value
                    }
                    if ($node.InnerText.Trim() -and $node.ChildNodes.Count -eq 1) {
                        Write-Info "  $label" $node.InnerText.Trim()
                    }
                }
            }
        } catch {
            Write-Result "Failed to parse $ClientUiXmlPath : $_" $false
        }
    } else {
        Write-Result "Client UI XML not found: $ClientUiXmlPath" $false
    }

    Write-Host ""
}

# -------------------------------------------------------
#  KIOSK MOVIE AUTOFIX
# -------------------------------------------------------
function Invoke-KioskMovieAutofix {
    Write-Header "Kiosk Movie Autofix"
    Write-Host ""
    Write-Host "  Checking: $KioskXmlPath" -ForegroundColor White

    if (-not (Test-Path $KioskXmlPath)) {
        Write-Result "Kiosk XML not found: $KioskXmlPath" $false
        return
    }

    try {
        [xml]$xml = Get-Content $KioskXmlPath -Raw
        $node = $xml.SelectSingleNode("//kiosk-movie")

        if ($null -eq $node) {
            Write-Result "No <kiosk-movie> element found in the file." $false
            return
        }

        $changed = $false

        if ([string]::IsNullOrWhiteSpace($node.GetAttribute("path"))) {
            Write-Host "  path attribute is empty - setting to: $KioskMoviePath" -ForegroundColor Gray
            $node.SetAttribute("path", $KioskMoviePath)
            $changed = $true
        } else {
            Write-Result "path attribute already set: $($node.GetAttribute('path'))"
        }

        if ([string]::IsNullOrWhiteSpace($node.GetAttribute("devicetype"))) {
            Write-Host "  devicetype attribute is empty - setting to: $KioskDeviceType" -ForegroundColor Gray
            $node.SetAttribute("devicetype", $KioskDeviceType)
            $changed = $true
        } else {
            Write-Result "devicetype attribute already set: $($node.GetAttribute('devicetype'))"
        }

        if ($changed) {
            $xml.Save($KioskXmlPath)
            Write-Result "Kiosk XML saved with corrections."
        } else {
            Write-Result "No changes needed."
        }
    } catch {
        Write-Result "Error processing kiosk XML: $_" $false
    }

    Write-Host ""
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
    Write-Host "  3. Client info"
    Write-Host "  4. Kiosk movie autofix"
    Write-Host "  Q. Quit"
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "  Select an option"
    switch ($choice.Trim().ToUpper()) {
        "1" { Invoke-ClientFixes }
        "2" { Invoke-ServerFixes }
        "3" { Show-ClientInfo }
        "4" { Invoke-KioskMovieAutofix }
        "Q" { Write-Host "  Goodbye." -ForegroundColor Cyan; break }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
} while ($choice.Trim().ToUpper() -ne "Q")
