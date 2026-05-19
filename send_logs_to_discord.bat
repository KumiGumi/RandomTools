@echo off
setlocal

:: ============================================================
::  CONFIGURATION — edit these four values before running
:: ============================================================
set WEBHOOK_URL=YOUR_DISCORD_WEBHOOK_URL_HERE
set LOG_DIR_1=C:\Path\To\Logs\App1
set LOG_DIR_2=C:\Path\To\Logs\App2
set LOG_EXT=*.log
set TAIL_LINES=30
:: ============================================================

:: Write the embedded PowerShell to a unique temp file
set PS_TEMP=%TEMP%\send_logs_discord_%RANDOM%.ps1

(
echo param^($WebhookUrl, $LogDir1, $LogDir2, $LogExt, $TailLines^)
echo.
echo $computerName = $env:COMPUTERNAME
echo.
echo $ip = try {
echo     ^(Get-NetIPAddress -AddressFamily IPv4 ^|
echo         Where-Object { $_.PrefixOrigin -ne 'WellKnown' } ^|
echo         Sort-Object InterfaceIndex ^|
echo         Select-Object -First 1^).IPAddress
echo } catch { 'unknown' }
echo if ^(-not $ip^) { $ip = 'unknown' }
echo.
echo function Get-LogTail^($dir, $ext, $n^) {
echo     $file = Get-ChildItem -Path $dir -Filter $ext -ErrorAction SilentlyContinue ^|
echo             Sort-Object LastWriteTime -Descending ^|
echo             Select-Object -First 1
echo     if ^(-not $file^) { return @{ name='(no log found)'; content='No log files found in this directory.' } }
echo     $lines = Get-Content $file.FullName -Tail $n -ErrorAction SilentlyContinue
echo     return @{ name=$file.Name; content=^($lines -join "`n"^) }
echo }
echo.
echo function Trim-Field^($text^) {
echo     if ^($text.Length -gt 1000^) { return $text.Substring^(0, 997^) + '...' }
echo     return $text
echo }
echo.
echo $log1 = Get-LogTail $LogDir1 $LogExt $TailLines
echo $log2 = Get-LogTail $LogDir2 $LogExt $TailLines
echo.
echo $field1val = "``````\n$^(Trim-Field $log1.content^)\n``````"
echo $field2val = "``````\n$^(Trim-Field $log2.content^)\n``````"
echo.
echo $payload = [ordered]@{
echo     username = 'Log Dump Bot'
echo     embeds   = @^(@{
echo         title     = "Log Dump -- $computerName ^($ip^)"
echo         color     = 3447003
echo         fields    = @^(
echo             @{ name="[1] $LogDir1 -> $^($log1.name^)"; value=$field1val; inline=$false },
echo             @{ name="[2] $LogDir2 -> $^($log2.name^)"; value=$field2val; inline=$false }
echo         ^)
echo         timestamp = ^(Get-Date^).ToUniversalTime^(^).ToString^("yyyy-MM-ddTHH:mm:ssZ"^)
echo     }^)
echo } ^| ConvertTo-Json -Depth 6
echo.
echo try {
echo     Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' ^| Out-Null
echo     Write-Host "Sent log dump to Discord ($computerName / $ip)"
echo } catch {
echo     Write-Host "ERROR: Failed to send to Discord -- $_"
echo     exit 1
echo }
) > "%PS_TEMP%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_TEMP%" "%WEBHOOK_URL%" "%LOG_DIR_1%" "%LOG_DIR_2%" "%LOG_EXT%" "%TAIL_LINES%"

del "%PS_TEMP%" >nul 2>&1
endlocal
