$ErrorActionPreference = "Stop"

$project = "C:\Azerothcore\wowweb"
$serviceHome = "C:\WowWebService"
$wrapper = "$serviceHome\WowWeb.exe"
$serviceConfig = "$serviceHome\WowWeb.xml"
$statusFile = "$serviceHome\service-status.txt"

$winswSource = "C:\Caddy\WinSW-x64.exe"
if (-not (Test-Path $winswSource)) {
    throw "WinSW was not found at $winswSource."
}

New-Item -ItemType Directory -Path $serviceHome -Force | Out-Null
Copy-Item -LiteralPath $winswSource -Destination $wrapper -Force
Copy-Item -LiteralPath "$project\deploy\WowWeb.xml" -Destination $serviceConfig -Force

$listener = Get-NetTCPConnection `
    -LocalAddress "127.0.0.1" `
    -LocalPort 8000 `
    -State Listen `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($listener) {
    Stop-Process -Id $listener.OwningProcess -Force
    Start-Sleep -Seconds 2
}

$existing = Get-Service -Name "WowWeb" -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name "WowWeb" -Force
        (Get-Service -Name "WowWeb").WaitForStatus("Stopped", (New-TimeSpan -Seconds 20))
    }
    & $wrapper uninstall
}

& $wrapper install
Start-Service -Name "WowWeb"
(Get-Service -Name "WowWeb").WaitForStatus("Running", (New-TimeSpan -Seconds 30))
Clear-DnsClientCache

Get-CimInstance Win32_Service -Filter "Name='WowWeb'" |
    Select-Object Name, State, StartMode, ProcessId, PathName |
    Format-List |
    Out-File -Encoding utf8 $statusFile
