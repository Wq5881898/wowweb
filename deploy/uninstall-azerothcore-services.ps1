$ErrorActionPreference = "Stop"

$serviceHome = "C:\AzerothCoreServices"
$services = @("AzerothCoreWorld", "AzerothCoreAuth")

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

foreach ($name in $services) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $service) {
        continue
    }

    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $name -Force
        (Get-Service -Name $name).WaitForStatus("Stopped", (New-TimeSpan -Seconds 200))
    }

    $wrapper = "$serviceHome\$name.exe"
    if (Test-Path -LiteralPath $wrapper) {
        & $wrapper uninstall
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to uninstall the $name service."
        }
    }
}

if (Get-Service -Name "WowWeb" -ErrorAction SilentlyContinue) {
    & sc.exe config WowWeb depend= "MySQL84" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restore the WowWeb service dependencies."
    }
}
