$ErrorActionPreference = "Stop"

$project = "C:\Azerothcore\wowweb"
$serverHome = "C:\Azerothcore\azerothcore-wotlk\build\bin\Debug"
$serviceHome = "C:\AzerothCoreServices"
$winswSource = "C:\Caddy\WinSW-x64.exe"

$serviceDefinitions = @(
    @{
        Name = "AzerothCoreAuth"
        Process = "authserver"
        Xml = "$project\deploy\AzerothCoreAuth.xml"
    },
    @{
        Name = "AzerothCoreWorld"
        Process = "worldserver"
        Xml = "$project\deploy\AzerothCoreWorld.xml"
    }
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell window."
    }
}

function Wait-TcpPort {
    param(
        [string]$Address,
        [int]$Port,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($Address, $Port)
            if ($task.Wait(1000) -and $client.Connected) {
                return
            }
        }
        catch {
            # The service may still be loading its databases.
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for ${Address}:$Port."
}

function Stop-StandaloneProcess {
    param([string]$ProcessName)

    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        $null = $process.CloseMainWindow()
        if (-not $process.WaitForExit(15000)) {
            Stop-Process -Id $process.Id -Force
            $null = $process.WaitForExit(10000)
        }
    }
}

function Install-WrappedService {
    param(
        [string]$Name,
        [string]$XmlSource
    )

    $wrapper = "$serviceHome\$Name.exe"
    $config = "$serviceHome\$Name.xml"
    $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if ($existing) {
        if ($existing.Status -ne "Stopped") {
            Stop-Service -Name $Name -Force
            (Get-Service -Name $Name).WaitForStatus("Stopped", (New-TimeSpan -Seconds 200))
        }
        if (Test-Path -LiteralPath $wrapper) {
            & $wrapper uninstall
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to uninstall the existing $Name service."
            }
        }
    }

    Copy-Item -LiteralPath $winswSource -Destination $wrapper -Force
    Copy-Item -LiteralPath $XmlSource -Destination $config -Force

    & $wrapper install
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install the $Name service."
    }
}

Assert-Administrator

$requiredFiles = @(
    $winswSource,
    "$serverHome\authserver.exe",
    "$serverHome\worldserver.exe",
    "$serverHome\configs\authserver.conf",
    "$serverHome\configs\worldserver.conf"
) + ($serviceDefinitions | ForEach-Object { $_.Xml })

foreach ($path in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file was not found: $path"
    }
}

New-Item -ItemType Directory -Path $serviceHome -Force | Out-Null
New-Item -ItemType Directory -Path "$serviceHome\logs\auth" -Force | Out-Null
New-Item -ItemType Directory -Path "$serviceHome\logs\world" -Force | Out-Null

$reverseDefinitions = [array]$serviceDefinitions.Clone()
[array]::Reverse($reverseDefinitions)
foreach ($definition in $reverseDefinitions) {
    $service = Get-Service -Name $definition.Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $definition.Name -Force
        (Get-Service -Name $definition.Name).WaitForStatus("Stopped", (New-TimeSpan -Seconds 200))
    }
}

foreach ($definition in $serviceDefinitions) {
    Stop-StandaloneProcess -ProcessName $definition.Process
    Install-WrappedService -Name $definition.Name -XmlSource $definition.Xml
}

Start-Service -Name "AzerothCoreAuth"
(Get-Service -Name "AzerothCoreAuth").WaitForStatus("Running", (New-TimeSpan -Seconds 30))
Wait-TcpPort -Address "127.0.0.1" -Port 3724 -TimeoutSeconds 120

Start-Service -Name "AzerothCoreWorld"
(Get-Service -Name "AzerothCoreWorld").WaitForStatus("Running", (New-TimeSpan -Seconds 30))
Wait-TcpPort -Address "127.0.0.1" -Port 8085 -TimeoutSeconds 300
Wait-TcpPort -Address "127.0.0.1" -Port 7878 -TimeoutSeconds 120

$wowWeb = Get-Service -Name "WowWeb" -ErrorAction SilentlyContinue
if ($wowWeb) {
    & sc.exe config WowWeb depend= "MySQL84/AzerothCoreWorld" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to update the WowWeb service dependencies."
    }
    Copy-Item -LiteralPath "$project\deploy\WowWeb.xml" -Destination "C:\WowWebService\WowWeb.xml" -Force
    Restart-Service -Name "WowWeb"
    (Get-Service -Name "WowWeb").WaitForStatus("Running", (New-TimeSpan -Seconds 30))
}

Get-CimInstance Win32_Service |
    Where-Object { $_.Name -in "MySQL84", "AzerothCoreAuth", "AzerothCoreWorld", "WowWeb", "Cloudflared" } |
    Select-Object Name, State, StartMode, ProcessId |
    Sort-Object Name |
    Format-Table -AutoSize
