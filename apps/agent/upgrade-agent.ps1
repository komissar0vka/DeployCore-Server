#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$Sha256
)

$ErrorActionPreference = 'Stop'
$msiFile = (Resolve-Path -LiteralPath $Msi).ProviderPath
if ([IO.Path]::GetExtension($msiFile) -ne '.msi' -or (Get-FileHash -LiteralPath $msiFile).Hash -ne $Sha256) {
    throw 'MSI checksum does not match the approved SHA-256.'
}
$serviceName = 'DeployCoreAgent'
$registered = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
$managed = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DeployCore Managed Agent\deploycore-agent.exe'
$legacy = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DeployCore\deploycore-agent.exe'
$legacyDirectory = Split-Path -Parent $legacy
$state = Join-Path $legacyDirectory 'state.dpapi'
$log = Join-Path $legacyDirectory ('DeployCore-MSI-' + [guid]::NewGuid().ToString('N') + '.log')
$isLegacy = $false
if ($registered) {
    $isLegacy = ($registered.PathName -ieq ('"' + $legacy + '" service')) -or ($registered.PathName -ieq ($legacy + ' service'))
    if (-not $isLegacy -and $registered.PathName -ine ('"' + $managed + '" service-msi') -and $registered.PathName -ine ($managed + ' service-msi')) {
        throw 'The existing service does not belong to a recognized DeployCore installation.'
    }
    if ($registered.StartName -ine 'LocalSystem') {
        throw 'The existing service does not use the expected LocalSystem account.'
    }
}
if (-not (Test-Path -LiteralPath $state -PathType Leaf)) { throw 'Existing protected DeployCore state is required.' }
$legacyRemoved = $false
try {
    if ($isLegacy) {
        foreach ($path in @($legacyDirectory, $legacy, $state)) {
            if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Unexpected reparse point in legacy deployment.'
            }
        }
        # Stop and delete only the service registration. The executable and DPAPI state remain on disk.
        Stop-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        & (Join-Path $env:SystemRoot 'System32\sc.exe') delete $serviceName | Out-Null
        if ($LASTEXITCODE) { throw 'Could not unregister the legacy service.' }
        $legacyRemoved = $true
        for ($i=0; $i -lt 30 -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'The legacy service is still being removed.' }
    }
    $result = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @(
        '/i', ('"' + $msiFile + '"'), '/qn', '/norestart', '/L*v', ('"' + $log + '"')
    ) -Wait -PassThru
    if ($result.ExitCode -notin @(0,3010)) { throw "Windows Installer failed ($($result.ExitCode)). Log: $log" }
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Output "DeployCore Agent active. Log: $log"
} catch {
    if ($legacyRemoved) {
        $candidate = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($candidate -and ($candidate.PathName -ieq ('"' + $managed + '" service-msi') -or $candidate.PathName -ieq ($managed + ' service-msi'))) {
            Start-Process msiexec.exe -ArgumentList @('/x', ('"' + $msiFile + '"'), '/qn', '/norestart') -Wait -PassThru | Out-Null
        }
    }
    if ($legacyRemoved -and -not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        New-Service -Name $serviceName -BinaryPathName ('"' + $legacy + '" service') -DisplayName 'DeployCore Agent' -StartupType Automatic | Out-Null
        Start-Service -Name $serviceName
    } elseif ($isLegacy -and -not $legacyRemoved -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Start-Service -Name $serviceName
    }
    throw
}
