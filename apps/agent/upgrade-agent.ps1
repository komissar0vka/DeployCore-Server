#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$Sha256
)

$ErrorActionPreference = 'Stop'
$msiFile = (Resolve-Path -LiteralPath $Msi).ProviderPath
$serviceName = 'DeployCoreAgent'
function Read-DeployCoreService {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\DeployCoreAgent')
    if ($key) {
        try {
            return @{ PathName = $key.GetValue('ImagePath'); StartName = $key.GetValue('ObjectName') }
        } finally {
            $key.Dispose()
        }
    }
}
$registered = Read-DeployCoreService
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
foreach ($path in @($legacyDirectory, $state)) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Unexpected reparse point in DeployCore state.'
    }
}
$staging = Join-Path $legacyDirectory ('upgrade-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
try {
    if ([IO.Path]::GetExtension($msiFile) -ne '.msi') { throw 'Expected an MSI installer.' }
    $stagedMsi = Join-Path $staging 'agent.msi'
    [IO.File]::Copy($msiFile, $stagedMsi, $false)
    $msiFile = $stagedMsi
    $hasher = [Security.Cryptography.SHA256]::Create()
    $source = [IO.File]::OpenRead($msiFile)
    try {
        $actualHash = [BitConverter]::ToString($hasher.ComputeHash($source)).Replace('-', '')
    } finally {
        $source.Dispose()
        $hasher.Dispose()
    }
    if ($actualHash -ne $Sha256) {
        throw 'MSI checksum does not match the approved SHA-256.'
    }
    # A strict installation has local trust on disk. Hashes handed out by Server cannot replace publisher trust.
    $replay = Join-Path $legacyDirectory 'job-replay.dpapi'
    $jobTrust = Join-Path $legacyDirectory 'job-trust.json'
    $publishers = Join-Path $legacyDirectory 'agent-update-publishers.json'
    if ((Test-Path -LiteralPath $replay) -or (Test-Path -LiteralPath $jobTrust) -or (Test-Path -LiteralPath $publishers)) {
        if (-not (Test-Path -LiteralPath $publishers -PathType Leaf)) {
            throw 'Agent update publisher policy is required for a strict installation.'
        }
        $policyFile = Get-Item -LiteralPath $publishers -Force
        if (($policyFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $policyFile.Length -gt 8192) {
            throw 'Invalid agent update publisher policy.'
        }
        $policy = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($publishers))
        $pins = @($policy.certificate_sha256)
        if ($pins.Count -eq 0 -or @($pins | Where-Object { $_ -notmatch '^[A-Fa-f0-9]{64}$' }).Count -ne 0) {
            throw 'Invalid agent update publisher fingerprints.'
        }
        $securityModule = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
        Import-Module -Name $securityModule
        $auth = Get-AuthenticodeSignature -LiteralPath $msiFile
        if ($auth.Status -ne 'Valid' -or -not $auth.SignerCertificate) {
            throw 'Agent update MSI does not have a valid Authenticode signature.'
        }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $fingerprint = [BitConverter]::ToString($hasher.ComputeHash($auth.SignerCertificate.RawData)).Replace('-', '')
        } finally { $hasher.Dispose() }
        if ($fingerprint -notin $pins) { throw 'Agent update publisher is outside the local allowlist.' }
        if (-not $registered) { throw 'Strict agent upgrade requires an installed service.' }
        $currentExecutable = if ($isLegacy) { $legacy } else { $managed }
        if ((Get-Item -LiteralPath $currentExecutable -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Unexpected reparse point in the installed agent.'
        }
        $currentVersion = [version](& $currentExecutable version)
        if ($LASTEXITCODE) { throw 'Could not determine the installed agent version.' }
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class DeployCoreMsiMetadata
{
    [DllImport("msi.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint MsiOpenDatabaseW(string path, IntPtr mode, out uint database);
    [DllImport("msi.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint MsiDatabaseOpenViewW(uint database, string query, out uint view);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewFetch(uint view, out uint record);
    [DllImport("msi.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint MsiRecordGetStringW(uint record, uint field, StringBuilder result, ref uint size);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiCloseHandle(uint handle);

    private static void Check(uint status)
    {
        if (status != 0) throw new Win32Exception((int)status);
    }

    public static Version ReadVersion(string path)
    {
        uint database = 0, view = 0, record = 0;
        try
        {
            Check(MsiOpenDatabaseW(path, IntPtr.Zero, out database));
            Check(MsiDatabaseOpenViewW(database, "SELECT `Value` FROM `Property` WHERE `Property`='ProductVersion'", out view));
            Check(MsiViewExecute(view, 0));
            Check(MsiViewFetch(view, out record));
            var version = new StringBuilder(64);
            uint length = (uint)version.Capacity;
            Check(MsiRecordGetStringW(record, 1, version, ref length));
            return Version.Parse(version.ToString());
        }
        finally
        {
            if (record != 0) MsiCloseHandle(record);
            if (view != 0) MsiCloseHandle(view);
            if (database != 0) MsiCloseHandle(database);
        }
    }
}
'@
        $candidateVersion = [DeployCoreMsiMetadata]::ReadVersion($msiFile)
        if ($candidateVersion -le $currentVersion) { throw 'Agent update must be newer than the installed version.' }

    }

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
            $candidate = Read-DeployCoreService
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

} finally {
    [IO.Directory]::Delete($staging, $true)
}
