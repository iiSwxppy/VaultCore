# Install the VaultCore native messaging host on Windows.
# Native messaging on Windows uses the registry to point at the manifest file.
#
# Usage:
#   .\install.ps1 -ExtensionId <id> [-HostPath <path-to-vault-mh.exe>]

param(
    [Parameter(Mandatory = $true)] [string] $ExtensionId,
    [string] $HostPath = (Join-Path $PSScriptRoot 'vault-mh.exe')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $HostPath)) {
    Write-Error "Binary not found at $HostPath. Build with: dotnet publish src\Vault.Host -c Release -r win-x64"
    exit 1
}

$Name = 'io.vaultcore.host'
$ManifestDir = Join-Path $env:LOCALAPPDATA 'VaultCore'
New-Item -ItemType Directory -Force -Path $ManifestDir | Out-Null
$ManifestPath = Join-Path $ManifestDir "$Name.json"

$manifest = @{
    name             = $Name
    description      = 'VaultCore native messaging host'
    path             = $HostPath
    type             = 'stdio'
    allowed_origins  = @("chrome-extension://$ExtensionId/")
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $ManifestPath -Encoding UTF8
Write-Host "Wrote manifest to $ManifestPath"

# Register in HKCU so admin isn't required.
$RegPaths = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$Name",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$Name",
    "HKCU:\Software\Chromium\NativeMessagingHosts\$Name",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$Name"
)
foreach ($p in $RegPaths) {
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name '(Default)' -Value $ManifestPath
    Write-Host "Registered $p"
}

Write-Host ''
Write-Host 'Done. Restart your browser.'
