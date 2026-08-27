[CmdletBinding()]
param(
    [ValidateSet('Preflight', 'Install', 'Test', 'Uninstall')]
    [string]$Action = 'Install',

    [switch]$VmConfirmed
)

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'silogin-authpak\Test-EIDAuthenticationPackage.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "SiLogin authentication-package installer not found: $installer"
}

$arguments = @{
    Action = $Action
}
if ($VmConfirmed) {
    $arguments.VmConfirmed = $true
}

& $installer @arguments

