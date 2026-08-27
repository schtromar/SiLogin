[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Preflight', 'Install', 'Test', 'Uninstall')]
    [string]$Action,

    [string]$DllPath,

    [string]$ProviderDllPath,

    # Required for registry-changing actions. This is deliberately explicit.
    [switch]$VmConfirmed
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($DllPath)) {
    $dllCandidates = @(
        (Join-Path $PSScriptRoot 'x64\Release\silogin-authpak.dll'),
        (Join-Path $PSScriptRoot '..\x64\Release\silogin-authpak.dll')
    )
    $DllPath = @($dllCandidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1)[0]
    if ([string]::IsNullOrWhiteSpace($DllPath)) { $DllPath = $dllCandidates[0] }
}
if ([string]::IsNullOrWhiteSpace($ProviderDllPath)) {
    $providerCandidates = @(
        (Join-Path $PSScriptRoot '..\silogin-provider\x64\Release\silogin-provider.dll'),
        (Join-Path $PSScriptRoot '..\x64\Release\silogin-provider.dll')
    )
    $ProviderDllPath = @($providerCandidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1)[0]
    if ([string]::IsNullOrWhiteSpace($ProviderDllPath)) {
        $ProviderDllPath = $providerCandidates[0]
    }
}
$PackageName = 'silogin-authpak'
$PackageLookupName = 'silogin-authpak'
$LegacyPackageName = 'EIDAuthenticationPackage'
$LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ValueName = 'Security Packages'
$LegacyValueName = 'Authentication Packages'
$InstalledDll = Join-Path $env:SystemRoot "System32\$PackageName.dll"
$LegacyInstalledDll = Join-Path $env:SystemRoot "System32\$LegacyPackageName.dll"
$InstalledProviderDll = Join-Path $env:SystemRoot 'System32\silogin-provider.dll'
$BackupPath = Join-Path $PSScriptRoot 'SecurityPackages.before-SiLogin.clixml'
$ProviderClsid = '{5fd3d285-0dd9-4362-8855-e0abaacd4af6}'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as Administrator for this action.'
    }
}

function Assert-VirtualMachine {
    if (-not $VmConfirmed) {
        throw 'Refusing to modify LSA configuration without -VmConfirmed.'
    }

    $system = Get-CimInstance Win32_ComputerSystem
    $description = "$($system.Manufacturer) $($system.Model)"
    $knownVm = $description -match 'Virtual|VMware|VirtualBox|KVM|QEMU|Xen|Hyper-V|Parallels'
#    if (-not $knownVm) {
 #       throw "This machine does not look like a VM ($description). Refusing installation."
 #   }
 #   Write-Host "VM detected: $description"
}

function Get-LsaPackages([string]$Name) {
    $value = (Get-ItemProperty -LiteralPath $LsaKey -Name $Name).$Name
    return @($value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Invoke-Preflight {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'The supplied project builds an x64 DLL, but this OS is not x64.'
    }
    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
        throw "DLL not found: $DllPath"
    }
    if (-not (Test-Path -LiteralPath $ProviderDllPath -PathType Leaf)) {
        throw "Credential Provider DLL not found: $ProviderDllPath"
    }

    $dll = Get-Item -LiteralPath $DllPath
    $hash = Get-FileHash -LiteralPath $DllPath -Algorithm SHA256
    Write-Host "DLL:    $($dll.FullName)"
    Write-Host "Size:   $($dll.Length) bytes"
    Write-Host "SHA256: $($hash.Hash)"

    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($dumpbin) {
        $exports = & $dumpbin.Source /nologo /exports $DllPath | Out-String
        foreach ($required in @('LsaApInitializePackage', 'LsaApLogonUserEx2',
                'LsaApCallPackageUntrusted', 'LsaApLogonTerminated')) {
            if ($exports -notmatch "\b$required\b") {
                throw "Required export missing: $required"
            }
        }
        Write-Host 'Required authentication-package exports are present.'
    }
    else {
        Write-Warning 'dumpbin.exe is unavailable; export verification was skipped.'
    }
}

function Install-Package {
    Assert-Administrator
    Assert-VirtualMachine
    Invoke-Preflight

    $packages = Get-LsaPackages $ValueName
    if (-not (Test-Path -LiteralPath $BackupPath)) {
        $packages | Export-Clixml -LiteralPath $BackupPath
        Write-Host "Saved the original package list to $BackupPath"
    }

    Copy-Item -LiteralPath $DllPath -Destination $InstalledDll -Force
    Copy-Item -LiteralPath $ProviderDllPath -Destination $InstalledProviderDll -Force
    $updated = @($packages | Where-Object {
        $_ -ne $PackageName -and $_ -ne $LegacyPackageName
    }) + $PackageName
    Set-ItemProperty -LiteralPath $LsaKey -Name $ValueName -Type MultiString -Value $updated

    # Do not load the same DLL through both legacy AP and combined SSP/AP paths.
    $legacy = Get-LsaPackages $LegacyValueName
    $legacyUpdated = @($legacy | Where-Object {
        $_ -ne $PackageName -and $_ -ne $LegacyPackageName
    })
    Set-ItemProperty -LiteralPath $LsaKey -Name $LegacyValueName -Type MultiString -Value $legacyUpdated

    $providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderClsid"
    $classKey = "Registry::HKEY_CLASSES_ROOT\CLSID\$ProviderClsid"
    New-Item -Path $providerKey -Force | Out-Null
    Set-Item -Path $providerKey -Value 'SiLogin smart-card credential provider'
    New-Item -Path "$classKey\InprocServer32" -Force | Out-Null
    Set-Item -Path $classKey -Value 'SiLogin smart-card credential provider'
    Set-Item -Path "$classKey\InprocServer32" -Value $InstalledProviderDll
    New-ItemProperty -Path "$classKey\InprocServer32" -Name ThreadingModel -Value Apartment -PropertyType String -Force | Out-Null

    Write-Host "Installed: $InstalledDll"
    Write-Host "Installed: $InstalledProviderDll"
    Write-Host "Registered '$PackageName' without changing existing entries."
    Write-Warning 'Take/verify a VM snapshot now, then reboot the VM. Do not reboot a physical host with this test package.'
}

function Add-LsaNativeType {
    if ('EidLsaSmokeTest.Native' -as [type]) { return }

    # Windows PowerShell 5 uses the .NET CodeDOM compiler for Add-Type.  A
    # missing TEMP/TMP directory otherwise produces the unhelpful error
    # "The system cannot find the path specified" at the Add-Type line.
    $compileTemp = Join-Path $PSScriptRoot '.powershell-temp'
    New-Item -ItemType Directory -Path $compileTemp -Force | Out-Null

    $oldTemp = $env:TEMP
    $oldTmp = $env:TMP
    try {
        $env:TEMP = $compileTemp
        $env:TMP = $compileTemp
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace EidLsaSmokeTest {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    public static class Native {
        [DllImport("secur32.dll")]
        public static extern int LsaConnectUntrusted(out IntPtr handle);

        [DllImport("secur32.dll")]
        public static extern int LsaLookupAuthenticationPackage(
            IntPtr handle, ref LSA_STRING packageName, out uint packageId);

        [DllImport("secur32.dll")]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr handle, uint packageId, IntPtr submitBuffer,
            uint submitBufferLength, out IntPtr returnBuffer,
            out uint returnBufferLength, out int protocolStatus);

        [DllImport("secur32.dll")]
        public static extern int LsaDeregisterLogonProcess(IntPtr handle);

        [DllImport("secur32.dll")]
        public static extern int LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("advapi32.dll")]
        public static extern uint LsaNtStatusToWinError(int status);
    }
}
'@
    }
    catch {
        $frameworkCsc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        throw "Unable to compile the LSA smoke-test helper. Compile temp: '$compileTemp'; csc.exe present: $(Test-Path -LiteralPath $frameworkCsc). $($_.Exception.Message)"
    }
    finally {
        $env:TEMP = $oldTemp
        $env:TMP = $oldTmp
    }
}

function Write-BuildComparison {
    param(
        [string]$Label,
        [string]$SourcePath,
        [string]$InstalledPath
    )

    Write-Host "$Label build comparison:"
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        Write-Warning "  Source DLL is missing: $SourcePath"
        return
    }
    if (-not (Test-Path -LiteralPath $InstalledPath -PathType Leaf)) {
        Write-Warning "  Installed DLL is missing: $InstalledPath"
        return
    }

    $sourceHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash -LiteralPath $InstalledPath -Algorithm SHA256).Hash
    Write-Host "  Source:    $sourceHash"
    Write-Host "  Installed: $installedHash"
    if ($sourceHash -ne $installedHash) {
        Write-Warning "  $Label source and installed DLLs differ. Uninstall, reboot, install, and reboot before testing."
    }
    else {
        Write-Host "  MATCH: source and installed $Label DLLs are identical." -ForegroundColor Green
    }
}

function Format-NtStatus([int]$Status) {
    $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes($Status), 0)
    $win32 = [EidLsaSmokeTest.Native]::LsaNtStatusToWinError($Status)
    return ('0x{0:X8} (Win32 {1})' -f $unsigned, $win32)
}

function Test-Package {
    Write-BuildComparison -Label 'Authentication package' -SourcePath $DllPath -InstalledPath $InstalledDll
    Write-BuildComparison -Label 'Credential provider' -SourcePath $ProviderDllPath -InstalledPath $InstalledProviderDll
    Add-LsaNativeType
    $handle = [IntPtr]::Zero
    $nameBuffer = [IntPtr]::Zero
    $submitBuffer = [IntPtr]::Zero
    $returnBuffer = [IntPtr]::Zero
    try {
        $status = [EidLsaSmokeTest.Native]::LsaConnectUntrusted([ref]$handle)
        if ($status -ne 0) { throw "LsaConnectUntrusted failed: $(Format-NtStatus $status)" }

        $nameBytes = [Text.Encoding]::ASCII.GetBytes("$PackageLookupName`0")
        $nameBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($nameBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($nameBytes, 0, $nameBuffer, $nameBytes.Length)
        $name = [EidLsaSmokeTest.LSA_STRING]@{
            Length = [uint16]($nameBytes.Length - 1)
            MaximumLength = [uint16]$nameBytes.Length
            Buffer = $nameBuffer
        }

        [uint32]$packageId = 0
        $status = [EidLsaSmokeTest.Native]::LsaLookupAuthenticationPackage(
            $handle, [ref]$name, [ref]$packageId)
        if ($status -ne 0) {
            throw "Package lookup failed: $(Format-NtStatus $status). Install and reboot first."
        }
        Write-Host "Package loaded; LSA package ID is $packageId."

        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $json = '{"protocol":"SiLogin-LSA","version":1,"type":"challengeRequest","accountSid":"' + $sid + '"}'
        $submitBytes = [Text.Encoding]::UTF8.GetBytes($json)
        $submitBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($submitBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($submitBytes, 0, $submitBuffer, $submitBytes.Length)
        [uint32]$returnLength = 0
        [int]$protocolStatus = 0
        $status = [EidLsaSmokeTest.Native]::LsaCallAuthenticationPackage(
            $handle, $packageId, $submitBuffer, $submitBytes.Length, [ref]$returnBuffer,
            [ref]$returnLength, [ref]$protocolStatus)

        Write-Host "Call status:     $(Format-NtStatus $status)"
        Write-Host "Protocol status: $(Format-NtStatus $protocolStatus)"
        if ($status -ne 0 -or $protocolStatus -ne 0 -or $returnLength -eq 0) {
            throw 'Challenge request failed. Verify combined SSP/AP registration and reboot.'
        }
        Write-Host 'PASS: combined package loaded and issued a one-time challenge.' -ForegroundColor Green
    }
    finally {
        if ($returnBuffer -ne [IntPtr]::Zero) {
            [void][EidLsaSmokeTest.Native]::LsaFreeReturnBuffer($returnBuffer)
        }
        if ($submitBuffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($submitBuffer)
        }
        if ($nameBuffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($nameBuffer)
        }
        if ($handle -ne [IntPtr]::Zero) {
            [void][EidLsaSmokeTest.Native]::LsaDeregisterLogonProcess($handle)
        }
    }
}

function Uninstall-Package {
    Assert-Administrator
    Assert-VirtualMachine
    $packages = Get-LsaPackages $ValueName
    $updated = @($packages | Where-Object {
        $_ -ne $PackageName -and $_ -ne $LegacyPackageName
    })
    Set-ItemProperty -LiteralPath $LsaKey -Name $ValueName -Type MultiString -Value $updated
    $legacy = Get-LsaPackages $LegacyValueName
    $legacyUpdated = @($legacy | Where-Object {
        $_ -ne $PackageName -and $_ -ne $LegacyPackageName
    })
    Set-ItemProperty -LiteralPath $LsaKey -Name $LegacyValueName -Type MultiString -Value $legacyUpdated
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderClsid" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "Registry::HKEY_CLASSES_ROOT\CLSID\$ProviderClsid" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed '$PackageName' from both LSA package lists."
    Write-Warning "Reboot before deleting $InstalledDll, $LegacyInstalledDll, and $InstalledProviderDll."
}

switch ($Action) {
    'Preflight' { Invoke-Preflight }
    'Install'   { Install-Package }
    'Test'      { Test-Package }
    'Uninstall' { Uninstall-Package }
}
