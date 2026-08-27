# SiLogin passwordless VM test

This build supports local Windows accounts only. Test it only in a disposable
x64 Windows VM with a known-good snapshot and a separate administrator account.

## Upgrade from the earlier AP-only test build

The earlier build was registered under `Authentication Packages`. The new build
is a combined SSP/AP and is registered under `Security Packages`.

1. Copy only the updated `Test-EIDAuthenticationPackage.ps1` into the VM.
2. In elevated Windows PowerShell, run:

   ```powershell
   Unblock-File .\Test-EIDAuthenticationPackage.ps1
   .\Test-EIDAuthenticationPackage.ps1 -Action Uninstall -VmConfirmed
   ```

3. Reboot. This releases the old DLL from LSASS.
4. Copy the complete updated project output into the VM.
5. Run the installation sequence below.

## Install

Build x64 Release before copying the project to the VM. In elevated Windows
PowerShell from the copied project directory:

```powershell
Unblock-File .\Test-EIDAuthenticationPackage.ps1
.\Test-EIDAuthenticationPackage.ps1 -Action Preflight
.\Test-EIDAuthenticationPackage.ps1 -Action Install -VmConfirmed
```

Confirm that the enrollment exists at:

```text
C:\ProgramData\SiLogin\Enrollments\<local-account-SID>.json
```

Reboot, then verify challenge issuance:

```powershell
.\Test-EIDAuthenticationPackage.ps1 -Action Test
```

Expected output ends with:

```text
PASS: combined package loaded and issued a one-time challenge.
```

At the sign-in screen select the SiLogin credential tile for the enrolled local
account, insert the enrolled card, and submit without a Windows password.

## Failure checks

Check LSA code-integrity failures:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3033, 3063
    StartTime = (Get-Date).AddMinutes(-15)
} | Format-List TimeCreated, Id, Message
```

Event 3033 means the DLL is still blocked by LSA signing policy. For an unsigned
development build, LSA protected-process enforcement must remain disabled only
inside the disposable VM. Production deployment requires Microsoft LSA signing.

## Remove

```powershell
.\Test-EIDAuthenticationPackage.ps1 -Action Uninstall -VmConfirmed
```

Reboot before deleting either DLL from `C:\Windows\System32`.
