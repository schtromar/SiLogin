#Requires -RunAsAdministrator

$installDirectory="C:/Program Files/SiLogin"
$system32Directory="C:/Windows/System32"
$credentialProviderDll="x64/Release/silogin-credentialProvider.dll"

## Check if the install directory exists, if not create it
if (-not (Test-Path $installDirectory)) {
	New-Item -ItemType Directory -Path $installDirectory
}

## Install the credential provider
cp $credentialProviderDll $system32Directory/.
regedit.exe /s register.reg

