# ATP-PowerShell-Scripts
Microsoft Signed PowerShell scripts

List of all the signed scripts available in `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection`

# Accessing the file

By default the files cannot be accessed. You need the TrustedInstaller privilege

https://github.com/Mr-Un1k0d3r/EDRs/blob/main/elevate_to_system_or_trustedinstaller.c

```
> elevate trusted
[GetProcByPID] Process winlogon.exe PID is 1640
[ElevateSystem] ImpersonateByPID(SYSTEM) succeeded.
[GetTrustedInstallerPID] QueryServiceStatusEx need 36 bytes.
[GetTrustedInstallerPID] TrustedInstaller Service PID is 14108
[ElevateTrustedInstaller] ImpersonateByPID(TrustedInstaller) succeeded.
[main] (SYSTEM) Token HANDLE 0x00000000000000AC.
[main] (TrustedInstaller) Token HANDLE 0x00000000000000D8.
[CreateProcessImpersonate] MultiByteToWideChar need 8 bytes.
```

The newly spawn `cmd.exe` can be used to browse the folder.

# Usage (More to come)

You can query the register:

```
import-module .\2495bc93-83e1-44f8-a623-46ad2323ee99.ps1
Get-RegistryValue -RegistryLocation HKLM\SYSTEM\CurrentControlSet\Services\sense -RegistryKey Start
0
2
```
