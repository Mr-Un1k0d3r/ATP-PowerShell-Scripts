# ATP-PowerShell-Scripts
Microsoft Signed PowerShell scripts

List of all the signed scripts available in `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection`

# Usage

You can query the register:

```
import-module .\2495bc93-83e1-44f8-a623-46ad2323ee99.ps1
Get-RegistryValue -RegistryLocation HKLM\SYSTEM\CurrentControlSet\Services\sense -RegistryKey Start
0
2
```
