
$Source = @"
    using System;
    using System.Text;
    using System.Diagnostics.Tracing;
    using Microsoft.PowerShell.Commands;
    using System.Management.Automation;
    using System.Runtime.InteropServices;

    public static class PasswordPolicyProvider
            {
                public static EventSource log = new EventSource("Microsoft.Windows.Sense.PasswordPolicyProvider", EventSourceSettings.EtwSelfDescribingEventFormat);
            }
                              
    // Based on https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_0 
    [StructLayout(LayoutKind.Sequential)]
    public struct USER_MODALS_INFO_0
    {
        public uint MinPasswdLen;
        public uint MaxPasswdAge;
        public uint MinPasswdAge;
        public uint ForceLogoff;
        public uint PasswordHistLen;
    }

    [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
    public class PasswordPolicyDto
    {
        public uint MinPasswdLen { get; set; }
        public uint MaxPasswdAge { get; set; }
        public uint MinPasswdAge { get; set; }
        public uint ForceLogoff { get; set; }
        public uint PasswordHistLen { get; set; }
	}

    public class PasswordPolicy {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint NetUserModalsGet(
            string server,
            int level,
            out IntPtr BufPtr
        );
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern uint NetApiBufferFree(
            IntPtr bufptr
        );
        public static IntPtr invoke_NetUserModalsGet(int level) {
            uint retVal;
            IntPtr myBuf;
        
            retVal = NetUserModalsGet(
                "\\\\" + Environment.GetEnvironmentVariable("COMPUTERNAME"), 
                level,
                out myBuf
            );
            if (retVal == 0) {
                return myBuf;
            }
            return IntPtr.Zero;
        }
    }
"@

Add-Type  -TypeDefinition $Source -Language CSharp -IgnoreWarnings

$Provider = [PasswordPolicyProvider]::log

Function Get-RegistryValue
{ 
    Param(
        [Parameter()]
        [String]
        $RegistryLocation,

        [Parameter()]
        [String]
        $RegistryKey
    )

    $registryResult = Get-ItemProperty -Path  "Registry::$RegistryLocation" -Name $RegistryKey -ErrorAction SilentlyContinue
    if ($null -eq $registryResult)
    {
        $registryValue = "null"
    }
    else
    {
        $registryValue = $registryResult.$registryKey
    }

    return $registryValue
}

function CallNetUserModalsGet {
    $myBuf = [PasswordPolicy]::invoke_NetUserModalsGet(0)
    if ($myBuf -ne 0 ) {
        $type = $null
        $type = (New-Object USER_MODALS_INFO_0).GetType()
        $out = [System.Runtime.InteropServices.Marshal]::PtrToStructure($myBuf, [System.Type]$type);
        [PasswordPolicy]::NetApiBufferFree($myBuf) | Out-Null
        return $out
    }
    return $null
}

# Get MEM's password configurtion 
$PasswordHistoryMEM = Get-registryValue -RegistryLocation 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock' -RegistryKey 'DevicePasswordHistory'
$MinPasswordLengthMEM = Get-registryValue -RegistryLocation 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock' -RegistryKey 'MinDevicePasswordLength'



$Result = CallNetUserModalsGet
if ($Result -ne $null) {     
    
    # for Password history and minimum password length, in case of a conflict between GPO and MEM the most restrictive setting wins.
    if(($null -ne $PasswordHistoryMEM) -and ($PasswordHistoryMEM -gt  $Result.PasswordHistLen))
    {
        $Result.PasswordHistLen = $PasswordHistoryMEM
    }
    
    if(($null -ne $MinPasswordLengthMEM) -and ($MinPasswordLengthMEM -gt  $Result.MinPasswdLen))
    {
        $Result.MinPasswdLen = $MinPasswordLengthMEM
    }

    #Using json as an interim representation to convert result into DTO object
    [PasswordPolicyDto]$ConvertedResult = $Result | ConvertTo-Json|  ConvertFrom-Json 
    


    $Provider.Write("PasswordPolicy", $ConvertedResult)
} else {
    Write-Host "Failed to read from 'NetUserModalsGet'"
}
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBLC5FnoC1rsObj
# qqKXuFDGHlGcDMEjAv9f9IlkxChg/6CCDZcwggYVMIID/aADAgECAhMzAAADEBr/
# fXDbjW9DAAAAAAMQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwODA0MjAyNjM5WhcNMjMwODAzMjAyNjM5WjCBlDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWlj
# cm9zb2Z0IFdpbmRvd3MgRGVmZW5kZXIgQWR2YW5jZWQgVGhyZWF0IFByb3RlY3Rp
# b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0y67idUrLERDl3ls1
# 1XkmCQNGqDqXUbrM7xeQ3MDX2TI2X7/wxqqVBo5wjSGMUEUxZpgrQRj7fyyeQWvy
# OKx7cxcBYXxRWjOQRSYWqk+hcaLj7E9CkuYyM1tuVxuAehDD1jqwLGS5LfFG9iE9
# tXCQHI59kCLocKMNm2C8RWNNKlPYN0dkN/pcEIpf6L+P+GXYN76jL+k7uXY0Vgpu
# uKvUZdxukyqhYbWy8aNr8BasPSOudq2+1VzK52kbUq79M7F3lN+JfDdyiG5YoSdc
# XDrvOU1fnP1Kc4PtUJL7tSHFuBylTiNyDnHfSORQeZPFg971CeZS7I8ZFojDLgTY
# kDQDAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wv
# ATAdBgNVHQ4EFgQU0X7BWbJmeu82AxuDs7MBJC8zJ8swRQYDVR0RBD4wPKQ6MDgx
# HjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNNDUxODk0
# KzQ3MjIyMDAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8E
# TTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBR
# BggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAw
# DQYJKoZIhvcNAQELBQADggIBAIXZp9/puv2exE6jflkfuJ3E8xrXA1ch9bnCloXS
# 01xOXTauGU/+1peumenJbgwCzn/iwGIJkuoHSx5F85n7OG9InPRApTNcYmAkGPIk
# /x5SNl67Su8eHlLGd8erjoEcseZBckRENr5mBHtELtOWR80cAH9dbALlY/gJ5FDq
# jOxA9Q6UDeaT9oeIJwSy/LD9sUKrUZ4zSvqFBjjEBx3g2TfmRe3qLfKJEOL1mzCk
# 06RHYwcU2uU1s5USCeePuafeQ159io+FVdW5f7703UeD4pzXOp4eZTtWl0875By+
# bWxAR8/dc41v2MEQoy0WplbGfkBm9BWT0w0pL3itBYcXRlzIfPForBPK2aIQOMPL
# CH8JR3uJXvbTJ5apXBAFOWl6dU1JqGTT/iuWsVznHBqDmq6zKf38QYocac0o7qL3
# RG1/eiQdbPQisNpFiqTzTd6lyUaXrPtk+BniKT4bVXJ2FrfsmLiXIcFhC6FAidok
# spWZVHS8T4WwSPVpmhjEgubZlhldva/wOT/OjtGzoy6L7yNKjcSadVou4VroLLK9
# qwYgKnjyzX8KEcGkKUXScwZIp8uWDp5bmKYh+5SQEa26bzHcX0a1iqmsUoP5JhYL
# xwloQM2AgY9AEAIHSFXfCo17ae/cxV3sEaLfuL09Z1sSQC5wm32hV3YyyEgsRDXE
# zXRCMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4
# MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3Y
# bqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUB
# FDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnbo
# MlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT
# +OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuy
# e4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEh
# NSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2
# z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3
# s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78Ic
# V9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E
# 11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5P
# M4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcV
# AQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBL
# hklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggr
# BgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsG
# AQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDB
# ZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc
# 8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYq
# wooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu
# 5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWI
# UUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXh
# j38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yH
# PgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtI
# EJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4Guzq
# N5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgR
# MiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQ
# zTGCGYwwghmIAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIG4l+u5VS3a0gzzTxG4D99Obhuyej+Qjex7FNi7HNEe+
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAbFr8FGYSnV8S
# CzLLA0Dd9BW+Q4+tKgX/ExOkxfDrxW/C7w9MgMMvniCh6hjjfTpq+1Y9yHPO/gO5
# NFeuVwafAsEl9LLPcSy8RkNuoVFztA3hcRybByXZkAYXwQlIIXGnkrMGCUkxyRIL
# BMpYZaQg3rR9r0RsPwvDgouYKOar2F4A5+7gMCYYAO4ODQdl4hf2r9vaVCzWW9rG
# aX4Q/71f7yJlUtKaA9jlf5tyah5wC7zl1FNy3fGOgx5ecU3i3LijtS433JjOhGLp
# rnG8wEleVIx61KBZarm5bYwSAYLoD1f8uXr3eEWzADHQeN316/cdt1QIDyCVq0g9
# rmfi0kcpd6GCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDiRb6KjEF3
# IvtrdgQtlSljJhOzXUQ0MuTP0ysDa0kEIAIGYxIQ/ZfXGBMyMDIyMDkyMDA5NTcx
# NS4zMTVaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIw
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
# ggT8oAMCAQICEzMAAAGOWdtGAKgQlMwAAQAAAY4wDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMDI4MTkyNzQ1WhcNMjMw
# MTI2MTkyNzQ1WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAKojAqujjMy2ucK7XH+wX/X9Vl1vZKamzgc4Dyb2hi62
# Ru7cIMKk0Vn9RZI6SSgThuUDyEcu2uiBVQMtFvrQWhV+CJ+A2wX9rRrm8mPfoUVP
# oUXsDyR+QmDr6T4e+xXxjOt/jpcEV6eWBEerQtFkSp95q8lqbeAsAA7hr9Cw9kI5
# 4YYLUVYnbIg55/fmi4zLjWqVIbLRqgq+yXEGbdGaz1B1v06kycpnlNXqoDaKxG03
# nelEMi2k1QJoVzUFwwoX2udup1u0UOy+LV1/S3NKILogkpD5buXazQOjTPM/lF0D
# gB8VXyEF5ovmN0ldoa9nXMW8vZ5U82L3+GQ6+VqXMLe7U3USCYm1x7F1jCq5js4p
# Yhg06C8d+Gv3LWRODTi55aykFjfWRvjsec0WqytRIUoWoTNLkDYW+gSY6d/nNHjc
# zBSdqi2ag6dv92JeUPuJPjAxy04qT+lQXcXHVX3eJoK1U8d2nzuSjX4DJ4Bhn4Um
# sBq2kVtvBIayzrKZiMYovdhO7453CdrXI4SwowQK1aT4d3GRuYN2VcuYogGqA2rM
# KTYJzBQCuVJ9a3ivjBYT4vYjJ71D8LUwwybeWBA+QwE95gVMaeUB97e0YWcACTS1
# i7aU3hhe7m/NbEimL9mq3WswHvVy0tdLVdqDj63J4hic5V1u1T78akDcXvJQgwNt
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU7EH5M/YE+ODf+RvLzR2snqfmleQwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEANVCvccyHk5SoUmy59G3pEeYGIemwdV0KZbgqggNebJGd+1IpWhScPPhpJQy8
# 5TYUj9pjojs1cgqvJJKap31HNNWWgXs0MYO+6nr49ojMoN/WCX3ogiIcWDhboMHq
# WKzzvDJQf6Lnv1YSIg29XjWE5T0pr96WpbILZK29KKNBdLlpl+BEFRikaNFBDbWX
# rVSMWtCfQ6VHY0Fj3hIfXBDPkYBNuucOVgFW/ljcdIloheIk2wpq1mlRDl/dnTag
# ZvW09VO5xsDeQsoKTQIBGmJ60zMdTeAI8TmwAgzeQ3bxpbvztA3zFlXOqpOoigxQ
# ulqV0EpDJa5VyCPzYaftPp6FOrXxKRyi7e32JvaH+Yv0KJnAsKP3pIjgo2JLad/d
# 6L6AtTtri7Wy5zFZROa2gSwTUmyDWekC8YgONZV51VSyMw4oVC/DFPQjLxuLHW4Z
# NhV/M767D+T3gSMNX2npzGbs9Fd1FwrVOTpMeX5oqFooi2UgotZY2sV/gRMEIopw
# ovrxOfW02CORW7kfLQ7hi4lbvyUqVRV681jD9ip9dbAiwBhI6iWFJjtbUWNvSnex
# 3CI9p4kgdD0Dgo2JZwp8sJw4p6ktQl70bIrI1ZUtUaeE5rpLPqRsYjBsxefM3G/o
# aBSsjjbi92/rYMUwM97BdwVV/bpPTORfjhKHsi8hny3pDQIwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHS
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRN
# aWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRo
# YWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQA9YivqT04R6oKWucbD
# 5omK7llbjKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA5tOg0DAiGA8yMDIyMDkyMDEwMTU0NFoYDzIwMjIwOTIx
# MTAxNTQ0WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDm06DQAgEAMAcCAQACAiNN
# MAcCAQACAhGNMAoCBQDm1PJQAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# WwRJm2irJYppNNKnpZKKxNd+zjyz/dMl8XHndjFU01H2YTfNMorlsua67IOY9mZk
# ZhKvSx5xMNMBYMkrWBbkHnGL/E4qWmqAdPI9VDhCvB/njXaeKsVzaTwrAouFhf53
# R9SfcSZM0s1UO4vobDuvH0EvNdqkrpbyOTwWlpDZeAAxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY5Z20YAqBCUzAABAAAB
# jjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCByiOViRkAnV3O3U3nZxaFW0L0p3wfMLecJu0eg8qFY
# gzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIL0FjyE74oGlLlefn/5VrNwV
# 2cCf5dZn/snpbuZ15sQlMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGOWdtGAKgQlMwAAQAAAY4wIgQgXDascHaFyH6HLf+9fBjqVFCy
# zIEqHrS/4eZLk890MPcwDQYJKoZIhvcNAQELBQAEggIAhWVA/Y+nXHRSUZKu32Op
# QYib88UlosXS8zQ85mwY6vZm1RTfPRrczi300GUHNXqDoPKq6S770XTU5p60Gpwr
# 5FA5KnH9m/JgVzmOpKmhOOGhjYe2/GNYXQE1PIwKcOoHibnGBLS5l6lxcGZhkJXs
# iz2kv6+wZokt1pikRzP/ScVJ0E5z1W/b/A8qiCv9dTAPAzxW8ehU0Xut6qfxlw/5
# K6F5kOxikZIb3PD/DXcwSYmvJWd+BA2JBRVqzk9aYSjiBBxg9JvRTH2t8wjUmrFv
# CeJquolI+ALeLnm8Y6mjm8CKzWY8r3E3XXN21ULStjWCSPoud30mxW9lUi+tNPsR
# kJ+w6b2cMutwi3F/zmUvJLqjSbh9dg+fskvXnmPL9fckrVV/rLoNJ8WtiFURzvt2
# YDMDaFHeCorcGdduK40Q795Er9ti1adljAFEGhv2f24XJm3K4sViDLkxAlydiciv
# wBJqTNGJn81Q62boA918PiNThuxyMB7rPqz7QDl0uHfTL58mHutKMfxmU0xwKnaS
# ybkudYFnRge4Ww2j/xzHp6y0F2MYPEHFZfDjYtvJycKolFiWW2MGNe61X6LEtIPO
# IxBZG5md3iuDlcb3Xk78xpS9ojz1pDTw1zv1teDYYfWNy0+dEyDG1eYcpdSJpmhT
# wUwsTUt2sEUN9Qrl+DmOpK4=
# SIG # End signature block
