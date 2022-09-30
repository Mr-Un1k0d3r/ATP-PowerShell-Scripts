
#region output interface

$Source = @"
                        using System;
                        using System.Text;
                        using System.Diagnostics.Tracing;
                        using Microsoft.PowerShell.Commands;
                        public static class EtwProvider
                              {
                                    public static EventSource log = new EventSource("Microsoft.Windows.Sense.AzureVmMetadata", EventSourceSettings.EtwSelfDescribingEventFormat);
                              }

                        [EventData]
                        public class AzureVmMetadata
                        {
                              public string SubscriptionId { get; set; }

                              public string VmId { get; set; }

                              public string ResourceId { get; set; }

                              public AzureVmMetadata(string subscriptionId, string vmId, string resourceId)
                              {
                                    this.SubscriptionId = subscriptionId;
                                    this.VmId = vmId;
                                    this.ResourceId = resourceId;
                              }
                        }

"@

                                                                                                                                                                                 
#endregion output interface 


#region definitions

# to fire the events
Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings
$etwProvider = [EtwProvider]::log

<#
    This function returns a tupple of (HResult, RegistryValue).
    if the registry value exists it is returned with HResult 0
    if the registry value doesn't exists it is returned as an empty string with HResult -2147024894
    Example of use:  Get-RegistryValue -RegistryLocation "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -RegistryKey "LimitBlankPasswordUse"
#>
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
    if ($registryResult -eq $null)
    {
        $hResult = -2147024894 # Registry not found error code
        $registryValue = $null
    }
    else
    {
        $hResult = 0
        $registryValue = $registryResult.$registryKey
    }

    return $hResult, $registryValue
}

function Is-Azure-Vm(){
      $isAzureAssetTag = Is-Azure-Asset-Tag
      $doesRegistryContainAzureVmId = Does-Registry-Contain-AzureVmId

      if ($isAzureAssetTag -ne  $doesRegistryContainAzureVmId){
            Write-Output "IsAzureAssetTag is: " $isAzureAssetTag "DoesRegistryContainAzureVmId is: " $doesRegistryContainAzureVmId
      }

      return $isAzureAssetTag -AND $doesRegistryContainAzureVmId
}

# BIOS Asset Tag check
# This code uses WMI Query service to check BIOS Asset Tag.
# Azure and Azure Stack VM has predefined Asset Tag for the private use.
# Checking registry is not enough for us since this value can be manipulated, so it's important that we can rely on a BIOS value that is constant.
function Is-Azure-Asset-Tag(){
      $wmiObject = Get-WmiObject -class Win32_SystemEnclosure -namespace "root\CIMV2"
      ($wmiObject.SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3286-77") -OR ($wmiObject.SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3283-84")
}

function Does-Registry-Contain-AzureVmId(){
      $vmIdRegResult = Get-RegistryValue -RegistryLocation "hkey_local_machine\SOFTWARE\Microsoft\Windows Azure" -RegistryKey "VmId"
      return ($vmIdRegResult[0] -eq 0) -AND $vmIdRegResult[1] # If vmIdRegResult[1] is an empty string or null, this will evaluate to false
}


function Collect-Azure-Vm-Metadata() {

      if (Is-Azure-Vm)
      {
            # Collecting Azure instance metadata info. See also: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
            $subscriptionId = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2020-06-01&format=text"
            $resourceId = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/resourceId?api-version=2020-06-01&format=text"
            $vmId = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2020-06-01&format=text"


            # Only if the subscription id is not null we will report the event.
            if (![string]::IsNullOrEmpty($subscriptionId))
            {
                  $collectedAzureVmMetadata = [AzureVmMetadata]::new($subscriptionId, $vmId, $resourceId)
                  $etwProvider.Write("AzureVmMetadata", $collectedAzureVmMetadata)      
            }       
      }
}


Collect-Azure-Vm-Metadata

# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBQTCLwai7SyKiS
# Iz7OOKOZED64V55x3DeJPcC1cswqX6CCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIMx7hYbPnAqpXahQ2oxGAT0IbNCQ+UnNFeDJ7xjuZTqQ
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAp5tZBGByQaMj
# J3F+wE4rK7WrndtEdwDeDgCplCmzcGDKM2yB98NofPQySsVzKb4vda0ozBpFwa34
# SDGleW9xyi5rjSpY4j5XVg4mJyfHoEMHOj4B9xEDU/L6QqbfnX36pBw2S5r4QT51
# VgS3Eg2qspOv/Cn6eVgfRfq5q9ad6m4gWZNrsRBhrUROkUP64dyrP6QSTovE1Ryh
# Jt/3gUbgUDo/JJGqv/byZc//kfHhvRwPWYE/4Ce1eNgC33ZDVD3rwmUq59V0J3Ex
# d/KxHNibD8FrCKnLtsxdSCC87VML77Iyp2hCe0eyWp7JmppvFgqshRdomDLCHsWW
# 0/eDawiiMqGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBWTtdMXCFs
# iWyWkxQ/H6DQidrhmShCbD18fY7FQuvNVQIGYxFhFs8TGBMyMDIyMDkyMDA5NTcy
# MC45MjJaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAx
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
# ggT8oAMCAQICEzMAAAGGeOUZifgkS8wAAQAAAYYwDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMDI4MTkyNzM5WhcNMjMw
# MTI2MTkyNzM5WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAMCNxtlqb+geCIwH64HyaZ3Tzj2DtWHfPr5X6CMTFt4H
# Qg0/syG2n4NeKTrtLdHpFEMetKez2nR+Do56jSBNaupXR/Z7Y9YCHZeB6uK3RB02
# eiRXRNuA0m1aKqkfkeCMOMNxj233NkN5H8shco/gzoZglsPxWYk1U5U+G3Xo8gFu
# q/yZ+H698S4274SE2ra9+lcss4ENGOFq+9x94FHC42LtKoh7rQw2+vqfsgwRpihc
# 5zlvMFbew/rtlRCaBOiZStBKVS2brHUs4XnLlMCV8W9rsoAGV5bGv3x5cFvWJ5Qa
# jByfopvR7iuV+MfP+QeXZLiKF+ZVhoxTGw9gOi7vz5lAeIStAheRtWGlLQazBO9w
# wCpMqZO0hJtwZSV8GPxq1aF1mFBhB8n65C5MLNEaBDKaCBIHm2TSqo0cp0SYEeHz
# wiqxIcBIk0wHOA1xnIuBxzpuuBENYP0gxzBaiClUsaFG5Bm3SjSh4ZmobiKwMuMH
# vbO62SbJL3mWGYg5rQLQbf4EKI8W2dbzvQtdUrYZK5pJEzC0H/XA85VRAXruiph1
# 9ks3uoIJ3tyOHMv+SFC5x2d6zOGaSXNLNiqRix2laxEMuMf5gJ+MmmH4Hh9zBAFp
# FY8v6kw4enAwhf4Ms902kA7bxZwCu9C6rWxLwT3QaXghv4ZPZdJWmM8IsshmPx6j
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUGbajRQPvZnRLv4d91IRzDesIXC4wHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAw+5noSWN30xyguIY/sAVgfOeOLmiYjDCB54SvTjUzO1a2k2M8dFP03CyeoMc
# NbUczObrvJLMCTZRzae0XnbAIsL4lUGVfQC/CG2USyU8DXoQsJPgVXGNoId2RmZs
# fLmrT2a0bnsoYU0w9j7xVS638IdpYgxv3RDzSB0yo+/Q5RHDyFqDglKe6dDkTMEP
# eZFWom6V/Pab44T5dhZtAgTt6V1yYNG8naUOXQw07/6m9PlmBf7zVRFPzKDBEKpV
# FlrlxAk6sek2sibiyerlOyuUMk5EP5duCIRow83+QBGTqyDWM5FlcjX1DqSMZyrF
# kwTdoo6Wf07p+aq5qPbzSA09JaG4J7pWntezWhDvaIhCSR9bUN+d3YbkYvgNND0e
# /NYmJcxeSVNQ6xHxMjcfAloBEYvdCyrGIIWQQg40Nw4iY31GS6jjXh6yX3Joc+f2
# 35vPmgGlD6WRXj9INCKJ3elzZOGImG1jxaKH3NC8HKkgC7biAMs+n93flGmWbKeN
# VOIQiKBo+oaAyLlPN/W6P5mfwIBEsBsSF7NIGVOgPtqiFHutEHQPevcFks7nCjor
# J4PRwkmSxdXanN0FGsK9AtFONe/OCqPb3JABt2pMGLlRnLOoTP0qhIaHvYx8HuF6
# fNQq0wdZffhCHbpAmz9JMs8dFmc7Xnogzea3YokEfZgSbpYwggdxMIIFWaADAgEC
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
# YWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQABrtg0c1pCpY5l8kl9
# ZKKxy+HzJ6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA5tOZkDAiGA8yMDIyMDkyMDA5NDQ0OFoYDzIwMjIwOTIx
# MDk0NDQ4WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDm05mQAgEAMAcCAQACAiMx
# MAcCAQACAhGEMAoCBQDm1OsQAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# ZtBFPjWF5w2QG/FbEIX4RTCiAsaIWlIvJJONEbVi6Vw1sLmFmDlvb+oYOG+70b9d
# nFyna0aJ1xiq/N09HrEkeup5IdcPwegCaRfmgWiGIPnXjJPFAAmllAOBqDzEaVui
# 5EJt/ZSwGglYCI8ngmP5ZS5DoVR414yPbfbgC9PGf/cxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYZ45RmJ+CRLzAABAAAB
# hjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCDf0gbR5YYiNUxBqmeC8qFr/SeWGc9JVTluh5LB6lte
# kDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIBqZiOCyLAhUxomMn0QEe5ux
# WtoLsVTSMNe5nAIqvEJ+MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGGeOUZifgkS8wAAQAAAYYwIgQgKrQqo9OIk0hrsMyW2GCtrT+q
# XNtdZTAEA781WGfDPCAwDQYJKoZIhvcNAQELBQAEggIAZPVIfcijN1F+ufmO2Aoa
# NCDZPPYnc2vpPtH3HjLeEHhCjGyHpGn+4GogLqajuSDz/1COTEcWv4JYOtRs7pwU
# DYhU9opg9xzuKmIKGx0Jw7nkxuI80Zny3n2DP+h2vdgE5Lb5JlFENm+sw2BByhhu
# 9YkHtQRDE7kvAyx3n1za47frFqe1va5qycC/k8ezFwbzzFRIE2okB4HmLBl6iAq5
# N7Tt6PgsIf8Jas2OJL3t+aHOo27K4a0trnTrAv2WMipx91Iv6V6h+VySWekvXcZc
# TKJ14cggLp/33ptCQl1WO1jf1kkticckQsciTj5JpscSzoNOIN7B/BnxPV9XmGFD
# 9+bjyWfyyPd2NP1ZPZQJNShlUPFZ/SJFde0/+xJP0Bi42lcWdyWSyD3aNInMne2Q
# l2HtzvcEUiwt+1cKH5w4qYpu4xD4SGwhBqmzBxgp2Z/BlBe3JxvCsvUOI0lNjhTk
# r/yU6M3yE2YL2kg1gw9ykAdoPzVZBIHUQjS8HPMR7Eg5oKwkp+rg/9MzPKlFD5eH
# XCSM/AQCIkHYmnq9A2/CbXqEF2Ue1Tef2VG+ZC2/K8pKQprXzkmGywDNVyGTLENh
# XLf7Z792ucpZO2y88F2cZPkt0o0AnJyZ4RtEu9g5x2BheitU//KUGdsFV11pERIM
# jUcJPy2E6a1lRCN/WycTr3Q=
# SIG # End signature block
