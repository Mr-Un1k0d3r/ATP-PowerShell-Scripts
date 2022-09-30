
<# 
{
"Data":{
    "IsPII":true,
    "ScrubMethod":3,
    "ScrubType":21,
    "PropertyType":1,
    "PropertyValue":"[
        {\"HResult\":0,\"Key\":\"Cve2022_30190_Mitigated",\"Value\":\"true\"},
        {\"HResult\":0,\"Key\":\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\DeferFeatureUpdates",\"Value\":\"0\"},
    ]
 }
#>
$Source = @"
                        using System;
                        using System.Text;
                        using System.Diagnostics.Tracing;
                        using Microsoft.PowerShell.Commands;
                        
                        public static class TvmInfoGatheringCollectorProvider
                        {
                            public static EventSource log = new EventSource("Microsoft.Windows.Sense.TvmInfoGatheringCollectorEtw", EventSourceSettings.EtwSelfDescribingEventFormat);
                        }

                        [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
                        public class CollectedInfoGathringValue
                        {
							    public int HResult { get; set; }
                                public String Key { get; set; }
                                public String Value { get; set; }

                                public CollectedInfoGathringValue(int hResult, string key, string value)
                                {
									this.HResult = hResult;
                                    this.Key = key;
                                    this.Value = value;
                                }
                        }        
                        
                        [EventData] 
                        public class CollectedInfoGathringValues
                        {
							    public String Data { get; set; }

                                public CollectedInfoGathringValues(string data)
                                {
							        this.Data = data;
                                }
                        }     
"@

Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings


<#
    This function runs the given $PowershellFunction and return a CollectedInfoGathringValue object of (hResult, Key, valueToReport).
#>
Function Create-CollectedInfoGathringValueObject
{ 
    Param(
        [Parameter()]
        [System.Object[]]
        $CollectedDataResult,

        [Parameter()]
        [String]
        $Key
    )

    New-Object CollectedInfoGathringValue($CollectedDataResult[0], $Key, $CollectedDataResult[1])
}

$CollectedInfoGathringValues = @()


#------------------------------------------------------------------------------------------------------------------------------------------------
# Get CVE_2022_30190_mitigation_status
$hkcrDrive = Get-PSDrive -PSProvider registry | where {$_.root -eq 'HKEY_CLASSES_ROOT'} | select name, root

if($hkcrDrive -eq $null)
{
    New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
    Set-Location HKCR:
}
else
{
    Set-Location "$($hkcrDrive.Name):"
}

$regKey = Get-ItemProperty .\ms-msdt -Name '(default)' -ErrorAction SilentlyContinue
$cve2022_30190_mitigated = If ($regKey -eq $null) { "Mitigated" } Else { "NotMitigated" }

$CollectedInfoGathringValues +=  Create-CollectedInfoGathringValueObject -Key "CVE_2022_30190_mitigation_status" -CollectedDataResult (0, $cve2022_30190_mitigated) 
#------------------------------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------------------------------------
# Get CVE_2013_3900_mitigation_status
$cve_2013_3900_regKey32bit = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
$cve_2013_3900_regKey64bit = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
$cve_2013_3900_32bitMitigated = ($regKey32bit.EnableCertPaddingCheck -eq 1)
$cve_2013_3900_64bitMitigated = ![Environment]::Is64BitOperatingSystem -or ($regKey64bit.EnableCertPaddingCheck -eq 1)

$cve_2013_3900_mitigated = If ($cve_2013_3900_32bitMitigated -and $cve_2013_3900_64bitMitigated) { "Mitigated" } Else { "NotMitigated" }

$CollectedInfoGathringValues +=  Create-CollectedInfoGathringValueObject -Key "CVE_2013_3900_mitigation_status" -CollectedDataResult (0, $cve_2013_3900_mitigated) 
#------------------------------------------------------------------------------------------------------------------------------------------------

##########################################################################################################################################
# Process generated data and send to ETW
##########################################################################################################################################
$CollectedInfoGathringValuesProvider = [TvmInfoGatheringCollectorProvider]::log

# Prepare the CollectedInfoGathringValues object to send to ETW
$CollectedInfoGathringValuesAsJson = ConvertTo-Json -InputObject $CollectedInfoGathringValues -Compress
$CollectedInfoGathringValuesObject = New-Object CollectedInfoGathringValues($CollectedInfoGathringValuesAsJson)

# Send data to ETW
$CollectedInfoGathringValuesProvider.Write("CollectedInfoGathringValues", $CollectedInfoGathringValuesObject)  

# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWus1vVRepoN//
# gVAD9il3wAlpdczDX8+0iEZcH0Wpy6CCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIAQ5XtSDlZ89zPvf6DNsT7esjVBXojYcg3zujTNrbvky
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEACULxpRDZj/Zj
# BWALlz6DNyJUCQFzRE18sfGk6CL151akSB6BF6eebnyQDBGwgBcBT1p/Dtj2N8on
# Zprya6z+dbpE0qbq4H6Mb70TpcJJ6fWb8tzIzjzvjCLG/r/pXikvsFVtMyBxVKKH
# h4eHZUtDILzgY/0Fr5zummsxKgW4KQkLNqdAcjf+h0Ep2IPL2Ql/w8iDRNUlcyEn
# Ij+NRj2amtBZAmOIrwTTMfw5drN9Da2OG5Nm7VYgoMp2kgj0d8WeX2t/7XsyrQaL
# g8GDqbsoVglMmy7A7ReNRtmL/SbaMbI7zb/rFK5Dl0nXGvLGaKjJwrytfCqlUtoL
# ovoZ21AgKaGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBQ3pRTmEbs
# uzHN5uO3mLXssvCMtAjV4S+j8OnbGuEOSwIGYxIL5SmoGBMyMDIyMDkyMDA5NTcx
# NS45NTZaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjE3OUUtNEJCMC04MjQ2
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
# ggT8oAMCAQICEzMAAAGKPjiN0g4C+ugAAQAAAYowDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMDI4MTkyNzQyWhcNMjMw
# MTI2MTkyNzQyWjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxNzlFLTRCQjAtODI0NjElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALf/rrehgwMgGb3oAYWoFndBqKk/JRRzHqaFjTizzxBK
# C7smuF95/iteBb5WcBZisKmqegfuhJCE0o5HnE0gekEQOJIr3ScnZS7yq4PLnbQb
# uuyyso0KsEcw0E0YRAsaVN9LXQRPwHsj/eZO6p3YSLvzqU+EBshiVIjA5ZmQIgz2
# ORSZIrVIBr8DAR8KICc/BVRARZ1YgFEUyeJAQ4lOqaW7+DyPe/r0IabKQyvvN4Gs
# mokQt4DUxst4jonuj7JdN3L2CIhXACUT+DtEZHhZb/0kKKJs9ybbDHfaKEv1ztL0
# jfYdg1SjjTI2hToJzeUZOYgqsJp+qrJnvoWqEf06wgUtM1417Fk4JJY1Abbde1AW
# 1vES/vSzcN3IzyfBGEYJTDVwmCzOhswg1xLxPU//7AL/pNXPOLZqImQ2QagYK/0r
# y/oFbDs9xKA2UNuqk2tWxJ/56cTJl3LaGUnvEkQ6oCtCVFoYyl4J8mjgAxAfhbXy
# Ivo3XFCW6T7QC+JFr1UkSoqVb/DBLmES3sVxAxAYvleLXygKWYROIGtKfkAomsBy
# wWTaI91EDczOUFZhmotzJ0BW2ZIam1A8qaPb2lhHlXjt+SX3S1o8EYLzF91SmS+e
# 3e45kY4lZZbl42RS8fq4SS+yWFabTj7RdTALTGJaejroJzqRvuFuDBh6o+2GHz9F
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUI9pD2P1sGdSXrqdJR4Q+MZBpJAMwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAxfTBErD1w3kbXxaNX+e+Yj3xfQEVm3rrjXzOfNyH08X82X9nb/5ntwzYvynD
# TRJ0dUym2bRuy7INHMv6SiBEDiRtn2GlsCCCmMLsgySNkOJFYuZs21f9Aufr0ELE
# HAr37DPCuV9n34nyYu7anhtK+fAo4MHu8QWL4Lj5o1DccE1rxI2SD36Y1VKGjwpe
# qqrNHhVG+23C4c0xBGAZwI/DBDYYj+SCXeD6eZRah07aXnOu2BZhrjv7iAP04zwX
# 3LTOZFCPrs38of8iHbQzbZCM/nv8Zl0hYYkBEdLgY0aG0GVenPtEzbb0TS2slOLu
# xHpHezmg180EdEblhmkosLTel3Pz6DT9K3sxujr3MqMNajKFJFBEO6qg9EKvEBcC
# tAygnWUibcgSjAaY1GApzVGW2L001puA1yuUWIH9t21QSVuF6OcOPdBx6OE41jas
# 9ez6j8jAk5zPB3AKk5z3jBNHT2L23cMwzIG7psnWyWqv9OhSJpCeyl7PY8ag4hNj
# 03mJ2o/Np+kP/z6mx7scSZsEDuH83ToFagBJBtVw5qaVSlv6ycQTdyMcla+kD/XI
# WNjGFWtG2wAiNnb1PkdkCZROQI6DCsuvFiNaZhU9ySga62nKcuh1Ixq7Vfv9VOdm
# 66xJQpVcuRW/PlGVmS6fNnLgs7STDEqlvpD+c8lQUryzPuAwggdxMIIFWaADAgEC
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
# YWxlcyBUU1MgRVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCA8PNjrxtTBQQdp/+M
# Hlaqc1fEoaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA5tOcFjAiGA8yMDIyMDkyMDA5NTUzNFoYDzIwMjIwOTIx
# MDk1NTM0WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDm05wWAgEAMAcCAQACAgwz
# MAcCAQACAhFvMAoCBQDm1O2WAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# SSUhKlNYx9NXrRl/F1et/pmzUZeMRM3UdHORn49KVzbT167eXanUo2/9LLq61CkY
# kD2SBd8VOj7FFK3RJ53lxA/PayuvJJk9lUIE3iIE3p3qnOP044Iz3yXUhrDWk2zj
# HE5A9+e4NXcBz+JSiBh7lOYJRBKGTtEhXMtToT6KKqExggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYo+OI3SDgL66AABAAAB
# ijANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCB6RdJi2Pp/S7yGvDi5aVEFSEIPxeGtXl8zMMIaXvc1
# szCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPS94Kt130q+fvO/fzD4MbWQ
# hQaE7RHkOH6AkjlNVCm9MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGKPjiN0g4C+ugAAQAAAYowIgQg4YlKllUPl/ArUXMivWPr6uDa
# 9vaozehuIIRSeDWPQDgwDQYJKoZIhvcNAQELBQAEggIAEX3IrXgORt1h8u57RHAf
# d1qhdbyxPmE1rF1vTbZ/0gAUo5DgQwyVEwk2Ih5ASASBmjtZYpQdlP0fnL/1AUL8
# z8YcIUhyO+M4iN0tVS7tozH6L//sXCOMRHjHHQfU1hG521JkfjMBmFLijhlX8lYW
# cmYLTZrTW+rdcAHSRPoySUmMjE6BRpkeWjnAFIRoWDShG16TeSVJyhqXHwO+iUFk
# atjvTCQSISfzY5CNVfSgR6Jtco7lQnBXzR1BAcrE5JO5bQNr4CTMlPwwmJhupzi9
# qWJksqpupdWnZ4p8RKCgxgumOk4suiT33UXbs95ej8fBy3kfafsYMd9qTAhQsPS+
# aJvxfTayfR+VMVNvVZcCz831FJwYevrWYMmrUFlJxARTv73wMXIm1IKbCoDY62Ne
# 0VXlWQmVYQiPmV82qzeKKJVPPzIbpJ7BGBC2fypJcDJssg5tBaPs00+CnNfxj0lr
# nSUtcF+vdoaLFJoXJYkJoaZIgVCmlorTN1o8CDpJwnBp+idMzpFBxYaEoqiUXtw/
# YtZenCc+B3sdEUu8uU5rYfkO0m9gd+ti7GVEi+awmMMfIXMaCqvL08XWv7O72RxC
# AtD9JD0QjY8ujRvxLzecXd5i78r3XxDkNVrsMi+EM7B+HH848cVKVqLwL+G3OGwL
# enlBryT4kFlTbnMJwHtQ9v0=
# SIG # End signature block
