# because of different permissiosn between the service and this script, this script shouldn't create any files inside the downloading folder of the Service
# if needed, it can create files under "stable"

function Get-Proxy-Address {
    # Get proxy configuration
    try {
        # Group policy proxy
        $group_policy_proxy = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' | Select-Object TelemetryProxyServer
        if(![string]::IsNullOrWhitespace($group_policy_proxy.TelemetryProxyServer)){
            return $group_policy_proxy.TelemetryProxyServer
        }

        # Netsh proxy
        $MethodDefinition = @'
        using System.Runtime.InteropServices;
        public enum AccessType
        {
            DefaultProxy = 0,
            NamedProxy = 3,
            NoProxy = 1
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WINHTTP_PROXY_INFO
        {
            public AccessType AccessType;
            public string Proxy;
            public string Bypass;
        }
        public class WinHttp
        {
            [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool WinHttpGetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO config);
        }
'@
        if (-not ([System.Management.Automation.PSTypeName]'AccessType').Type) {
            $asm = Add-Type -TypeDefinition $MethodDefinition -PassThru
        }
        $proxy_info = New-Object WINHTTP_PROXY_INFO
        $proxy_info.AccessType = [AccessType]::DefaultProxy
        $ret = [WinHttp]::WinHttpGetDefaultProxyConfiguration([ref]$proxy_info)
        if (![string]::IsNullOrWhitespace($proxy_info.Proxy)) {
            return $proxy_info.Proxy
        }
    }
    catch {
        Write-Host "Error occurred when try to get proxy settings"
    }
}


function Download-Stable-Version($stable_version_url, $script_update_folder) {
    $web_client = New-Object System.Net.WebClient
    $proxy_address = Get-Proxy-Address
    if (![string]::IsNullOrWhitespace($proxy_address)) {
        $web_proxy = New-Object System.Net.WebProxy($proxy_address, $true)
        $web_client.Proxy = $web_proxy
    }
    $web_client.OpenRead($stable_version_url) | Out-Null
    #There is a download, using different folders to fix permissions issues
    $msi_folder = $script_update_folder
    $msi_file = $msi_folder + '\MdatpNetworkScanAgent.msi'
    Remove-Item $msi_folder -Recurse -ErrorAction Ignore
    New-Item $msi_folder -ItemType Directory | Out-Null
    $web_client.DownloadFile($stable_version_url, $msi_file)
    Write-Host "Stable version downloaded"
    return $msi_file
}

function Write-ETW-Log($message)
{
    try {
        $EtwProvider = [NetworkScannerEventSource]::new()
        $etw = New-Object "NetworkScanAgentTrace" -Property @{
            Level = "Info"
            Message = $message
        }
        $EtwProvider.Write("NetworkScanAgentTrace", $etw)
    }
    catch {}
}

$exe_file = "$env:Programfiles\MDATP Network Scan Agent\MdatpNetworkScanAgent.exe";

if (!(Test-Path $exe_file))
{
    Write-Host "Petra agent doesn't exist, nothing to update, exiting."
    Exit 0;
}

# Add ETW logger
try {
    $EtwWriter = @"
    using System;
    using System.Text;
    using System.Diagnostics.Tracing;
    using Microsoft.PowerShell.Commands;

    [EventSource(Name = "Microsoft.Windows.Sense.Tvm.NetworkScanner")]
    public sealed class NetworkScannerEventSource : EventSource
    {
        public NetworkScannerEventSource() : base(EventSourceSettings.EtwSelfDescribingEventFormat) { }
    }

    [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
    public class NetworkScanAgentTrace
    {
        public String Level { get; set; }
        public String Message { get; set; }
    }
"@

    Add-Type -TypeDefinition $EtwWriter -Language CSharp -IgnoreWarnings
}
catch {
    Write-Host "Error occurred when try to config ETW logger"
}

Write-Host "================================================"
Write-Host "Start Update MDATP network scan agent"
Write-ETW-Log -message "PowerShell (DDC): Start Update MDATP network scan agent"

$msi_folder = $env:ProgramData + '\Microsoft Defender for Endpoint network scanner'
$script_update_folder = $env:ProgramData + '\Microsoft Defender for Endpoint network scanner update'
$msi_file = $msi_folder + '\MdatpNetworkScanAgent.msi'

try {
    #Determine environment
    $sense_reg_key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
    $sense_geo_location_url = (Get-ItemProperty -Path $sense_reg_key -Name "onBoardedInfo")."onBoardedInfo" | ConvertFrom-Json | % {$_.body} | ConvertFrom-Json | % {$_.geoLocationUrl}

    if($sense_geo_location_url.contains("-stg")) {
        $stable_version_url = "https://tvmnetscanstablestgeus.blob.core.windows.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
    } 
    elseif($sense_geo_location_url.contains("-can")) {
        $stable_version_url = "https://tvmnetscanstableprdcane.blob.core.windows.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
    } 
    elseif($sense_geo_location_url.contains("-usg")) {
        $stable_version_url = "https://tvmnetscanstableffusgv.blob.core.usgovcloudapi.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
    } 
    elseif($sense_geo_location_url.contains("-usm")) {
        $stable_version_url = "https://tvmnetscanstablefmusmv.blob.core.usgovcloudapi.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
    } 
    else {
        $stable_version_url = "https://tvmnetscanstableprdeus.blob.core.windows.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
    }
}
catch {
    Write-ETW-Log -message "PowerShell (DDC): Error occurred when try to determine stable version url"
    # We fallback to prod url
    $stable_version_url = "https://tvmnetscanstableprdeus.blob.core.windows.net/networkscannerstable/MdatpScanAgentSetupStable.msi"
}

# Check if stable version msi exist
try {
    $msi_file = Download-Stable-Version -stable_version_url $stable_version_url -script_update_folder $script_update_folder
}
catch [System.Net.WebException] {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $msi_file = Download-Stable-Version -stable_version_url $stable_version_url -script_update_folder $script_update_folder
    }
    catch {
        Write-ETW-Log -message "PowerShell (DDC): No stable version exist"
    }
}

#Validate msi
if(![System.IO.File]::Exists($msi_file))
{
    Write-ETW-Log -message "PowerShell (DDC): No msi in the folder, exit code 1"
    Exit 1
}
$fileHandler = [System.IO.File]::Open($msi_file, "Open", "Read", "Read")

$msi_signature = Get-AuthenticodeSignature -FilePath $msi_file

#Check if the digital signature is valid
if ($msi_signature.Status -ne "valid")
{
    Write-ETW-Log -message "PowerShell (DDC): Msi signature not valid, exit code 2"
    Exit 2
}

$dnDict = ($msi_signature.SignerCertificate.Subject -split ', ') |
            foreach `
                { $dnDict = @{} } `
                { $item = $_.Split('='); $dnDict[$item[0]] = $item[1] } `
                { $dnDict }

#Check if the msi signed by Microsoft
if($dnDict['CN'] -ne "Microsoft Corporation")
{
    Write-ETW-Log -message "PowerShell (DDC): Msi signature not signned by Microsoft, exit code 3"
    Exit 3
}

#Stoping MDATP network scan agent
Stop-Service -DisplayName "MDATP network scan agent" -Force
Write-ETW-Log -message "PowerShell (DDC): Service stopped for update"
Start-Sleep -s 10

#Install new version
msiexec /i $msi_file /qn
Write-ETW-Log -message "PowerShell (DDC): New version installed"
Start-Sleep -s 15

#Starting MDATP network scan agent
Start-Service -DisplayName "MDATP network scan agent"
Write-ETW-Log -message "PowerShell (DDC): Service started after update"

#close file handler
$fileHandler.close()

#Remove temp files
Remove-Item -LiteralPath $msi_file -Force

Write-ETW-Log -message "PowerShell (DDC): Finish Update MDATP network scan agent "
Write-Host "Finish Update MDATP network scan agent"
Write-Host "================================================"
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCj22yFFGiVqaFw
# a9farN33xomZVrTmf6RyB3FuuoUfYKCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEICEZ4qNzl0D3gMnkwLybAaDFHFu/4jVNBaJztRIequqj
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAB0FZWrKgtsHB
# FjbAGLI/MS28M1b96qjS3i7dT37svGIrMeVr8FePOVQMMKNhLiUAQaOMdGv0aPA3
# c1B1qRUZ24l4arD50q3DX83Is5iF1O1U+w/gp0XRmB/dg06gEz8v17MI3rgrf5j7
# kAOYH3TnuXXYU92McYC09gw/z1y1ikpfM4ZG5Xf9O/GmfL7ttqgvP/W8tsf8hTfq
# NRKHQgojjlF8aBxHUST58NwkMPbR+EpfuwhfDvWJ6CHSroKe/dXQlkt9BrbOnxri
# L8NHlLdmw8gDoxHZPKke/AqZKsz/xwI5vz9lNdVs6isFEHN5RjEg84k9P8hHN+5F
# /FUjggyD+6GCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCdHR1ffV2S
# Qljjp4TYvgla4TlZyRNlAASDazxI2p80egIGYxIQ/ZhUGBMyMDIyMDkyMDA5NTcx
# Ni45MzVaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
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
# MC8GCSqGSIb3DQEJBDEiBCA9fALrvKV9wjsMKM2Sd0ThUau/2GQNDitPpi4TH0oK
# bjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIL0FjyE74oGlLlefn/5VrNwV
# 2cCf5dZn/snpbuZ15sQlMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGOWdtGAKgQlMwAAQAAAY4wIgQgXDascHaFyH6HLf+9fBjqVFCy
# zIEqHrS/4eZLk890MPcwDQYJKoZIhvcNAQELBQAEggIAKB3mjojt3d1VpHO47NGj
# j15H7ILOQp9Toq1pjGuSpTVJt769ZaeeU7CtCDW4GkMxORk0+fNdrtf3/eNxUT8R
# Xko1ykukenbprVgQn7ZBthkzuWMjgckqOEG067BHCdfFQXpnzIHc7CSguTPE+6p1
# /g2by1ZuoME0q/EG2Qxvr1NW/eZD8UFoDd2Sdj0/I9pVv9tacW6aO+L7dltsz8HP
# 513ESKEe6QLy1OuiPE8gFnkkvbcTImM5O4rEu3C5yFfxDBQiBgBW8H2ofbaN0l7v
# wYAAv5F6PCBOPof3lJZUPLSsZ6HMwy9LVqT3R8C9GGFPf6kQbwrItFXhCahzrVxD
# kNockM7EeLq6xkTSTcFb6Y2dtyHEBsBT/TCOuUBv2nMeTPjuclsDDx9w0kS+rRW4
# UJs7+FXEJCqothfijnGS7oqkyrjoSqICx3JquyZ+5aWOILUyVVqZ4Q9Ecn3IKg3f
# ivKXjwU9Shz+aCZklR0+2yzUfEapZAHH1ZMrFfoybFrXPNebdx8Mw0NPuKMBXArU
# 4+SnwafDPNXlWhY13VwKmDFERXiNx4hZEJdzr95kTu5uxWbMdBJEqILQytlBeNip
# 8sMm4Pm75MR2UvFOd2x5ysQUeBMg1uM+9EIKzRPdly33kBHpAJZia3fU0TBJ2Xe+
# wIUUEfsfBNTEyjLkmHefKE0=
# SIG # End signature block
