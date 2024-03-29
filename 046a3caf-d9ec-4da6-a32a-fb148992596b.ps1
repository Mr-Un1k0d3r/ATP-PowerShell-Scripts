﻿function Get-MacFromIp
{
    param(
    [Parameter(Mandatory=$true)]
    [string]$RemoteIP
    )
    
    $arpTable = Get-NetNeighbor -IPAddress $RemoteIP -State Stale,Reachable -ErrorAction SilentlyContinue | Select-Object -First 1
    if($arpTable -ne $null -and $arpTable -ne "00-00-00-00-00-00")
    {
        return $arpTable.LinkLayerAddress
    }

    return $null
}

function Get-DefaultGatewayIpAddress
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalIp
    )

    $DefaultGatewayIp = $null
    try
    {
        $DefaultGatewayIps = (Get-wmiObject Win32_networkAdapterConfiguration -ErrorAction Stop | ?{$_.IPAddress -contains $LocalIp}  | Select-Object -ExpandProperty DefaultIPGateway)
        if($DefaultGatewayIps.count -gt 0)
        {
           return $DefaultGatewayIps
        }            
    }
    catch
    { }

    try
    {
        $Index = Get-NetIPAddress -IPAddress $LocalIp -AddressFamily IPv4 | Select-Object -ExpandProperty InterfaceIndex
        $DefaultGatewayIps = Get-NetRoute -InterfaceIndex $Index | where {$_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq "::/0"} | Select-Object -ExpandProperty NextHop
        return $DefaultGatewayIps
    }
    catch
    { }

    return $null
}


function Get-StaticRoutes
{
    param(
    [Parameter(Mandatory=$true)]
    [string]$Index
    )

    try
    {
        $StaticRoutes = Get-NetRoute -InterfaceIndex $Index | Where-Object -FilterScript { $_.DestinationPrefix -Ne "0.0.0.0/0" } | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | Select-Object -ExpandProperty NextHop | Get-Unique
        return $StaticRoutes
    }
    catch
    { }

    return $null  
}

function WriteEtw
{
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Ip,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$NetworkName,
        [Parameter(Mandatory=$true)]
        [byte]$IsStaticRoute,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$NetworkAdapterId
        )
    
    try
    {
        if([string]::IsNullOrEmpty($Ip))
        {
            Write-Host "Cannot get Ip address"
            return $null 
        }

        if([string]::IsNullOrEmpty($NetworkName))
        {
            Write-Host "Cannot get NetworkName"
            return $null 
        }

        $Mac = Get-MacFromIp $Ip
        if([string]::IsNullOrEmpty($Mac))
        {
            Write-Host "Cannot get Mac address from Ip"
            return $null 
        }
    
        $etw = New-Object "NdrCollectorDefaultGatewayDiscoveryEvent" -Property @{
            Ip = $Ip
            Mac = $Mac
            NetworkName = $NetworkName 
            IsStaticRoute = $IsStaticRoute
            NetworkAdapterId = $NetworkAdapterId
            AdapterDefaultGatewaysMac = $Mac
        }

        $global:EtwProvider.Write("NdrCollectorDefaultGatewayDiscoveryEvent", $etw)
    }

    catch
    {
        Write-Host $_.Exception.ToString()
    }
}

[System.Diagnostics.Tracing.EventSource(Name = "Microsoft.Windows.NdrCollector", Guid = "ac39453b-eb9e-463f-b8ff-9c1a08b5931b")]
class NdrEventSource : System.Diagnostics.Tracing.EventSource
{
     NdrEventSource() : base([System.Diagnostics.Tracing.EventSourceSettings]::EtwSelfDescribingEventFormat -bOr [System.Diagnostics.Tracing.EventSourceSettings]::ThrowOnEventWriteErrors) { }
}

[System.Diagnostics.Tracing.EventData()]
class NdrCollectorDefaultGatewayDiscoveryEvent
{
    [string]$Ip
    [string]$Mac
    [string]$NetworkName
    [byte]$IsStaticRoute
    [string]$NetworkAdapterId
    [string]$AdapterDefaultGatewaysMac
}

$global:EtwProvider =  [NdrEventSource]::new()

try
{
    $Interfaces = Get-NetConnectionProfile

    foreach($Interface in $Interfaces)
    {
        $NetworkName = $Interface.Name
        $InterfaceIndex =  $Interface.InterfaceIndex
        $NetworkAdapterId = $Interface.InstanceID
        # Default gateway
        $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1 -ExpandProperty IPAddress
        $DefaultGatewayIps = Get-DefaultGatewayIpAddress -LocalIp $IpAddress
        foreach($DefaultGatewayIp in $DefaultGatewayIps)
        {
            WriteEtw -Ip $DefaultGatewayIp -NetworkName $NetworkName -IsStaticRoute 0 -NetworkAdapterId $NetworkAdapterId
        }

        # Static Routes
        $StaticRoutes = Get-StaticRoutes -Index $InterfaceIndex
        foreach($StaticRoute in $StaticRoutes)
        {
            if ($DefaultGatewayIps  -NotContains $StaticRoute)
            {
                WriteEtw -Ip $StaticRoute -NetworkName $NetworkName -IsStaticRoute 1 -NetworkAdapterId $NetworkAdapterId
            }
        }
    }

}
catch
{
    Write-Host $_.Exception.ToString()
}
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9Bvh4yxbV7Bni
# qEJVtYGqEdr3g2eYwSkdk9/s63aRXqCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIDlkoya8SmNeXSXVRC1HgLs56bLS2PW4O+GS5pV+nFJ3
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAcHuTp8RPjMCU
# fNyIP+DAEk1LD0vORqxw2CoxoWOHzrczaBJMNkyYNSeeWogspwN2/WCi7xtHD0gF
# /kGJgr7QxVllRx2xWaCuN3D8x3Y9843f+2HLPozNrRj4rD+ps4TOpP3MvzdRbT9g
# GNYEX4eE9z6IeA6JQ2b3QiZmNyPhvNdI9dyJlu3P6X4oYhyfLU80zpbRf7HGEVd8
# vLrgU41See3B9Z1E7QKHulys3MJdF7xexNgiFiTXPN0BtMhoGrTrUbeVrcmr8F5e
# bWUH0cGe8XcgnqW8DcqE0a0gwHplP2cLJVglVgJs6iFp2qocfzc0kQI3NT4/8Ki8
# p2woJ5/j8KGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCMUw0A9Stu
# nnWdd8k+cCOEyre94nQ1uAl42Uk1NeUIJQIGYxIJsT6TGBMyMDIyMDkyMDA5NTcx
# OC4wMTVaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
# ggT8oAMCAQICEzMAAAGILs3GgUHhvCoAAQAAAYgwDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMDI4MTkyNzQwWhcNMjMw
# MTI2MTkyNzQwWjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAJrnEAgEJpHFx8g61eEvPFXiYNlxqjSnFqbK2qUShVnI
# YYy7H/zPVzfW4M5yzePAVzwLTpcKHnQdpDeG2XTz9ynUTW2KtbTRVIfFJ5owgq/g
# oy5a4oB3JktEfq7DdoATF5SxGYdlvwjrg/VTi7G9j9ow6eN91eK1AAFFvNjO64PN
# XdznHLTvtV1tYdxLW0LUukBJMOg2CLr31+wMPI1x2Z7DLoD/GQNaLaa6UzVIf80V
# guwicgc8pkCA0gnVoVXw+LIcXvkbOtWsX9u204OR/1f0pDXfYczOjav8tjowyqy7
# bjfYUud+evboUzUHgIQFQ33h6RM5TL7Vzsl+jE5nt45x3Rz4+hi0/QDESKwH/eoT
# 2DojxAbx7a4OjKYiN/pejZW0jrNevxU3pY09frHbFhrRU2b3mvaQKldWge/eWg5J
# merEZuY7XZ1Ws36Fqx3d7w3od+VldPL1uE5TnxHFdvim2oqz8WhZCePrZbCfjH7F
# Tok6/2Zw4GjGh5886IHpSNwKHw1PSE2zJE7U8ayz8oE20XbW6ba5y8wZ9o80eEyX
# 5EKPoc1rmjLuTrTGYildiOTDtJtZirlAIKKvuONi8PAkLo/RAthfJ02yW9jXFA4P
# u+HYCYrPz/AWvzq5cVvk64HOkzxsQjrU+9/VKnrJb1g+qzUOlBDvX+71g5IXdr7b
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUZHm1UMSju867vfqNuxoz5YzJSkowHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAQBBa2/tYCCbL/xii0ts2r5tnpNe+5pOMrugbkulYiLi9HttGDdnXV3olIRHY
# ZNxUbaPxg/d5OUiMjSel/qfLkDDsSNt2DknchMyycIe/n7btCH/Mt8egCdEtXddj
# me37GKpYx1HnHJ3kvQ1qoqR5PLjPJtmWwYUZ1DfDOIqoOK6CRpmSmfRXPGe2RyYD
# Pe4u3yMgPYSR9Ne89uVqwyZcWqQ+XZjMjcs83wFamgcnpgqAZ+FZEQhjSEsdMUZX
# G/d1uhDYSRdTQYzJd3ClRB1uHfGNDWYaXVw7Xi5PR4GycngiNnzfRgawktQdWpPt
# feDxomSi/PoLSuzaKwKADELxZGIKx61gmH41ej6LgtzfgOsDga3JFTh0/T1CAyuQ
# Awh+Ga2kInXkvSw/4pihzNyOImsz5KHB3BRwfcqOXfZTCWfqZwAFoJUEIzFoVKpx
# P5ZQPhKo2ztJQMZZlLVYqFVLMIU96Sug4xUVzPy1McE7bbn89cwYxC5ESGfLgstW
# JDMXwRcBKLP0BSJQ2hUr1J+CIlmQN1S3wBI8udYicCto0iB8PtW4wiPhQR3Ak0R9
# qT9/oeQ5UOQGf3b3HzawEz9cMM9uSK/CoCjmx0QiGB+FSNla5jm6EhxRu/SWx3ZD
# 1Uo3y8U7k7KIeRc6FNbebqxtK8LpaGWRWcU5K8X8k5Ib5owwggdxMIIFWaADAgEC
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
# YWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDhPIrMfCAXlT0sHg/N
# OZeUHXoOQqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA5tOZ3TAiGA8yMDIyMDkyMDA5NDYwNVoYDzIwMjIwOTIx
# MDk0NjA1WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDm05ndAgEAMAcCAQACAgtF
# MAcCAQACAhFuMAoCBQDm1OtdAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# iuYXC8coCc/wfMpjuHlrn7LzlrU6qzFqsSK83TCBkBSuozidGj/IzL4GLJ+W3aaE
# n+ynItKoNmK2gLxZY7QGlzHkpCKZ1FmulFJywOKsosh2fZv8tGAaQoJH6jMipwRu
# IlHSah6bi7t1OZ87ds7tdmKLS4q9bIztfUusGxQ8ohcxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYguzcaBQeG8KgABAAAB
# iDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCF+URg4JkfCabvM2c3n4rdWLcXO+YKyZ1RgF0g0oY8
# 1DCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGbp3u2sBjdGhIL4z+ycjtzS
# pe4bLV/AoYaypl7SSUClMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGILs3GgUHhvCoAAQAAAYgwIgQgvdHPxo5uBQt9dco6MqwieVju
# 71dTb23p9he3LnoP000wDQYJKoZIhvcNAQELBQAEggIAMQBBW32GxLpVk7Kns/hs
# gY+npyy0tXrDePc76d+OGDFFO/wxxlm/9KcrmOuM13wFFBVhhl5EtWX7Tynx90ar
# 79bRLO6PmwhLwwpp8seJnplNT57mGgZY8nezHaxI3CueX3SjKX2aGRgTQujE6DDV
# 0Y1/rajRw39GayrpYsgPIBUOfoAJkx/L5gHxOTeGXIvnsT15ygXqUWsg0rymXPnk
# 09AhLy2+62uIQEItMpEaCMIYWVBH2YY1mZKHXrLffGYIw+LdK4xGytg5emkj1lsY
# iXPXH/5LHVDJ5hfz6k1JxCCYOXjB7OvoU4wc9vwvMGDijCzXQ+oCJMWJVVKi3RBb
# ziSdxYIggzV2NXvfbeJAS+1GN+i+XQb09xxcePS9O9RSfDwu+IM//vRSmMJ2kp2/
# Xz2eEhnVMR7k+wqxtUmuEaBrNe8A0t7GkbCAuz1njfmrJaqLjkQlcSGPFJGNn0ry
# LSinefFwSSAgJO4iVeJdc2N7619Khg7IoG/rYGC+eR+QX7hkKI03Ldzr5v05jN1N
# Iwl9yZ7Ocyk/wfhoCkQhGUURXKpX7DkNDor1dj8SrE04gyqFMFhlbkIrghnNgN7S
# 4TEHvxsSH6SYeGaETAZ6ZABapquW7HrAh9+JzluDYsfboPToiajGsOdMmyGMACLP
# O3Zn6LhfuRXcyiibGSrvX3U=
# SIG # End signature block
