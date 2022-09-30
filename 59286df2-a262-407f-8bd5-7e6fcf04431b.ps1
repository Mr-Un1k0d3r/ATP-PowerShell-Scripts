function Get-Subject-Type($cert) {
    $basicConstraints = ($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Basic Constraints"}).format(1)
    $subjectTypeLine = ($basicConstraints -split '\r?\n')[0]
    $subjectTypeValue = ($subjectTypeLine -split '=')[1]
    return $subjectTypeValue
}

$Source = @"
	using System;
    using System.Text;
    using System.Diagnostics.Tracing;
    using Microsoft.PowerShell.Commands;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using System.Linq;

    public static class TvmCertificatesEtwProvider
    {
        public static EventSource log = new EventSource("Microsoft.Windows.Sense.TvmCertificateCollectionEtw", EventSourceSettings.EtwSelfDescribingEventFormat);
    }

    [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
    public class CollectedCertificate
    {
        public String PsPath { get; set; }
        public String Thumbprint { get; set; }
        public String SerialNumber { get; set; }
        public String Subject { get; set; }
        public String Issuer { get; set; }
        public String FriendlyName { get; set; }
        public String NotAfter { get; set; }
        public String NotBefore { get; set; }
        public String SignatureAlgorithm { get; set; }
        public int KeyLength { get; set; }
        public bool HasPrivateKey { get; set; }
        public String KeyUsage { get; set; }
        public String SubjectAlternativeName { get; set; }
        public String SubjectType { get; set; }
        public String ExtendedKeyUsage { get; set; }
        public String ThumbprintChain { get; set; }

        public CollectedCertificate(
            string psPath,
            string thumbprint,
            string serialNumber,
            string subject,
            string issuer,
            string friendlyName,
            string notAfter,
            string notBefore,
            string signatureAlgorithm,
            int keyLength,
            bool hasPrivateKey,
            string keyUsage,
            string subjectAlternativeName,
            string subjectType,
            string extendedKeyUsage,
            string thumbprintChain
        )
        {
            this.PsPath = psPath;
            this.Thumbprint = thumbprint;
            this.SerialNumber = serialNumber;
            this.Subject = subject;
            this.Issuer = issuer;
            this.FriendlyName = friendlyName;
            this.NotAfter = notAfter;
            this.NotBefore = notBefore;
            this.SignatureAlgorithm = signatureAlgorithm;
            this.KeyLength = keyLength;
            this.HasPrivateKey = hasPrivateKey;
            this.KeyUsage = keyUsage;
            this.SubjectAlternativeName = subjectAlternativeName;
            this.SubjectType = subjectType;
            this.ExtendedKeyUsage = extendedKeyUsage;
            this.ThumbprintChain = thumbprintChain;
        }
    }

    [EventData] 
    public class CollectedCertificateIndex
    {
			public String Index { get; set; }

            public CollectedCertificateIndex(string index)
            {
				this.Index = index;
            }
    }                                                  
"@
Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings

echo "Start certificates script version 1.1"

$certificates = Get-ChildItem Cert:\ -Recurse | 
    where {$_.PSIsContainer -eq $false} | 
    select PSPath, Thumbprint, SerialNumber, Subject, Issuer, FriendlyName, NotAfter, NotBefore, @{n="SignatureAlgorithm";e={$_.SignatureAlgorithm.FriendlyName}}, @{n="KeyLength";e={$_.PublicKey.Key.KeySize}}, HasPrivateKey, 
    @{n="KeyUsage";e={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Key Usage"}).Format(1)}}, @{n="SubjectAlternativeName";e={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}).Format(1)}}, @{n="SubjectType";e={Get-Subject-Type -cert $_}},
    @{n="ExtendedKeyUsage";e={($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Enhanced Key Usage"}).Format(1)}}

$certificatesIndex = @()

$CollectedCertificateProvider = [TvmCertificatesEtwProvider]::log

ForEach ($certificate in $certificates) {

	$psPath = $certificate.PSPath
	$thumbprint = $certificate.Thumbprint
	$serialNumber = $certificate.SerialNumber
	$subject = $certificate.Subject
	$issuer = $certificate.Issuer
	$friendlyName = $certificate.FriendlyName
	$notAfter = $certificate.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
	$notBefore = $certificate.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
	$signatureAlgorithm = $certificate.SignatureAlgorithm
	$keyLength = $certificate.KeyLength
    $hasPrivateKey = $certificate.HasPrivateKey
    $keyUsage = $certificate.KeyUsage
    $subjectAlternativeName = $certificate.SubjectAlternativeName
    $subjectType = $certificate.SubjectType
    $extendedKeyUsage = $certificate.ExtendedKeyUsage

    #get cert path
    $splitted = $psPath.Split("::")[2]
    $path = "Cert:\" + $splitted
    #get full cert
    $my_cert = Get-ChildItem $path
    #get cert chain
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain 

    $isBuild = $chain.Build($my_cert) 

    #skip first as it is the current cert and take only the chain certificates thumbprints
    [array]$chainElements = $chain.ChainElements | select -Skip 1 | % {$_.Certificate.Thumbprint}

    #join into one string with delimiter of ;
    $thumbprintChain = $chainElements -join ";"

    $certificateArgumentList = @($psPath, $thumbprint, $serialNumber, $subject, $issuer, $friendlyName, $notAfter, $notBefore, $signatureAlgorithm, $keyLength, $hasPrivateKey, $keyUsage, $subjectAlternativeName, $subjectType, $extendedKeyUsage, $thumbprintChain)
    $collectedCertificate = New-Object CollectedCertificate -ArgumentList $certificateArgumentList   

    # Send data to ETW
    $CollectedCertificateProvider.Write("CollectedCertificates", $collectedCertificate)

    $certificatesIndex += "{0}_{1}" -f $certificate.Thumbprint, $certificate.PSPath
}

$certificatesIndexAsJson = ConvertTo-Json -InputObject $certificatesIndex -Compress
$collectedServicesIndex = [CollectedCertificateIndex]::new($certificatesIndexAsJson)
$CollectedCertificateProvider.Write("CollectedCertificatesIndex", $collectedServicesIndex) 
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCApents4/2ddMnV
# hKzP2Hjaqom2zaETA+5C1X3u+LL4+KCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIJasuh+6KkuDRxJOF4lIdA74qRWeWKXhsun28KSfGkHU
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAm8Qn0n/gOeoU
# lbcw9cRkEdQj6iw7OngC1aJjpT+v/ZmHY6QCeQtyWcfi9CG43lvI/Pt13aBjlorx
# WFta8LbPzBgGmdYvVgn9g2dsQtA+kzWC8SOJdQqs6WGSHZYQ9vFxsAvznAwJ+QZ8
# x+V+SS+kp/NxVy+/XHy5kXo4hL8rSzMtr13OITDKVMJ2GfeDZdOMSEi9+zC9o/Af
# SZ/F4j+BOC0Hyp7WgHJ/k5vRygQAVFCAIvoGO8aScz+Y62uH8dMaYaV9Z5kUMnMD
# i0H4K4Bz1Yj2dQDJdpj4n03KpYacvRF6FGg6WMErBYPubHTZ+/DP1p8pWG0tzGCb
# w7C88fbPFKGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAsrjc4w8A1
# 0hZEFilLACMXPxblA6buHfL1msCQ1LytvgIGYxIJsUDLGBMyMDIyMDkyMDA5NTcy
# NS4zNzlaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
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
# MC8GCSqGSIb3DQEJBDEiBCC6hvdX5dm39mD5X1Zl4GsCMr75aoeEhKEjdqIX3Ktg
# yjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGbp3u2sBjdGhIL4z+ycjtzS
# pe4bLV/AoYaypl7SSUClMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGILs3GgUHhvCoAAQAAAYgwIgQgvdHPxo5uBQt9dco6MqwieVju
# 71dTb23p9he3LnoP000wDQYJKoZIhvcNAQELBQAEggIAF6QR2C8nHGkwlTp03nNg
# 4/5S7z9XV4Hft7ej1VAniDExON4snf/cG/QNOrF2Akn0hqHH/O+LVS9VbVwLAxou
# e2mDOT15Nv9w/ypJX40+nEl7N7yu5UMvtg+ELfzJWAUDj5axvaaGhDjPmoWTu69D
# lg7zLtUjlkQtv5eom5hTKWRsgvleHIN99vZOuO8B2Q/8WP+5Emn8rFhViHuFm5A4
# kaMJH468eDBrlefYym/tHO3yJKzNFUj+retXo7akl5IYwQoqzO+gqBYcJF/nMP2m
# 021Sq1noKbly7bkO4CuRkJrI8a7AWp6ACRktB2/7q/HgB1W5eaB7cTKBwkkaqhSy
# j4ObmF1ASRLqUTBjM/1DZzOkVLPMGa2IDrbkD+A0FccNsmpSg2y88zMUnv8SlKjU
# u+JCV5VxBrt8u2IH9EvpCS3MunX6e5tO14JKMIaHBkS+HE+6DZ5k0xRNBN2DPx3u
# 3qB9iZG7/TGBZfGgidbj4XB6jsUIqQctRjaJeSkwnmqotI0aIRL5Ed020xmO6NCw
# gm5vl7elJchfoaYKV44sjauLDeBZGHAhziWXxfAvkuuQ8KdmYg0wURGUOimkNlBZ
# jgA4OA3Rg0EGj5IaPQr3fYRzIlDSatSnEpsoWF2CkAR/99UpXQnO/X9qBcXZz4Wo
# KrcIX3dA6iHwgqGwKsf5m20=
# SIG # End signature block
