# Copied from UnicastScanner
$EtwWriter = @"
using System;
using System.Text;
using System.Diagnostics.Tracing;
using Microsoft.PowerShell.Commands;

[EventSource(Name = "Microsoft.Windows.NdrScanner", Guid = "a4bfed93-f051-4c33-a524-8ccc50d0dd2b")]
public sealed class NdrEventSource : EventSource
{
    public NdrEventSource() : base(EventSourceSettings.EtwSelfDescribingEventFormat | EventSourceSettings.ThrowOnEventWriteErrors) { }
}

[EventSource(Name = "Microsoft.Windows.Sense.CollectionEtw")]
public sealed class SenseEventSource : EventSource
{
    public SenseEventSource() : base(EventSourceSettings.EtwSelfDescribingEventFormat | EventSourceSettings.ThrowOnEventWriteErrors) { }
}

[EventData]
public class NdrScannerTelemetriesEvent
{
    public UInt64 TelemetryTimestamp { get; set; }
    public string TelemetryName { get; set; }
    public string TelemetriesInfoAsJson { get; set; }
}

[EventData]
public class NdrCveLocalScannerEvent
{
    public UInt64 ScanTimestamp { get; set; }
    public string CveName { get; set; }
    public string ScannerVersion { get; set; }
    public string ScanInfoAsJson { get; set; }
}
"@

Add-Type -TypeDefinition $EtwWriter -Language CSharp -IgnoreWarnings
$global:EtwProvider =  [NdrEventSource]::new()

[string]$ScriptName = "Log4jLocalScanner"
[string]$ScriptVersion = "V1.1.0"

try
{
    [string]$RegistryMachineId = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name senseId -ErrorAction Stop
    $MachineIdLastCharacters = $RegistryMachineId.Substring(30)
    if ($MachineIdLastCharacters.Length -ne 10)
    {
        Write-Host "MachineId invalid length $($RegistryMachineId.Length)"
        return;
    }
}
catch
{
    Write-Host "Cannot get MachineId from registry"
    return;
}

function Test-ChainStatusValid
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Chain] $Chain,

        [Switch] $IgnoreCertTime
    )

    if ($Chain.ChainStatus.Length -eq 0)
    {
        return $true
    }

    $CheckStatus = $Chain.ChainStatus[0].Status
    $IsError = $CheckStatus -ne [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
    $IsErrorInvalidTime = $Chain.ChainStatus.Length -eq 1 -And $CheckStatus -eq [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
    return !$IsError -Or $IgnoreCertTime -And $IsErrorInvalidTime
}

function Test-CertificateSignature
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $CertObj,

        [Parameter(Mandatory = $true)]
        [Byte[]] $BodyBytes,

        [Parameter(Mandatory = $true)]
        [Byte[]] $SignatureBytes,

        [Parameter(Mandatory = $true)]
        [String] $OID
    )

    # Reverse first as it is more likely to succeed
    [array]::Reverse($SignatureBytes)
    $Res = $CertObj.PublicKey.Key.VerifyData($BodyBytes, $OID, $SignatureBytes)
    if (!$Res)
    {
        [array]::Reverse($SignatureBytes)
        $Res = $CertObj.PublicKey.Key.VerifyData($BodyBytes, $OID, $SignatureBytes)
    }

    return $Res
}


function Convert-Base64StringToCert
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $CertStr
    )

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($CertStr))
}

function Validate-ConfigSignatures
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Body,

        [Parameter(Mandatory = $true)]
        [String] $Signature,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String] $Signature256,

        [Parameter(Mandatory = $true)]
        [String] $Cert,

        [Parameter(Mandatory = $true)]
        [String[]] $CertChain,

        [Switch] $IgnoreCertTime
    )

    $CertObj = Convert-Base64StringToCert($Cert)
    $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)

    $SignatureBytes = [System.Convert]::FromBase64String($Signature)
    $OID = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA1")
    if (!(Test-CertificateSignature $CertObj $BodyBytes $SignatureBytes $OID))
    {
        Write-Host "Failed validating config signature"
    }

    if ($Signature256 -ne '')
    {
        $SignatureBytes = [System.Convert]::FromBase64String($Signature256)
        $OID = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256")
        if (!(Test-CertificateSignature $CertObj $BodyBytes $SignatureBytes $OID))
        {
            Write-Host "Failed validating config sha256"
        }
    }

    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $CertChain | ForEach-Object { Convert-Base64StringToCert($_) } | ForEach-Object { [void]$Chain.ChainPolicy.ExtraStore.Add($_) }
    $Chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

    [void]$Chain.Build($CertObj)
    if (!(Test-ChainStatusValid $Chain -IgnoreCertTime:$IgnoreCertTime))
    {
        Write-Host "Failed validating chain with status $CheckStatus"
    }
}

function Read-RegistryKey
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $KeyName,

        [Parameter(Mandatory = $true)]
        [String] $KeyPath
    )

    try
    {
        return Get-ItemProperty -Path $KeyPath -Name $KeyName | Select-Object -ExpandProperty $KeyName
    }
    catch
    {
        return $null
    }
}

function Get-OnboardedData
{
    $OnboardedDataJson = Read-RegistryKey 'OnboardedInfo' 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection'

    try
    {
        $OnboardedData = ConvertFrom-Json -InputObject $OnboardedDataJson
    }
    catch
    {
        Write-Host "Failed to convert config json"
    }

    $Body = $OnboardedData.Body
    $Signature = $OnboardedData.sig
    $Signature256 = $OnboardedData.sha256sig
    $Cert = $OnboardedData.Cert
    $CertChain = $OnboardedData.Chain

    Validate-ConfigSignatures $Body $Signature $Signature256 $Cert $CertChain -IgnoreCertTime

    return $Body
}

function Get-Config
{
    $OnboardingDataBodyJson = Get-OnboardedData
    try
    {
        $OnboardingDataBody = ConvertFrom-Json -InputObject $OnboardingDataBodyJson
    }
    catch
    {
        Write-Host "Failed to get config"
    }

    return $OnboardingDataBody
}


function Invoke-WebRequestWithRootCaVerification
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri] $Uri
    )

    $MsRootThumbprint = '8F43288AD272F3103B6FB1428485EA3014C0BCFE'
    $MsAzureThumbprint = 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4'
    $Request = [System.Net.HttpWebRequest]::Create($Uri)

    try
    {
        $Resp = $Request.GetResponse()
        $BodyStreamReader = New-Object System.IO.StreamReader($Resp.GetResponseStream())
        $BodyRes = $BodyStreamReader.ReadToEnd()
    }
    catch
    {
        Write-Host "Failed to perform web request"
        return
    }
    finally
    {
        if ($Resp)
        {
            $Resp.Dispose()
        }
    }

    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    if (!$Chain.Build($Request.ServicePoint.Certificate) -Or !(Test-ChainStatusValid $Chain))
    {
        Write-Host "Failed validating web server certificate chain $($Chain.ChainStatus[0].Status)"
    }

    $RootValidated = $false
    $RootCert = $Chain.ChainElements[$Chain.ChainElements.Count - 1].Certificate
    $RootValidated = $RootCert.Thumbprint.ToUpperInvariant() -eq $MsRootThumbprint

    if (!$RootValidated)
    {
        Write-Host "Failed validating web server root certificate $RootCert"
    }

    return $BodyRes
}


function Write-Telemetry
{
    param([string]$TelemetryDataAsJson,
        [string]$ProviderName = "Log4jLocalScannerTelemetry")

    $TelemetryData = $TelemetryDataAsJson | ConvertFrom-Json
    $TelemetryData | Add-Member -NotePropertyName "ScriptVersion" -NotePropertyValue $ScriptVersion
    $TelemetryData | Add-Member -NotePropertyName "ScriptName" -NotePropertyValue $ScriptName

    $TelemetryDataAsJson = $TelemetryData | ConvertTo-Json

    $NdrTelemetriesEvent = New-Object "NdrScannerTelemetriesEvent" -Property @{
        TelemetryTimestamp = $(Get-Date).ToFileTime()
        TelemetryName = $ProviderName
        TelemetriesInfoAsJson = $TelemetryDataAsJson
    }

    $global:EtwProvider.Write("NdrScannerTelemetriesEvent",$NdrTelemetriesEvent)
}

function Write-Scan-Event
{
    param([string]$ScanDataAsJson,
        [string]$CveName = "CVE-2021-44228")

    $NdrCveScanEvent = New-Object "NdrCveLocalScannerEvent" -Property @{
        ScanTimestamp = $(Get-Date).ToFileTime()
        CveName = $CveName
        ScannerVersion = $ScriptName + " " + $ScriptVersion
        ScanInfoAsJson = $ScanDataAsJson
    }

    $global:EtwProvider.Write("NdrCveLocalScannerEvent",$NdrCveScanEvent)
}

# Log4j vulnerability (AKA log4shell)
function Scan-CVE-2021-44228
{
    param(
    [Parameter(Mandatory=$true)]
    [string]$RemoteIP,
    [string]$RemoteMac,
    [string]$LocalIP
    )

    try
    {
        $result = [CVE202144228]::ScanExploitTargets($LocalIP, $RemoteIP, [CVE202144228+JndiPayloadType]::Dns, $MachineIdLastCharacters)
    }
    catch
    {
        $Telemetry = New-Object psobject @{
                    ScannerException = $_.Exception.Message
                }
        Write-Telemetry -ProviderName "CVE-2021-44228-LocalScanner" -TelemetryDataAsJson $Telemetry
        return;
    }
    
    $resultTelemetries = @{}
    if ($result -ne $null -and ($result.Count -gt 0))
    {
        foreach ($specificResult in $result)
        {
            if ($specificResult.Port -ne $null -and (-not($specificResult.Port.ToString() -in $resultTelemetries.Keys)))
            {
                $resultTelemetries.Add($specificResult.Port.ToString(), $specificResult)
            }
        }
    }

    Write-Telemetry -ProviderName "CVE-2021-44228-LocalScanner" -TelemetryDataAsJson $($resultTelemetries | ConvertTo-Json)
    Write-Scan-Event -ScanDataAsJson $($resultTelemetries | ConvertTo-Json)
}

$CVE202144228ScannerSource = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public class CVE202144228
{
    private const string c_scannerId = "MDEDiscovery";
    private const string c_httpVersion = "HTTP/1.1";
    private const string c_httpHeaderTemplate = c_httpVersion + " XXX";
    private const ushort c_smtpHeaderLength = 3;
    private const string c_userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36";
    private const ushort c_dnsPort = 5353;
    private const int c_numberOfThreads = 6;
    private const int c_threadTimeoutMilliseconds = 30 * 1000;
    private const string c_userAgentExploitIdentifier = "User-Agent";
    private const string c_uriExploitIdentifier = "Uri";
    private const string c_uriPostExploitIdentifier = "UriPost";
    private const string c_remoteIpToken = "RemoteIp";
    private const string c_httpPost = "POST";
    private const string c_httpGet = "GET";
    private const string c_httpRootUri = "/";
    private const string c_smtpServerHello = "220";
    private const string c_smtpServerOk = "250";
    private const string c_jndiDnsPayloadFormat = "$`{{jndi:dns://{0}{1}-{2}}}";
    private const string c_jndiDnsPayloadDnsServerIpPortFormat = "{0}:{1}/{2}";
    private const string c_jndiPayloadEmailAddressSuffix = "@mdediscover.com";
    private const string c_machineIdExploitIdentifierFormat = "{0}{1}";

    private static readonly ExploitScanTarget[] s_exploitScanTargets = new ExploitScanTarget[]
    {

        new ExploitScanTarget() { Headers = new string[] { "If-Modified-Since: {0}" }, Uris = new string[] { "/struts2-showcase/struts/utils.js", "/struts2-showcase/struts/tooltip.gif", "/struts2-showcase/struts/domtt.css", "/struts2-showcase/struts/domTT.js", "/struts2-showcase/struts/inputtransfersselect.js", "/struts2-showcase/struts/optiontransferselect.js", "/struts2-showcase", "/index.action/struts/utils.js" }, HttpCommand = c_httpGet, ExploitIndicator = "ApacheStruts2"},
        new ExploitScanTarget() { Headers = new string[] { "Accept-Language: en-US,en;q=0.9,ca;q=0.8", "Cache-Control: no-cache", "Content-Type: application/x-www-form-urlencoded", "Pragma: no-cache", "Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate", "Sec-Fetch-Site: none", "Sec-Fetch-User: ?1", "Upgrade-Insecure-Requests: 1", "Accept-Encoding: gzip" }, Uris = new string[] { "/struts2-showcase/token/transfer4.action" }, HttpCommand = c_httpPost, PostData = "struts.token.name={0}", ExploitIndicator = "ApacheStruts2"},

        new ExploitScanTarget() { Uris = new string[] { "/struts2-showcase/{0}" }, HttpCommand = c_httpGet, ExploitIndicator = "ApacheStruts2" },

        new ExploitScanTarget() {Headers = new string[] { "Connection: close", "Accept-Encoding: gzip" }, Uris = new string[] { "/struts2-showcase/token/transfer4.action" }, HttpCommand = c_httpPost, PostData = "struts.token.name={0}", ExploitIndicator = "ApacheStruts2" },

        new ExploitScanTarget() { Uris = new string[] { "/analytics/telemetry/ph/api/hyper/send?_c={0}&i=test" }, HttpCommand = c_httpPost, ExploitIndicator = "VMwarevCenter" },

        new ExploitScanTarget() { Uris = new string[] { "/solr/admin/cores?action=CREATE&name={0}&wt=json", "/solr/admin/collections?action={0}" }, HttpCommand = c_httpGet, Ports = new ushort[] { 8983, 80, 443 }, ExploitIndicator = "ApacheSolr" },

        new ExploitScanTarget() { Uris = new string[] { "/druid/coordinator/v1/lookups/config/{0}" }, HttpCommand = "DELETE", Ports = new ushort[] { 8888 }, ExploitIndicator = "ApacheDruid" },

        new ExploitScanTarget() { Uris = new string[] { "/JSPWiki/wiki/{0}" }, HttpCommand = c_httpGet, ExploitIndicator = "ApacheJspWiki" },

        new ExploitScanTarget() { Headers = new string[] { "Cookie: OFBiz.Visitor={0}" }, Uris = new string[] { "/webtools/control/main" }, HttpCommand = c_httpGet, ExploitIndicator = "ApacheOFBiz" },

        new ExploitScanTarget() { Uris = new string[] { "/broker/xml" }, HttpCommand = c_httpPost, PostData = "<?xml version='1.0' encoding='UTF-8'?><broker version='14.0'><do-submit-authentication><screen><name>windows-password</name><params><param><name>username</name><values><value>hello</value></values></param><param><name>domain</name><values><value>{0}</value></values></param><param><name>password</name><values><value>{{SSO-AES:1}}ZXbtEwRmeGs80cyD1sRsS6sVRgVt7pYR</value></values></param></params></screen></do-submit-authentication></broker>", ExploitIndicator = "VMwareHorizon" },
        new ExploitScanTarget() { Uris = new string[] { "/broker/xml" }, HttpCommand = c_httpPost, PostData = "<?xml version='1.0' encoding='UTF-8'?><broker version='{0}'></broker>", ExploitIndicator = "VMwareHorizon" },
        new ExploitScanTarget() { Headers = new string[] { "Accept-Language: {0}" }, Uris = new string[] { "/portal/info.jsp" }, HttpCommand = c_httpGet, ExploitIndicator = "VMwareHorizon" },

        new ExploitScanTarget() { Headers = new string[] { "Connection: Keep-Alive", "Accept-Charset: {0}", "Access-Control-Request-Method: {0}", "Pragma: {0}", "IP: {0}", "Accept-Language: {0}", "Cache-Control: {0}", "Dnt: {0}", "Content-Length: {0}", "Date: {0}", "From: {0}", "Front-End-Https: {0}", "HTTP2-Settings: {0}", "If-Range: {0}", "Content-Type: {0}", "Hostname: {0}", "Prefer: {0}", "TE: {0}", "Accept: {0}", "Transfer-Encoding: {0}", "Content-Disposition: {0}", "Proxy-Authorization: {0}", "Accept-Datetime: {0}" }, Uris = new string[] { "/ui/login?referer=" }, Ports = new ushort[] { 1610, 1611 }, HttpCommand = c_httpGet, ExploitIndicator = "UiLoginReferer" },

        new ExploitScanTarget() { Uris = new string[] { "/{0}" }, HttpCommand = c_httpGet, Ports = new ushort[] { 7001 }, ExploitIndicator = "WebLogic"},

        new ExploitScanTarget() { Headers = new string[] { string.Format("Referer: https://{0}/mifs/user/login.jsp", c_remoteIpToken) }, Uris = new string[] { "/mifs/j_spring_security_check" }, HttpCommand = c_httpPost, Ports = new ushort[] { 443 }, PostData = "j_username={0}&j_password=mdediscovery&logincontext=employee", ExploitIndicator = "MobileIron"},

        new ExploitScanTarget() { Headers = new string[] { "Referer: {0}", "Connection: close", "Accept-Encoding: gzip" }, UserAgent = "{0}", Uris = new string[] { "/?x={0}" }, HttpCommand = c_httpGet, ExploitIndicator = "xParam"},

        new ExploitScanTarget() { Headers = new string[] { "Connection: keep-alive" }, UserAgent = "{0}", Uris = new string[] { "/?v={0}" }, HttpCommand = c_httpPost, ExploitIndicator = "vPostParam"},

        new ExploitScanTarget() { Headers = new string[] { "Connection: Close", "Pragma: no-cache", "Cache-Control: no-cache", "Accept-Language: en", "Accept-Charset: iso-8859-1,*,utf-8" }, Uris = new string[] { "/?param={0}" }, HttpCommand = c_httpPost, ExploitIndicator = "ParamUriParam"},

        new ExploitScanTarget() { Headers = new string[] { "Connection: keep-alive" }, UserAgent = "{0}", Uris = new string[] { "/?v={0}" }, HttpCommand = c_httpGet, ExploitIndicator = "vGetParam"},

        new ExploitScanTarget() { Uris = new string[] { c_httpRootUri }, HttpCommand = c_httpPost, PostData = "data={0}", ExploitIndicator = "GenericPostParam"},

        new ExploitScanTarget() { Headers = new string[] { "Cookie: {0}={0};JSESSIONID={0};SESSIONID={0};PHPSESSID={0};token={0};session={0}" }, Uris = new string[] { c_httpRootUri }, HttpCommand = c_httpGet, ExploitIndicator = "GenericCookie" },

        new ExploitScanTarget() { Headers = new string[] { "Referer: {0}", "X-Forwarded-For: {0}" }, Uris = new string[] { "/{0}" }, HttpCommand = c_httpGet, ExploitIndicator = "Code42", UserAgent = "{0}", Ports = new ushort[] { 4285 } },
        new ExploitScanTarget() { Headers = new string[] { "Referer: {0}", "X-Forwarded-For: {0}" }, Uris = new string[] { "/{0}" }, HttpCommand = c_httpPost, ExploitIndicator = "Code42", UserAgent = "{0}", Ports = new ushort[] { 4285 } },

        new ExploitScanTarget() { Uris = new string[] { "/api/login" }, HttpCommand = c_httpPost, PostData = "{{\"username\":\"admin\",\"password\":\"mdediscovery\",\"remember\":\"{0}\",\"strict\":true}}", ContentType = "application/json", ExploitIndicator = "Ubiquiti", UserAgent = "{0}", Ports = new ushort[] { 7443, 8443 } },  // [SuppressMessage("Microsoft.Security", "CS001:SecretInline", Justification="Stub password")]
        new ExploitScanTarget() { Uris = new string[] { "/api/2.0/login" }, HttpCommand = c_httpPost, PostData = "{{\"username\":\"{0}\",\"password\":\"mdediscovery\"}}", ExploitIndicator = "Ubiquiti", Ports = new ushort[] { 7443, 8443 }, ContentType = "application/json"},  // [SuppressMessage("Microsoft.Security", "CS001:SecretInline", Justification="Stub password")]

        new ExploitScanTarget() { Uris = new string[] { "/oXygenLicenseServlet/index.jsp" }, Headers = new string[] { "X-Api-Version: {0}", "Connection: keep-alive" }, HttpCommand = c_httpGet, ExploitIndicator = "oXygenLicenseServlet", Ports = new ushort[] { 8080 } },

        new ExploitScanTarget() { Uris = new string[] { "/dashboard/" }, Headers = new string[] { "X-Api-Version: {0}", "Connection: keep-alive" }, HttpCommand = c_httpGet, ExploitIndicator = "dashboard", Ports = new ushort[] { 8080 } },

        new ExploitScanTarget() { Uris = new string[] { "/js/?{0}", "/api/v2/{0}", "/api/?{0}", "/index.html?{0}" }, HttpCommand = c_httpGet, ExploitIndicator = "SeenInTheWildGet" },
        new ExploitScanTarget() { Uris = new string[] { "/login" }, HttpCommand = c_httpGet, ExploitIndicator = "SeenInTheWildPost" },

        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, HttpCommand = c_httpGet, ExploitIndicator = c_uriExploitIdentifier },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, HttpCommand = c_httpPost, ExploitIndicator = c_uriPostExploitIdentifier},
        new ExploitScanTarget() { Uris = new string[] { "/login"}, HttpCommand = c_httpPost, ExploitIndicator = c_uriPostExploitIdentifier, PostData = "data={0}"},
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, HttpCommand = c_httpGet, UserAgent = "{0}", ExploitIndicator = c_userAgentExploitIdentifier },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "A-IM: {0}" }, ExploitIndicator = "A-IM" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Accept-Charset: {0}" }, ExploitIndicator = "Accept-Charset" }, new ExploitScanTarget() { Headers = new string[] { "Accept-Language: {0}" }, ExploitIndicator = "Accept-Language" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Accept-Datetime: {0}" }, ExploitIndicator = "Accept-Datetime" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Access-Control-Request-Method: {0}" }, ExploitIndicator = "Access-Control-Request-Method" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Access-Control-Request-Headers: {0}" }, ExploitIndicator = "Access-Control-Request-Headers" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Authorization: {0}" }, ExploitIndicator = "Authorization" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Cache-Control: {0}" }, ExploitIndicator = "Cache-Control" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Content-Type: {0}" }, ExploitIndicator = "Content-Type" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Content-Length: {0}" }, ExploitIndicator = "Content-Length" },
        new ExploitScanTarget() { Headers = new string[] { "Content-Disposition: {0}" }, ExploitIndicator = "Content-Disposition" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Cookie: {0}" }, ExploitIndicator = "Cookie" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Date: {0}" }, ExploitIndicator = "Date" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Expect: {0}" }, ExploitIndicator = "Expect" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Forwarded: {0}" }, ExploitIndicator = "Forwarded" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "From: {0}" }, ExploitIndicator = "From" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "If-None-Match: {0}" }, ExploitIndicator = "If-None-Match" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "If-Range: {0}" }, ExploitIndicator = "If-Range" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Range: {0}" }, ExploitIndicator = "Range" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Origin: {0}" }, ExploitIndicator = "Origin" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Pragma: {0}" }, ExploitIndicator = "Pragma" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Proxy-Authorization: {0}" }, ExploitIndicator = "Proxy-Authorization" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Referer: {0}" }, ExploitIndicator = "Referer" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "TE: {0}" }, ExploitIndicator = "TE" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Upgrade: {0}" }, ExploitIndicator = "Upgrade" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Via: {0}" }, ExploitIndicator = "Via" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Warning: {0}" }, ExploitIndicator = "Warning" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Api-Version: {0}" }, ExploitIndicator = "X-Api-Version" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Upgrade-Insecure-Requests: {0}" }, ExploitIndicator = "Upgrade-Insecure-Requests" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Requested-With: {0}" }, ExploitIndicator = "X-Requested-With" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-CSRF-Token: {0}" }, ExploitIndicator = "X-CSRF-Token" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-XSRF-Token: {0}" }, ExploitIndicator = "X-XSRF-Token" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Dnt: {0}" }, ExploitIndicator = "Dnt" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Content-Disposition: {0}" }, ExploitIndicator = "Content-Disposition" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Content-Encoding: {0}" }, ExploitIndicator = "Content-Encoding" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Amz-Target: {0}" }, ExploitIndicator = "X-Amz-Target" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Amz-Date: {0}" }, ExploitIndicator = "X-Amz-Date" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Username: {0}" }, ExploitIndicator = "Username" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "IP: {0}" }, ExploitIndicator = "IP" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "IPaddress: {0}" }, ExploitIndicator = "IPaddress" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Hostname: {0}" }, ExploitIndicator = "Hostname" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Original-Url: {0}" }, ExploitIndicator = "X-Original-Url" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Content-MD5: {0}" }, ExploitIndicator = "Content-MD5" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "HTTP2-Settings: {0}" }, ExploitIndicator = "HTTP2-Settings" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Prefer: {0}" }, ExploitIndicator = "Prefer" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Trailer: {0}" }, ExploitIndicator = "Trailer" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-For: {0}" }, ExploitIndicator = "X-Forwarded-For" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Host: {0}" }, ExploitIndicator = "X-Forwarded-Host" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Proto: {0}" }, ExploitIndicator = "X-Forwarded-Proto" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Client-Ip: {0}" }, ExploitIndicator = "X-Client-Ip" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-ProxyUser-Ip: {0}" }, ExploitIndicator = "X-ProxyUser-Ip" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Front-End-Https: {0}" }, ExploitIndicator = "Front-End-Https" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Http-Method-Override: {0}" }, ExploitIndicator = "X-Http-Method-Override" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-ATT-DeviceId: {0}" }, ExploitIndicator = "X-ATT-DeviceId" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Wap-Profile: {0}" }, ExploitIndicator = "X-Wap-Profile" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Proxy-Connection: {0}" }, ExploitIndicator = "Proxy-Connection" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-UIDH: {0}" }, ExploitIndicator = "X-UIDH" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Request-ID: {0}" }, ExploitIndicator = "X-Request-ID" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Correlation-ID: {0}" }, ExploitIndicator = "X-Correlation-ID" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Save-Data: {0}" }, ExploitIndicator = "Save-Data" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Remote-Addr: {0}" }, ExploitIndicator = "X-Remote-Addr" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Max-Forwards: {0}" }, ExploitIndicator = "Max-Forwards" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "True-Client-Ip: {0}" }, ExploitIndicator = "True-Client-Ip" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Client-Error-Invalid-Server-Address: {0}" }, ExploitIndicator = "Client-Error-Invalid-Server-Address" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Cf-Connection_ip: {0}" }, ExploitIndicator = "Cf-Connection_ip" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Appversion: {0}" }, ExploitIndicator = "Appversion" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth: {0}" }, ExploitIndicator = "Auth" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth-Digest: {0}" }, ExploitIndicator = "Auth-Digest" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth-Realm: {0}" }, ExploitIndicator = "Auth-Realm" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Bad-Request: {0}" }, ExploitIndicator = "Bad-Request" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "App-Version: {0}" }, ExploitIndicator = "App-Version" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Asid: {0}" }, ExploitIndicator = "Asid" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth-Gssneg: {0}" }, ExploitIndicator = "Auth-Gssneg" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Authenticated_user: {0}" }, ExploitIndicator = "Authenticated_user" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Avail-Dictionary: {0}" }, ExploitIndicator = "Avail-Dictionary" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Bae-Env-Addr-Bcms: {0}" }, ExploitIndicator = "Bae-Env-Addr-Bcms" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth-Any: {0}" }, ExploitIndicator = "Auth-Any" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "Auth-Clientid: {0}" }, ExploitIndicator = "Auth-Clientid" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Server: {0}" }, ExploitIndicator = "X-Forwarded-Server" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Ssl: {0}" }, ExploitIndicator = "X-Forwarded-Ssl" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarder-For: {0}" }, ExploitIndicator = "X-Forwarder-For" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forward-For: {0}" }, ExploitIndicator = "X-Forward-For" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Frame-Options: {0}" }, ExploitIndicator = "X-Frame-Options" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-From: {0}" }, ExploitIndicator = "X-From" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Geoip-Country: {0}" }, ExploitIndicator = "X-Geoip-Country" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Http-Destinationurl: {0}" }, ExploitIndicator = "X-Http-Destinationurl" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Http-Host-Override: {0}" }, ExploitIndicator = "X-Http-Host-Override" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Http-Method: {0}" }, ExploitIndicator = "X-Http-Method" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-HTTP-Method-Override: {0}" }, ExploitIndicator = "X-HTTP-Method-Override" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Http-Path-Override: {0}" }, ExploitIndicator = "X-Http-Path-Override" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Do-Not-Track: {0}" }, ExploitIndicator = "X-Do-Not-Track" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-By: {0}" }, ExploitIndicator = "X-Forwarded-By" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-For-Original: {0}" }, ExploitIndicator = "X-Forwarded-For-Original" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Protocol: {0}" }, ExploitIndicator = "X-Forwarded-Protocol" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Forwarded-Scheme: {0}" }, ExploitIndicator = "X-Forwarded-Scheme" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Https: {0}" }, ExploitIndicator = "X-Https" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Htx-Agent: {0}" }, ExploitIndicator = "X-Htx-Agent" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Hub-Signature: {0}" }, ExploitIndicator = "X-Hub-Signature" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-If-Unmodified-Since: {0}" }, ExploitIndicator = "X-If-Unmodified-Since" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Insight: {0}" }, ExploitIndicator = "X-Insight" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Ip: {0}" }, ExploitIndicator = "X-Ip" },
        new ExploitScanTarget() { Uris = new string[] { "/", "/:undefined"}, Headers = new string[] { "X-Ip-Trail: {0}" }, ExploitIndicator = "X-Ip-Trail" }
    };

    private static readonly string[] s_uris = new string[]
    {
        c_httpRootUri,
        "/cgi-bin/"
    };

    private static readonly HashSet<ushort> s_httpsPorts = new HashSet<ushort>()
    {
        443,
        7443,
        8443,
        8843,
        4285,
        9200
    };

    private static readonly HashSet<ushort> s_smtpsPorts = new HashSet<ushort>()
    {
        465,
        587
    };

    private static readonly ushort[] s_defaultHttpScanPorts = new ushort[]
    {
        80,
        8080,
        8000,
        443,
        8443,
        8843,
        8880,
        9200,
        8081
    };

    private static readonly ushort[] s_defaultSmtpScanPorts = new ushort[]
    {
        25,
        465,
        587
    };

    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; }

    private static string GenerateJndiPayload(JndiPayloadType jndiPayloadType, JndiPayloadParameterType jndiPayloadParameterType, string localIp, string remoteIp, ushort port, string exploitIdentifier)
    {
        string jndiPayload;

        switch (jndiPayloadType)
        {
            case JndiPayloadType.DnsWithSpecificIpAndPort:
                jndiPayload = string.Format(c_jndiDnsPayloadFormat, string.Format(c_jndiDnsPayloadDnsServerIpPortFormat, localIp, c_dnsPort, c_scannerId), exploitIdentifier, port);
                break;
            case JndiPayloadType.Dns:
                jndiPayload = string.Format(c_jndiDnsPayloadFormat, c_scannerId, exploitIdentifier, port);
                break;
            default:
                throw new Exception(string.Format("Unsupported JndiPayloadType value {0}", jndiPayloadType));
        }

        switch (jndiPayloadParameterType)
        {
            case JndiPayloadParameterType.EmailAddress:
                jndiPayload += c_jndiPayloadEmailAddressSuffix;
                break;
        }

        return jndiPayload;
    }

    public static VulnerabilityScanResult ScanSmtpServer(string localIp, string remoteIp, ushort port, JndiPayloadType jndiPayloadType, string machineIdentifier)
    {
        string exploitIdentifier = string.Format(c_machineIdExploitIdentifierFormat, machineIdentifier, "Smtp");
        string emailAddressJndiPayload = GenerateJndiPayload(jndiPayloadType, JndiPayloadParameterType.EmailAddress, localIp, remoteIp, port, exploitIdentifier);
        string dataJndiPayload = GenerateJndiPayload(jndiPayloadType, JndiPayloadParameterType.Data, localIp, remoteIp, port, exploitIdentifier);

        VulnerabilityScanResult result = new VulnerabilityScanResult() { ExitCode = ExitCode.Success, Uri = "SMTP", Port = port};

        using (TcpScanner cveScanner = new TcpScanner(remoteIp, port, connectTimeout: 400, receiveTimeout: 500,
            sendTimeout: 500, maxReads: 1))
        {
            if (!cveScanner.Connect())
            {
                cveScanner.Close();
                throw new ExitCodeException(ExitCode.FailedToConnect);
            }

            if (s_smtpsPorts.Contains(port))
            {
                if (!cveScanner.CreateSslConnection(
                    new RemoteCertificateValidationCallback(ValidateServerCertificate)))
                {
                    throw new ExitCodeException(ExitCode.SslWrapFailed);
                }
            }

            byte[] smtpResponse = cveScanner.Read();
            if (smtpResponse == null)
            {
                throw new ExitCodeException(ExitCode.NoResponseFromServer);
            }

            if (Encoding.ASCII.GetString(smtpResponse.Take(c_smtpHeaderLength).ToArray()) != c_smtpServerHello)
            {
                throw new ExitCodeException(ExitCode.SmtpServerError);
            }

            smtpResponse = cveScanner.SendAndReceive(Encoding.ASCII.GetBytes("EHLO MDEDiscovery\r\n"), closeAfterResponse: false);
            if (smtpResponse == null)
            {
                throw new ExitCodeException(ExitCode.NoResponseFromServer);
            }

            if (Encoding.ASCII.GetString(smtpResponse.Take(c_smtpHeaderLength).ToArray()) != c_smtpServerOk)
            {
                throw new ExitCodeException(ExitCode.SmtpServerError);
            }

            cveScanner.SendAndReceive(Encoding.ASCII.GetBytes(string.Format("MAIL FROM:{0}\r\n", emailAddressJndiPayload)), closeAfterResponse: false);
            cveScanner.SendAndReceive(Encoding.ASCII.GetBytes(string.Format("RCPT TO:{0}\r\n", emailAddressJndiPayload)), closeAfterResponse: false);
            cveScanner.SendAndReceive(Encoding.ASCII.GetBytes("DATA\r\n"), closeAfterResponse: false);
            cveScanner.SendAndReceive(Encoding.ASCII.GetBytes(string.Format("{0}\n", dataJndiPayload)), closeAfterResponse: false);
            cveScanner.SendAndReceive(Encoding.ASCII.GetBytes("QUIT\r\n"));

            return result;
        }
    }

    public static VulnerabilityScanResult ScanVmwareVcenter(string localIp, string remoteIp, ushort port, JndiPayloadType jndiPayloadType, string machineIdentifier)
    {
        WebClient webClient = new WebClient();

        string loginUri;
        if (s_httpsPorts.Contains(port))
        {
            loginUri = string.Format("https://{0}/ui/login", remoteIp);
        }
        else
        {
            loginUri = string.Format("http://{0}/ui/login", remoteIp);
        }

        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, cert, chain, sslPolicyErrors) => true;

        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(loginUri);
        request.Method = c_httpGet;
        request.AllowAutoRedirect = false;
        request.Timeout = 500;

        WebResponse result;

        try
        {
            result = request.GetResponse();
        }
        catch (System.Net.WebException e)
        {
            if (e.Message != "The operation has timed out")
            {
                throw;
            }

            throw new ExitCodeException(ExitCode.NoResponseFromServer);
        }

        string machineName;

        try
        {
            machineName = result.Headers.GetValues("Location")[0].Split('/')[6].Split('?')[0];
        }
        catch
        {
            throw new ExitCodeException(ExitCode.VmwareVcenterLoginPageError);
        }

        return ScanHttpTarget(localIp, remoteIp, port, new string[] { "X-Forwarded-For: {0}" }, "VmwareVcenter", machineIdentifier, string.Format("/websso/SAML2/SSO/{0}?SAMLRequest=", machineName), c_httpGet, jndiPayloadType);
    }

    public static VulnerabilityScanResult ScanHttpTarget(string localIp, string remoteIp, ushort port, string[] headers, string exploitIdentifier, string machineIdentifier, string uri, string httpCommand, JndiPayloadType jndiPayloadType, string userAgent = c_userAgent, string postData = null, string contentType = null)
    {
        VulnerabilityScanResult result = new VulnerabilityScanResult() { ExitCode = ExitCode.Success, Uri = uri, Port = port };

        using (TcpScanner cveScanner = new TcpScanner(remoteIp, port, connectTimeout: 400, receiveTimeout: 1,
            sendTimeout: 500, receiveBufferLength: (ushort)c_httpHeaderTemplate.Length, maxReads: 1))
        {
            if (!cveScanner.Connect())
            {
                cveScanner.Close();
                throw new ExitCodeException(ExitCode.FailedToConnect);
            }

            if (s_httpsPorts.Contains(port))
            {
                if (!cveScanner.CreateSslConnection(new RemoteCertificateValidationCallback(ValidateServerCertificate)))
                {
                    throw new ExitCodeException(ExitCode.SslWrapFailed);
                }
            }

            StringBuilder sb = new StringBuilder();

            string jndiPayload = GenerateJndiPayload(jndiPayloadType, JndiPayloadParameterType.Data, localIp, remoteIp, port, string.Format(c_machineIdExploitIdentifierFormat, machineIdentifier, exploitIdentifier));

            sb.Append(string.Format("{0} {1} HTTP/1.1\r\n", httpCommand, string.Format(uri, jndiPayload)));
            sb.Append(string.Format("Host: {0}:{1}\r\n", remoteIp, port));
            sb.Append(string.Format("User-Agent: {0}\r\n", string.Format(userAgent, jndiPayload)));
            sb.Append("Accept: */*\r\n");

            if (headers != null && headers.Length > 0)
            {
                result.Header = string.Join("\r\n", headers);
                foreach (string header in headers.Where(header => !string.IsNullOrEmpty(header)))
                {
                    string formattedHeader = header.Replace(c_remoteIpToken, remoteIp);
                    formattedHeader = string.Format(formattedHeader, jndiPayload);
                    sb.Append(formattedHeader);
                    sb.Append("\r\n");
                }
            }

            if (httpCommand == c_httpPost && !string.IsNullOrEmpty(postData) && postData.Length > 0)
            {
                string formattedPayload = string.Format(postData, jndiPayload);
                sb.Append(string.Format("Content-Length: {0}\r\n", formattedPayload.Length));
                if (string.IsNullOrEmpty(contentType))
                {
                    sb.Append("Content-Type: application/x-www-form-urlencoded\r\n");
                }
                else
                {
                    sb.Append(string.Format("Content-Type: {0}\r\n", contentType));
                }

                sb.Append("\r\n");
                sb.Append(formattedPayload);
            }
            else
            {
                sb.Append("\r\n");
            }

            byte[] httpResponse = cveScanner.SendAndReceive(Encoding.ASCII.GetBytes(sb.ToString()));
            if (httpResponse == null)
            {
                throw new ExitCodeException(ExitCode.NoResponseFromServer);
            }

            string httpStatus = Encoding.ASCII.GetString(httpResponse).Substring(c_httpVersion.Length + 1);

            result.HttpStatusCode = httpStatus;

            return result;
        }
    }

    public static void ScanExploitTargetsThread(string localIp, string remoteIp, JndiPayloadType jndiPayloadType, int index, List<VulnerabilityScanResult> threadResults, string machineIdentifier)
    {
        HashSet<ushort> closedPorts = new HashSet<ushort>();

        try
        {
            int targetsPerThread = s_exploitScanTargets.Length / Math.Min(c_numberOfThreads, s_exploitScanTargets.Length);
            for (int i = 0; i < targetsPerThread; i++)
            {
                ExploitScanTarget specificScanTarget = s_exploitScanTargets[(index * targetsPerThread) + i];

                ushort[] ports = specificScanTarget.Ports;
                if (ports == null || ports.Length == 0)
                {
                    ports = s_defaultHttpScanPorts;
                }

                string[] uris = specificScanTarget.Uris;
                if (uris == null || uris.Length == 0)
                {
                    uris = s_uris;
                }

                foreach (string uri in uris)
                {
                    ports = ports.Except(closedPorts).ToArray();
                    foreach (ushort port in ports)
                    {
                        try
                        {
                            threadResults.Add(ScanHttpTarget(localIp, remoteIp, port, specificScanTarget.Headers, specificScanTarget.ExploitIndicator, machineIdentifier, uri, specificScanTarget.HttpCommand, jndiPayloadType, c_userAgent, specificScanTarget.PostData, specificScanTarget.ContentType));
                        }
                        catch (ExitCodeException e)
                        {
                            threadResults.Add(new VulnerabilityScanResult() { ExitCode = e.ExitCode, Header = string.Join("\r\n", specificScanTarget.Headers), Uri = uri, Port = port });
                            if (e.ExitCode == ExitCode.FailedToConnect)
                            {
                                closedPorts.Add(port);
                            }
                        }
                        catch (Exception e)
                        {
                            threadResults.Add(new VulnerabilityScanResult() { ExitCode = ExitCode.ExceptionThrown, ExceptionMessage = e.Message, Header = string.Join("\r\n", specificScanTarget.Headers), Uri = uri, Port = port });
                        }
                    }
                }
            }
        }
        catch
        {
            threadResults.Add(new VulnerabilityScanResult() { ExitCode = ExitCode.ThreadExceptionThrown });
        }
    }

    public static List<VulnerabilityScanResult> ScanExploitTargets(string localIp, string remoteIp, JndiPayloadType jndiPayloadType, string machineIdentifier)
    {
        List<VulnerabilityScanResult> scanResults = new List<VulnerabilityScanResult>();

        List<Thread> threads = new List<Thread>();
        List<List<VulnerabilityScanResult>> threadsResults = new List<List<VulnerabilityScanResult>>();
        List<VulnerabilityScanResult> unifiedResults = new List<VulnerabilityScanResult>();

        int threadNumber = Math.Min(c_numberOfThreads, s_exploitScanTargets.Length);
        for (int i = 0; i < threadNumber; i++)
        {
            List<VulnerabilityScanResult> threadResult = new List<VulnerabilityScanResult>();
            int threadIndex = i;
            var t = new Thread(() => ScanExploitTargetsThread(localIp, remoteIp, jndiPayloadType, threadIndex, threadResult, machineIdentifier));
            t.Start();
            threads.Add(t);
            threadsResults.Add(threadResult);
        }

        for (int i = 0; i < threadNumber; i++)
        {
            if (!threads[i].Join(c_threadTimeoutMilliseconds))
            {
                unifiedResults = new List<VulnerabilityScanResult>() { new VulnerabilityScanResult() { ExitCode = ExitCode.ThreadTimeout } };
                break;
            }

            unifiedResults.AddRange(threadsResults[i]);
        }

        scanResults.AddRange(unifiedResults);

        foreach (ushort port in s_defaultSmtpScanPorts)
        {
            try
            {
                scanResults.Add(ScanSmtpServer(localIp, remoteIp, port, jndiPayloadType, machineIdentifier));
            }
            catch (ExitCodeException e)
            {
                scanResults.Add(new VulnerabilityScanResult() { ExitCode = e.ExitCode, Uri = "SMTP", Port = port });
            }
            catch (Exception e)
            {
                scanResults.Add(new VulnerabilityScanResult() { ExitCode = ExitCode.ExceptionThrown, ExceptionMessage = e.Message, Uri = "SMTP", Port = port });
            }
        }

        try
        {
            scanResults.Add(ScanVmwareVcenter(localIp, remoteIp, 443, jndiPayloadType, machineIdentifier));
        }
        catch (ExitCodeException e)
        {
            scanResults.Add(new VulnerabilityScanResult() { ExitCode = e.ExitCode, Uri = "VMwareVcenter", Port = 443 });
        }
        catch (Exception e)
        {
            scanResults.Add(new VulnerabilityScanResult() { ExitCode = ExitCode.ExceptionThrown, ExceptionMessage = e.Message, Uri = "VMwareVcenter", Port = 443 });
        }

        return scanResults;
    }

    public enum ExitCode
    {
        Success,
        SslWrapFailed,
        NoResponseFromServer,
        FailedToConnect,
        ExceptionThrown,
        ThreadExceptionThrown,
        ThreadTimeout,
        SmtpServerError,
        VmwareVcenterLoginPageError
    }

    public enum JndiPayloadType
    {
        Dns,
        DnsWithSpecificIpAndPort
    }

    private enum JndiPayloadParameterType
    {
        Data,
        EmailAddress
    }

    public class ExitCodeException : Exception
    {
        public ExitCode ExitCode;

        public ExitCodeException(ExitCode exitCode)
        {
            ExitCode = exitCode;
        }
    }

    public class VulnerabilityScanResult
    {
        public ExitCode ExitCode;
        public string HttpStatusCode;
        public string Header;
        public string ExceptionMessage;
        public string Uri;
        public ushort Port;
    }

    public class ExploitScanTarget
    {
        public string[] Headers = Array.Empty<string>();
        public string[] Uris;
        public string HttpCommand = c_httpGet;
        public ushort[] Ports;
        public string PostData;
        public string ExploitIndicator;
        public string UserAgent = c_userAgent;
        public string ContentType;
    }

    public class TcpScanner : IDisposable
    {

        private const ushort c_defaultReceiveBufferLength = 2048;

        private const ushort c_defaultMaxReads = 5;

        private const ushort c_defaultReceiveTimeout = 700;

        private const ushort c_defaultConnectTimeout = 500;

        private const ushort c_defaultSendTimeout = 500;

        private readonly ushort m_receiveBufferLength;

        private readonly ushort m_maxReads;

        private readonly ushort m_receiveTimeout;

        private readonly ushort m_connectTimeout;

        private readonly ushort m_sendTimeout;

        private readonly TcpClient m_tcpClient;

        private Stream m_networkStream;

        public IPAddress DestinationIpAddress { get; set; }

        public ushort DestinationPort { get; set; }

        public bool ConnectionStatus { get; private set; }

        public bool SslConnectionStatus { get; private set; }

        public TcpScanner(string ipAddress, ushort port, ushort connectTimeout = c_defaultConnectTimeout, ushort receiveTimeout = c_defaultReceiveTimeout, ushort sendTimeout = c_defaultSendTimeout, ushort receiveBufferLength = c_defaultReceiveBufferLength, ushort maxReads = c_defaultMaxReads)
            : this(IPAddress.Parse(ipAddress), port, connectTimeout, receiveTimeout, sendTimeout, receiveBufferLength, maxReads) { }

        public TcpScanner(IPAddress ipAddress, ushort port, ushort connectTimeout = c_defaultConnectTimeout, ushort receiveTimeout = c_defaultReceiveTimeout, ushort sendTimeout = c_defaultSendTimeout, ushort receiveBufferLength = c_defaultReceiveBufferLength, ushort maxReads = c_defaultMaxReads)
        {
            DestinationIpAddress = ipAddress;
            DestinationPort = port;
            ConnectionStatus = false;
            SslConnectionStatus = false;
            m_tcpClient = new TcpClient();
            m_connectTimeout = connectTimeout;
            m_receiveTimeout = receiveTimeout;
            m_sendTimeout = sendTimeout;
            m_receiveBufferLength = receiveBufferLength;
            m_maxReads = maxReads;
        }

        public bool Connect()
        {
            try
            {
                if (!m_tcpClient.ConnectAsync(DestinationIpAddress, DestinationPort).Wait(m_connectTimeout))
                {
                    Close();
                    return false;
                }
            }
            catch
            {
                Close();
                return false;
            }

            m_networkStream = m_tcpClient.GetStream();
            m_networkStream.ReadTimeout = m_receiveTimeout;
            m_networkStream.WriteTimeout = m_sendTimeout;
            ConnectionStatus = true;
            return true;
        }

        public bool CreateSslConnection(RemoteCertificateValidationCallback certificateValidateCallback, string host = null)
        {
            if (m_networkStream == null || !m_tcpClient.Connected || certificateValidateCallback == null)
            {
                Close();
                return false;
            }

            Stream previousStream = m_networkStream;
            int receiveTimeout = m_tcpClient.ReceiveTimeout;
            try
            {
                m_tcpClient.ReceiveTimeout = m_connectTimeout;
                m_networkStream = new SslStream(m_networkStream, false, certificateValidateCallback);
                if (m_networkStream == null || !m_tcpClient.Connected)
                {
                    Close();
                    return false;
                }

                host = host ?? DestinationIpAddress.ToString();
                ((SslStream)m_networkStream).AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
            }
            catch (AuthenticationException)
            {
                m_networkStream = previousStream;
                return false;
            }
            catch (IOException)
            {
                m_networkStream = previousStream;
                return false;
            }
            finally
            {
                m_tcpClient.ReceiveTimeout = receiveTimeout;
            }

            m_networkStream.ReadTimeout = m_receiveTimeout;
            m_networkStream.WriteTimeout = m_sendTimeout;
            SslConnectionStatus = true;

            return true;
        }

        public X509Certificate GetRemoteCertificate()
        {
            if (!SslConnectionStatus || m_networkStream == null || m_networkStream.GetType() != typeof(SslStream))
            {
                return null;
            }

            return ((SslStream)m_networkStream).RemoteCertificate;
        }

        public bool ScanPort(ushort port)
        {
            DestinationPort = port;
            bool results = Connect();
            Close();
            return results;
        }

        public byte[] SendAndReceive(byte[] payload, bool closeAfterResponse = true, bool readAllPackets = false)
        {
            try
            {
                if (m_networkStream == null)
                {
                    throw new Exception("Network stream is null");
                }

                if (payload == null || payload.Length == 0)
                {
                    return null;
                }

                try
                {
                    m_networkStream.Write(payload, 0, payload.Length);
                }
                catch (ObjectDisposedException)
                {
                    return null;
                }
                catch (System.IO.IOException)
                {
                    return null;
                }

                byte[] response;

                if (readAllPackets)
                {
                    response = ReadAllPackets();
                }
                else
                {
                    response = Read();
                }

                return response;
            }
            finally
            {
                if (closeAfterResponse)
                {
                    Close();
                }
            }
        }

        public bool Send(byte[] payload)
        {
            if (m_networkStream == null)
            {
                throw new Exception("Network stream is null");
            }

            if (payload == null || payload.Length == 0)
            {
                return false;
            }

            try
            {
                m_networkStream.Write(payload, 0, payload.Length);
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }

            return true;
        }

        public byte[] Read()
        {
            byte[] receiveBuffer = new byte[m_receiveBufferLength];
            byte[] response = null;
            int responseLength;
            try
            {
                responseLength = m_networkStream.Read(receiveBuffer, 0, receiveBuffer.Length);

                if (responseLength > 0)
                {
                    response = receiveBuffer.Take(responseLength).ToArray();
                }
            }
            catch (System.IO.IOException)
            {
            }
            catch (ObjectDisposedException)
            {
            }

            return response;
        }

        public byte[] ReadAllPackets()
        {
            byte[] receiveBuffer = new byte[m_receiveBufferLength];
            byte[] response = null;
            int responseLength;
            try
            {
                int i = 0;
                do
                {
                    responseLength = m_networkStream.Read(receiveBuffer, 0, receiveBuffer.Length);

                    if (responseLength > 0)
                    {
                        if (response == null || response.Length == 0)
                        {
                            response = receiveBuffer.Take(responseLength).ToArray();
                        }
                        else if (response.Length < m_receiveBufferLength)
                        {
                            byte[] currentResponse = receiveBuffer.Take(responseLength).ToArray();
                            int newResponseLength = currentResponse.Length;
                            if (newResponseLength + response.Length > m_receiveBufferLength)
                            {
                                newResponseLength = m_receiveBufferLength - response.Length;
                            }

                            byte[] newResponse = new byte[response.Length + newResponseLength];
                            Buffer.BlockCopy(response, 0, newResponse, 0, response.Length);
                            Buffer.BlockCopy(currentResponse, 0, newResponse, response.Length, newResponseLength);
                            response = newResponse;
                        }
                        else
                        {

                            return response;
                        }
                    }

                    i++;
                }
                while (i < m_maxReads && responseLength != 0);
            }
            catch
            {
            }

            return response;
        }

        public byte[] SendAndReceive(string payload)
        {
            return SendAndReceive(Encoding.UTF8.GetBytes(payload));
        }

        public void Close()
        {
            if (m_networkStream != null)
            {
                m_networkStream.Close();
            }

            if (m_tcpClient != null)
            {
                m_tcpClient.Close();
            }

            ConnectionStatus = false;
        }

        public void Dispose()
        {
            Close();
            if (m_tcpClient != null)
            {
                m_tcpClient.Dispose();
            }

            if (m_networkStream != null)
            {
                m_networkStream.Dispose();
            }
        }
    }
}
"@


Write-Host "Checking if log4j ff is on"
$OnboardingDataBody = Get-Config

$CloudGateway = $OnboardingDataBody.geoLocationUrl
if ($CloudGateway[$CloudGateway.Length - 1] -eq "/")
{
    $CloudGateway = $CloudGateway.Substring(0, $CloudGateway.Length - 1)
}

$MachineId = $OnboardedDataJson = Read-RegistryKey 'senseId' 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection'
$OrgId = $OnboardingDataBody.orgId

$FfResult = Invoke-WebRequestWithRootCaVerification "$CloudGateway/commands/isenabled?machineId=$MachineId&orgId=$OrgId"
if ($FfResult -eq "false")
{
    Write-Host "FF is disabled"
    exit
}
if ($FfResult -ne "true")
{
    Write-Host "FF is undefined $FfResult"
    exit
}

Write-Host "FF is enabled"


Add-Type -TypeDefinition $CVE202144228ScannerSource -Language CSharp -IgnoreWarnings
Write-Host "Initiating local log4j vulnerability scan $ScriptName $ScriptVersion"
$StartTime = Get-Date 

Scan-CVE-2021-44228 -LocalIP $null -RemoteIP "127.0.0.1" -RemoteMac $null

$Timespan = New-TimeSpan -Start $StartTime -End (Get-Date) | Select-Object -ExpandProperty TotalSeconds 
$ProcessInfo = (Get-Process -Id $Pid)
$CpuUsage = $ProcessInfo.CPU #The amount of processor time that the process has used on all processors, in seconds
$CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
$CpuTimespan = $Timespan*$CpuCores
$CpuLoadPercentage = [Decimal]::Round(($CpuUsage/$CpuTimespan)*100, 2)
$MemoryUsage = $ProcessInfo.WS/1024 #MemoryUsage in KB 

Write-Host "Writing telemtry" 

Write-Host "Duration ->" $Timespan 
Write-Host "Memory -> " $MemoryUsage"Kb"
Write-Host "Cpu -> " $CpuLoadPercentage
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8HNtiQ+om6nQZ
# RFNXH8kmCSCkIPKnd7WxiPHRB2GSCKCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIMnagqCgNg7IUvUep123KpnjtXu0MOqkEq9bT3fP0236
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEATYUPjW9Kxhjd
# uy+KWz3aNVte/k2aY/IFO5hzld+HVthFnaNJHT/oeoPF3oNwBWyRls+UfQdZJG1P
# /iITa18G7Eu19k80EX6qQdW96ETmFCBpXg5x749EB7OeltvVH1YhEgCj26mHKbYR
# R1hkJMZ3T6qDcEGgGDz1sbeJNDQotPnUTeShdfd0k+8hEau5pjaxteflKapXKVfb
# FnGWkw9hD1TEGM7tjE39yZlGS1ok5+bTNexA+KDJmCt9+WkQtt1+BQdYBpHsXwxb
# GagVHfG+hnJXgbhL0eevlqaMjvFPgWdzCNNg/L8EI1FQT7JoBhetlNtkAMpm7H79
# t2B649/ExaGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAwup+g0eqv
# fwtrLabcAhjpEnlNDc+iVgdxdcCdKkX9iQIGYxIJsT4OGBMyMDIyMDkyMDA5NTcx
# Ni4yMDhaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
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
# MC8GCSqGSIb3DQEJBDEiBCCbEqlL3Vl9qpEST7UGI4VmVtDJ4JU72flcjeR9J4z6
# iDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGbp3u2sBjdGhIL4z+ycjtzS
# pe4bLV/AoYaypl7SSUClMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGILs3GgUHhvCoAAQAAAYgwIgQgvdHPxo5uBQt9dco6MqwieVju
# 71dTb23p9he3LnoP000wDQYJKoZIhvcNAQELBQAEggIAHrG95fjf8Af05nBilz2i
# oaaSCuFCchD339ui0NW1JMZLDx0fFxdzP3MdiTPBE1Zr65nnQGmrchPXMZt2PbQ6
# EcZV9/LuigwV4+L2kcXa7VCyV/C3DGnlHOqxoxHApGxpxZZ53aLAsaUMGdWfZAld
# rn0vCmtp07jxFCCeIqS5KAqtP8BMigGMorlp3+cR5NFBuvigXCGWqjEonrYF3SCs
# j9c0SFrmTUUFHehFiBrNau56zYO47TK+nDmGcf5RY8nJi8tG8wcDa+jeaRVRu8YR
# jIO/VvA4kVUI6CPtsZFEVFoU2KU8UqFJH+XQhA/b6t8gYkc657shqck/Q3qJXR8b
# mBXMQRX4yulnsiuzyu9nMuTGrZ+rTOYu4mDoynFM5BfxZjD1sf6lmZ7/os8MJjUt
# KCsMd6dqamZ6b3gS9UNaTys86tpitytSLKgDjPbRlafiLviPLTxKovKi1qP5iZ2V
# QsstU5xRlfVwQkZFz+mz6IIJBe6388Jm8d/6swhlb2p4kV9BTubOHGgtSderw+vw
# 3pQay9US28NsxWtuSPGXkOex97PiE6tGiJn2vnFVXXDx73jqq+JNQSkwJJrjTLhh
# ajOFbl7otuFoWKNO8QU4taIrKOzKgOa5pkc/xyKlFvTeqiuXLdUh2WMEI9TQ2MX4
# 0rQZAhV6mYm8luYKZBRDK4k=
# SIG # End signature block
