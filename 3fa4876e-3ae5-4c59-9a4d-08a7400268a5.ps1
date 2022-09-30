#region params

# Example of passing parameters: .\GetProductsInformationsFromFiles.ps1 -VerbosePreference Continue -enablePiiOutput
# This will make verbose level messages write to console and trigger results writing to console

param (
    [switch]$enablePiiOutput = $false,
    [string]$VerbosePreference = "SilentlyContinue"
 )

#endregion params

$ScriptStartTime = Get-Date
write-host "Script start time $($ScriptStartTime.ToUniversalTime())"

#region output interface

$Source = @"
                        using System;
                        using System.Text;
                        using System.Diagnostics.Tracing;
                        using Microsoft.PowerShell.Commands;
                        public static class EtwProvider
                        {
                            public static EventSource log = new EventSource("Microsoft.Windows.Sense.CollectionEtw", EventSourceSettings.EtwSelfDescribingEventFormat);
                        }

                        [EventData]
                        public class FileProductMetadataEvent
                        {
							public string ExecPath { get; set; }  

							public string ProductVersion { get; set; } 

							public string ProductVendor { get; set; } 

                            public string ProductName { get; set; } 

							public string Source { get; set; } 
                        }

                        [EventData]
                        public class FileProductMetadataIndexingEvent
                        {
							public string ExecPaths { get; set;}
                        }
"@


#endregion output interface 

#region initialization

# init the event type

Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings
# load ZIP methods
Add-Type -AssemblyName System.IO.Compression.FileSystem
$etwProvider = [EtwProvider]::log
$dotnetRootCertificateThumbprint = "8F43288AD272F3103B6FB1428485EA3014C0BCFE"

$shell = New-Object -ComObject WScript.Shell
$isWmiDeprecated = (Get-Host).Version.Major -ge 3  # Get-WmiObject has been deprecated since pwsh
if ($isWmiDeprecated) {
    Set-Alias -Name Get-WmiObject -Value Get-CimInstance
}
# Regular expression to extract normal windows path of folders
# Examples:
# "C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p" -> "C:\WINDOWS\system32\svchost.exe"
# "C:\WINDOWS\System32\DriverStore\FileRepository\fn.inf_amd64_62cf4e1fc023f9a9\driver\TPHKLOAD.exe" -> "C:\WINDOWS\System32\DriverStore\FileRepository\fn.inf_amd64_62cf4e1fc023f9a9\driver\TPHKLOAD.exe"
# "\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe\"" -> "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
# "C:\Users\robelio\AppData\Local\Apps\2.0\G73TRZOM.2JK\XTXO8N1K.8JJ\kust..tion_a7cae1245bd53d87_0001.0000_984990bb36c1582d\Kusto.Explorer.exe.FriendlyAppName" -> "C:\Users\robelio\AppData\Local\Apps\2.0\G73TRZOM.2JK\XTXO8N1K.8JJ\kust..tion_a7cae1245bd53d87_0001.0000_984990bb36c1582d\Kusto.Explorer.exe"
$FolderRx = New-Object System.Text.RegularExpressions.Regex('([a-z]:\\(?:[^\/:*?\"<>|\r\n]+))\\',
    ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))

# Regex to extract MANIFEST.MF files
$ImpTitleRx = New-Object System.Text.RegularExpressions.Regex('Implementation-Title:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$SpecTitleRx = New-Object System.Text.RegularExpressions.Regex('Specification-Title:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$ImpVendorRx = New-Object System.Text.RegularExpressions.Regex('Implementation-Vendor:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$SpecVendorRx = New-Object System.Text.RegularExpressions.Regex('Specification-Vendor:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$ImpVersionRx = New-Object System.Text.RegularExpressions.Regex('Implementation-Version:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$SpecVersionRx = New-Object System.Text.RegularExpressions.Regex('Specification-Version:.+?([^"\r\n]{1,200})', [System.Text.RegularExpressions.RegexOptions]::Compiled)

# dotnet output regex
$dotnetSdkRx = New-Object System.Text.RegularExpressions.Regex('^([^\s]{1,200}) \[(.{1,200})\]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$dotnetRuntimeRx = New-Object System.Text.RegularExpressions.Regex('^Microsoft\.([^\s]{1,200}) ([^\s]{1,200}) \[(.{1,200})\]', ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))

# version regex, takes only Major.Minor.Build
$VersionRx = New-Object System.Text.RegularExpressions.Regex('(.+?\..+?\.[\d\w]+)',
    ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))

# Folder patterns not scanned
$bannedFolders = @(
    ":\windows"
)

# Retrieval of Start Menues directory
try {
    $CommonStartMenu = [Environment]::GetFolderPath("CommonStartMenu")
    # Retrieval of *.lnk file from start menues
    $commonShortcuts = Get-ChildItem -LiteralPath $CommonStartMenu -Recurse -Filter *.lnk -ErrorAction SilentlyContinue
} catch {
    $commonShortcuts = @()
    Write-Verbose "Could not retrieve CommonStartMenu Path, Exception: $_"
}

try {
    $UsersStartMenu = Get-WmiObject win32_userprofile | Select-Object localpath | ForEach-Object { join-path $_.localpath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs" }
    $usersShortcuts = Get-ChildItem -LiteralPath $UsersStartMenu -Recurse -Filter *.lnk -ErrorAction SilentlyContinue
}
catch {
    $usersShortcuts = @()
    Write-Verbose "Could not retrieve UserStartMenu Path, Exception: $_"
}

# Services WmiObject
try {
    if ($isWmiDeprecated) {
        $services = Get-WmiObject Win32_Service
    }
    else {
        $services = Get-WmiObject -EnableAllPrivileges Win32_Service
    }
    
}
catch {
    $services = @()
    Write-Verbose "Could not retrieve Services, Exception: $_"
}

# Initialization of data-structures
$folderScanner = @{}
$visitedBinaries = New-Object 'Collections.Generic.HashSet[string]'
$filesEvents = New-Object 'Collections.Generic.Dictionary[string, FileProductMetadataEvent]'
$filesPaths = New-Object System.Collections.Generic.HashSet[string]
$indexingEvent = New-Object FileProductMetadataIndexingEvent

#endregion initialization

#region logic

# Generate unique name per product for collision detection on $filesEvents Dictionary
function UniqueName($fileMetadata) {
	# Take version up to build (3rd value), for better aggregation of products.
	$versionMatch = $VersionRx.Match($fileMetadata.ProductVersion)
	$version = if ($versionMatch.Success) { $versionMatch.Groups[1].Value } else { $fileMetadata.ProductVersion }
	return "$($fileMetadata.ProductName)-_-$($fileMetadata.ProductVendor)-_-$version"
}

function VerifyBinarySignature($filePath, $fileRootThumbprint) {
    Write-Host "Validating $filePath Certificate"
    $Authenticode = Get-AuthenticodeSignature $filePath
    if ($Authenticode.Status -ne "Valid" -or $null -eq $Authenticode.Status) {
        Write-Error "Failed to authenticate file"
        return $false
    }
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain 
    if (-not $chain.Build($Authenticode.SignerCertificate)) {
        Write-Error "Failed to build certificate chain"
        return $false
    }

    $chainLength = $chain.ChainElements.Count
    $thumbprintMatch = ($chain.ChainElements[$chainLength - 1].Certificate.Thumbprint -eq $fileRootThumbprint)
    if (-not $thumbprintMatch) {
        Write-Error "Root Certificate Thumbprint mismatch: $($chain.ChainElements[$chainLength - 1].Certificate.Thumbprint) is not $($fileRootThumbprint)"
        return $false
    }
    return $true
}

# Go over all collected folders, scan them for matching files and retrieve full paths,
# Concatenate all collected sources from hashset to a comma delimited string
# Populate the fileEvents dictionary
function ExtractFilesFromCollectedFolders() {
    foreach ($folder in $folderScanner.Keys) {
        try {
            $execFiles = Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue | Where-Object { '.exe' -eq $_.Extension }
            $jarFiles = Get-ChildItem -LiteralPath $folder -File -Force  -ErrorAction SilentlyContinue | Where-Object { ('.jar', '.war', '.ear') -contains $_.Extension}
            $sources = $folderScanner[$folder] -join ","  # values has hashet of sources
            PopulateFileEvents ${function:\GetExecMetadataFromPath} $execFiles $sources
            PopulateFileEvents ${function:\GetJARMetadataFromPath} $jarFiles $sources
        } catch {
            Write-Error "Failed to retrieve files from $folder."
            Write-Verbose "$_"
        }
    }
}

# Given a Metadata extraction function and the filepaths matching the extraction
# (.exe or .jar extraction), go over all file paths, extract metadata,
# attach sources string, compose a unique name,
# add to the fileEvents dictionary a key with unique name, and value of metadata
function PopulateFileEvents($function, $filePaths, $sources) {
    foreach ($filePath in $filePaths) {

        # Try to add the filepath to the visited list. If it returns falls, the item is already there and we don't need to check it again
        if (-not $visitedBinaries.Add($filePath))
        {
            continue
        }        
        
        try {
            $fileMetadata = Invoke-Command $function -ArgumentList $filePath.FullName, $sources
            if ($fileMetadata) {
                $uniqueName = UniqueName $fileMetadata
                if (-NOT $filesEvents.ContainsKey($uniqueName)) {
                    $filesEvents.Add($uniqueName, $fileMetadata)
                }
            } 
        } catch {
            # File can't be extract
            Write-Error "File $($filePath.FullName) excepted on extraction: $_"
        }
    }
}

# Get a raw string of paths, use regex to match all paths,
# Test for existence, normalize, get parent if path is a leaf
# Add to a [string]FolderPath->[Hashset<string>]Sources hashmap,
# create a hashset if needed
# ignore paths that are in the banned list of paths
function AddFolderScan($rawPath, $source) {
    $folders = ExtractRxForAllFolders $rawPath
    foreach ($folder in $folders) {
        if (Test-Path -LiteralPath $folder){
            $folder = [System.IO.Path]::GetFullPath($folder)  # normalizing paths like, ~,.,C:\PROGRA~3\
            if (Test-Path -LiteralPath $folder -PathType Leaf) {
                $folder = Split-Path $folder
            }
            # Check if entry exists and has a hashset as value, if entry exists then its not banned
            if ($folderScanner.ContainsKey($folder)) {
                $folderScanner[$folder].Add($source)
            }
            else {
                foreach ($bannedFolder in $bannedFolders) {
                    if (-NOT $folder.ToLower().Contains($bannedFolder)) {
                        $set = New-Object System.Collections.Generic.HashSet[string]
                        $set.Add($source)
                        $folderScanner[$folder] = $set
                    }
                }
            }
        }
    }
}

# Extract Dotnet tool, sdks and runtime
function ExtractDotNet() {
    try {
        $dotnetToolPath = (Get-Command dotnet).Path
        AddFolderScan $dotnetToolPath "Dotnet"
        $binaryStreamForLock = [System.IO.File]::Open($dotnetToolPath, 'Open', 'Read', 'Read')
        $verification = VerifyBinarySignature $dotnetToolPath $dotnetRootCertificateThumbprint
        if ($true -eq $verification) {
            # Get sdks
            $sdksOutput = Invoke-Expression "& '$dotnetToolPath' --list-sdks"
            ForEach ($line in $sdksOutput)
            {
                $match = $dotnetSdkRx.Match($line)
                if ($match.Success -AND $match.Groups[1].Success -AND $match.Groups[2].Success) {
                    $fileMetadata = New-Object FileProductMetadataEvent;
                    $fileMetadata.ExecPath = [IO.Path]::Combine($match.Groups[2].Value.Trim(), $match.Groups[1].Value.Trim(), ".version")
                    $fileMetadata.ProductVersion = $match.Groups[1].Value.Trim()
                    $fileMetadata.ProductVendor = "Microsoft"
                    $fileMetadata.ProductName = ".net_core_sdk"
                    $fileMetadata.Source = "Dotnet"
                    $uniqueName = UniqueName $fileMetadata
                    if (-NOT $filesEvents.ContainsKey($uniqueName)) {
                        $filesEvents.Add($uniqueName, $fileMetadata)
                    }
                }
            }

            $runtimeOutput = Invoke-Expression "& '$dotnetToolPath' --list-runtimes"
            ForEach ($line in $runtimeOutput) {
                $match = $dotnetRuntimeRx.Match($line)
                if ($match.Success -AND $match.Groups[1].Success -AND $match.Groups[2].Success -AND $match.Groups[3].Success) {
                    $fileMetadata = New-Object FileProductMetadataEvent;
                    $fileMetadata.ExecPath = [IO.Path]::Combine($match.Groups[3].Value.Trim(), $match.Groups[2].Value.Trim(), ".version")
                    $fileMetadata.ProductVersion = $match.Groups[2].Value.Trim()
                    $fileMetadata.ProductVendor = "Microsoft"
                    $fileMetadata.ProductName = "$($match.Groups[1].Value.Trim())"
                    $fileMetadata.Source = "Dotnet"
                    $uniqueName = UniqueName $fileMetadata
                    if (-NOT $filesEvents.ContainsKey($uniqueName)) {
                        $filesEvents.Add($uniqueName, $fileMetadata)
                    }
                }
            }
        }
        $binaryStreamForLock.Close()
    } catch {
        Write-Verbose "Dotnet tool could not be found."
    }
}


# Extract only the manifest file from java archive file
# This file contains similar metadata to the one found on executables
function ExtractManifest($path) {
    try {
        # open ZIP archive for reading
        $zip = [System.IO.Compression.ZipFile]::OpenRead($path)

        $ze = $zip.GetEntry('META-INF/MANIFEST.MF')
        $reader = New-Object System.IO.StreamReader($ze.Open(), [System.Text.Encoding]::UTF8)
        $ret = $reader.ReadToEnd();

        $zip.Dispose() # close ZIP file
        return $ret
    } catch {
        Write-Verbose "JAR/WAR/EAR file error for path: $path, Exception: $_"
        return $null
    }
}

# Parse MANIFEST.MF file, Fail if ProductName or Vendor are missing
function GetJARMetadataFromPath($targetPath, $source) {
    if ((-NOT [string]::IsNullOrWhiteSpace($targetPath)) -And (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        $fileMetadata = New-Object FileProductMetadataEvent;
        $manifestData = ExtractManifest $targetPath 
        if (-NOT [string]::IsNullOrWhiteSpace($manifestData)) {
            $fileMetadata.ExecPath = $targetPath
            $fileMetadata.ProductVersion = (ExtractRxFromText $manifestData ($ImpVersionRx, $SpecVersionRx)).Trim()
            $fileMetadata.ProductVendor = (ExtractRxFromText $manifestData ($ImpVendorRx, $SpecVendorRx)).Trim()
            $fileMetadata.ProductName = (ExtractRxFromText $manifestData ($ImpTitleRx, $SpecTitleRx)).Trim()
            $fileMetadata.Source = $source

            if ([string]::IsNullOrEmpty($fileMetadata.ProductName) -Or [string]::IsNullOrEmpty($fileMetadata.ProductVendor)) {
                Write-Verbose "Cannot create a CollectedFile object from: $targetPath, vendor or title are missing"
                return $null
            } else {
                return $fileMetadata
            }
        }
    }
    # Empty path: ignore
    # Path is directory
    # Bad Manifest
    # Not supported file type
    return $null
}

# Get FileVersionInfo for executable, Fail if ProductName or Vendor are missing
function GetExecMetadataFromPath($targetPath, $source) {
    if ((-NOT [string]::IsNullOrWhiteSpace($targetPath)) -And (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        $fileMetadata = New-Object FileProductMetadataEvent;

        # Metadata 
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($targetPath)
        if ([string]::IsNullOrWhiteSpace($versionInfo.ProductName) -Or [string]::IsNullOrWhiteSpace($versionInfo.CompanyName)) {
            Write-Verbose "Cannot create a CollectedFile object from: $targetPath, vendor or title are missing"
            return $null
        }
        $fileMetadata.ExecPath = $targetPath
        # This null check allows us to send products without versions
        $fileMetadata.ProductVersion = if ($versionInfo.ProductVersion) { $versionInfo.ProductVersion.Trim() } else { [string]::Empty }

        $fileMetadata.ProductVendor = $versionInfo.CompanyName.Trim()
        $fileMetadata.ProductName = $versionInfo.ProductName.Trim()
        $fileMetadata.Source = $source

        return $fileMetadata
    } 
    # Empty path: ignore
    # Path is directory
    # Not supported file type
    return $null
}

# Iterates through Regular Expressions array,
# returning on the first regex match (greedy/lazy) that can be used to extract a MatchGroup from the text.
# Regex should have only 1 capture group
function ExtractRxFromText($text, [Regex[]]$regexArray) {
    if (-NOT [string]::IsNullOrWhiteSpace($text))
    {
        foreach ($regex in $regexArray)
        {
            $match = $regex.Match($text)
            if ($match.Success -AND $match.Groups[1].Success)
            {
                return $match.Groups[1].Value;
            }
        }
    }

    return [string]::Empty;
}

# Matches all Windows path like strings from a raw text
# return an ArrayList of all matches,
# important for parsing paths passed to executable as arguments
function ExtractRxForAllFolders($text) {
    [System.Collections.ArrayList]$folders = @()
    if (-NOT [string]::IsNullOrWhiteSpace($text)) {
        $match = $FolderRx.Match($text)
        while ($match.Success -AND $match.Groups[1].Success) {
            $null = $folders.Add($match.Groups[1].Value)
            $match = $match.NextMatch()
        }
    }
    return $folders
}

#region Getting events
foreach ($shortcut in $commonShortcuts) {
    try { 
        $target = $shell.CreateShortcut($shortcut.FullName)
        $null = AddFolderScan $target.TargetPath "CommonShortcuts"
        # Taking arguments as well for java.exe -jar scenarios
        $null = AddFolderScan $target.Arguments "CommonShortcuts"
    }
    catch {
        Write-Error "An error getting exectuables metadata for common shortcuts." -TargetObject $shortcut
    }
}

foreach ($shortcut in $usersShortcuts) {
    try {
        $target = $shell.CreateShortcut($shortcut.FullName)
        $null = AddFolderScan $target.TargetPath "UsersShortucts"
        $null = AddFolderScan $target.Arguments "UsersShortucts"
    }
    catch {
        Write-Error "An error getting exectuables metadata for user shortcuts." -TargetObject $shortcut
    }
}

try {
    # Iterate over services from the WMI-object, extract path name
    foreach ($service in $services) {
        $null = AddFolderScan $service.PathName "Services"
    }
} catch {
    Write-Error "An error reading services WMIObject. Exception: $_"
}

#endregion Getting events

#Extracting DotNet runtimes and sdks
ExtractDotNet

#region folder pass without duplicates
ExtractFilesFromCollectedFolders
# filesEvents and filePaths are now populated without duplicates
#endregion folder pass without duplicates

#endregion logic


#region firing the events

foreach ($evt in $filesEvents.Values) {
    $etwProvider.Write("FileProductMetadataEvent", $evt)  

    $null = $filesPaths.Add($evt.ExecPath)
}

$indexingEvent.ExecPaths = ConvertTo-Json $filesPaths -Compress
$etwProvider.Write("FileProductMetadataIndexingEvent", $indexingEvent) 

if ($enablePiiOutput) 
{
    Write-Output $filesEvents | Format-Table -Wrap -Property @{ Name = "Product-Vendor-Version Tuple"; Expression = { $_.Key } }, @{ Name = "Sources"; Expression = { $_.Value.Source } }, @{ Name = "Path"; Expression = { $_.Value.ExecPath } }
    Write-Output "Total Collected: $($filesEvents.Count)"
}

#endregion firing the events

try {
    # Print script execution time
	$ScriptEndTime = Get-Date
	$diff = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
	Write-Host "Script elapsed $($diff.TotalSeconds) seconds"
} catch {
    Write-Error "Failed getting script elapsed time"
}

# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBLniOdVgj2xz16
# 2oLAahH2QXRNImjXZ/yuwrqH95ubg6CCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIEg19o/SXWM60m8afITFHGj65p5yInvjKh3GSepPRxaH
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAIXu6mro84eKD
# L6htwX2biS6NoORsV+Z22TdnZzIcueNGWha8oqhfIruGVOM9zh5w8vXwUViWjziY
# +Qcnb3oksLD/Mypdy35P111F00kZIUzl6b3LM0U3me3xqDY8HAYmwi+gUOCliEOA
# CfDEFre8oMaHTHhU+j2GNRZbSNQYwOEUwzc3WBUANbAVVg1Cf0ZKkJvoCCScenxJ
# BDB7M1+RyRZ87+dORgVOdU6iSKKIzT12PkLJPqO7Wjpfw+OnNd/sGoxFx3N0N1sa
# AZ3qsulpaDN+N1p46XtUUpTj+Ejxb2CkVzSomCsVvdCuwO45Yxmpr3PpxnSLfs6J
# HYaevoZp0aGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBWafFy0ss9
# hVI7faxeDTCqlk3m+ZA/s9FvDxHk7RywGgIGYxFhFtCrGBMyMDIyMDkyMDA5NTcy
# Ni40MzZaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
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
# MC8GCSqGSIb3DQEJBDEiBCBBR7e4p/n7CmKpat2+vaMLA/FZ5V1kTVDoJBWxU6OK
# uDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIBqZiOCyLAhUxomMn0QEe5ux
# WtoLsVTSMNe5nAIqvEJ+MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGGeOUZifgkS8wAAQAAAYYwIgQgKrQqo9OIk0hrsMyW2GCtrT+q
# XNtdZTAEA781WGfDPCAwDQYJKoZIhvcNAQELBQAEggIAJ4Vj6L7rLBctTnbf6W7A
# 71L0mAkqD+F0kavnKkFA+IkNiDyrbKo/CAtDZ8+mQYOEKZNnmdVU566Q/RsBqflL
# y+hxJV4EaHLaWfF+Y5kguiPz7Tq87xg3bxrepJaIT010py7gi6G8q0X7WYODDrv7
# Ayztx5+1TJyc/2ZAEfWGTiAdMaxP6Qw8dAx+QDTNRSQZcMGrK57iNk/kCPvRPCkq
# ZgRR6i4EOh4tiwOoNfy9FiKLDWBsd7Nnwx3yr0/8gInkfLLa91+8R7x5jprh9AdR
# RK10TkoylN8tIpCJutvc5iqDYoTaFHeVU7liKKFVx4FbJOqFr5nBqS7/D3+7DTKQ
# QyvvNgNgqXOfRHckEurobO/Za7oefQVrmTTy55ZXnTxAtVLMdbyvau3+CCaiDWnT
# +GUkBy3AivqGVuq/Vr7XVALJw6+HlWUfHXIYq/XRLDo0CHtnrjSwjVbav3nIXaSA
# VtXd9IJIXf2Tc7dV9Go5x/BoUdFSflsZTUgNHHrlgoSaBL3ybqW9u/usLYIW+xHS
# WiV8PqkvUk+NEZOaBdPf7QG4ny8K8kP9FGMa3HGwq82iZNuARQzTAKLUhtTeYV8S
# o7lGaU1g2sg2XGE90KxYXApii55Z52hMHjBqzlJqd1SDgP/nCz9VNu9g4ic9YqGb
# 8o4CFpSefUeGauQbzGMmNRs=
# SIG # End signature block
