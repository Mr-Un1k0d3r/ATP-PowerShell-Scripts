$Source = @"
                        using System;
                        using System.Text;
                        using System.Diagnostics.Tracing;
                        using Microsoft.PowerShell.Commands;
                        
                        public static class BrowserExtensionEtwProvider
                        {
                            public static EventSource log = new EventSource("Microsoft.Windows.Sense.BrowserExtensionCollection", EventSourceSettings.EtwSelfDescribingEventFormat);
                        }

                        [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
                        public class CollectedExtension
                        {
                            public CollectedExtension() {}

                            public String User { get; set; }

                            public String Id { get; set; }

                            public String TargetSoftware { get; set; }

                            public String Vendor { get; set; }

                            public String Name { get; set; }

                            public String Description { get; set; }

                            public String Version { get; set; }

                            public String VersionName { get; set; }

                            public bool Enabled { get; set; }

                            public String Permissions { get; set; }

                            public String OptionalPermissions { get; set; }

                            public String ActivePermissions { get; set; }

                            public String GrantedPermissions { get; set; }

                            public String InstallationTime { get; set; }

                            public bool InstalledByDefault { get; set; }

                            public bool InstalledFromStore { get; set; }

                            public bool InstalledByOEM { get; set; }

                            public bool IsApp { get; set; }

                            public int LocationFlags { get; set; }

                            public String InstallationPath { get; set; }
                        }

                        [EventData] 
                        public class CollectedExtensionsIndex
                        {
							public String Index { get; set; }
                            
                            public String TargetSoftware { get; set; }

                            public CollectedExtensionsIndex(string targetSoftware, string index)
                            {
						        this.Index = index;
                                this.TargetSoftware = targetSoftware;
                            }
                        } 
"@

Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings
$collectedExtensionProvider = [BrowserExtensionEtwProvider]::log

##########################################################################

class BrowserConfig {
    [String]$TargetSoftware
    [String]$Path
    [String[]]$Index = @()
}

$chromiumBrowsersConfig = @(
    New-Object -TypeName BrowserConfig -Property @{TargetSoftware="chrome"; Path="AppData\Local\Google\Chrome\User Data\"};
    New-Object -TypeName BrowserConfig -Property @{TargetSoftware="edge"; Path="AppData\Local\Microsoft\Edge\User Data\"};
)

$firefoxConfig = New-Object -TypeName BrowserConfig -Property @{TargetSoftware="firefox"; Path="AppData\Roaming\Mozilla\Firefox\Profiles\"};

function Parse-Chromium-Extension()
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetSoftware,
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$ExtensionId,
        [Parameter(Mandatory=$true)]
        [System.Object]$ExtensionProps
    )

    $result = New-Object -TypeName CollectedExtension
    $result.User = $User
    $result.Id = $ExtensionId
    $result.TargetSoftware = $TargetSoftware
    $result.Vendor = $ExtensionProps.manifest.author
    $result.Name = $ExtensionProps.manifest.name
    $result.Description = $ExtensionProps.manifest.description
    $result.Version = $ExtensionProps.manifest.version
    $result.VersionName = $ExtensionProps.manifest.version_name
    $result.Enabled = $ExtensionProps.state -eq 1
    #Permissions
    $result.Permissions = $ExtensionProps.manifest.permissions | ConvertTo-Json
    $result.OptionalPermissions = $ExtensionProps.manifest.optional_permissions | ConvertTo-Json
    $result.ActivePermissions = $ExtensionProps.active_permissions | ConvertTo-Json
    $result.GrantedPermissions = $ExtensionProps.granted_permissions | ConvertTo-Json
    #End Permissions
    $result.InstallationTime = $ExtensionProps.install_time
    $result.InstalledByDefault = $ExtensionProps.was_installed_by_default
    $result.InstalledFromStore = $ExtensionProps.from_webstore
    $result.InstalledByOEM = $ExtensionProps.was_installed_by_oem
    $result.IsApp = $null -ne $ExtensionProps.manifest.app
    $result.LocationFlags = $ExtensionProps.location
    $result.InstallationPath = $ExtensionProps.path
                                

    return $result
}

function Parse-Firefox-Extension()
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [System.Object]$ExtensionProps
    )

    $result = New-Object -TypeName CollectedExtension
    $result.User = $User
    $result.Id = $ExtensionProps.id
    $result.TargetSoftware = "firefox"

    $result.Vendor = $ExtensionProps.defaultLocale.creator
    $result.Name = $ExtensionProps.defaultLocale.name
    $result.Description = $ExtensionProps.defaultLocale.description
    $result.Version = $ExtensionProps.version
    $result.VersionName = $ExtensionProps.version
    $result.Enabled = $ExtensionProps.active
    $result.Permissions = $ExtensionProps.userPermissions | ConvertTo-Json
    $result.OptionalPermissions = $ExtensionProps.optionalPermissions | ConvertTo-Json
    $result.InstallationTime = $ExtensionProps.installDate
    $result.InstallationPath = $ExtensionProps.path

    # These fields are not relevant for firefox
    # ActivePermissions, GrantedPermissions, InstalledByDefault, InstalledFromStore, InstalledByOEM, LocationFlags, IsApp

    return $result
}

function CollectChromiumExtensions()
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPath
    )

    $preferencesFiles = @("Preferences", "Secure Preferences");

    # go over every browser configuration
    foreach ($config in $chromiumBrowsersConfig)
    {
        $basePath = "$($UserPath)\$($config.Path)"
        
        if (Test-Path -Path $basePath) {
            # Default profile folder
            $profiles = @("Default")

            # In addition to default profile folder other profiles will be named "Profile #" where # is a number
            # Add all existing profiles so we can scan them as well
            foreach ($p in (Get-ChildItem -Path $basePath -Filter "Profile*").Name) {
                $profiles += $p
            }

            foreach ($profile in $profiles) {
                foreach ($pref in $preferencesFiles) {
                    $preferencesPath = "$($basePath)$($profile)\$($pref)"
                    
                    if (Test-Path -Path $preferencesPath)
                    {
                        $preferences = Get-Content -Raw -Path $preferencesPath |  ConvertFrom-Json
                        $settings = $preferences.extensions.settings
                
                        # create new extensions index array
                        foreach ($extension in $settings.PSObject.Properties)
                        {
                            try {
                                $collectedExtension = Parse-Chromium-Extension -ExtensionId $extension.Name  -ExtensionProps $extension.Value -TargetSoftware $config.TargetSoftware -User ($UserPath | Split-Path -Leaf)
                                $collectedExtensionProvider.Write("CollectedExtension", $collectedExtension)

                                # add the current extensions to the index 
                                $config.Index += $extension.Name
                        }
                            catch
                            {
                                Write-Host "Error occurred while parsing extension:$($extension.Name)"
                                Write-Host $_
                            }
                        }
                    }
                }
            }
        }
    }
}

function CollectFirefoxExtensions()
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPath
    )

    $profilesPath = "$($UserPath)\$($firefoxConfig.Path)"

    # check if the extension folder exists
    if (Test-Path -Path $profilesPath)
    {
        $profilesFolders = Get-ChildItem -Path $profilesPath -Directory

        foreach ($profile in $profilesFolders)
        {
            $extensionsFile = "$($profilesPath)\$($profile)\extensions.json"
            
            if(Test-Path -Path $extensionsFile)
            {
                $preferences = Get-Content -Raw -Path $extensionsFile |  ConvertFrom-Json
                $addons = $preferences.addons

                foreach ($extension in $addons)
                {
                    try 
                    {
                        # parse and send only non default extensions
                        if ($extension.type -eq "extension" -And $extension.location -eq "app-profile")
                        {
                            $collectedExtension = Parse-Firefox-Extension -User ($UserPath | Split-Path -Leaf) -ExtensionProps $extension
                            $collectedExtensionProvider.Write("CollectedExtension", $collectedExtension)

                            # add the current extensions to the index 
                            $firefoxConfig.Index += $collectedExtension.Id
                        }
                    } catch 
                    {
                        Write-Host "Error occurred while parsing firefox extension:$($extension.id)"
                        Write-Host $_
                    }
                        
                }
            }
        }
    }
    
}

function SendIndexEventIfNeeded()
{
    param(
        [Parameter(Mandatory=$true)]
        [BrowserConfig]$BrowserConfig
    )

    if ($BrowserConfig.Index.Count -gt 0)
    {
        try {
            # since the index event is aggreagated for all users it might contain the same ids
            # first remove duplicates
            $uniqueExtensions = $BrowserConfig.Index | sort -uniq
            
            $extensionsIndexAsJson = ConvertTo-Json -InputObject $uniqueExtensions -Compress
            $extensionsIndexEvent = New-Object -TypeName CollectedExtensionsIndex -ArgumentList $BrowserConfig.TargetSoftware, $extensionsIndexAsJson
            $collectedExtensionProvider.Write("CollectedExtensionsIndex", $extensionsIndexEvent)
        } catch {
            Write-Host "Error occurred while sending extensions index"
            Write-Host $_
        }
    }
}


try
{
    $localUsers = Get-WmiObject Win32_UserProfile -Filter "Special = False" | Select LocalPath

    # foreach user 
    foreach ($user in $localUsers)
    {
        $userPath = $user.LocalPath

        # Collect chromium based extensions (chrome + edge chromium)
        CollectChromiumExtensions -UserPath $userPath

        # Collect firefox extensions
        CollectFirefoxExtensions -UserPath $userPath
    }


    # We send index events only after we collected extensions for all users
    foreach ($config in $chromiumBrowsersConfig)
    {
        SendIndexEventIfNeeded -BrowserConfig $config
    }

    SendIndexEventIfNeeded -BrowserConfig $firefoxConfig
}
catch
{
    Write-Host "Error occurred while reading client extensions:"
    Write-Host $_
}
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBdmfWV38rs4YIf
# t+ef2+7FTuSf7L6cc9rUNhyd+TLzyqCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIGoZIOj674dZvd5CXPMXu/3cLCsynF/3rFR3U8gP2/MA
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAawwegiadsoO2
# S8TDVZ3yTVA8Q40yf/zewch0/EHQAkZB3jODivCzQYk/Iea+xFlb5LNuG+BqNtsc
# iH8jchQts0En5A4TFfsVdqeCBVp8zdp80GQEigsVHo9PR8/oLzs+qFO2lrES9zbb
# pPdvlPuBIZxQtBuhbdsVkmtaSLdN+auaJLOfEx24WeUFbr/AekzXalpvB8KawSBP
# OpSqylCLPl/cPUw0z6ogvG+obwb9C8534RBbSS7wIgEB/7gXw6y2EBrAKNwUNWG3
# QeAvi0HFbxSnLF+Cxw5l3N5RhEduI9vp1OkhgvLS/PiNOtIl7tBakna0A71KRBZy
# 7CzuhkiOt6GCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4GCSqGSIb3DQEHAqCC
# Fu8wghbrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAz90nrwFFZ
# J6ZUzAKWAJ9krjVERU3PkJn/kBQR39H14wIGYxIL5SzXGBMyMDIyMDkyMDA5NTcy
# Ni44MjZaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
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
# MC8GCSqGSIb3DQEJBDEiBCCo9PsAcHIgFYkKKp3LaXpN7gfYA/oxl0D3TjA0vw7U
# ujCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPS94Kt130q+fvO/fzD4MbWQ
# hQaE7RHkOH6AkjlNVCm9MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGKPjiN0g4C+ugAAQAAAYowIgQg4YlKllUPl/ArUXMivWPr6uDa
# 9vaozehuIIRSeDWPQDgwDQYJKoZIhvcNAQELBQAEggIAfINO7FmAJpJQ0NK4L0NR
# 3gB6O86Rwmih2hrXmpGvic4LVvd8ac5W4PVYphCylMDv+terd7anmR0DPflCJX+B
# R/blxf2UmyB6mBTYD56r3oKrJT7gpivgmzcd6acahHR1FUabn7jCjoauFka1IOeU
# b0O88cCRgYWWHWTwDSgXwGKRu6fOW75xhL4giI08f51f5reh0rYXpG3RebEsAXmL
# esu89lW0T+U/qp4GcVHqV1zxeAlKO9ULsSEbq1Bl/aV9RId2nP7OJXTkaIhTrn+T
# E0SdqFLl58WzHeI9gqd6kh3ssV8uWRXPK0IWSYHo95PRVpefz16QroESwmVzGRjJ
# cEEgFPNLEayZGqldHfDy3Jb/7Act3rn0/UrQ7J4KwRiuqnveiW77+oWdNEjTDjTW
# 8lTq86rjm/P/DQtG6Lyyu3jOJfNjnVqlOKcrOaQlEhMIe/XjgoOGD+nygWbKTyjf
# x6ZsuzTxT+EEnFXJKXoDo0gKssyfKS9E1I1wQJ833pzBB0pl+PcQgQ4zSOEeh7qp
# ZDBoXGVWlsJXl/SwpMlq74pjPTvKafP6I4AWPQ29O8Trt43JOOViveTm3qRKN/gN
# boAnRDwFPnBnNKyFHo6SC14Yf1Up7vXdH8yeZfio00xmGdvY9HFXK22KgCd+i/Cx
# VCtu6OZj3k8f0DiNGBtS+2M=
# SIG # End signature block
