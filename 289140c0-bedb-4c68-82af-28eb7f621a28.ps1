$Source = @"
                        using System;
                        using System.Text;
                        using System.Diagnostics.Tracing;
                        using Microsoft.PowerShell.Commands;
                        
                        public static class ScheduledTasksEtwProvider
                        {
                            public static EventSource log = new EventSource("Microsoft.Windows.Sense.ScheduledTasksCollection", EventSourceSettings.EtwSelfDescribingEventFormat);
                        }

                        [EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
                        public class CollectedScheduledTask
                        {
                            public String Name { get; set; }
                            public String Path { get; set; }
                            public String State { get; set; }
                            public String Author { get; set; }
                            public String Version { get; set; }
                            public String LastRunTime { get; set; }
                            public uint LastResult { get; set; }
                            public String NextRunTime { get; set; }
                            public uint NumberOfMissedRuns { get; set; }
                            public String Actions { get; set; }
                            public String Settings { get; set; }
                            public String Triggers { get; set; }

                            public CollectedScheduledTask(string name, string path, string state, string author, string version, string lastRunTime, uint lastResult, string nextRunTime, uint numberOfMissedRuns, string actions, string settings, string triggers)
                            {
                                this.Name = name;
                                this.Path = path;
                                this.State = state;
                                this.Author = author;
                                this.Version = version;
                                this.LastRunTime = lastRunTime;
                                this.LastResult = lastResult;
                                this.NextRunTime = nextRunTime;
                                this.NumberOfMissedRuns = numberOfMissedRuns;
                                this.Actions = actions;
                                this.Settings = settings;
                                this.Triggers = triggers;
                            }
                        }

                        [EventData] 
                        public class CollectedScheduledTasksIndex
                        {
							    public String Index { get; set; }

                                public CollectedScheduledTasksIndex(string index)
                                {
							        this.Index = index;
                                }
                        }                                  

"@
Add-Type -TypeDefinition $Source -Language CSharp -IgnoreWarnings
$collectedScheduledTasksProvider = [ScheduledTasksEtwProvider]::log


$tasks = Get-ScheduledTask
$tasksIndex = @()
foreach ($task in $tasks){
    $taskinfo = $task | Get-ScheduledTaskInfo 
    $tasksIndex += $task.TaskName
    $taskName = $task.TaskName
    $taskPath = $task.TaskPath
    $taskState = $task.State
    $taskAuthor = $task.Author
    $taskVersion = $task.Version
    $taskLastRunTime = $taskinfo.LastRunTime
    $taskLastResult = $taskinfo.LastTaskResult
    $taskNextRunTime = $taskinfo.NextRunTime
    $taskNumberOfMissedRuns = $taskinfo.NumberOfMissedRuns
    $taskActions = $task.Actions | Select-Object -Property * -ExcludeProperty PSComputerName, Cim*
    $taskActionsAsJson = ConvertTo-Json -InputObject @($taskActions) -Compress
    $taskSettings = $task.Settings | Select-Object -Property * -ExcludeProperty PSComputerName, Cim*, *Settings
    $taskSettingsAsJson = ConvertTo-Json -InputObject @($taskSettings) -Compress
    $taskTriggers = $task.Triggers | Select-Object -Property * -ExcludeProperty PSComputerName, Repetition, Cim*
    $taskTriggersAsJson = ConvertTo-Json -InputObject @($taskTriggers) -Compress

    $collectedTask=[CollectedScheduledTask]::new($taskName, $taskPath, $taskState, $taskAuthor, $taskVersion, $taskLastRunTime, $taskLastResult, $taskNextRunTime, $taskNumberOfMissedRuns, $taskActionsAsJson, $taskSettingsAsJson, $taskTriggersAsJson)
    $collectedScheduledTasksProvider.Write("CollectedScheduledTask", $collectedTask)
}

$scheduledTasksIndexAsJson = ConvertTo-Json -InputObject $tasksIndex -Compress
$collectedScheduledTasksIndex = [CollectedScheduledTasksIndex]::new($scheduledTasksIndexAsJson)
$collectedScheduledTasksProvider.Write("CollectedScheduledTasksIndex", $collectedScheduledTasksIndex)

# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLnJA1JCjeptZa
# p7Y30JUBiQzJVOmixbZ8hOslcskFuaCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# zTGCGYswghmHAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIJeTLKcX4IQYWCzpQCyeFgQVpjCuI/9v87UnVXrHGWhI
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAtB5Fp1ItKQHn
# e6scc4aP95SHzBT5+ZNbVhOnB0CMZhfC78ldJvPSAqaeioHCNX2M+aae0UINsB/h
# 1NBsXywHjb+1Xa0+t2I1xJxXv8iwa/Yku58Hirz9rYijoTRWL8XthuY0oYGFKkeU
# qZRi/OkXaYUMROMdGD5kH7NiSQucYwzbGJiHDIqWjzCcJjzIuhCkxGhNOua8G7Id
# EsWsUWTP8nEKK2e/zCChJs4yKD/demwFlNBjHAvsjUJPGtijOB++NTHGj/DpQEhW
# /OyRZ7xR0J80hQObSysTFdfspKqBkQfTIqhlxR6M+gR4LdxdCloJhmlJxlR5y8fG
# 8cwomK6hn6GCFxUwghcRBgorBgEEAYI3AwMBMYIXATCCFv0GCSqGSIb3DQEHAqCC
# Fu4wghbqAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcE
# ggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBMP6DLoRfM
# n5lRS8DOQlyuVumNSdNIS+EtmV5BTnHUIgIGYxFhFs39GBIyMDIyMDkyMDA5NTcx
# Ny4yM1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMg
# TGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MkFENC00QjkyLUZBMDEx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFlMIIHFDCC
# BPygAwIBAgITMwAAAYZ45RmJ+CRLzAABAAABhjANBgkqhkiG9w0BAQsFADB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEwMjgxOTI3MzlaFw0yMzAx
# MjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAwI3G2Wpv6B4IjAfrgfJpndPOPYO1Yd8+vlfoIxMW3gdC
# DT+zIbafg14pOu0t0ekUQx60p7PadH4OjnqNIE1q6ldH9ntj1gIdl4Hq4rdEHTZ6
# JFdE24DSbVoqqR+R4Iw4w3GPbfc2Q3kfyyFyj+DOhmCWw/FZiTVTlT4bdejyAW6r
# /Jn4fr3xLjbvhITatr36VyyzgQ0Y4Wr73H3gUcLjYu0qiHutDDb6+p+yDBGmKFzn
# OW8wVt7D+u2VEJoE6JlK0EpVLZusdSzhecuUwJXxb2uygAZXlsa/fHlwW9YnlBqM
# HJ+im9HuK5X4x8/5B5dkuIoX5lWGjFMbD2A6Lu/PmUB4hK0CF5G1YaUtBrME73DA
# Kkypk7SEm3BlJXwY/GrVoXWYUGEHyfrkLkws0RoEMpoIEgebZNKqjRynRJgR4fPC
# KrEhwEiTTAc4DXGci4HHOm64EQ1g/SDHMFqIKVSxoUbkGbdKNKHhmahuIrAy4we9
# s7rZJskveZYZiDmtAtBt/gQojxbZ1vO9C11SthkrmkkTMLQf9cDzlVEBeu6KmHX2
# Sze6ggne3I4cy/5IULnHZ3rM4ZpJc0s2KpGLHaVrEQy4x/mAn4yaYfgeH3MEAWkV
# jy/qTDh6cDCF/gyz3TaQDtvFnAK70LqtbEvBPdBpeCG/hk9l0laYzwiyyGY/HqMC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQZtqNFA+9mdEu/h33UhHMN6whcLjAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDD7mehJY3fTHKC4hj+wBWB8544uaJiMMIHnhK9ONTM7VraTYzx0U/TcLJ6gxw1
# tRzM5uu8kswJNlHNp7RedsAiwviVQZV9AL8IbZRLJTwNehCwk+BVcY2gh3ZGZmx8
# uatPZrRueyhhTTD2PvFVLrfwh2liDG/dEPNIHTKj79DlEcPIWoOCUp7p0ORMwQ95
# kVaibpX89pvjhPl2Fm0CBO3pXXJg0bydpQ5dDDTv/qb0+WYF/vNVEU/MoMEQqlUW
# WuXECTqx6TayJuLJ6uU7K5QyTkQ/l24IhGjDzf5AEZOrINYzkWVyNfUOpIxnKsWT
# BN2ijpZ/Tun5qrmo9vNIDT0lobgnulae17NaEO9oiEJJH1tQ353dhuRi+A00PR78
# 1iYlzF5JU1DrEfEyNx8CWgERi90LKsYghZBCDjQ3DiJjfUZLqONeHrJfcmhz5/bf
# m8+aAaUPpZFeP0g0Iond6XNk4YiYbWPFoofc0LwcqSALtuIAyz6f3d+UaZZsp41U
# 4hCIoGj6hoDIuU839bo/mZ/AgESwGxIXs0gZU6A+2qIUe60QdA969wWSzucKOisn
# g9HCSZLF1dqc3QUawr0C0U41784Ko9vckAG3akwYuVGcs6hM/SqEhoe9jHwe4Xp8
# 1CrTB1l9+EIdukCbP0kyzx0WZzteeiDN5rdiiQR9mBJuljCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046MkFENC00QjkyLUZBMDExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAAGu2DRzWkKljmXySX1k
# orHL4fMnoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDm05mQMCIYDzIwMjIwOTIwMDk0NDQ4WhgPMjAyMjA5MjEw
# OTQ0NDhaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAObTmZACAQAwBwIBAAICIzEw
# BwIBAAICEYQwCgIFAObU6xACAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBm
# 0EU+NYXnDZAb8VsQhfhFMKICxohaUi8kk40RtWLpXDWwuYWYOW9v6hg4b7vRv12c
# XKdrRonXGKr83T0esSR66nkh1w/B6AJpF+aBaIYg+deMk8UACaWUA4GoPMRpW6Lk
# Qm39lLAaCVgIjyeCY/llLkOhVHjXjI9t9uAL08Z/9zGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABhnjlGYn4JEvMAAEAAAGG
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIDxSTb4b5IapHjgH9JjT5nKh8sXyTVb8us7DjCTWqTl3
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGpmI4LIsCFTGiYyfRAR7m7Fa
# 2guxVNIw17mcAiq8Qn4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAYZ45RmJ+CRLzAABAAABhjAiBCAqtCqj04iTSGuwzJbYYK2tP6pc
# 211lMAQDvzVYZ8M8IDANBgkqhkiG9w0BAQsFAASCAgBJy4rPVvbHMdVJpTWW5raR
# dTZijLHdpnpg8V+6zPBfqJhyOuSk9SHI5wraR1u0hMpaUkHvMTfxTJqxnkbhSMiG
# XCnbo1GCZ84qRPGalYiy/JgvviT8QzrwPJz3zjGebt5dq7ZdvmKyB3DRFibBz3+I
# 0s82RigEAZVaAUUHoIiChVF3mhYc3WbyzsEeiro+ITOIpHb1vHtOGrm+xa/Te4QY
# 8i2W8RVlRnRrPEM6FIzSXwNcfTdBxUqVrXOOQMyPtKly6ursSmKSLXt6b/h1FViF
# uq+fwct+kLrUTP0GgiDfd5Brs3xMUgwu6PIeUrpD9etBgYLb1IUT9gIMs5B+YuAr
# CE6tJxLlCoWmpAuS2X+3JuLxhrUH3wqi2gW7MRGh/P3amxQ0/0uay0X8byI34Vn0
# ZSP0jX6kLO10o2/RzuuO9YuLt2owD67dLcYNEjmLu4LWB2AVNmJY9TQxUPw66Wmu
# u4bqqE/aCYJb2RMx090d4rNMeybGNIqTJfWHb8T7vbildluMI5l0w9+pa+IZxond
# aQQzB4+gmQrhsrsmP5wTXUbx9Ow9Fn7QqGJ5yuQQbyQpxFO9gq7FD90kX9qzU5UT
# Q5IsKFKHwJgTcgFZg9HxxQ5atinko4aRaphc0iGYyo+2mZWffUVsmimYag+GzoU+
# FDPCvmEMPNEm3Kz3NUjSrg==
# SIG # End signature block
