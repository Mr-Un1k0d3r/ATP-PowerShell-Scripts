$NativeCalls = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class NativeTools
{
    public enum SYSTEM_INFORMATION_CLASS : uint
    {
        SystemBasicInformation,
        SystemProcessorInformation,             // obsolete...delete
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemVerifierAddDriverInformation,
        SystemVerifierRemoveDriverInformation,
        SystemProcessorIdleInformation,
        SystemLegacyDriverInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemVerifierThunkExtend,
        SystemSessionProcessInformation,
        SystemLoadGdiDriverInSystemSpace,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchdogTimerHandler,
        SystemWatchdogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWow64SharedInformationObsolete,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        SystemThreadPriorityClientIdInformation,
        SystemProcessorIdleCycleTimeInformation,
        SystemVerifierCancellationInformation,
        SystemProcessorPowerInformationEx,
        SystemRefTraceInformation,
        SystemSpecialPoolInformation,
        SystemProcessIdInformation,
        SystemErrorPortInformation,
        SystemBootEnvironmentInformation,
        SystemHypervisorInformation,
        SystemVerifierInformationEx,
        SystemTimeZoneInformation,
        SystemImageFileExecutionOptionsInformation,
        SystemCoverageInformation,
        SystemPrefetchPatchInformation,
        SystemVerifierFaultsInformation,
        SystemSystemPartitionInformation,
        SystemSystemDiskInformation,
        SystemProcessorPerformanceDistribution,
        SystemNumaProximityNodeInformation,
        SystemDynamicTimeZoneInformation,
        SystemCodeIntegrityInformation,
        SystemProcessorMicrocodeUpdateInformation,
        SystemProcessorBrandString,
        SystemVirtualAddressInformation,
        SystemLogicalProcessorAndGroupInformation,
        SystemProcessorCycleTimeInformation,
        SystemStoreInformation,
        SystemRegistryAppendString,
        SystemAitSamplingValue,
        SystemVhdBootInformation,
        SystemCpuQuotaInformation,
        SystemSpare0,
        SystemSpare1,
        SystemLowPriorityIoInformation,
        SystemTpmBootEntropyInformation,
        SystemVerifierCountersInformation,
        SystemPagedPoolInformationEx,
        SystemSystemPtesInformationEx,
        SystemNodeDistanceInformation,
        SystemAcpiAuditInformation,
        SystemBasicPerformanceInformation,
        SystemSessionBigPoolInformation,
        SystemBootGraphicsInformation,
        SystemScrubPhysicalMemoryInformation,
        SystemBadPageInformation,
        MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
    };

    public enum SYSTEM_MEMORY_LIST_COMMAND : int
    {
        MemoryCaptureAccessedBits,
        MemoryCaptureAndResetAccessedBits,
        MemoryEmptyWorkingSets,
        MemoryFlushModifiedList,
        MemoryPurgeStandbyList,
        MemoryPurgeLowPriorityStandbyList,
        MemoryCommandMax
    };
    
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_SINGLE_PRIVILEGE
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public uint HighPart;
    };

    [Flags]
    public enum PrivilegeAttributes : uint
    {
        SE_PRIVILEGE_DISABLED = 0x00000000,
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_REMOVED = 0x00000004,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
    };

    [Serializable]
    [Flags]
    [System.Runtime.InteropServices.ComVisible(true)]
    public enum TokenAccessLevels
    {
        AssignPrimary = 0x00000001,
        Duplicate = 0x00000002,
        Impersonate = 0x00000004,
        Query = 0x00000008,
        QuerySource = 0x00000010,
        AdjustPrivileges = 0x00000020,
        AdjustGroups = 0x00000040,
        AdjustDefault = 0x00000080,
        AdjustSessionId = 0x00000100,

        Read = 0x00020000 | Query,

        Write = 0x00020000 | AdjustPrivileges | AdjustGroups | AdjustDefault,

        AllAccess = 0x000F0000 |
                              AssignPrimary |
                              Duplicate |
                              Impersonate |
                              Query |
                              QuerySource |
                              AdjustPrivileges |
                              AdjustGroups |
                              AdjustDefault |
                              AdjustSessionId,

        MaximumAllowed = 0x02000000
    }

    [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
    public static extern int NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TokenAccessLevels DesiredAccess,
        [Out] out IntPtr TokenHandle);

    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        [In] IntPtr TokenHandle,
        [In] bool DisableAllPrivileges,
        [In] ref TOKEN_SINGLE_PRIVILEGE NewState,
        [In] uint BufferLength,
        [In, Out] ref TOKEN_SINGLE_PRIVILEGE PreviousState,
        [Out] out uint ReturnLength);

    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LookupPrivilegeValueW(
    [In] string lpSystemName,
    [In] string lpName,
    [Out] out LUID lpLuid);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint GetLastError();

    [DllImport("kernel32", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hFile);

    public static void PurgeStandbyListMemory()
    {
        var purgeCommand = Marshal.AllocHGlobal(sizeof(int));
        Marshal.WriteInt32(purgeCommand, (int)SYSTEM_MEMORY_LIST_COMMAND.MemoryPurgeStandbyList);
    
        var ntStatus = NtSetSystemInformation(
            SYSTEM_INFORMATION_CLASS.SystemMemoryListInformation,
            purgeCommand,
            sizeof(int));
    
        if(ntStatus != 0)
        {
            throw new Exception(string.Format("Failed to purge standby list memory. NTSTATUS: {0}", ntStatus));
        }
    
        Marshal.FreeHGlobal(purgeCommand);
    }

    public static void PurgeModifiedPageListMemory()
    {
        var purgeCommand = Marshal.AllocHGlobal(sizeof(int));
        Marshal.WriteInt32(purgeCommand, (int)SYSTEM_MEMORY_LIST_COMMAND.MemoryFlushModifiedList);
    
        var ntStatus = NtSetSystemInformation(
            SYSTEM_INFORMATION_CLASS.SystemMemoryListInformation,
            purgeCommand,
            sizeof(int));
    
        if(ntStatus != 0)
        {
            throw new Exception(string.Format("Failed to purge modified page list memory. NTSTATUS: {0}", ntStatus));   
        }

        Marshal.FreeHGlobal(purgeCommand);
    }

    public static void EnablePrivilege(string privilegeName)
    {
        var currentProcess = GetCurrentProcess();

        IntPtr tokenHandle = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(currentProcess, TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query, out tokenHandle))
            {
                throw new Exception(string.Format("Unable to open current process token: {0}", System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }

            LUID privilegeLuid;
            if (!LookupPrivilegeValueW(null, privilegeName, out privilegeLuid))
            {
                throw new Exception(string.Format("Unable to lookup privilege: {0}", System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }

            TOKEN_SINGLE_PRIVILEGE singlePrivilege;
            singlePrivilege.PrivilegeCount = 1;
            singlePrivilege.Luid = privilegeLuid;
            singlePrivilege.Attributes = (uint)(PrivilegeAttributes.SE_PRIVILEGE_ENABLED);

            TOKEN_SINGLE_PRIVILEGE previousSinglePrivilege = new TOKEN_SINGLE_PRIVILEGE();
            uint returnLength;

            if (!AdjustTokenPrivileges(tokenHandle, false, ref singlePrivilege, (uint)Marshal.SizeOf(singlePrivilege), ref previousSinglePrivilege, out returnLength))
            {
                throw new Exception(string.Format("Unable to apply privileges: {0}", System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
            {
                CloseHandle(tokenHandle);
            }

            if (currentProcess != IntPtr.Zero)
            {
                CloseHandle(currentProcess);
            }
        }
    }
}
"@

Add-Type -TypeDefinition $NativeCalls -Language CSharp -IgnoreWarnings

try
{
    Write-Host "Enabling required privileges"
    [NativeTools]::EnablePrivilege("SeProfileSingleProcessPrivilege")
    [NativeTools]::EnablePrivilege("SeIncreaseQuotaPrivilege")

    Write-Host "Purging standby list"
    [NativeTools]::PurgeStandbyListMemory()
    Write-Host "Purged standby list"

    Write-Host "Purging modified page list"
    [NativeTools]::PurgeModifiedPageListMemory()
    Write-Host "Purged modified page list"
}
catch
{
    Write-Host $_
    Write-Host $_.ScriptStackTrace
}
# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBvkksuB7yzEQh/
# PL6FYPtYNVC6GPNIqNE14NpzFsOX5KCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIDHktpfe8cx7B9IrFVU+pZWrgakvCgVfrTSNPxP7tlk3
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAAvDqFQfzd5m3
# Gpu3sOqBT4utIMZVcB1ksr3tbdMnHL3FMCH44eOvPfyyRTSt2VOk42kHvZsqc4Ou
# +/Uux958ULGyksBZueNXjS70vxmPRrora4d953NDHEvNPSimtdMSVM7F4U7zShhi
# Z865g3a2bOQCeqwcTD2AT5ujt2JOd3w+O5q1Y4N3OGGuA4pD4gBFU6xgxLjEWa3q
# ur735WCaQIRekfHTYiuKEW4093gdd+LqhYS5xLzmZ+bznItPRf1k77nvE9jw0Ctr
# ck0qBmYrkIyElFsmwrMNnrEJuda8ZMAdjImgiJA+5upifNTbANjm6SiL4b6iOTgW
# 3pjvBM5LoKGCFxUwghcRBgorBgEEAYI3AwMBMYIXATCCFv0GCSqGSIb3DQEHAqCC
# Fu4wghbqAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcE
# ggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCLKj8pM8sR
# P3gIbupg2mAU/sAvhVYAs0BCDf2ociK7+AIGYxIL5So9GBIyMDIyMDkyMDA5NTcx
# Ny45MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMg
# TGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFlMIIHFDCC
# BPygAwIBAgITMwAAAYo+OI3SDgL66AABAAABijANBgkqhkiG9w0BAQsFADB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEwMjgxOTI3NDJaFw0yMzAx
# MjYxOTI3NDJaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAt/+ut6GDAyAZvegBhagWd0GoqT8lFHMepoWNOLPPEEoL
# uya4X3n+K14FvlZwFmKwqap6B+6EkITSjkecTSB6QRA4kivdJydlLvKrg8udtBu6
# 7LKyjQqwRzDQTRhECxpU30tdBE/AeyP95k7qndhIu/OpT4QGyGJUiMDlmZAiDPY5
# FJkitUgGvwMBHwogJz8FVEBFnViAURTJ4kBDiU6ppbv4PI97+vQhpspDK+83gaya
# iRC3gNTGy3iOie6Psl03cvYIiFcAJRP4O0RkeFlv/SQoomz3JtsMd9ooS/XO0vSN
# 9h2DVKONMjaFOgnN5Rk5iCqwmn6qsme+haoR/TrCBS0zXjXsWTgkljUBtt17UBbW
# 8RL+9LNw3cjPJ8EYRglMNXCYLM6GzCDXEvE9T//sAv+k1c84tmoiZDZBqBgr/SvL
# +gVsOz3EoDZQ26qTa1bEn/npxMmXctoZSe8SRDqgK0JUWhjKXgnyaOADEB+FtfIi
# +jdcUJbpPtAL4kWvVSRKipVv8MEuYRLexXEDEBi+V4tfKApZhE4ga0p+QCiawHLB
# ZNoj3UQNzM5QVmGai3MnQFbZkhqbUDypo9vaWEeVeO35JfdLWjwRgvMX3VKZL57d
# 7jmRjiVlluXjZFLx+rhJL7JYVptOPtF1MAtMYlp6OugnOpG+4W4MGHqj7YYfP0UC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQj2kPY/WwZ1Jeup0lHhD4xkGkkAzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDF9MESsPXDeRtfFo1f575iPfF9ARWbeuuNfM583IfTxfzZf2dv/me3DNi/KcNN
# EnR1TKbZtG7Lsg0cy/pKIEQOJG2fYaWwIIKYwuyDJI2Q4kVi5mzbV/0C5+vQQsQc
# CvfsM8K5X2ffifJi7tqeG0r58Cjgwe7xBYvguPmjUNxwTWvEjZIPfpjVUoaPCl6q
# qs0eFUb7bcLhzTEEYBnAj8MENhiP5IJd4Pp5lFqHTtpec67YFmGuO/uIA/TjPBfc
# tM5kUI+uzfyh/yIdtDNtkIz+e/xmXSFhiQER0uBjRobQZV6c+0TNtvRNLayU4u7E
# ekd7OaDXzQR0RuWGaSiwtN6Xc/PoNP0rezG6Ovcyow1qMoUkUEQ7qqD0Qq8QFwK0
# DKCdZSJtyBKMBpjUYCnNUZbYvTTWm4DXK5RYgf23bVBJW4Xo5w490HHo4TjWNqz1
# 7PqPyMCTnM8HcAqTnPeME0dPYvbdwzDMgbumydbJaq/06FImkJ7KXs9jxqDiE2PT
# eYnaj82n6Q//PqbHuxxJmwQO4fzdOgVqAEkG1XDmppVKW/rJxBN3IxyVr6QP9chY
# 2MYVa0bbACI2dvU+R2QJlE5AjoMKy68WI1pmFT3JKBrracpy6HUjGrtV+/1U52br
# rElClVy5Fb8+UZWZLp82cuCztJMMSqW+kP5zyVBSvLM+4DCCB3EwggVZoAMCAQIC
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
# bGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAIDw82OvG1MFBB2n/4we
# VqpzV8ShoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDm05wWMCIYDzIwMjIwOTIwMDk1NTM0WhgPMjAyMjA5MjEw
# OTU1MzRaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAObTnBYCAQAwBwIBAAICDDMw
# BwIBAAICEW8wCgIFAObU7ZYCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBJ
# JSEqU1jH01etGX8XV63+mbNRl4xEzdR0c5Gfj0pXNtPXrt5dqdSjb/0surrUKRiQ
# PZIF3xU6PsUUrdEnneXED89rK68kmT2VQgTeIgTeneqc4/TjgjPfJdSGsNaTbOMc
# TkD357g1dwHP4lKIGHuU5glEEoZO0SFcy1OhPooqoTGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABij44jdIOAvroAAEAAAGK
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIFYAGfeGN64FXEFFvwPivAvG1e8lxR2+eZQh5w2gJa0H
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg9L3gq3XfSr5+879/MPgxtZCF
# BoTtEeQ4foCSOU1UKb0wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAYo+OI3SDgL66AABAAABijAiBCDhiUqWVQ+X8CtRcyK9Y+vq4Nr2
# 9qjN6G4ghFJ4NY9AODANBgkqhkiG9w0BAQsFAASCAgBDWMTB1myVtfVEVHD9DJE7
# jE4S72lpztshfh2lM6jSRSHSwXaaHtpxUwGLHVgTYj0r/COA4XhCX1jpFifHzyNQ
# YhdbpBfZe6w7uj1tsg3yOJet6JuksCeWIX4Fk6RGR0JThmWzrX1nDl/iBBSBaU61
# Tk/SrMPtk6+tI82WWbNfrZHxKm0r0mklreN7WtbairVlifDErGQScWoasSGSjSRC
# qFzWtBokDzek3VAdModhd9+Bomb8Yozdd+51RnjRnkm+Q5BfYVJz60W/YVHKijLQ
# ORBJT0YrTo+kai6Vq3Pb3F7Ii/XNAVoR2ntaKRHe/JwoBYOzD3a7uOAWNUwvo8jm
# /o0Z6wkCLJ9ooFhIwinM2AN+r+csIs0fmvLvgj+PAkHMCogjWMEIlZ3605xRqdQQ
# /TSiqQ5BZ9OWnnI+g8CrXq2HVzfEiJabDA4AgT6KXJVS/cUBgPfWxCaNFWcyvPeA
# JpMSNPIp3Kmgi4t3kFjpzrgtE5yl99cZdKSus/BItzCgKKEzSPqxe2Ez6WaJ0Gup
# hGQMqmzdEmav9M3h/6xF46Z0FrTD+WP8DNsYKxw43Hay4TSUs4lqfti3jj7MLd+M
# RRIk2l565tqpZoyVylJXzEf2hQC/qk0TeabMYyDfWE70/QRaqgnykFZ0ti2kNl4j
# nxTIXFOARhKbKUBK0L5aQA==
# SIG # End signature block
