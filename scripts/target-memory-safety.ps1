# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# The target runner uses this narrow seam for host-memory conversion,
# validation, boundary decisions, and manifest state.  Tests can inject the
# resulting samples without launching a target or creating memory pressure.

if ($null -eq ("SharpEmu.TargetRunner.NativeMethods" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace SharpEmu.TargetRunner
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PerformanceInformation
    {
        public UInt32 cb;
        public UIntPtr CommitTotal;
        public UIntPtr CommitLimit;
        public UIntPtr CommitPeak;
        public UIntPtr PhysicalTotal;
        public UIntPtr PhysicalAvailable;
        public UIntPtr SystemCache;
        public UIntPtr KernelTotal;
        public UIntPtr KernelPaged;
        public UIntPtr KernelNonpaged;
        public UIntPtr PageSize;
        public UInt32 HandleCount;
        public UInt32 ProcessCount;
        public UInt32 ThreadCount;
    }

    public static class NativeMethods
    {
        public static UInt32 PerformanceInformationSize =>
            (UInt32)Marshal.SizeOf<PerformanceInformation>();

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetPerformanceInfo(
            ref PerformanceInformation performanceInformation,
            UInt32 cb);
    }
}
"@
}

function Convert-PageCountToBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [UInt64]$PageCount,
        [Parameter(Mandatory = $true)]
        [UInt64]$PageSizeBytes
    )

    if ($PageSizeBytes -eq 0) {
        throw "Cannot convert page counts with a zero page size."
    }

    $product = [System.Numerics.BigInteger]$PageCount *
        [System.Numerics.BigInteger]$PageSizeBytes
    $maximum = [System.Numerics.BigInteger]::Parse([UInt64]::MaxValue.ToString())
    if ($product -gt $maximum) {
        throw "Page-count conversion overflowed UInt64."
    }

    return [UInt64]$product
}

function Convert-GiBToBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$GiB,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([double]::IsNaN($GiB) -or [double]::IsInfinity($GiB) -or $GiB -le 0) {
        throw "$Name must be a finite positive GiB value."
    }

    $bytes = [decimal]$GiB * [decimal]1GB
    if ($bytes -gt [decimal][UInt64]::MaxValue) {
        throw "$Name is too large to represent as bytes."
    }

    return [UInt64][Math]::Ceiling($bytes)
}

function Get-OptionalGiBLimit {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Limits,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Limits.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $null
    }

    try {
        $value = [double]$property.Value
    }
    catch {
        throw "$Name must be a finite positive GiB value."
    }

    return $value
}

function Get-HostMemoryThresholds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Limits
    )

    $minimumAvailableGiB = Get-OptionalGiBLimit -Limits $Limits -Name "minimumAvailablePhysicalGiB"
    $minimumCommitGiB = Get-OptionalGiBLimit -Limits $Limits -Name "minimumCommitHeadroomGiB"
    $minimumAvailableBytes = if ($null -eq $minimumAvailableGiB) {
        $null
    }
    else {
        Convert-GiBToBytes -GiB $minimumAvailableGiB -Name "minimumAvailablePhysicalGiB"
    }
    $minimumCommitBytes = if ($null -eq $minimumCommitGiB) {
        $null
    }
    else {
        Convert-GiBToBytes -GiB $minimumCommitGiB -Name "minimumCommitHeadroomGiB"
    }

    return [pscustomobject]@{
        minimumAvailablePhysicalGiB = $minimumAvailableGiB
        minimumAvailablePhysicalBytes = $minimumAvailableBytes
        minimumCommitHeadroomGiB = $minimumCommitGiB
        minimumCommitHeadroomBytes = $minimumCommitBytes
    }
}

function Get-HostMemorySnapshot {
    [CmdletBinding()]
    param()

    if (-not $IsWindows) {
        throw "GetPerformanceInfo host memory sampling is supported on Windows only."
    }

    $information = [SharpEmu.TargetRunner.PerformanceInformation]::new()
    $structureSize = [SharpEmu.TargetRunner.NativeMethods]::PerformanceInformationSize
    $information.cb = $structureSize
    if (-not [SharpEmu.TargetRunner.NativeMethods]::GetPerformanceInfo(
            [ref]$information,
            $structureSize)) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $message = [ComponentModel.Win32Exception]::new($lastError).Message
        throw "GetPerformanceInfo failed with Win32 error ${lastError}: $message"
    }

    $pageSizeBytes = [UInt64]$information.PageSize.ToUInt64()
    $physicalTotalPages = [UInt64]$information.PhysicalTotal.ToUInt64()
    $physicalAvailablePages = [UInt64]$information.PhysicalAvailable.ToUInt64()
    $commitTotalPages = [UInt64]$information.CommitTotal.ToUInt64()
    $commitLimitPages = [UInt64]$information.CommitLimit.ToUInt64()
    if ($pageSizeBytes -eq 0 -or $physicalTotalPages -eq 0 -or $commitLimitPages -eq 0) {
        throw "GetPerformanceInfo returned invalid zero host-memory values."
    }
    if ($physicalAvailablePages -gt $physicalTotalPages) {
        throw "GetPerformanceInfo returned more available physical pages than total pages."
    }
    if ($commitTotalPages -gt $commitLimitPages) {
        throw "GetPerformanceInfo returned commit total greater than commit limit."
    }

    $commitHeadroomPages = $commitLimitPages - $commitTotalPages
    return [pscustomobject][ordered]@{
        pageSizeBytes = Convert-PageCountToBytes -PageCount 1 -PageSizeBytes $pageSizeBytes
        physicalTotalBytes = Convert-PageCountToBytes -PageCount $physicalTotalPages -PageSizeBytes $pageSizeBytes
        physicalAvailableBytes = Convert-PageCountToBytes -PageCount $physicalAvailablePages -PageSizeBytes $pageSizeBytes
        commitTotalBytes = Convert-PageCountToBytes -PageCount $commitTotalPages -PageSizeBytes $pageSizeBytes
        commitLimitBytes = Convert-PageCountToBytes -PageCount $commitLimitPages -PageSizeBytes $pageSizeBytes
        commitHeadroomBytes = Convert-PageCountToBytes -PageCount $commitHeadroomPages -PageSizeBytes $pageSizeBytes
    }
}

function Get-RequiredHostMemoryValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Sample,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Sample.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "Host-memory sample is missing '$Name'."
    }

    try {
        return [UInt64]$property.Value
    }
    catch {
        throw "Host-memory sample contains an invalid '$Name'."
    }
}

function Assert-ValidHostMemorySample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Sample
    )

    $physicalTotalBytes = Get-RequiredHostMemoryValue -Sample $Sample -Name "physicalTotalBytes"
    $physicalAvailableBytes = Get-RequiredHostMemoryValue -Sample $Sample -Name "physicalAvailableBytes"
    $commitTotalBytes = Get-RequiredHostMemoryValue -Sample $Sample -Name "commitTotalBytes"
    $commitLimitBytes = Get-RequiredHostMemoryValue -Sample $Sample -Name "commitLimitBytes"
    $commitHeadroomBytes = Get-RequiredHostMemoryValue -Sample $Sample -Name "commitHeadroomBytes"
    if ($physicalTotalBytes -eq 0 -or $commitLimitBytes -eq 0) {
        throw "Host-memory sample contains an invalid zero total."
    }
    if ($physicalAvailableBytes -gt $physicalTotalBytes) {
        throw "Host-memory sample contains more available physical memory than total memory."
    }
    if ($commitTotalBytes -gt $commitLimitBytes) {
        throw "Host-memory sample contains commit total greater than commit limit."
    }
    if ($commitHeadroomBytes -ne ($commitLimitBytes - $commitTotalBytes)) {
        throw "Host-memory sample commit headroom does not match commit total and limit."
    }
}

function New-TerminationBoundary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason,
        [Parameter(Mandatory = $true)]
        [string]$Boundary,
        [AllowNull()]
        [UInt64]$ThresholdBytes,
        [Parameter(Mandatory = $true)]
        [UInt64]$SampledValueBytes
    )

    return [ordered]@{
        reason = $Reason
        boundary = $Boundary
        thresholdBytes = $ThresholdBytes
        sampledValueBytes = $SampledValueBytes
    }
}

function Get-TargetTerminationBoundary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [UInt64]$WorkingSetBytes,
        [Parameter(Mandatory = $true)]
        [UInt64]$WorkingSetLimitBytes,
        [Parameter(Mandatory = $true)]
        [object]$HostMemorySample,
        [Parameter(Mandatory = $true)]
        [object]$HostMemoryThresholds
    )

    if ($WorkingSetLimitBytes -eq 0) {
        throw "Working-set limit must be positive."
    }

    Assert-ValidHostMemorySample -Sample $HostMemorySample
    if ($WorkingSetBytes -ge $WorkingSetLimitBytes) {
        return New-TerminationBoundary `
            -Reason "working-set-limit" `
            -Boundary "working-set" `
            -ThresholdBytes $WorkingSetLimitBytes `
            -SampledValueBytes $WorkingSetBytes
    }

    $minimumAvailableBytes = $HostMemoryThresholds.minimumAvailablePhysicalBytes
    if ($null -ne $minimumAvailableBytes -and
        [UInt64]$HostMemorySample.physicalAvailableBytes -le [UInt64]$minimumAvailableBytes) {
        return New-TerminationBoundary `
            -Reason "physical-headroom-limit" `
            -Boundary "physical-headroom" `
            -ThresholdBytes ([UInt64]$minimumAvailableBytes) `
            -SampledValueBytes ([UInt64]$HostMemorySample.physicalAvailableBytes)
    }

    $minimumCommitBytes = $HostMemoryThresholds.minimumCommitHeadroomBytes
    if ($null -ne $minimumCommitBytes -and
        [UInt64]$HostMemorySample.commitHeadroomBytes -le [UInt64]$minimumCommitBytes) {
        return New-TerminationBoundary `
            -Reason "commit-headroom-limit" `
            -Boundary "commit-headroom" `
            -ThresholdBytes ([UInt64]$minimumCommitBytes) `
            -SampledValueBytes ([UInt64]$HostMemorySample.commitHeadroomBytes)
    }

    return $null
}

function New-HostMemoryManifestSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StartupSample,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$MinimumPhysicalAvailableBytes,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$MinimumCommitHeadroomBytes,
        [Parameter(Mandatory = $true)]
        [object]$FinalSample,
        [AllowNull()]
        [object]$TerminationBoundary
    )

    Assert-ValidHostMemorySample -Sample $StartupSample
    Assert-ValidHostMemorySample -Sample $FinalSample
    return [ordered]@{
        pageSizeBytesAtStartup = [UInt64]$StartupSample.pageSizeBytes
        physicalTotalBytesAtStartup = [UInt64]$StartupSample.physicalTotalBytes
        physicalAvailableBytesAtStartup = [UInt64]$StartupSample.physicalAvailableBytes
        minimumPhysicalAvailableBytes = if ($null -eq $MinimumPhysicalAvailableBytes) {
            $null
        }
        else {
            [UInt64]$MinimumPhysicalAvailableBytes
        }
        commitTotalBytesAtStartup = [UInt64]$StartupSample.commitTotalBytes
        commitLimitBytesAtStartup = [UInt64]$StartupSample.commitLimitBytes
        minimumCommitHeadroomBytes = if ($null -eq $MinimumCommitHeadroomBytes) {
            $null
        }
        else {
            [UInt64]$MinimumCommitHeadroomBytes
        }
        finalSample = $FinalSample
        terminationBoundary = $TerminationBoundary
    }
}
