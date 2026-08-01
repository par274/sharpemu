# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Deterministic host-memory safety regressions.  All samples are synthetic;
# this test never launches SharpEmu or creates real memory pressure.
#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "target-memory-safety.ps1")

function Assert-Equal {
    param(
        [AllowNull()]
        [Parameter(Mandatory = $true)]
        [object]$Expected,
        [AllowNull()]
        [Parameter(Mandatory = $true)]
        [object]$Actual,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message. Expected '$Expected', received '$Actual'."
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
    }

    if (-not $threw) {
        throw $Message
    }
}

function New-SyntheticHostMemorySample {
    param(
        [UInt64]$PhysicalAvailableBytes = 8GB,
        [UInt64]$CommitTotalBytes = 4GB,
        [UInt64]$CommitLimitBytes = 12GB
    )

    return [pscustomobject]@{
        pageSizeBytes = [UInt64]4096
        physicalTotalBytes = [UInt64]16GB
        physicalAvailableBytes = $PhysicalAvailableBytes
        commitTotalBytes = $CommitTotalBytes
        commitLimitBytes = $CommitLimitBytes
        commitHeadroomBytes = $CommitLimitBytes - $CommitTotalBytes
    }
}

Assert-Equal `
    -Expected ([UInt64]4096000) `
    -Actual (Convert-PageCountToBytes -PageCount 1000 -PageSizeBytes 4096) `
    -Message "Page-count conversion was incorrect"
Assert-Throws `
    -Action { Convert-PageCountToBytes -PageCount 1 -PageSizeBytes 0 } `
    -Message "Zero page size did not fail closed"

$thresholdConfig = [pscustomobject]@{
    minimumAvailablePhysicalGiB = 2.5
    minimumCommitHeadroomGiB = 4
}
$thresholds = Get-HostMemoryThresholds -Limits $thresholdConfig
Assert-Equal -Expected ([UInt64]([decimal]2.5 * 1GB)) -Actual $thresholds.minimumAvailablePhysicalBytes -Message "Physical threshold conversion was incorrect"
Assert-Equal -Expected ([UInt64](4GB)) -Actual $thresholds.minimumCommitHeadroomBytes -Message "Commit threshold conversion was incorrect"

$safeSample = New-SyntheticHostMemorySample
$safeBoundary = Get-TargetTerminationBoundary `
    -WorkingSetBytes 1GB `
    -WorkingSetLimitBytes 10GB `
    -HostMemorySample $safeSample `
    -HostMemoryThresholds $thresholds
Assert-Equal -Expected $null -Actual $safeBoundary -Message "Safe synthetic values terminated the target"

$workingSetBoundary = Get-TargetTerminationBoundary `
    -WorkingSetBytes 10GB `
    -WorkingSetLimitBytes 10GB `
    -HostMemorySample $safeSample `
    -HostMemoryThresholds $thresholds
Assert-Equal -Expected "working-set-limit" -Actual $workingSetBoundary.reason -Message "Working-set boundary reason was incorrect"

$physicalBoundary = Get-TargetTerminationBoundary `
    -WorkingSetBytes 1GB `
    -WorkingSetLimitBytes 10GB `
    -HostMemorySample (New-SyntheticHostMemorySample -PhysicalAvailableBytes $thresholds.minimumAvailablePhysicalBytes) `
    -HostMemoryThresholds $thresholds
Assert-Equal -Expected "physical-headroom-limit" -Actual $physicalBoundary.reason -Message "Physical-headroom boundary reason was incorrect"

$commitBoundarySample = New-SyntheticHostMemorySample -CommitTotalBytes 8GB -CommitLimitBytes 12GB
$commitBoundary = Get-TargetTerminationBoundary `
    -WorkingSetBytes 1GB `
    -WorkingSetLimitBytes 10GB `
    -HostMemorySample $commitBoundarySample `
    -HostMemoryThresholds $thresholds
Assert-Equal -Expected "commit-headroom-limit" -Actual $commitBoundary.reason -Message "Commit-headroom boundary reason was incorrect"

$missingHostValue = [pscustomobject]@{
    physicalTotalBytes = [UInt64]16GB
    physicalAvailableBytes = [UInt64]8GB
    commitTotalBytes = [UInt64]4GB
    commitLimitBytes = [UInt64]12GB
}
Assert-Throws `
    -Action {
        Get-TargetTerminationBoundary `
            -WorkingSetBytes 1GB `
            -WorkingSetLimitBytes 10GB `
            -HostMemorySample $missingHostValue `
            -HostMemoryThresholds $thresholds
    } `
    -Message "Missing host-memory data did not fail closed"

$invalidHostValue = New-SyntheticHostMemorySample -CommitTotalBytes 13GB -CommitLimitBytes 12GB
Assert-Throws `
    -Action {
        Get-TargetTerminationBoundary `
            -WorkingSetBytes 1GB `
            -WorkingSetLimitBytes 10GB `
            -HostMemorySample $invalidHostValue `
            -HostMemoryThresholds $thresholds
    } `
    -Message "Invalid host-memory data did not fail closed"

$invalidThresholdConfig = [pscustomobject]@{
    minimumAvailablePhysicalGiB = 0
}
Assert-Throws `
    -Action { Get-HostMemoryThresholds -Limits $invalidThresholdConfig } `
    -Message "Invalid configured host threshold did not fail closed"

$missingOptionalThresholds = Get-HostMemoryThresholds -Limits ([pscustomobject]@{})
Assert-Equal -Expected $null -Actual $missingOptionalThresholds.minimumAvailablePhysicalBytes -Message "Missing optional physical threshold was not disabled"
Assert-Equal -Expected $null -Actual $missingOptionalThresholds.minimumCommitHeadroomBytes -Message "Missing optional commit threshold was not disabled"

$manifestSection = New-HostMemoryManifestSection `
    -StartupSample $safeSample `
    -MinimumPhysicalAvailableBytes $physicalBoundary.thresholdBytes `
    -MinimumCommitHeadroomBytes $commitBoundary.thresholdBytes `
    -FinalSample $commitBoundarySample `
    -TerminationBoundary $commitBoundary
$manifestRoundTrip = $manifestSection | ConvertTo-Json -Depth 8 | ConvertFrom-Json
Assert-Equal -Expected ([UInt64]16GB) -Actual $manifestRoundTrip.physicalTotalBytesAtStartup -Message "Manifest startup physical total was incorrect"
Assert-Equal -Expected ([UInt64]8GB) -Actual $manifestRoundTrip.physicalAvailableBytesAtStartup -Message "Manifest startup physical availability was incorrect"
Assert-Equal -Expected ([UInt64]4GB) -Actual $manifestRoundTrip.minimumCommitHeadroomBytes -Message "Manifest minimum commit headroom was incorrect"
Assert-Equal -Expected "commit-headroom-limit" -Actual $manifestRoundTrip.terminationBoundary.reason -Message "Manifest termination boundary reason was incorrect"
Assert-Equal -Expected ([UInt64]4GB) -Actual $manifestRoundTrip.finalSample.commitHeadroomBytes -Message "Manifest final host sample was incorrect"

$cleanupState = @{ stopRequested = $false }
$cleanupCounters = @{ calls = 0 }
$cleanupAction = {
    param([int]$RootProcessId)
    if ($RootProcessId -ne 77) {
        throw "Unexpected synthetic process ID $RootProcessId."
    }
    $cleanupCounters.calls++
}
$firstCleanup = Invoke-TargetProcessTreeStopOnce `
    -State $cleanupState `
    -RootProcessId 77 `
    -StopAction $cleanupAction
$secondCleanup = Invoke-TargetProcessTreeStopOnce `
    -State $cleanupState `
    -RootProcessId 77 `
    -StopAction $cleanupAction
Assert-Equal -Expected $true -Actual $firstCleanup -Message "First process-tree cleanup was not performed"
Assert-Equal -Expected $false -Actual $secondCleanup -Message "Repeated process-tree cleanup was not suppressed"
Assert-Equal -Expected 1 -Actual $cleanupCounters.calls -Message "Process-tree cleanup ran more than once"

Write-Host "Target host-memory safety regressions passed."
