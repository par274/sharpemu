# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$compareScript = Join-Path $PSScriptRoot "compare-runs.ps1"
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "sharpemu-compare-runs-$([Guid]::NewGuid().ToString('N'))"

function New-TestManifest {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter(Mandatory = $true)]
        [bool]$IncludeComparisonArguments,
        [Parameter(Mandatory = $true)]
        [bool]$ChangeStableOption
    )

    $stableArguments = @(
        "--memory-diagnostics={runDirectory}\memory-diagnostics.jsonl"
    )
    if ($ChangeStableOption) {
        $stableArguments += "--resolution=1920x1080"
    }

    $manifest = [ordered]@{
        schemaVersion = 1
        runId = "synthetic-run-$Index"
        startedAtUtc = ([DateTimeOffset]::UtcNow.AddMinutes(-$Index)).ToString("O")
        repositoryCommit = "0123456789abcdef0123456789abcdef01234567"
        repositoryDirty = $false
        target = [ordered]@{
            titleId = "synthetic"
            region = "synthetic"
            version = "1.004.000"
            ebootSha256 = "A" * 64
            route = "synthetic"
            expectedCheckpoint = "synthetic"
        }
        emulator = [ordered]@{
            sha256 = "B" * 64
            arguments = @(
                "--memory-diagnostics=C:\synthetic\trial-$Index\memory-diagnostics.jsonl"
            )
        }
        limits = [ordered]@{
            wallTimeSeconds = 900
            workingSetBytes = 6GB
            sampleIntervalMilliseconds = 250
        }
        machine = [ordered]@{
            computerName = "synthetic"
            operatingSystem = "synthetic"
            operatingSystemVersion = "synthetic"
            operatingSystemBuild = "synthetic"
            cpu = "synthetic"
            processorCount = 1
            dotnetRuntime = "synthetic"
            gpu = "synthetic"
            driverVersion = "synthetic"
            vulkanVersion = "synthetic"
        }
        result = [ordered]@{
            terminationReason = "process-exited"
            durationMilliseconds = 1000
            peakWorkingSetBytes = 1GB
            peakPrivateBytes = 1GB
            checkpointObserved = "synthetic"
        }
    }

    if ($IncludeComparisonArguments) {
        $manifest.emulator.comparisonArguments = $stableArguments
    } else {
        $manifest.emulator.arguments = $stableArguments
    }

    return $manifest
}

function Write-TestManifests {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [bool]$IncludeComparisonArguments,
        [Parameter(Mandatory = $true)]
        [bool]$ChangeStableOption
    )

    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    foreach ($index in 1..3) {
        $runDirectory = Join-Path $Root "run-$index"
        New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
        $manifest = New-TestManifest -Index $index -IncludeComparisonArguments $IncludeComparisonArguments -ChangeStableOption ($ChangeStableOption -and $index -eq 3)
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDirectory "manifest.json") -Encoding utf8
    }
}

function Invoke-Comparison {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    & pwsh -NoProfile -File $compareScript -RunRoot $Root -Latest 3 *> $null
    return $LASTEXITCODE
}

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

    $expandedPathRoot = Join-Path $testRoot "expanded"
    Write-TestManifests -Root $expandedPathRoot -IncludeComparisonArguments $true -ChangeStableOption $false
    if ((Invoke-Comparison -Root $expandedPathRoot) -ne 0) {
        throw "Three runs with distinct expanded diagnostic paths were not comparable."
    }

    $legacyPathRoot = Join-Path $testRoot "legacy"
    Write-TestManifests -Root $legacyPathRoot -IncludeComparisonArguments $false -ChangeStableOption $false
    if ((Invoke-Comparison -Root $legacyPathRoot) -ne 0) {
        throw "Older manifests containing only emulator.arguments were not comparable."
    }

    $changedOptionRoot = Join-Path $testRoot "changed-option"
    Write-TestManifests -Root $changedOptionRoot -IncludeComparisonArguments $true -ChangeStableOption $true
    if ((Invoke-Comparison -Root $changedOptionRoot) -eq 0) {
        throw "A real stable emulator option change was incorrectly considered comparable."
    }

    Write-Host "compare-runs stable-argument regression passed."
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
