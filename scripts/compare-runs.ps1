# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param(
    [string]$RunRoot = "artifacts-local/runs",
    [ValidateRange(1, 100)]
    [int]$Latest = 3
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$resolvedRunRoot = if ([System.IO.Path]::IsPathRooted($RunRoot)) {
    [System.IO.Path]::GetFullPath($RunRoot)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $RunRoot))
}

if (-not (Test-Path -LiteralPath $resolvedRunRoot -PathType Container)) {
    throw "Run root was not found at '$resolvedRunRoot'."
}

$records = @(Get-ChildItem -LiteralPath $resolvedRunRoot -Filter manifest.json -File -Recurse | ForEach-Object {
    $manifest = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    [pscustomobject]@{
        Manifest = $manifest
        StartedAt = [DateTimeOffset]::Parse([string]$manifest.startedAtUtc)
    }
})
$manifests = @($records |
    Sort-Object StartedAt -Descending |
    Select-Object -First $Latest |
    ForEach-Object { $_.Manifest })

if ($manifests.Count -eq 0) {
    throw "No run manifests were found."
}

function Get-ComparisonEmulator {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    $comparisonArgumentsProperty = $Manifest.emulator.PSObject.Properties["comparisonArguments"]
    $comparisonArguments = if ($null -ne $comparisonArgumentsProperty -and $null -ne $comparisonArgumentsProperty.Value) {
        @($comparisonArgumentsProperty.Value | ForEach-Object { [string]$_ })
    } else {
        @($Manifest.emulator.arguments | ForEach-Object { [string]$_ })
    }

    return [ordered]@{
        sha256 = [string]$Manifest.emulator.sha256
        arguments = $comparisonArguments
    }
}

$comparisonIdentities = foreach ($manifest in $manifests) {
    $identity = [ordered]@{
        repositoryCommit = $manifest.repositoryCommit
        repositoryDirty = $manifest.repositoryDirty
        target = $manifest.target
        emulator = Get-ComparisonEmulator -Manifest $manifest
        limits = $manifest.limits
        machine = $manifest.machine
    }
    $identityJson = $identity | ConvertTo-Json -Depth 8 -Compress
    $identityHash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($identityJson)))
    [pscustomobject]@{
        Run = $manifest.runId
        Hash = $identityHash
    }
}

$identityGroups = @($comparisonIdentities | Group-Object Hash)
if ($identityGroups.Count -ne 1) {
    $details = $comparisonIdentities | ForEach-Object { "$($_.Run)=$($_.Hash.Substring(0, 12))" }
    throw "Selected runs are not comparable. Their commit, target, emulator, arguments, limits, or host identity differs: $($details -join '; ')"
}

$dirtyRuns = @($manifests | Where-Object { $_.repositoryDirty })
if ($dirtyRuns.Count -ne 0) {
    throw "Selected runs use a dirty repository state and cannot form an accepted baseline: $($dirtyRuns.runId -join ', ')"
}

$rows = foreach ($manifest in $manifests | Sort-Object startedAtUtc) {
    [pscustomobject]@{
        Run = $manifest.runId
        Commit = ([string]$manifest.repositoryCommit).Substring(0, 7)
        Dirty = $manifest.repositoryDirty
        Termination = $manifest.result.terminationReason
        DurationMinutes = [Math]::Round([double]$manifest.result.durationMilliseconds / 60000, 2)
        PeakWorkingSetGiB = [Math]::Round([double]$manifest.result.peakWorkingSetBytes / 1GB, 2)
        PeakPrivateGiB = [Math]::Round([double]$manifest.result.peakPrivateBytes / 1GB, 2)
        Checkpoint = $manifest.result.checkpointObserved
    }
}

$rows | Format-Table -AutoSize
