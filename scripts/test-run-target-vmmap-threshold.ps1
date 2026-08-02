# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Focused regression coverage for VMMap near-cutoff validation.  The synthetic
# probes stop before target launch and do not require the retail target.

#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = $PSScriptRoot
$runnerPath = Join-Path $scriptRoot "run-target.ps1"
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sharpemu-vmmap-threshold-" + [Guid]::NewGuid().ToString("N"))
$configPath = Join-Path $probeRoot "target.json"
$vmMapPath = (Get-Command pwsh -ErrorAction Stop).Source

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-RunnerProbe {
    param(
        [Parameter(Mandatory = $true)]
        [double]$ThresholdGiB,
        [Parameter(Mandatory = $true)]
        [string]$ProbeName
    )

    $outputRoot = Join-Path $probeRoot $ProbeName
    $arguments = @(
        "-NoProfile",
        "-File",
        $runnerPath,
        "-ConfigPath",
        $configPath,
        "-Runs",
        "1",
        "-OutputRoot",
        $outputRoot,
        "-VmMapPath",
        $vmMapPath,
        "-VmMapOutputRoot",
        (Join-Path $outputRoot "vmmap"),
        "-VmMapCheckpointMode",
        "near-cutoff",
        "-VmMapNearCutoffGiB",
        $ThresholdGiB.ToString([Globalization.CultureInfo]::InvariantCulture)
    )

    $output = (& pwsh @arguments 2>&1 | Out-String)
    [pscustomobject]@{
        exitCode = [int]$LASTEXITCODE
        output = $output
    }
}

try {
    New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null

    $pwshHash = (Get-FileHash -LiteralPath $vmMapPath -Algorithm SHA256).Hash
    $syntheticConfig = [ordered]@{
        titleId = "SYNTHETIC"
        region = "Synthetic"
        version = "1.004.000"
        ebootPath = $vmMapPath
        ebootSha256 = $pwshHash
        emulatorPath = $vmMapPath
        arguments = @()
        route = "synthetic"
        expectedCheckpoint = "synthetic"
        host = [ordered]@{
            gpu = "Synthetic"
            driverVersion = "Synthetic"
            vulkanVersion = "Synthetic"
        }
        limits = [ordered]@{
            wallTimeSeconds = 900
            workingSetGiB = 10
            minimumAvailablePhysicalGiB = $null
            minimumCommitHeadroomGiB = $null
            sampleIntervalMilliseconds = 250
        }
    }
    $syntheticConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding utf8

    $accepted = Invoke-RunnerProbe -ThresholdGiB 7.0 -ProbeName "accepted"
    Assert-True -Condition ($accepted.exitCode -ne 0) -Message "The accepted probe unexpectedly completed successfully."
    Assert-True -Condition ($accepted.output -like "*VMMap-assisted runs require the opt-in*") -Message "7.0 GiB was not accepted with a 10 GiB working-set limit; output was: $($accepted.output)"
    Assert-True -Condition ($accepted.output -notlike "*Cannot validate argument on parameter 'VmMapNearCutoffGiB'*") -Message "7.0 GiB was rejected during parameter binding."
    Assert-True -Condition ($accepted.output -notlike "*VMMap near-cutoff threshold must remain below*") -Message "7.0 GiB was rejected by the working-set invariant."

    foreach ($threshold in @(10.0, 10.1)) {
        $rejected = Invoke-RunnerProbe -ThresholdGiB $threshold -ProbeName ("rejected-{0}" -f $threshold.ToString("0.0", [Globalization.CultureInfo]::InvariantCulture))
        Assert-True -Condition ($rejected.exitCode -ne 0) -Message "$threshold GiB unexpectedly passed the working-set invariant."
        Assert-True -Condition ($rejected.output -like "*VMMap near-cutoff threshold must remain below*") -Message "$threshold GiB did not hit the working-set invariant; output was: $($rejected.output)"
    }

    $belowMinimum = Invoke-RunnerProbe -ThresholdGiB 0.9 -ProbeName "below-minimum"
    Assert-True -Condition ($belowMinimum.exitCode -ne 0) -Message "0.9 GiB unexpectedly passed parameter validation."
    Assert-True -Condition ($belowMinimum.output -like "*Cannot validate argument on parameter 'VmMapNearCutoffGiB'*") -Message "0.9 GiB did not remain rejected by the 1.0 GiB minimum; output was: $($belowMinimum.output)"

    Write-Host "VMMap near-cutoff validation regression passed."
}
finally {
    if (Test-Path -LiteralPath $probeRoot) {
        Remove-Item -LiteralPath $probeRoot -Recurse -Force
    }
}
