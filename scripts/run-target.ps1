# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param(
    [string]$ConfigPath = ".local/target.json",
    [ValidateRange(1, 20)]
    [int]$Runs = 1,
    [string]$OutputRoot = "artifacts-local/runs",
    [string[]]$AdditionalArguments = @()
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Resolve-RepositoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw "Target configuration is missing '$Name'."
    }

    return $property.Value
}

function Get-ProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processes = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId)
    $ids = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ids.Add($RootProcessId)

    do {
        $added = $false
        foreach ($process in $processes) {
            if ($ids.Contains([int]$process.ParentProcessId) -and $ids.Add([int]$process.ProcessId)) {
                $added = $true
            }
        }
    } while ($added)

    $running = foreach ($processId in $ids) {
        Get-Process -Id $processId -ErrorAction SilentlyContinue
    }

    return @($running)
}

function Stop-ProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    & taskkill.exe /PID $RootProcessId /T /F 2>$null | Out-Null
    $taskkillExitCode = $LASTEXITCODE
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)

    do {
        $remaining = @(Get-ProcessTree -RootProcessId $RootProcessId)
        if ($remaining.Count -eq 0) {
            return
        }

        foreach ($remainingProcess in $remaining) {
            Stop-Process -Id $remainingProcess.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    $remainingIds = @(Get-ProcessTree -RootProcessId $RootProcessId | ForEach-Object { $_.Id })
    throw "Failed to stop SharpEmu process tree within 10 seconds. taskkill exit code: $taskkillExitCode; remaining PIDs: $($remainingIds -join ', ')"
}

if (-not $IsWindows) {
    throw "The controlled target runner supports Windows only."
}

$resolvedConfigPath = Resolve-RepositoryPath -Path $ConfigPath
if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
    throw "Target configuration was not found at '$resolvedConfigPath'. Copy scripts/target.example.json to .local/target.json and complete it on the Windows host."
}

$config = Get-Content -LiteralPath $resolvedConfigPath -Raw | ConvertFrom-Json
$titleId = [string](Get-RequiredProperty -Object $config -Name "titleId")
$region = [string](Get-RequiredProperty -Object $config -Name "region")
$version = [string](Get-RequiredProperty -Object $config -Name "version")
$ebootPath = [System.IO.Path]::GetFullPath([string](Get-RequiredProperty -Object $config -Name "ebootPath"))
$expectedEbootHash = ([string](Get-RequiredProperty -Object $config -Name "ebootSha256")).ToUpperInvariant()
$emulatorPath = Resolve-RepositoryPath -Path ([string](Get-RequiredProperty -Object $config -Name "emulatorPath"))
$route = [string](Get-RequiredProperty -Object $config -Name "route")
$expectedCheckpoint = [string](Get-RequiredProperty -Object $config -Name "expectedCheckpoint")
$hostConfig = Get-RequiredProperty -Object $config -Name "host"
$gpu = [string](Get-RequiredProperty -Object $hostConfig -Name "gpu")
$driverVersion = [string](Get-RequiredProperty -Object $hostConfig -Name "driverVersion")
$vulkanVersion = [string](Get-RequiredProperty -Object $hostConfig -Name "vulkanVersion")

if ($version -ne "1.004.000") {
    throw "This fork currently targets version 1.004.000, but the configuration specifies '$version'."
}

if ($titleId -eq "SET_ON_WINDOWS" -or $region -eq "SET_ON_WINDOWS" -or $gpu -eq "SET_ON_WINDOWS" -or $driverVersion -eq "SET_ON_WINDOWS" -or $vulkanVersion -eq "SET_ON_WINDOWS") {
    throw "Replace every SET_ON_WINDOWS value in the target configuration before running."
}

if (-not (Test-Path -LiteralPath $ebootPath -PathType Leaf)) {
    throw "The configured eboot was not found."
}

if (-not (Test-Path -LiteralPath $emulatorPath -PathType Leaf)) {
    throw "The configured emulator executable was not found. Publish the Release win-x64 CLI first."
}

$actualEbootHash = (Get-FileHash -LiteralPath $ebootPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($expectedEbootHash -notmatch "^[0-9A-F]{64}$") {
    throw "ebootSha256 must be a 64-character SHA-256 value. Actual file hash: $actualEbootHash"
}
if ($expectedEbootHash -ne $actualEbootHash) {
    throw "The configured eboot SHA-256 does not match the selected file. Actual: $actualEbootHash"
}

$emulatorHash = (Get-FileHash -LiteralPath $emulatorPath -Algorithm SHA256).Hash.ToUpperInvariant()
$limits = Get-RequiredProperty -Object $config -Name "limits"
$wallTimeSeconds = [int](Get-RequiredProperty -Object $limits -Name "wallTimeSeconds")
$workingSetGiB = [double](Get-RequiredProperty -Object $limits -Name "workingSetGiB")
$sampleIntervalMilliseconds = [int](Get-RequiredProperty -Object $limits -Name "sampleIntervalMilliseconds")

if ($wallTimeSeconds -lt 1 -or $workingSetGiB -le 0 -or $sampleIntervalMilliseconds -lt 250) {
    throw "Target limits must use a positive wall time and working-set limit, with a sampling interval of at least 250 ms."
}

$arguments = @()
if ($null -ne $config.PSObject.Properties["arguments"]) {
    $arguments = @($config.arguments | ForEach-Object { [string]$_ })
}

$resolvedOutputRoot = Resolve-RepositoryPath -Path $OutputRoot
[System.IO.Directory]::CreateDirectory($resolvedOutputRoot) | Out-Null
$repositoryCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
$repositoryDirty = -not [string]::IsNullOrWhiteSpace((& git -C $repositoryRoot status --porcelain) -join "`n")
$workingSetLimitBytes = [long]($workingSetGiB * 1GB)
$cpuNames = @(Get-CimInstance Win32_Processor -Property Name | ForEach-Object { $_.Name.Trim() } | Sort-Object -Unique)
$operatingSystem = Get-CimInstance Win32_OperatingSystem -Property Caption, Version, BuildNumber
if ($cpuNames.Count -eq 0 -or $null -eq $operatingSystem) {
    throw "Windows hardware identity could not be read through CIM."
}
$machine = [ordered]@{
    computerName = $env:COMPUTERNAME
    operatingSystem = $operatingSystem.Caption
    operatingSystemVersion = $operatingSystem.Version
    operatingSystemBuild = $operatingSystem.BuildNumber
    cpu = $cpuNames -join " + "
    processorCount = [System.Environment]::ProcessorCount
    dotnetRuntime = [System.Environment]::Version.ToString()
    gpu = $gpu
    driverVersion = $driverVersion
    vulkanVersion = $vulkanVersion
}

for ($trial = 1; $trial -le $Runs; $trial++) {
    $startedAt = [DateTimeOffset]::UtcNow
    $runId = "{0}-{1}-trial-{2:D2}" -f $startedAt.ToString("yyyyMMddTHHmmssfffZ"), $repositoryCommit.Substring(0, 7), $trial
    $runDirectory = Join-Path $resolvedOutputRoot $runId
    [System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
    $manifestPath = Join-Path $runDirectory "manifest.json"
    $metricsPath = Join-Path $runDirectory "metrics.jsonl"
    $logPath = Join-Path $runDirectory "sharpemu.log"
    $terminationReason = "process-exited"
    $peakWorkingSetBytes = 0L
    $peakPrivateBytes = 0L
    $sampleCount = 0
    $exitCode = $null
    $processStarted = $false
    $emulationProcessIds = [System.Collections.Generic.HashSet[int]]::new()
    $comparisonArguments = @($arguments + $AdditionalArguments)
    $launchAdditionalArguments = @($AdditionalArguments | ForEach-Object {
        ([string]$_).Replace("{runDirectory}", $runDirectory).Replace("{runId}", $runId)
    })

    $manifest = [ordered]@{
        schemaVersion = 1
        runId = $runId
        status = "running"
        startedAtUtc = $startedAt.ToString("O")
        completedAtUtc = $null
        repositoryCommit = $repositoryCommit
        repositoryDirty = $repositoryDirty
        target = [ordered]@{
            titleId = $titleId
            region = $region
            version = $version
            ebootSha256 = $actualEbootHash
            route = $route
            expectedCheckpoint = $expectedCheckpoint
        }
        emulator = [ordered]@{
            sha256 = $emulatorHash
            arguments = @($arguments + $launchAdditionalArguments)
            comparisonArguments = $comparisonArguments
        }
        limits = [ordered]@{
            wallTimeSeconds = $wallTimeSeconds
            workingSetBytes = $workingSetLimitBytes
            sampleIntervalMilliseconds = $sampleIntervalMilliseconds
        }
        machine = $machine
        result = $null
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $emulatorPath
    $startInfo.WorkingDirectory = [System.IO.Path]::GetDirectoryName($ebootPath)
    $startInfo.UseShellExecute = $false
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    foreach ($argument in $launchAdditionalArguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    [void]$startInfo.ArgumentList.Add("--log-file=$logPath")
    [void]$startInfo.ArgumentList.Add($ebootPath)

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    Write-Host "Starting trial $trial of ${Runs}: $runId"

    try {
        if (-not $process.Start()) {
            throw "SharpEmu did not start."
        }
        $processStarted = $true

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $process.HasExited) {
            $processTree = @(Get-ProcessTree -RootProcessId $process.Id)
            $workingSetBytes = [long](($processTree | Measure-Object -Property WorkingSet64 -Sum).Sum)
            $privateBytes = [long](($processTree | Measure-Object -Property PrivateMemorySize64 -Sum).Sum)
            $emulationProcessId = $null
            if ($AdditionalArguments.Count -gt 0) {
                $treeIds = [System.Collections.Generic.HashSet[int]]::new()
                foreach ($treeProcess in $processTree) {
                    [void]$treeIds.Add([int]$treeProcess.Id)
                }

                $emulationProcess = Get-CimInstance Win32_Process -Property ProcessId, Name, CommandLine |
                    Where-Object {
                        $treeIds.Contains([int]$_.ProcessId) -and
                        $_.Name -eq "SharpEmu.exe" -and
                        $_.CommandLine -like "*--sharpemu-mitigated-child*"
                    } |
                    Select-Object -First 1
                if ($null -ne $emulationProcess) {
                    $emulationProcessId = [int]$emulationProcess.ProcessId
                    [void]$emulationProcessIds.Add($emulationProcessId)
                }
            }
            $peakWorkingSetBytes = [Math]::Max($peakWorkingSetBytes, $workingSetBytes)
            $peakPrivateBytes = [Math]::Max($peakPrivateBytes, $privateBytes)
            $sampleCount++

            $sample = [ordered]@{
                timestampUtc = [DateTimeOffset]::UtcNow.ToString("O")
                elapsedMilliseconds = [long]$stopwatch.Elapsed.TotalMilliseconds
                processCount = $processTree.Count
                emulationProcessId = $emulationProcessId
                workingSetBytes = $workingSetBytes
                privateBytes = $privateBytes
            }
            Add-Content -LiteralPath $metricsPath -Value ($sample | ConvertTo-Json -Compress) -Encoding utf8

            if ($workingSetBytes -ge $workingSetLimitBytes) {
                $terminationReason = "working-set-limit"
                Stop-ProcessTree -RootProcessId $process.Id
                break
            }

            if ($stopwatch.Elapsed.TotalSeconds -ge $wallTimeSeconds) {
                $terminationReason = "wall-time-limit"
                Stop-ProcessTree -RootProcessId $process.Id
                break
            }

            Start-Sleep -Milliseconds $sampleIntervalMilliseconds
            $process.Refresh()
        }

        if (-not $process.WaitForExit(5000)) {
            throw "SharpEmu did not report exit within five seconds after its process tree stopped."
        }
        $exitCode = $process.ExitCode
    }
    finally {
        if ($processStarted -and -not $process.HasExited) {
            Stop-ProcessTree -RootProcessId $process.Id
            if (-not $process.WaitForExit(5000)) {
                throw "SharpEmu did not report exit within five seconds after forced termination."
            }
        }

        $completedAt = [DateTimeOffset]::UtcNow
        $manifest.status = "completed"
        $manifest.completedAtUtc = $completedAt.ToString("O")
        $manifest.result = [ordered]@{
            terminationReason = $terminationReason
            exitCode = $exitCode
            durationMilliseconds = [long]($completedAt - $startedAt).TotalMilliseconds
            sampleCount = $sampleCount
            peakWorkingSetBytes = $peakWorkingSetBytes
            peakPrivateBytes = $peakPrivateBytes
            emulationProcessIds = @($emulationProcessIds | Sort-Object)
            checkpointObserved = $null
            notes = "Record the observed checkpoint after reviewing the run. Do not infer it from process exit."
        }
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
        if ($null -ne $process) {
            $process.Dispose()
        }
    }

    Write-Host "Completed $runId ($terminationReason, peak working set $([Math]::Round($peakWorkingSetBytes / 1GB, 2)) GiB)."
}

Write-Host "Run artifacts: $resolvedOutputRoot"
