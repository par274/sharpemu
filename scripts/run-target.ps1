# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param(
    [string]$ConfigPath = ".local/target.json",
    [ValidateRange(1, 20)]
    [int]$Runs = 1,
    [string]$OutputRoot = "artifacts-local/runs",
    [string[]]$AdditionalArguments = @(),
    [string]$VmMapPath = "",
    [string]$VmMapOutputRoot = "C:\sharpemu-investigation\vmmap-captures",
    [ValidateRange(1.0, 5.9)]
    [double]$VmMapNearCutoffGiB = 5.0,
    [ValidateSet("all", "near-cutoff")]
    [string]$VmMapCheckpointMode = "all"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "vmmap-capture-lifecycle.ps1")

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

function Get-ActualEmulationProcess {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessTree
    )

    $treeIds = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($treeProcess in $ProcessTree) {
        [void]$treeIds.Add([int]$treeProcess.Id)
    }

    $processes = @(Get-CimInstance Win32_Process -Property ProcessId, Name, CommandLine)
    $child = $processes |
        Where-Object {
            $treeIds.Contains([int]$_.ProcessId) -and
            $_.Name -eq "SharpEmu.exe" -and
            $_.CommandLine -like "*--sharpemu-mitigated-child*"
        } |
        Select-Object -First 1
    if ($null -ne $child) {
        return $child
    }

    # A directly launched Release executable is already the emulation process;
    # this fallback still excludes the PowerShell runner and any dotnet host.
    return $processes |
        Where-Object {
            $treeIds.Contains([int]$_.ProcessId) -and $_.Name -eq "SharpEmu.exe"
        } |
        Select-Object -First 1
}

function Get-DiagnosticState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $latestSample = $null
    $correctedDispatchObserved = $false
    $guestMappings = @{}
    $vulkanHostMappings = @{}
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            try {
                $record = $line | ConvertFrom-Json -Depth 64
            }
            catch {
                # The diagnostics writer may be between two JSONL writes.
                continue
            }

            if ($record.kind -eq "sample") {
                $latestSample = $record
                continue
            }

            if ($record.kind -ne "event") {
                continue
            }

            if ($record.event -eq "guest-work-frontier" -and
                $record.data.phase -eq "corrected-dispatch-complete") {
                $correctedDispatchObserved = $true
                continue
            }

            if ($record.event -eq "guest-host-mapping") {
                $data = $record.data
                $key = "{0:X16}:{1:X}" -f
                    [uint64]$data.baseAddress,
                    [uint64]$data.reservedBytes
                if ($data.action -eq "release") {
                    [void]$guestMappings.Remove($key)
                }
                else {
                    $guestMappings[$key] = [ordered]@{
                        baseAddress = [uint64]$data.baseAddress
                        reservedBytes = [uint64]$data.reservedBytes
                        committedBytes = [uint64]$data.committedBytes
                        executable = [bool]$data.executable
                        reservedOnly = [bool]$data.reservedOnly
                    }
                }
            }

            if ($record.event -eq "vulkan-host-memory-map") {
                $data = $record.data
                $key = [string]$data.memoryHandle
                if ($data.action -eq "unmap") {
                    [void]$vulkanHostMappings.Remove($key)
                }
                else {
                    $vulkanHostMappings[$key] = [ordered]@{
                        memoryHandle = [uint64]$data.memoryHandle
                        address = [uint64]$data.address
                        size = [uint64]$data.size
                        label = [string]$data.label
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        LatestSample = $latestSample
        CorrectedDispatchObserved = $correctedDispatchObserved
        GuestMappings = @($guestMappings.Values | Sort-Object baseAddress)
        VulkanHostMappings = @($vulkanHostMappings.Values | Sort-Object address)
    }
}

function Get-ProcessCounters {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }

    $process.Refresh()
    return [ordered]@{
        processId = $ProcessId
        workingSetBytes = [long]$process.WorkingSet64
        privateBytes = [long]$process.PrivateMemorySize64
    }
}

function Start-VmMapCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [string]$Reason,
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryCommit,
        [Parameter(Mandatory = $true)]
        [string]$TargetHash,
        [Parameter(Mandatory = $true)]
        [object]$TargetArguments,
        [Parameter(Mandatory = $true)]
        [object]$DiagnosticState,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Pending,
        [object]$ProcessCounters,
        [long]$TriggerThresholdBytes
    )

    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    $startedAt = [DateTimeOffset]::UtcNow
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ToolPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    # VMMap 3.4's verified command line is:
    #   vmmap64.exe -p <pid> <output.csv>
    [void]$startInfo.ArgumentList.Add("-p")
    [void]$startInfo.ArgumentList.Add($ProcessId.ToString())
    [void]$startInfo.ArgumentList.Add($OutputPath)

    $vmMapProcess = [System.Diagnostics.Process]::new()
    $vmMapStarted = $false
    try {
        $vmMapProcess.StartInfo = $startInfo
        if (-not $vmMapProcess.Start()) {
            throw "VMMap did not start for PID $ProcessId."
        }
        $vmMapStarted = $true

        $capture = [pscustomobject]@{
            process = $vmMapProcess
            processId = $ProcessId
            runId = $RunId
            repositoryCommit = $RepositoryCommit
            targetEbootSha256 = $TargetHash
            targetArguments = @($TargetArguments)
            reason = $Reason
            outputPath = $OutputPath
            command = @("-p", $ProcessId.ToString(), $OutputPath)
            captureStartedAtUtc = $startedAt.ToString("O")
            captureCompletedAtUtc = $null
            captureDurationMilliseconds = $null
            exitCode = $null
            outputExists = $false
            cleanupError = $null
            nearestDiagnosticsSample = $DiagnosticState.LatestSample
            guestMappingsAtStart = @($DiagnosticState.GuestMappings)
            vulkanHostMappingsAtStart = @($DiagnosticState.VulkanHostMappings)
            processCountersAtStart = $ProcessCounters
            triggerThresholdBytes = $TriggerThresholdBytes
        }

        # Register before returning so an exception in the caller cannot leave
        # a successfully started VMMap process outside the guaranteed cleanup.
        [void]$Pending.Add($capture)
        return $capture
    }
    catch {
        try {
            # Also probe after a Start() exception: the native process may have
            # been created before the wrapper reported the exception.
            if ($vmMapStarted -or $vmMapProcess.HasExited -eq $false) {
                Stop-Process -Id $vmMapProcess.Id -Force -ErrorAction SilentlyContinue
                [void]$vmMapProcess.WaitForExit(1000)
            }
        }
        catch {
            # Preserve the start/registration failure.
        }

        try {
            $vmMapProcess.Dispose()
        }
        catch {
            # Preserve the start/registration failure.
        }
        throw
    }
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
$workingSetLimitBytes = [long]($workingSetGiB * 1GB)
$vmMapEnabled = -not [string]::IsNullOrWhiteSpace($VmMapPath)
$resolvedVmMapPath = $null
$vmMapVersion = $null
$resolvedVmMapOutputRoot = $null
$vmMapNearCutoffBytes = $null
if ($vmMapEnabled) {
    $resolvedVmMapPath = Resolve-RepositoryPath -Path $VmMapPath
    if (-not (Test-Path -LiteralPath $resolvedVmMapPath -PathType Leaf)) {
        throw "VMMap was not found at '$resolvedVmMapPath'. Use the official Microsoft Sysinternals VMMap download."
    }

    $vmMapVersion = [string](Get-Item -LiteralPath $resolvedVmMapPath).VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($vmMapVersion)) {
        throw "VMMap file version could not be read from '$resolvedVmMapPath'."
    }

    $resolvedVmMapOutputRoot = Resolve-RepositoryPath -Path $VmMapOutputRoot
    [System.IO.Directory]::CreateDirectory($resolvedVmMapOutputRoot) | Out-Null
    $vmMapNearCutoffBytes = [long]($VmMapNearCutoffGiB * 1GB)
    if ($vmMapNearCutoffBytes -ge $workingSetLimitBytes) {
        throw "VMMap near-cutoff threshold must remain below the configured 6 GiB safety limit."
    }
}
$repositoryCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
$repositoryDirty = -not [string]::IsNullOrWhiteSpace((& git -C $repositoryRoot status --porcelain) -join "`n")
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
    $diagnosticsPath = $null
    foreach ($argument in $launchAdditionalArguments) {
        if ($argument -like "--memory-diagnostics=*") {
            $diagnosticsPath = $argument.Substring("--memory-diagnostics=".Length)
            break
        }
    }
    if ($vmMapEnabled -and [string]::IsNullOrWhiteSpace($diagnosticsPath)) {
        throw "VMMap-assisted runs require the opt-in --memory-diagnostics={runDirectory}\\memory-diagnostics.jsonl argument."
    }
    $vmMapPending = [System.Collections.ArrayList]::new()
    $vmMapCompleted = [System.Collections.ArrayList]::new()
    $vmMapRunDirectory = $null
    if ($vmMapEnabled) {
        $vmMapRunDirectory = Join-Path $resolvedVmMapOutputRoot $runId
        [System.IO.Directory]::CreateDirectory($vmMapRunDirectory) | Out-Null
    }
    $latestDiagnosticState = [pscustomobject]@{
        LatestSample = $null
        CorrectedDispatchObserved = $false
        GuestMappings = @()
        VulkanHostMappings = @()
    }
    $correctedCaptureRequested = $false
    $plateauCaptureRequested = $false
    $nearCutoffCaptureRequested = $false
    $texturePlateauSignature = $null
    $texturePlateauSamples = 0

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
        diagnostics = [ordered]@{
            path = $diagnosticsPath
            enabled = $null -ne $diagnosticsPath
        }
        vmmap = if ($vmMapEnabled) {
            [ordered]@{
                enabled = $true
                toolPath = $resolvedVmMapPath
                toolVersion = $vmMapVersion
                outputDirectory = $vmMapRunDirectory
                command = "vmmap64.exe -p <actual SharpEmu child PID> <output.csv>"
                nearCutoffThresholdBytes = $vmMapNearCutoffBytes
                safetyWorkingSetLimitBytes = $workingSetLimitBytes
                checkpointMode = $VmMapCheckpointMode
                captures = @()
            }
        }
        else {
            [ordered]@{
                enabled = $false
                captures = @()
            }
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
    $primaryFailure = $null

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
            $emulationProcess = Get-ActualEmulationProcess -ProcessTree $processTree
            if ($null -ne $emulationProcess) {
                $emulationProcessId = [int]$emulationProcess.ProcessId
                [void]$emulationProcessIds.Add($emulationProcessId)
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

            if ($vmMapEnabled) {
                if ($null -ne $diagnosticsPath) {
                    $latestDiagnosticState = Get-DiagnosticState -Path $diagnosticsPath
                }

                [void](Complete-VmMapCaptures -Pending $vmMapPending -Completed $vmMapCompleted)
                $actualCounters = if ($null -ne $emulationProcessId) {
                    Get-ProcessCounters -ProcessId $emulationProcessId
                }
                else {
                    $null
                }

                if ($null -ne $emulationProcessId -and $null -ne $vmMapRunDirectory) {
                    $captureStartedThisSample = $false
                    if ($VmMapCheckpointMode -eq "all" -and
                        $null -ne $actualCounters -and
                        $latestDiagnosticState.CorrectedDispatchObserved -and
                        -not $correctedCaptureRequested -and
                        -not $captureStartedThisSample -and
                        $vmMapPending.Count -eq 0) {
                        $capture = Start-VmMapCapture `
                            -ToolPath $resolvedVmMapPath `
                            -OutputPath (Join-Path $vmMapRunDirectory "vmmap-corrected-dispatch.csv") `
                            -ProcessId $emulationProcessId `
                            -Reason "corrected-dispatch" `
                            -RunId $runId `
                            -RepositoryCommit $repositoryCommit `
                            -TargetHash $actualEbootHash `
                            -TargetArguments @($arguments + $launchAdditionalArguments) `
                            -DiagnosticState $latestDiagnosticState `
                            -Pending $vmMapPending `
                            -ProcessCounters $actualCounters `
                            -TriggerThresholdBytes ([long]$actualCounters.workingSetBytes)
                        $correctedCaptureRequested = $true
                        $captureStartedThisSample = $true
                    }

                    $resources = $null
                    if ($null -ne $latestDiagnosticState.LatestSample) {
                        $diagnosticsProperty =
                            $latestDiagnosticState.LatestSample.PSObject.Properties["Diagnostics"]
                        if ($null -ne $diagnosticsProperty -and
                            $null -ne $diagnosticsProperty.Value) {
                            $resources = $diagnosticsProperty.Value.resources
                        }
                    }
                    if ($VmMapCheckpointMode -eq "all" -and
                        $null -ne $actualCounters -and
                        $latestDiagnosticState.CorrectedDispatchObserved -and
                        $null -ne $resources) {
                        $cacheCount = [int]$resources.textureCacheCount
                        $cacheImageBytes = [long]$resources.textureCacheImageBytes
                        $cacheStagingBytes = [long]$resources.textureCacheStagingBytes
                        $signature = "{0}:{1}:{2}" -f $cacheCount, $cacheImageBytes, $cacheStagingBytes
                        if ($cacheCount -gt 0 -and $signature -eq $texturePlateauSignature) {
                            $texturePlateauSamples++
                        }
                        elseif ($cacheCount -gt 0) {
                            $texturePlateauSignature = $signature
                            $texturePlateauSamples = 1
                        }
                        else {
                            $texturePlateauSignature = $null
                            $texturePlateauSamples = 0
                        }

                        if ($texturePlateauSamples -ge 4 -and
                            -not $plateauCaptureRequested -and
                            -not $captureStartedThisSample -and
                            $vmMapPending.Count -eq 0 -and
                            -not ($null -ne $actualCounters -and
                                [long]$actualCounters.workingSetBytes -ge $vmMapNearCutoffBytes)) {
                            $capture = Start-VmMapCapture `
                                -ToolPath $resolvedVmMapPath `
                                -OutputPath (Join-Path $vmMapRunDirectory "vmmap-cache-plateau.csv") `
                                -ProcessId $emulationProcessId `
                                -Reason "cache-plateau" `
                                -RunId $runId `
                                -RepositoryCommit $repositoryCommit `
                                -TargetHash $actualEbootHash `
                                -TargetArguments @($arguments + $launchAdditionalArguments) `
                                -DiagnosticState $latestDiagnosticState `
                                -Pending $vmMapPending `
                                -ProcessCounters $actualCounters `
                                -TriggerThresholdBytes ([long]$actualCounters.workingSetBytes)
                            $plateauCaptureRequested = $true
                            $captureStartedThisSample = $true
                        }
                    }

                    if ($null -ne $actualCounters -and
                        [long]$actualCounters.workingSetBytes -ge $vmMapNearCutoffBytes -and
                        -not $nearCutoffCaptureRequested -and
                        -not $captureStartedThisSample -and
                        $vmMapPending.Count -eq 0) {
                        $capture = Start-VmMapCapture `
                            -ToolPath $resolvedVmMapPath `
                            -OutputPath (Join-Path $vmMapRunDirectory "vmmap-near-cutoff.csv") `
                            -ProcessId $emulationProcessId `
                            -Reason "near-cutoff" `
                            -RunId $runId `
                            -RepositoryCommit $repositoryCommit `
                            -TargetHash $actualEbootHash `
                            -TargetArguments @($arguments + $launchAdditionalArguments) `
                            -DiagnosticState $latestDiagnosticState `
                            -Pending $vmMapPending `
                            -ProcessCounters $actualCounters `
                            -TriggerThresholdBytes $vmMapNearCutoffBytes
                        $nearCutoffCaptureRequested = $true
                        $captureStartedThisSample = $true
                    }
                }
            }

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

        if ($vmMapEnabled) {
            $vmMapDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
            do {
                [void](Complete-VmMapCaptures -Pending $vmMapPending -Completed $vmMapCompleted)
                if ($vmMapPending.Count -eq 0) {
                    break
                }

                Start-Sleep -Milliseconds 250
            } while ([DateTimeOffset]::UtcNow -lt $vmMapDeadline)

            if ($vmMapPending.Count -gt 0) {
                Stop-AndDispose-VmMapCaptures `
                    -Pending $vmMapPending `
                    -Completed $vmMapCompleted `
                    -TimeoutSeconds 10
            }
        }
    }
    catch {
        $primaryFailure = $_
        throw
    }
    finally {
        $cleanupFailures = [System.Collections.Generic.List[object]]::new()

        # This is deliberately in finally: capture handling must run even when
        # diagnostics, process-tree termination, or manifest work fails.
        if ($vmMapEnabled) {
            try {
                Stop-AndDispose-VmMapCaptures `
                    -Pending $vmMapPending `
                    -Completed $vmMapCompleted `
                    -TimeoutSeconds 10
            }
            catch {
                [void]$cleanupFailures.Add($_)
            }
        }

        try {
            if ($processStarted -and -not $process.HasExited) {
                Stop-ProcessTree -RootProcessId $process.Id
                if (-not $process.WaitForExit(5000)) {
                    throw "SharpEmu did not report exit within five seconds after forced termination."
                }
            }
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }

        $completedAt = [DateTimeOffset]::UtcNow
        $manifest.status = if ($null -eq $primaryFailure -and $cleanupFailures.Count -eq 0) {
            "completed"
        }
        else {
            "failed"
        }
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
        if ($cleanupFailures.Count -gt 0) {
            $manifest.result.cleanupErrors = @($cleanupFailures | ForEach-Object {
                $_.Exception.Message
            })
        }
        if ($vmMapEnabled) {
            $manifest.vmmap.captures = @($vmMapCompleted | ForEach-Object {
                [ordered]@{
                    processId = $_.processId
                    runId = $_.runId
                    repositoryCommit = $_.repositoryCommit
                    targetEbootSha256 = $_.targetEbootSha256
                    targetArguments = @($_.targetArguments)
                    reason = $_.reason
                    outputPath = $_.outputPath
                    command = @($_.command)
                    captureStartedAtUtc = $_.captureStartedAtUtc
                    captureCompletedAtUtc = $_.captureCompletedAtUtc
                    captureDurationMilliseconds = $_.captureDurationMilliseconds
                    exitCode = $_.exitCode
                    outputExists = $_.outputExists
                    cleanupError = $_.cleanupError
                    nearestDiagnosticsSample = $_.nearestDiagnosticsSample
                    guestMappingsAtStart = @($_.guestMappingsAtStart)
                    vulkanHostMappingsAtStart = @($_.vulkanHostMappingsAtStart)
                    processCountersAtStart = $_.processCountersAtStart
                    triggerThresholdBytes = $_.triggerThresholdBytes
                }
            })
        }
        try {
            $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }
        finally {
            if ($null -ne $process) {
                try {
                    $process.Dispose()
                }
                catch {
                    [void]$cleanupFailures.Add($_)
                }
            }
        }

        # A cleanup failure is useful when it is the only failure, but it must
        # never replace a failure raised by the target or diagnostics body.
        if ($null -eq $primaryFailure -and $cleanupFailures.Count -gt 0) {
            $messages = @($cleanupFailures | ForEach-Object { $_.Exception.Message })
            throw "Target-run cleanup failed: $($messages -join ' | ')"
        }
    }

    Write-Host "Completed $runId ($terminationReason, peak working set $([Math]::Round($peakWorkingSetBytes / 1GB, 2)) GiB)."
}

Write-Host "Run artifacts: $resolvedOutputRoot"
