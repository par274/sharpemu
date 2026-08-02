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
    [ValidateScript({
        if ([double]::IsNaN([double]$_) -or
            [double]::IsInfinity([double]$_) -or
            [double]$_ -lt 1.0) {
            throw "VmMapNearCutoffGiB must be a finite value of at least 1.0 GiB."
        }

        return $true
    })]
    [double]$VmMapNearCutoffGiB = 5.0,
    [ValidateSet("all", "near-cutoff")]
    [string]$VmMapCheckpointMode = "all"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "vmmap-capture-lifecycle.ps1")
. (Join-Path $PSScriptRoot "target-memory-safety.ps1")
. (Join-Path $PSScriptRoot "runner-supervision.ps1")

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

function Start-VmMapCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [object]$ProcessIdentity,
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
            processIdentity = $ProcessIdentity
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

$mitigationDisableEnvironmentValue = [Environment]::GetEnvironmentVariable("SHARPEMU_DISABLE_MITIGATION_RELAUNCH")
$expectedSupervisionMode = Get-ControlledSupervisionMode `
    -ExecutablePath $emulatorPath `
    -WindowsHost $IsWindows `
    -MitigationDisableEnvironmentValue $mitigationDisableEnvironmentValue

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
$hostMemoryThresholds = Get-HostMemoryThresholds -Limits $limits

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
        throw "VMMap near-cutoff threshold must remain below the configured $workingSetGiB GiB working-set safety limit."
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
    $startupHostMemory = Get-HostMemorySnapshot
    $lastHostMemory = $startupHostMemory
    $minimumPhysicalAvailableBytes = [UInt64]$startupHostMemory.physicalAvailableBytes
    $minimumCommitHeadroomBytes = [UInt64]$startupHostMemory.commitHeadroomBytes
    $terminationReason = "process-exited"
    $terminationBoundary = $null
    $peakWorkingSetBytes = 0L
    $peakPrivateBytes = 0L
    $sampleCount = 0
    $exitCode = $null
    $processStarted = $false
    $supervisionState = $null
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
        schemaVersion = 2
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
            workingSetGiB = $workingSetGiB
            workingSetBytes = $workingSetLimitBytes
            minimumAvailablePhysicalGiB = $hostMemoryThresholds.minimumAvailablePhysicalGiB
            minimumAvailablePhysicalBytes = $hostMemoryThresholds.minimumAvailablePhysicalBytes
            minimumCommitHeadroomGiB = $hostMemoryThresholds.minimumCommitHeadroomGiB
            minimumCommitHeadroomBytes = $hostMemoryThresholds.minimumCommitHeadroomBytes
            sampleIntervalMilliseconds = $sampleIntervalMilliseconds
        }
        hostMemory = New-HostMemoryManifestSection `
            -StartupSample $startupHostMemory `
            -MinimumPhysicalAvailableBytes $hostMemoryThresholds.minimumAvailablePhysicalBytes `
            -MinimumCommitHeadroomBytes $hostMemoryThresholds.minimumCommitHeadroomBytes `
            -FinalSample $startupHostMemory `
            -TerminationBoundary $null
        diagnostics = [ordered]@{
            path = $diagnosticsPath
            enabled = $null -ne $diagnosticsPath
        }
        supervision = [ordered]@{
            expectedMode = $expectedSupervisionMode
            mitigationRelaunchDisabled = [string]::Equals(
                $mitigationDisableEnvironmentValue,
                "1",
                [StringComparison]::Ordinal)
            launcher = $null
            actualEmulation = $null
            actualChild = $null
            childDiscoveredAtUtc = $null
            launcherExitedAtUtc = $null
            monitoringContinuedAfterLauncherExit = $false
            finalChildDiscoveryAttempted = $false
            finalChildDiscoveryAtUtc = $null
            expectedChildNeverConfirmed = $false
            knownSupervisedIdentities = @()
            samples = @()
            identityMismatches = @()
            lookupFailures = @()
            cleanupTargets = @()
            cleanupEnumerationIncomplete = @()
            cleanupFailures = @()
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
    $supervisionSamples = [System.Collections.Generic.List[object]]::new()
    $supervisionEarlyFailures = [System.Collections.Generic.List[object]]::new()

    try {
        if (-not $process.Start()) {
            throw "SharpEmu did not start."
        }
        $processStarted = $true

        $launcherObservedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
        # Capture the root directly from the exact Process object returned by
        # Start(), before the first CIM inventory can fail or lose the root.
        $launcherIdentity = New-SupervisedProcessIdentityFromProcess `
            -Process $process `
            -ConfiguredExecutablePath $emulatorPath
        $supervisionState = New-SupervisionState `
            -LauncherIdentity $launcherIdentity `
            -ObservedAtUtc $launcherObservedAtUtc `
            -ExpectedMode $expectedSupervisionMode
        $manifest.supervision.launcher = $launcherIdentity
        $manifest.supervision.actualEmulation = [ordered]@{
            mode = $supervisionState.actualEmulation.mode
            identity = $supervisionState.actualEmulation.identity
        }
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $observedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            $processInventory = @(Get-TargetProcessInventory)
            $supervisionSample = Get-SupervisionSample `
                -State $supervisionState `
                -ProcessRecords $processInventory `
                -ObservedAtUtc $observedAtUtc

            $loopDecision = Get-SupervisionLoopDecision `
                -State $supervisionState `
                -Sample $supervisionSample
            if ($loopDecision -eq "final-child-discovery") {
                # The launcher can disappear between child creation and the
                # ordinary promotion sample.  Spend exactly one strict
                # inventory attempt on the launcher-associated child.
                $finalDiscoveryObservedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
                try {
                    $finalProcessInventory = @(Get-TargetProcessInventory)
                }
                catch {
                    $supervisionState.finalChildDiscoveryAttempted = $true
                    $supervisionState.finalChildDiscoveryAtUtc = $finalDiscoveryObservedAtUtc
                    throw
                }
                $finalChildResult = Invoke-SupervisionFinalChildDiscovery `
                    -State $supervisionState `
                    -ProcessRecords $finalProcessInventory `
                    -ObservedAtUtc $finalDiscoveryObservedAtUtc
                if ($finalChildResult.status -eq "found") {
                    $supervisionSample = Get-SupervisionSample `
                        -State $supervisionState `
                        -ProcessRecords $finalProcessInventory `
                        -ObservedAtUtc $finalDiscoveryObservedAtUtc
                    $loopDecision = Get-SupervisionLoopDecision `
                        -State $supervisionState `
                        -Sample $supervisionSample
                }
                else {
                    $terminationReason = "supervision-failure"
                    $terminationBoundary = [ordered]@{
                        reason = "supervision-failure"
                        boundary = "expected-child-confirmation"
                        expectedMode = $supervisionState.expectedMode
                        detail = "Expected mitigated child was never safely confirmed before launcher exit."
                        discoveryStatus = $finalChildResult.status
                    }
                    throw "Expected mitigated child was never safely confirmed: $($finalChildResult.reason)"
                }
            }
            if ($loopDecision -eq "supervision-failure") {
                $terminationReason = "supervision-failure"
                $terminationBoundary = [ordered]@{
                    reason = "supervision-failure"
                    boundary = "expected-child-confirmation"
                    expectedMode = $supervisionState.expectedMode
                    detail = "Expected mitigated child was never safely confirmed before launcher exit."
                }
                throw "Expected mitigated child was never safely confirmed."
            }
            if ($loopDecision -eq "process-exited") {
                break
            }

            $workingSetBytes = [long]$supervisionSample.workingSetBytes
            $privateBytes = [long]$supervisionSample.privateBytes
            $hostMemory = Get-HostMemorySnapshot
            $lastHostMemory = $hostMemory
            if ([UInt64]$hostMemory.physicalAvailableBytes -lt $minimumPhysicalAvailableBytes) {
                $minimumPhysicalAvailableBytes = [UInt64]$hostMemory.physicalAvailableBytes
            }
            if ([UInt64]$hostMemory.commitHeadroomBytes -lt $minimumCommitHeadroomBytes) {
                $minimumCommitHeadroomBytes = [UInt64]$hostMemory.commitHeadroomBytes
            }
            $hostBoundary = Get-TargetTerminationBoundary `
                -WorkingSetBytes ([UInt64]$workingSetBytes) `
                -WorkingSetLimitBytes ([UInt64]$workingSetLimitBytes) `
                -HostMemorySample $hostMemory `
                -HostMemoryThresholds $hostMemoryThresholds
            $emulationProcessIdentity = $supervisionSample.actualEmulationIdentity
            $emulationProcessId = if ($null -eq $emulationProcessIdentity -or
                $null -eq $supervisionSample.actualEmulationCounters) {
                $null
            }
            else {
                [int]$emulationProcessIdentity.processId
            }
            if ($null -ne $emulationProcessId) {
                [void]$emulationProcessIds.Add($emulationProcessId)
            }
            $peakWorkingSetBytes = [Math]::Max($peakWorkingSetBytes, $workingSetBytes)
            $peakPrivateBytes = [Math]::Max($peakPrivateBytes, $privateBytes)
            $sampleCount++

            $sample = [ordered]@{
                timestampUtc = [DateTimeOffset]::UtcNow.ToString("O")
                elapsedMilliseconds = [long]$stopwatch.Elapsed.TotalMilliseconds
                processCount = [int]$supervisionSample.processCount
                emulationProcessId = $emulationProcessId
                workingSetBytes = $workingSetBytes
                privateBytes = $privateBytes
                privateMemoryBytes = $privateBytes
                launcherAlive = $supervisionSample.launcherAlive
                actualChildAlive = $supervisionSample.actualChildAlive
                supervisedProcessIds = @($supervisionSample.supervisedProcessIds)
                supervisedIdentities = @($supervisionSample.supervisedIdentities)
                counterSources = @($supervisionSample.counterSources)
                launcherTree = $supervisionSample.launcherTree
                childTree = $supervisionSample.childTree
                childWorkingSetBytes = if ($null -eq $supervisionSample.actualChildCounters) { $null } else { [UInt64]$supervisionSample.actualChildCounters.workingSetBytes }
                childPrivateBytes = if ($null -eq $supervisionSample.actualChildCounters) { $null } else { [UInt64]$supervisionSample.actualChildCounters.privateBytes }
                aggregateWorkingSetBytes = [UInt64]$supervisionSample.workingSetBytes
                aggregatePrivateBytes = [UInt64]$supervisionSample.privateBytes
                monitoringContinuedAfterLauncherExit = $supervisionSample.monitoringContinuedAfterLauncherExit
                pageSizeBytes = [UInt64]$hostMemory.pageSizeBytes
                physicalTotalBytes = [UInt64]$hostMemory.physicalTotalBytes
                physicalAvailableBytes = [UInt64]$hostMemory.physicalAvailableBytes
                commitTotalBytes = [UInt64]$hostMemory.commitTotalBytes
                commitLimitBytes = [UInt64]$hostMemory.commitLimitBytes
                commitHeadroomBytes = [UInt64]$hostMemory.commitHeadroomBytes
            }
            Add-Content -LiteralPath $metricsPath -Value ($sample | ConvertTo-Json -Compress) -Encoding utf8
            [void]$supervisionSamples.Add([ordered]@{
                    timestampUtc = $sample.timestampUtc
                    elapsedMilliseconds = $sample.elapsedMilliseconds
                    launcherAlive = $sample.launcherAlive
                    actualChildAlive = $sample.actualChildAlive
                    supervisedProcessIds = @($sample.supervisedProcessIds)
                    counterSources = @($sample.counterSources)
                    workingSetBytes = $sample.workingSetBytes
                    privateBytes = $sample.privateBytes
                    childWorkingSetBytes = $sample.childWorkingSetBytes
                    childPrivateBytes = $sample.childPrivateBytes
                })

            if ($vmMapEnabled) {
                if ($null -ne $diagnosticsPath) {
                    $latestDiagnosticState = Get-DiagnosticState -Path $diagnosticsPath
                }

                [void](Complete-VmMapCaptures -Pending $vmMapPending -Completed $vmMapCompleted)
                $actualCounters = $supervisionSample.actualEmulationCounters

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
                            -ProcessIdentity $emulationProcessIdentity `
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
                                -ProcessIdentity $emulationProcessIdentity `
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
                            -ProcessIdentity $emulationProcessIdentity `
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

            if ($null -ne $hostBoundary) {
                $terminationReason = [string]$hostBoundary.reason
                $terminationBoundary = $hostBoundary
                Stop-SupervisedRoots `
                    -State $supervisionState `
                    -Reason $terminationReason | Out-Null
                break
            }

            if ($stopwatch.Elapsed.TotalSeconds -ge $wallTimeSeconds) {
                $terminationReason = "wall-time-limit"
                $terminationBoundary = [ordered]@{
                    reason = "wall-time-limit"
                    boundary = "wall-time"
                    thresholdSeconds = $wallTimeSeconds
                    sampledElapsedMilliseconds = [long]$stopwatch.Elapsed.TotalMilliseconds
                }
                Stop-SupervisedRoots `
                    -State $supervisionState `
                    -Reason $terminationReason | Out-Null
                break
            }

            Start-Sleep -Milliseconds $sampleIntervalMilliseconds
        }

        if (-not $process.WaitForExit(5000)) {
            throw "SharpEmu did not report exit within five seconds after its process tree stopped."
        }
        $exitCode = $process.ExitCode
        if ($null -eq $terminationBoundary) {
            $terminationBoundary = [ordered]@{
                reason = "process-exited"
                boundary = "process-exit"
            }
        }

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
        if ($null -ne $supervisionState -and
            ($supervisionState.identityMismatches.Count -gt 0 -or
                $supervisionState.lookupFailures.Count -gt 0 -or
                $supervisionState.expectedChildNeverConfirmed)) {
            $terminationReason = "supervision-failure"
        }
        if ($_.Exception.Message -like "SharpEmu process lookup failed:*" -or
            $_.Exception.Message -like "SharpEmu launcher identity could not be captured*") {
            $terminationReason = "supervision-failure"
            $failureRecord = [ordered]@{
                process = "process-inventory"
                reason = $_.Exception.Message
                observedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            }
            if ($null -ne $supervisionState) {
                [void]$supervisionState.lookupFailures.Add($failureRecord)
            }
            else {
                [void]$supervisionEarlyFailures.Add($failureRecord)
            }
        }
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
            if ($null -ne $supervisionState) {
                # Always retry both retained roots independently.  The
                # launcher may already be gone and the child may no longer be
                # reachable through its former parent relationship.
                Stop-SupervisedRoots `
                    -State $supervisionState `
                    -Reason "finally-cleanup" | Out-Null
                if ($processStarted -and -not $process.WaitForExit(5000)) {
                    throw "SharpEmu launcher did not report exit within five seconds after cleanup."
                }
            }
            elseif ($processStarted) {
                throw "SharpEmu cleanup was not attempted because launcher identity was never confirmed."
            }
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }

        if ($null -ne $supervisionState) {
            $manifest.supervision.launcher = $supervisionState.launcher.identity
            $manifest.supervision.actualEmulation = [ordered]@{
                mode = $supervisionState.actualEmulation.mode
                identity = $supervisionState.actualEmulation.identity
            }
            $manifest.supervision.expectedMode = $supervisionState.expectedMode
            $manifest.supervision.finalChildDiscoveryAttempted = $supervisionState.finalChildDiscoveryAttempted
            $manifest.supervision.finalChildDiscoveryAtUtc = $supervisionState.finalChildDiscoveryAtUtc
            $manifest.supervision.expectedChildNeverConfirmed = $supervisionState.expectedChildNeverConfirmed
            $manifest.supervision.actualChild = if ($null -eq $supervisionState.actualChild) {
                $null
            }
            else {
                [ordered]@{
                    identity = $supervisionState.actualChild.identity
                    discoveredAtUtc = $supervisionState.actualChild.discoveredAtUtc
                    exitedAtUtc = $supervisionState.actualChild.exitedAtUtc
                    lastCounters = $supervisionState.actualChild.lastCounters
                }
            }
            $manifest.supervision.childDiscoveredAtUtc = if ($null -eq $supervisionState.actualChild) {
                $null
            }
            else {
                $supervisionState.actualChild.discoveredAtUtc
            }
            $manifest.supervision.launcherExitedAtUtc = $supervisionState.launcher.exitedAtUtc
            $manifest.supervision.monitoringContinuedAfterLauncherExit = $supervisionState.monitoringContinuedAfterLauncherExit
            $manifest.supervision.knownSupervisedIdentities = @($supervisionState.knownSupervisedIdentities | ForEach-Object {
                    [ordered]@{
                        identity = $_.identity
                        firstObservedAtUtc = $_.firstObservedAtUtc
                        lastObservedAtUtc = $_.lastObservedAtUtc
                        sources = @($_.sources)
                    }
                })
            $manifest.supervision.samples = @($supervisionSamples)
            $manifest.supervision.identityMismatches = @($supervisionState.identityMismatches)
            $manifest.supervision.lookupFailures = @($supervisionState.lookupFailures)
            $manifest.supervision.cleanupTargets = @($supervisionState.cleanupTargets)
            $manifest.supervision.cleanupEnumerationIncomplete = @($supervisionState.cleanupEnumerationIncomplete)
            $manifest.supervision.cleanupFailures = @($supervisionState.cleanupFailures)
        }
        else {
            $manifest.supervision.lookupFailures = @($supervisionEarlyFailures)
        }

        $completedAt = [DateTimeOffset]::UtcNow
        $manifest.status = if ($null -eq $primaryFailure -and $cleanupFailures.Count -eq 0) {
            "completed"
        }
        else {
            "failed"
        }
        $manifest.completedAtUtc = $completedAt.ToString("O")
        $manifest.hostMemory = New-HostMemoryManifestSection `
            -StartupSample $startupHostMemory `
            -MinimumPhysicalAvailableBytes $minimumPhysicalAvailableBytes `
            -MinimumCommitHeadroomBytes $minimumCommitHeadroomBytes `
            -FinalSample $lastHostMemory `
            -TerminationBoundary $terminationBoundary
        $manifest.result = [ordered]@{
            terminationReason = $terminationReason
            terminationBoundary = $terminationBoundary
            primaryError = if ($null -eq $primaryFailure) { $null } else { $primaryFailure.Exception.Message }
            exitCode = $exitCode
            durationMilliseconds = [long]($completedAt - $startedAt).TotalMilliseconds
            sampleCount = $sampleCount
            peakWorkingSetBytes = $peakWorkingSetBytes
            peakPrivateBytes = $peakPrivateBytes
            emulationProcessIds = @($emulationProcessIds | Sort-Object)
            emulationProcessIdentity = if ($null -eq $supervisionState) {
                $null
            }
            else {
                $supervisionState.actualEmulation.identity
            }
            checkpointObserved = $null
            notes = "Record the observed checkpoint after reviewing the run. Do not infer it from process exit."
        }
        if ($supervisionEarlyFailures.Count -gt 0) {
            $manifest.result.earlySupervisionFailures = @($supervisionEarlyFailures)
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
                    processIdentity = $_.processIdentity
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
