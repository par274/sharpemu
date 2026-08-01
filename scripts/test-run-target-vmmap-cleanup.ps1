# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Deterministic state-machine regression for VMMap cleanup.  It uses fake
# Process-shaped objects and never launches SharpEmu, VMMap, or a timer.
#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "vmmap-capture-lifecycle.ps1")

function New-FakeVmMapProcess {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $true)]
        [bool]$HasExited,
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $state = [pscustomobject]@{
        StopCalls = 0
        WaitCalls = 0
        DisposeCalls = 0
    }
    $process = [pscustomobject]@{
        Id = $Id
        HasExited = $HasExited
        ExitCode = $ExitCode
        State = $state
    }
    Add-Member -InputObject $process -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int]$Milliseconds = 0)
        $this.State.WaitCalls++
        return [bool]$this.HasExited
    }
    Add-Member -InputObject $process -MemberType ScriptMethod -Name Dispose -Value {
        $this.State.DisposeCalls++
    }

    return [pscustomobject]@{
        Process = $process
        State = $state
    }
}

function New-FakeCapture {
    param(
        [Parameter(Mandatory = $true)]
        [object]$FakeProcess,
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    return [pscustomobject]@{
        process = $FakeProcess.Process
        processId = $FakeProcess.Process.Id
        reason = $Reason
        outputPath = (Join-Path ([System.IO.Path]::GetTempPath()) "sharpemu-vmmap-test.csv")
        captureStartedAtUtc = "2026-08-01T00:00:00.0000000+00:00"
        captureCompletedAtUtc = $null
        captureDurationMilliseconds = $null
        exitCode = $null
        outputExists = $false
        cleanupError = $null
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Expected,
        [Parameter(Mandatory = $true)]
        [object]$Actual,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message. Expected '$Expected', received '$Actual'."
    }
}

$completed = [System.Collections.ArrayList]::new()
$pending = [System.Collections.ArrayList]::new()
$alreadyExited = New-FakeVmMapProcess -Id 101 -HasExited $true -ExitCode 0
$stoppable = New-FakeVmMapProcess -Id 102 -HasExited $false -ExitCode 17
$alreadyExitedCapture = New-FakeCapture -FakeProcess $alreadyExited -Reason "completed"
$stoppableCapture = New-FakeCapture -FakeProcess $stoppable -Reason "stoppable"
[void]$pending.Add($alreadyExitedCapture)
[void]$pending.Add($stoppableCapture)

$stopAction = {
    param([int]$ProcessId)
    if ($ProcessId -ne $stoppable.Process.Id) {
        throw "Unexpected fake VMMap PID $ProcessId."
    }
    $stoppable.State.StopCalls++
    $stoppable.Process.HasExited = $true
}
$noSleep = {
    param([int]$Milliseconds)
    throw "The successful cleanup path unexpectedly slept."
}

Stop-AndDispose-VmMapCaptures `
    -Pending $pending `
    -Completed $completed `
    -TimeoutSeconds 1 `
    -StopProcessAction $stopAction `
    -SleepAction $noSleep

Assert-Equal -Expected 0 -Actual $pending.Count -Message "Successful cleanup left pending captures"
Assert-Equal -Expected 2 -Actual $completed.Count -Message "Successful cleanup lost completed metadata"
Assert-Equal -Expected 0 -Actual $alreadyExited.State.StopCalls -Message "Exited capture was stopped"
Assert-Equal -Expected 1 -Actual $alreadyExited.State.WaitCalls -Message "Exited capture wait count"
Assert-Equal -Expected 1 -Actual $alreadyExited.State.DisposeCalls -Message "Exited capture dispose count"
Assert-Equal -Expected 1 -Actual $stoppable.State.StopCalls -Message "Active capture stop count"
Assert-Equal -Expected 1 -Actual $stoppable.State.WaitCalls -Message "Active capture wait count"
Assert-Equal -Expected 1 -Actual $stoppable.State.DisposeCalls -Message "Active capture dispose count"
Assert-Equal -Expected 0 -Actual $alreadyExitedCapture.exitCode -Message "Exited capture exit code"
Assert-Equal -Expected 17 -Actual $stoppableCapture.exitCode -Message "Stopped capture exit code"
if ($null -eq $alreadyExitedCapture.captureCompletedAtUtc -or
    $null -eq $stoppableCapture.captureCompletedAtUtc -or
    $null -ne $alreadyExitedCapture.process -or
    $null -ne $stoppableCapture.process) {
    throw "Successful cleanup did not preserve completion metadata and clear Process references."
}

# A failing stop/wait operation still disposes and records the capture.  The
# second cleanup pass must not dispose it again.
$failedCompleted = [System.Collections.ArrayList]::new()
$failedPending = [System.Collections.ArrayList]::new()
$uncooperative = New-FakeVmMapProcess -Id 103 -HasExited $false -ExitCode 23
$uncooperativeCapture = New-FakeCapture -FakeProcess $uncooperative -Reason "uncooperative"
[void]$failedPending.Add($uncooperativeCapture)
$failingStop = {
    param([int]$ProcessId)
    $uncooperative.State.StopCalls++
    throw "synthetic stop failure"
}
$failingSleep = {
    param([int]$Milliseconds)
    throw "synthetic sleep failure"
}

$cleanupThrew = $false
try {
    Stop-AndDispose-VmMapCaptures `
        -Pending $failedPending `
        -Completed $failedCompleted `
        -TimeoutSeconds 1 `
        -StopProcessAction $failingStop `
        -SleepAction $failingSleep
}
catch {
    $cleanupThrew = $true
}

Assert-Equal -Expected $true -Actual $cleanupThrew -Message "Failed cleanup did not report its failure"
Assert-Equal -Expected 0 -Actual $failedPending.Count -Message "Failed cleanup left a pending capture"
Assert-Equal -Expected 1 -Actual $failedCompleted.Count -Message "Failed cleanup did not preserve capture metadata"
Assert-Equal -Expected 1 -Actual $uncooperative.State.DisposeCalls -Message "Failed cleanup disposed more than once or not at all"
if ($null -ne $uncooperativeCapture.process -or
    [string]::IsNullOrWhiteSpace($uncooperativeCapture.cleanupError)) {
    throw "Failed cleanup did not clear the Process reference and record the cleanup error."
}

Stop-AndDispose-VmMapCaptures -Pending $failedPending -Completed $failedCompleted -TimeoutSeconds 1
Assert-Equal -Expected 1 -Actual $uncooperative.State.DisposeCalls -Message "Repeated cleanup disposed a Process twice"

Write-Host "VMMap capture lifecycle cleanup regression passed."
