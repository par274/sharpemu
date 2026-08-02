# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Deterministic runner-supervision regressions.  These tests use process-shaped
# records and injected cleanup actions; they launch no process and use no
# sleeps, retail data, or timing races.
#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "runner-supervision.ps1")

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

function New-FakeProcessRecord {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [int]$ParentProcessId,
        [Parameter(Mandatory = $true)]
        [string]$StartTimeUtc,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CommandLine,
        [Parameter(Mandatory = $true)]
        [UInt64]$WorkingSetBytes,
        [Parameter(Mandatory = $true)]
        [UInt64]$PrivateBytes
    )

    return [pscustomobject][ordered]@{
        processId = $ProcessId
        parentProcessId = $ParentProcessId
        name = $Name
        executablePath = "C:\synthetic\$Name"
        commandLine = $CommandLine
        startTimeUtc = $StartTimeUtc
        workingSetBytes = $WorkingSetBytes
        privateBytes = $PrivateBytes
    }
}

function New-TestState {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records
    )

    $identity = New-SupervisedProcessIdentity -ProcessRecord $Records[0]
    return New-SupervisionState `
        -LauncherIdentity $identity `
        -ObservedAtUtc "2026-08-02T00:00:00.0000000Z"
}

$launcher = New-FakeProcessRecord `
    -ProcessId 100 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:00.1000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe eboot.bin" `
    -WorkingSetBytes 100 `
    -PrivateBytes 1000
$child = New-FakeProcessRecord `
    -ProcessId 101 `
    -ParentProcessId 100 `
    -StartTimeUtc "2026-08-02T00:00:00.2000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe --sharpemu-mitigated-child eboot.bin" `
    -WorkingSetBytes 200 `
    -PrivateBytes 2000
$grandchild = New-FakeProcessRecord `
    -ProcessId 102 `
    -ParentProcessId 101 `
    -StartTimeUtc "2026-08-02T00:00:00.3000000Z" `
    -Name "SharpEmuWorker.exe" `
    -CommandLine "SharpEmuWorker.exe" `
    -WorkingSetBytes 300 `
    -PrivateBytes 3000
$unrelated = New-FakeProcessRecord `
    -ProcessId 999 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:00.9000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe unrelated" `
    -WorkingSetBytes 900 `
    -PrivateBytes 9000

# Direct launch remains the actual emulation root when no mitigated child is
# present.
$directState = New-TestState -Records @($launcher)
$directSample = Get-SupervisionSample `
    -State $directState `
    -ProcessRecords @($launcher) `
    -ObservedAtUtc "2026-08-02T00:00:01.0000000Z"
Assert-Equal -Expected "direct-launch" -Actual $directState.actualEmulation.mode -Message "Direct launch was not retained as the actual emulation process"
Assert-Equal -Expected 100 -Actual $directSample.actualEmulationIdentity.processId -Message "Direct launch identity was not preserved"
Assert-Equal -Expected $null -Actual $directState.actualChild -Message "Direct launch invented a mitigated child"

# The launcher tree and independently tracked child tree overlap.  The
# aggregate must count each stable PID/start-time identity once.
$state = New-TestState -Records @($launcher)
$bothAlive = Get-SupervisionSample `
    -State $state `
    -ProcessRecords @($launcher, $child, $grandchild, $unrelated) `
    -ObservedAtUtc "2026-08-02T00:00:02.0000000Z"
Assert-True -Condition ($state.handoffObserved) -Message "Mitigated child handoff was not recorded"
Assert-Equal -Expected "mitigated-child" -Actual $state.actualEmulation.mode -Message "Mitigated child was not promoted to actual emulation"
Assert-Equal -Expected 101 -Actual $state.actualChild.identity.processId -Message "Actual child PID was not recorded"
Assert-Equal -Expected 3 -Actual $bothAlive.processCount -Message "Overlapping process trees were not deduplicated"
Assert-Equal -Expected 600 -Actual $bothAlive.workingSetBytes -Message "Deduplicated working set was incorrect"
Assert-Equal -Expected 6000 -Actual $bothAlive.privateBytes -Message "Deduplicated private memory was incorrect"
Assert-Equal -Expected 500 -Actual $bothAlive.childTree.workingSetBytes -Message "Child tree working set was not preserved separately"
Assert-Equal -Expected 5000 -Actual $bothAlive.childTree.privateBytes -Message "Child tree private memory was not preserved separately"
Assert-Equal -Expected 200 -Actual $bothAlive.actualChildCounters.workingSetBytes -Message "Actual-child working set was not preserved"
Assert-Equal -Expected 2000 -Actual $bothAlive.actualChildCounters.privateBytes -Message "Actual-child private memory was not preserved"
Assert-True -Condition ($bothAlive.counterSources -contains "launcher" -and $bothAlive.counterSources -contains "child") -Message "Counter source provenance was not recorded"
Assert-True -Condition (-not ($bothAlive.supervisedProcessIds -contains 999)) -Message "Unrelated SharpEmu process entered the supervised aggregate"

# Once the launcher exits, the retained child root keeps both monitoring and
# cleanup independent of the old parent relationship.
$childAfterLauncher = Get-SupervisionSample `
    -State $state `
    -ProcessRecords @($child, $grandchild) `
    -ObservedAtUtc "2026-08-02T00:00:03.0000000Z"
Assert-True -Condition (-not $childAfterLauncher.launcherAlive -and $childAfterLauncher.actualChildAlive) -Message "Launcher-to-child handoff did not keep the child supervised"
Assert-True -Condition ($childAfterLauncher.anySupervisedProcessAlive) -Message "Monitoring stopped when the launcher exited"
Assert-True -Condition ($childAfterLauncher.monitoringContinuedAfterLauncherExit) -Message "Post-launcher monitoring was not recorded"
Assert-Equal -Expected 2 -Actual $childAfterLauncher.processCount -Message "Post-launcher child tree was not sampled"
Assert-Equal -Expected 500 -Actual $childAfterLauncher.workingSetBytes -Message "Post-launcher working-set sampling stopped"
Assert-Equal -Expected 5000 -Actual $childAfterLauncher.privateBytes -Message "Post-launcher private-memory sampling stopped"
Assert-True -Condition ($null -ne $state.launcher.exitedAtUtc) -Message "Launcher exit time was not recorded"

# Natural child exit ends the loop only after the launcher is already gone.
$childEnded = Get-SupervisionSample `
    -State $state `
    -ProcessRecords @() `
    -ObservedAtUtc "2026-08-02T00:00:04.0000000Z"
Assert-True -Condition (-not $childEnded.anySupervisedProcessAlive) -Message "Naturally exited child remained falsely supervised"
Assert-True -Condition ($null -ne $state.actualChild.exitedAtUtc) -Message "Natural child exit was not recorded"

# A PID reused with another start time is rejected before sampling or stop.
$reuseState = New-TestState -Records @($launcher)
$reusedLauncher = New-FakeProcessRecord `
    -ProcessId 100 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:09.9000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe unrelated" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
Assert-Throws `
    -Action {
        Get-SupervisionSample `
            -State $reuseState `
            -ProcessRecords @($reusedLauncher) `
            -ObservedAtUtc "2026-08-02T00:00:05.0000000Z"
    } `
    -Message "PID reuse was accepted as the retained launcher"
Assert-True -Condition ($reuseState.identityMismatches.Count -eq 1) -Message "PID reuse mismatch was not recorded"

# CIM and System.Diagnostics expose the same Windows start time with slightly
# different fractional precision; that representation difference is not PID
# reuse and must remain matchable at the identity boundary.
$precisionRecord = New-FakeProcessRecord `
    -ProcessId 104 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:10.4036420Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
$precisionObserved = New-FakeProcessRecord `
    -ProcessId 104 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:10.4036428Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
$precisionResult = Test-SupervisedProcessIdentity `
    -RecordedIdentity (New-SupervisedProcessIdentity -ProcessRecord $precisionRecord) `
    -ObservedProcess $precisionObserved
Assert-True -Condition $precisionResult.matches -Message "Start-time representation precision was mistaken for PID reuse"

# Missing process lookup is a failure, not an empty successful run.
Assert-Throws `
    -Action { Get-TargetProcessInventory -QueryAction { throw "synthetic lookup failure" } } `
    -Message "Process lookup failure silently produced a successful inventory"

# Missing command evidence for a same-executable descendant fails closed
# instead of guessing that it is direct launch or losing it after handoff.
$unknownChild = New-FakeProcessRecord `
    -ProcessId 103 `
    -ParentProcessId 100 `
    -StartTimeUtc "2026-08-02T00:00:00.4000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
$unknownChild.commandLine = $null
$unknownState = New-TestState -Records @($launcher)
Assert-Throws `
    -Action {
        Get-SupervisionSample `
            -State $unknownState `
            -ProcessRecords @($launcher, $unknownChild) `
            -ObservedAtUtc "2026-08-02T00:00:06.0000000Z"
    } `
    -Message "Unavailable child command evidence did not fail closed"

# Cleanup receives validated identities, retries the independently tracked
# child even when the launcher is absent, and never targets an unrelated same-
# name process.
$cleanupState = New-TestState -Records @($launcher)
Get-SupervisionSample `
    -State $cleanupState `
    -ProcessRecords @($launcher, $child, $grandchild, $unrelated) `
    -ObservedAtUtc "2026-08-02T00:00:07.0000000Z" | Out-Null
$cleanupFixture = [pscustomobject]@{
    records = @($child, $grandchild, $unrelated)
    stopped = [System.Collections.Generic.List[int]]::new()
}
$inventoryAction = { @($cleanupFixture.records) }
$stopAction = {
    param([object]$Record)
    [void]$cleanupFixture.stopped.Add([int]$Record.processId)
    $cleanupFixture.records = @($cleanupFixture.records | Where-Object { [int]$_.processId -ne [int]$Record.processId })
}
Stop-SupervisedRoots `
    -State $cleanupState `
    -Reason "synthetic-safety-boundary" `
    -InventoryAction $inventoryAction `
    -StopProcessAction $stopAction `
    -SleepAction { param([int]$Milliseconds) throw "Synthetic cleanup unexpectedly slept." } | Out-Null
Assert-True -Condition ($cleanupFixture.stopped -contains 101 -and $cleanupFixture.stopped -contains 102) -Message "Safety cleanup did not stop the retained child tree"
Assert-True -Condition (-not ($cleanupFixture.stopped -contains 999)) -Message "Cleanup targeted an unrelated SharpEmu PID"
Assert-True -Condition (@($cleanupState.cleanupTargets | Where-Object { $_.processId -eq 100 }).Count -gt 0) -Message "Launcher cleanup identity was not recorded"
Assert-True -Condition (@($cleanupState.cleanupTargets | Where-Object { $_.processId -eq 101 }).Count -gt 0) -Message "Independent child cleanup identity was not recorded"

# A retained child is cleaned independently after its launcher has already
# exited, and a reused child PID is rejected before the stop action runs.
$childCleanupState = New-TestState -Records @($launcher)
Get-SupervisionSample `
    -State $childCleanupState `
    -ProcessRecords @($launcher, $child) `
    -ObservedAtUtc "2026-08-02T00:00:08.0000000Z" | Out-Null
$childCleanupFixture = [pscustomobject]@{
    records = @($child)
    stopped = [System.Collections.Generic.List[int]]::new()
}
$childInventoryAction = { @($childCleanupFixture.records) }
$childStopAction = {
    param([object]$Record)
    [void]$childCleanupFixture.stopped.Add([int]$Record.processId)
    $childCleanupFixture.records = @()
}
Stop-SupervisedRoots `
    -State $childCleanupState `
    -Reason "finally-cleanup" `
    -InventoryAction $childInventoryAction `
    -StopProcessAction $childStopAction `
    -SleepAction { param([int]$Milliseconds) throw "Synthetic child cleanup unexpectedly slept." } | Out-Null
Assert-True -Condition ($childCleanupFixture.stopped -contains 101) -Message "Final cleanup skipped the child after launcher exit"
Assert-True -Condition (@($childCleanupState.cleanupTargets | Where-Object { $_.processId -eq 100 -and $_.status -eq "already-exited" }).Count -eq 1) -Message "Final cleanup did not retry the exited launcher independently"

$mismatchCleanupState = New-TestState -Records @($launcher)
$mismatchStopCalls = [System.Collections.Generic.List[int]]::new()
$mismatchStopAction = {
    param([object]$Record)
    [void]$mismatchStopCalls.Add([int]$Record.processId)
}
Assert-Throws `
    -Action {
        Stop-SupervisedRoots `
            -State $mismatchCleanupState `
            -Reason "synthetic-reuse" `
            -InventoryAction { @($reusedLauncher) } `
            -StopProcessAction $mismatchStopAction `
            -SleepAction { param([int]$Milliseconds) throw "Synthetic mismatch cleanup unexpectedly slept." }
    } `
    -Message "Cleanup accepted a reused PID"
Assert-Equal -Expected 0 -Actual $mismatchStopCalls.Count -Message "Cleanup invoked a stop action after identity mismatch"

Write-Host "Runner supervision regressions passed."
