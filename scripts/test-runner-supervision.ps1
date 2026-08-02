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
        [object[]]$Records,
        [ValidateSet("direct-launch", "expected-mitigated-child")]
        [string]$ExpectedMode = "direct-launch"
    )

    $identity = New-SupervisedProcessIdentity -ProcessRecord $Records[0]
    return New-SupervisionState `
        -LauncherIdentity $identity `
        -ObservedAtUtc "2026-08-02T00:00:00.0000000Z" `
        -ExpectedMode $ExpectedMode
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
$state = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
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
$unknownState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
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
$cleanupState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
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
$childCleanupState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
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

# The controlled SharpEmu executable expects the mitigated relaunch on
# Windows unless the documented environment switch disables it.  Other
# executables remain explicit direct launches.
Assert-Equal `
    -Expected "expected-mitigated-child" `
    -Actual (Get-ControlledSupervisionMode -ExecutablePath "C:\synthetic\SharpEmu.exe" -WindowsHost $true -MitigationDisableEnvironmentValue $null) `
    -Message "Controlled SharpEmu launch did not require the mitigated child"
Assert-Equal `
    -Expected "direct-launch" `
    -Actual (Get-ControlledSupervisionMode -ExecutablePath "C:\synthetic\SharpEmu.exe" -WindowsHost $true -MitigationDisableEnvironmentValue "1") `
    -Message "Explicit mitigation disable did not preserve direct-launch mode"
Assert-Equal `
    -Expected "direct-launch" `
    -Actual (Get-ControlledSupervisionMode -ExecutablePath "C:\synthetic\other.exe" -WindowsHost $true -MitigationDisableEnvironmentValue $null) `
    -Message "Unknown executable was assigned SharpEmu child expectations"

# The first identity is captured from the exact Process object, including the
# configured executable path, before any inventory is available.
$trustedProcessObject = [pscustomobject]@{
    Id = 100
    StartTime = "2026-08-02T00:00:00.1000000Z"
    ProcessName = "SharpEmu"
}
$trustedIdentity = New-SupervisedProcessIdentityFromProcess `
    -Process $trustedProcessObject `
    -ConfiguredExecutablePath "C:\synthetic\SharpEmu.exe"
Assert-Equal -Expected 100 -Actual $trustedIdentity.processId -Message "Trusted launcher identity lost the PID"
Assert-Equal -Expected "2026-08-02T00:00:00.1000000+00:00" -Actual $trustedIdentity.startTimeUtc -Message "Trusted launcher identity lost the start time"
Assert-Equal -Expected "SharpEmu" -Actual $trustedIdentity.name -Message "Trusted launcher identity lost the process name"
Assert-Equal -Expected "C:\synthetic\SharpEmu.exe" -Actual $trustedIdentity.executablePath -Message "Trusted launcher identity lost the configured executable path"

# If the first inventory fails, the root is already tracked and fallback
# cleanup uses only that exact PID/start-time identity.
$initialInventoryFailureState = New-SupervisionState `
    -LauncherIdentity $trustedIdentity `
    -ObservedAtUtc "2026-08-02T00:00:00.0000000Z" `
    -ExpectedMode "expected-mitigated-child"
$initialFallbackFixture = [pscustomobject]@{
    records = @($launcher)
    stopped = [System.Collections.Generic.List[int]]::new()
}
$initialFallbackLookup = {
    param([int]$ProcessId)
    @($initialFallbackFixture.records | Where-Object { [int]$_.processId -eq $ProcessId })
}
$initialFallbackStop = {
    param([object]$Record)
    [void]$initialFallbackFixture.stopped.Add([int]$Record.processId)
    $initialFallbackFixture.records = @($initialFallbackFixture.records | Where-Object { [int]$_.processId -ne [int]$Record.processId })
}
Stop-SupervisedRoots `
    -State $initialInventoryFailureState `
    -Reason "synthetic-initial-inventory-failure" `
    -InventoryAction { throw "synthetic initial CIM failure" } `
    -ProcessLookupAction $initialFallbackLookup `
    -StopProcessAction $initialFallbackStop `
    -SleepAction { param([int]$Milliseconds) throw "Initial fallback unexpectedly slept." } | Out-Null
Assert-True -Condition ($initialFallbackFixture.stopped -contains 100) -Message "Initial inventory failure did not target the exact launcher identity"
Assert-True -Condition ($initialInventoryFailureState.cleanupEnumerationIncomplete.Count -eq 1) -Message "Initial inventory failure did not report incomplete descendant enumeration"
Assert-True -Condition (@($initialInventoryFailureState.cleanupTargets | Where-Object { $_.method -eq "fallback-individual" -and $_.processId -eq 100 }).Count -eq 1) -Message "Initial fallback cleanup target was not recorded"

# After a successful child sample, an inventory failure still falls back to
# every known launcher/child identity, independently of their tree relation.
$postDiscoveryFailureState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
Get-SupervisionSample `
    -State $postDiscoveryFailureState `
    -ProcessRecords @($launcher, $child) `
    -ObservedAtUtc "2026-08-02T00:00:09.0000000Z" | Out-Null
$postDiscoveryFallbackFixture = [pscustomobject]@{
    records = @($launcher, $child)
    stopped = [System.Collections.Generic.List[int]]::new()
}
$postDiscoveryFallbackLookup = {
    param([int]$ProcessId)
    @($postDiscoveryFallbackFixture.records | Where-Object { [int]$_.processId -eq $ProcessId })
}
$postDiscoveryFallbackStop = {
    param([object]$Record)
    [void]$postDiscoveryFallbackFixture.stopped.Add([int]$Record.processId)
    $postDiscoveryFallbackFixture.records = @($postDiscoveryFallbackFixture.records | Where-Object { [int]$_.processId -ne [int]$Record.processId })
}
Stop-SupervisedRoots `
    -State $postDiscoveryFailureState `
    -Reason "synthetic-post-discovery-inventory-failure" `
    -InventoryAction { throw "synthetic post-discovery CIM failure" } `
    -ProcessLookupAction $postDiscoveryFallbackLookup `
    -StopProcessAction $postDiscoveryFallbackStop `
    -SleepAction { param([int]$Milliseconds) throw "Post-discovery fallback unexpectedly slept." } | Out-Null
Assert-True -Condition ($postDiscoveryFallbackFixture.stopped -contains 100 -and $postDiscoveryFallbackFixture.stopped -contains 101) -Message "Post-discovery fallback did not target both exact supervised roots"
Assert-True -Condition ($postDiscoveryFallbackFixture.stopped -notcontains 999) -Message "Post-discovery fallback targeted an unrelated same-name process"
Assert-True -Condition ($postDiscoveryFailureState.cleanupEnumerationIncomplete.Count -eq 1) -Message "Post-discovery inventory failure did not report incomplete descendant enumeration"

# PID reuse is rejected by the Get-Process fallback before the stop action is
# called, even though the reused process has the same name and executable.
$fallbackReuseState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
$fallbackStopCalls = [System.Collections.Generic.List[int]]::new()
$fallbackReusedRecord = New-FakeProcessRecord `
    -ProcessId 100 `
    -ParentProcessId 1 `
    -StartTimeUtc "2026-08-02T00:00:19.9000000Z" `
    -Name "SharpEmu.exe" `
    -CommandLine "SharpEmu.exe unrelated" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
Assert-Throws `
    -Action {
        Stop-SupervisedRoots `
            -State $fallbackReuseState `
            -Reason "synthetic-fallback-reuse" `
            -InventoryAction { throw "synthetic CIM unavailable" } `
            -ProcessLookupAction { param([int]$ProcessId) @($fallbackReusedRecord) } `
            -StopProcessAction { param([object]$Record) [void]$fallbackStopCalls.Add([int]$Record.processId) } `
            -SleepAction { param([int]$Milliseconds) throw "Fallback reuse unexpectedly slept." }
    } `
    -Message "Fallback cleanup accepted a reused PID"
Assert-Equal -Expected 0 -Actual $fallbackStopCalls.Count -Message "Fallback cleanup invoked a stop action after PID reuse"
Assert-True -Condition (@($fallbackReuseState.cleanupFailures | Where-Object { $_.processId -eq 100 }).Count -eq 1) -Message "Fallback PID reuse failure was not recorded"

# The ordinary state model closes the launcher-exit window.  A child that is
# present only after launcher exit is recovered by the one strict attempt.
$immediateState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
$preFinalSample = Get-SupervisionSample `
    -State $immediateState `
    -ProcessRecords @($child) `
    -ObservedAtUtc "2026-08-02T00:00:20.0000000Z"
Assert-Equal -Expected "final-child-discovery" -Actual (Get-SupervisionLoopDecision -State $immediateState -Sample $preFinalSample) -Message "Launcher exit without promotion was treated as process-exited"
$strictResult = Invoke-SupervisionFinalChildDiscovery `
    -State $immediateState `
    -ProcessRecords @($child) `
    -ObservedAtUtc "2026-08-02T00:00:20.1000000Z"
Assert-Equal -Expected "found" -Actual $strictResult.status -Message "Strict final child discovery did not recover the child"
$strictSample = Get-SupervisionSample `
    -State $immediateState `
    -ProcessRecords @($child) `
    -ObservedAtUtc "2026-08-02T00:00:20.1000000Z"
Assert-True -Condition $strictSample.actualChildAlive -Message "Strictly recovered child was not supervised"

$missingExpectedChildState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
$missingExpectedChildSample = Get-SupervisionSample `
    -State $missingExpectedChildState `
    -ProcessRecords @() `
    -ObservedAtUtc "2026-08-02T00:00:21.0000000Z"
Assert-Equal -Expected "final-child-discovery" -Actual (Get-SupervisionLoopDecision -State $missingExpectedChildState -Sample $missingExpectedChildSample) -Message "Missing expected child skipped strict final discovery"
$missingResult = Invoke-SupervisionFinalChildDiscovery `
    -State $missingExpectedChildState `
    -ProcessRecords @() `
    -ObservedAtUtc "2026-08-02T00:00:21.1000000Z"
Assert-Equal -Expected "not-found" -Actual $missingResult.status -Message "Unobservable expected child was reported as found"
$missingAfterFinalSample = Get-SupervisionSample `
    -State $missingExpectedChildState `
    -ProcessRecords @() `
    -ObservedAtUtc "2026-08-02T00:00:21.1000000Z"
Assert-Equal -Expected "supervision-failure" -Actual (Get-SupervisionLoopDecision -State $missingExpectedChildState -Sample $missingAfterFinalSample) -Message "Unobservable expected child became a successful process-exited run"

$directExitState = New-TestState -Records @($launcher) -ExpectedMode "direct-launch"
$directExitSample = Get-SupervisionSample `
    -State $directExitState `
    -ProcessRecords @() `
    -ObservedAtUtc "2026-08-02T00:00:22.0000000Z"
Assert-Equal -Expected "process-exited" -Actual (Get-SupervisionLoopDecision -State $directExitState -Sample $directExitSample) -Message "Explicit direct-launch mode invented a missing mitigated child"

# An unrelated descendant carrying the exact marker is not a candidate when
# its executable/name is incompatible with the launcher.
$unrelatedMarkedDescendant = New-FakeProcessRecord `
    -ProcessId 104 `
    -ParentProcessId 100 `
    -StartTimeUtc "2026-08-02T00:00:00.4000000Z" `
    -Name "SharpEmuWorker.exe" `
    -CommandLine "SharpEmuWorker.exe --sharpemu-mitigated-child" `
    -WorkingSetBytes 1 `
    -PrivateBytes 1
$candidateRestrictionState = New-TestState -Records @($launcher) -ExpectedMode "expected-mitigated-child"
$candidateRestrictionSample = Get-SupervisionSample `
    -State $candidateRestrictionState `
    -ProcessRecords @($launcher, $unrelatedMarkedDescendant) `
    -ObservedAtUtc "2026-08-02T00:00:23.0000000Z"
Assert-True -Condition ($null -eq $candidateRestrictionState.actualChild) -Message "Incompatible marked descendant was promoted as the actual child"
Assert-True -Condition (-not $candidateRestrictionSample.actualChildAlive) -Message "Incompatible marked descendant entered actual-child metrics"

Assert-True -Condition (Test-SupervisionMitigatedChildMarker -CommandLine "SharpEmu.exe --sharpemu-mitigated-child") -Message "Exact mitigated-child marker was not recognized"
Assert-True -Condition (-not (Test-SupervisionMitigatedChildMarker -CommandLine "SharpEmu.exe --sharpemu-mitigated-child-copy")) -Message "Marker prefix was accepted as the mitigated-child flag"

Write-Host "Runner supervision regressions passed."
