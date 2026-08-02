# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Deterministic real-process handoff regression.  Named events synchronize the
# authored launcher and child; the test uses no sleeps, retail data, or target
# executable.
#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw "The real-process supervision fixture requires Windows."
}

. (Join-Path $PSScriptRoot "runner-supervision.ps1")

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

$fixturePath = Join-Path $PSScriptRoot "runner-supervision-process-fixture.ps1"
$nonce = [Guid]::NewGuid().ToString("N")
$readyEventName = "Local\SharpEmuRunnerReady-$nonce"
$releaseEventName = "Local\SharpEmuRunnerRelease-$nonce"
$exitEventName = "Local\SharpEmuRunnerExit-$nonce"
$readyCreated = $false
$releaseCreated = $false
$exitCreated = $false
$readyEvent = [Threading.EventWaitHandle]::new(
    $false,
    [Threading.EventResetMode]::ManualReset,
    $readyEventName,
    [ref]$readyCreated)
$releaseEvent = [Threading.EventWaitHandle]::new(
    $false,
    [Threading.EventResetMode]::ManualReset,
    $releaseEventName,
    [ref]$releaseCreated)
$exitEvent = [Threading.EventWaitHandle]::new(
    $false,
    [Threading.EventResetMode]::ManualReset,
    $exitEventName,
    [ref]$exitCreated)
$launcher = $null
$state = $null

try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -ErrorAction Stop).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in @(
            "-NoProfile",
            "-File",
            $fixturePath,
            "-Role",
            "launcher",
            "-ReadyEventName",
            $readyEventName,
            "-ReleaseEventName",
            $releaseEventName,
            "-ExitEventName",
            $exitEventName,
            "-Marker",
            "--sharpemu-mitigated-child")) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $launcher = [System.Diagnostics.Process]::new()
    $launcher.StartInfo = $startInfo
    if (-not $launcher.Start()) {
        throw "Synthetic launcher did not start."
    }

    $inventoryBeforeChild = @(Get-TargetProcessInventory)
    $launcherRecord = @($inventoryBeforeChild | Where-Object { [int]$_.processId -eq $launcher.Id })
    Assert-True -Condition ($launcherRecord.Count -eq 1) -Message "Synthetic launcher identity was not observable."
    $launcherIdentity = New-SupervisedProcessIdentity -ProcessRecord $launcherRecord[0]
    $state = New-SupervisionState `
        -LauncherIdentity $launcherIdentity `
        -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString("O"))

    Assert-True -Condition $readyEvent.WaitOne(10000) -Message "Synthetic child did not reach the ready handoff point."
    $inventory = @(Get-TargetProcessInventory)

    $bothAlive = Get-SupervisionSample `
        -State $state `
        -ProcessRecords $inventory `
        -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString("O"))
    Assert-True -Condition ($bothAlive.actualChildAlive -and $state.handoffObserved) -Message "Real mitigated child was not promoted while launcher was alive."
    Assert-True -Condition ($state.actualChild.identity.processId -ne $launcher.Id) -Message "Real child identity was not independent of launcher identity."

    [void]$exitEvent.Set()
    Assert-True -Condition $launcher.WaitForExit(10000) -Message "Synthetic launcher did not exit after child handoff."
    $afterLauncherExit = Get-SupervisionSample `
        -State $state `
        -ProcessRecords @(Get-TargetProcessInventory) `
        -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString("O"))
    Assert-True -Condition (-not $afterLauncherExit.launcherAlive -and $afterLauncherExit.actualChildAlive) -Message "Real child did not remain supervised after launcher exit."
    Assert-True -Condition $afterLauncherExit.monitoringContinuedAfterLauncherExit -Message "Real handoff continuation was not recorded."

    Stop-SupervisedRoots -State $state -Reason "synthetic-cleanup" | Out-Null
    $remaining = @(Get-TargetProcessInventory | Where-Object {
            [int]$_.processId -eq [int]$state.actualChild.identity.processId
        })
    Assert-True -Condition ($remaining.Count -eq 0) -Message "Corrected cleanup left the synthetic actual child alive."
    Write-Host "Real-process runner supervision handoff regression passed."
}
finally {
    [void]$releaseEvent.Set()
    [void]$exitEvent.Set()
    if ($null -ne $state) {
        try {
            Stop-SupervisedRoots -State $state -Reason "synthetic-finally-cleanup" | Out-Null
        }
        catch {
            # Preserve the primary test failure; the explicit release event
            # lets the fixture child finish if cleanup already observed exit.
        }
    }
    if ($null -ne $launcher) {
        try {
            if (-not $launcher.HasExited) {
                $launcher.Kill()
            }
            [void]$launcher.WaitForExit(5000)
        }
        catch {
        }
        $launcher.Dispose()
    }
    $readyEvent.Dispose()
    $releaseEvent.Dispose()
    $exitEvent.Dispose()
}
