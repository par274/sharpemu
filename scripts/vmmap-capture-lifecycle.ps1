# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# The runner owns the capture records; these helpers own each Process object from
# start through completion or forced cleanup.  The stop and sleep actions are
# injectable so the state machine can be tested without a target process.

function Complete-VmMapCapture {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Capture,
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Pending,
        [System.Collections.ArrayList]$Completed
    )

    if ($null -eq $Capture.process) {
        [void]$Pending.Remove($Capture)
        if (-not $Completed.Contains($Capture)) {
            [void]$Completed.Add($Capture)
        }
        return $true
    }

    $captureProcess = $Capture.process
    if (-not $captureProcess.HasExited) {
        return $false
    }

    $completedAt = [DateTimeOffset]::UtcNow
    $metadataFailure = $null
    try {
        # HasExited is already true, so the zero-timeout wait is bounded while
        # still allowing the process wrapper to publish its exit state.
        [void]$captureProcess.WaitForExit(0)
        $Capture.captureCompletedAtUtc = $completedAt.ToString("O")
        $Capture.captureDurationMilliseconds = [long](
            $completedAt - [DateTimeOffset]::Parse($Capture.captureStartedAtUtc)).TotalMilliseconds
        $Capture.exitCode = $captureProcess.ExitCode
        $Capture.outputExists = Test-Path -LiteralPath $Capture.outputPath -PathType Leaf
    }
    catch {
        $metadataFailure = $_
        if ($Capture.PSObject.Properties["cleanupError"]) {
            $Capture.cleanupError = $_.Exception.Message
        }
    }
    finally {
        # Set the record to null before returning it to the completed list so a
        # repeated cleanup pass cannot dispose this Process a second time.
        $Capture.process = $null
        $captureProcess.Dispose()
    }

    [void]$Pending.Remove($Capture)
    if (-not $Completed.Contains($Capture)) {
        [void]$Completed.Add($Capture)
    }

    if ($null -ne $metadataFailure) {
        throw $metadataFailure
    }

    return $true
}

function Complete-VmMapCaptures {
    param(
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Pending,
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Completed
    )

    foreach ($capture in @($Pending.ToArray())) {
        [void](Complete-VmMapCapture -Capture $capture -Pending $Pending -Completed $Completed)
    }
}

function Stop-AndDispose-VmMapCaptures {
    param(
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Pending,
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Completed,
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 10,
        [scriptblock]$StopProcessAction = {
            param([int]$ProcessId)
            Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        },
        [scriptblock]$SleepAction = {
            param([int]$Milliseconds)
            Start-Sleep -Milliseconds $Milliseconds
        }
    )

    $cleanupFailures = [System.Collections.Generic.List[object]]::new()
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)

    try {
        Complete-VmMapCaptures -Pending $Pending -Completed $Completed
    }
    catch {
        [void]$cleanupFailures.Add($_)
    }

    foreach ($capture in @($Pending.ToArray())) {
        if ($null -eq $capture.process) {
            continue
        }

        try {
            if (-not $capture.process.HasExited) {
                & $StopProcessAction ([int]$capture.process.Id)
            }
        }
        catch {
            [void]$cleanupFailures.Add($_)
            if ($capture.PSObject.Properties["cleanupError"]) {
                $capture.cleanupError = $_.Exception.Message
            }
        }
    }

    do {
        try {
            Complete-VmMapCaptures -Pending $Pending -Completed $Completed
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }

        if ($Pending.Count -eq 0) {
            break
        }

        $remainingMilliseconds = [int][Math]::Max(
            0,
            [Math]::Min(100, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds))
        if ($remainingMilliseconds -le 0) {
            break
        }

        try {
            & $SleepAction $remainingMilliseconds
        }
        catch {
            [void]$cleanupFailures.Add($_)
            break
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    # A process can race the last completion poll.  Stop and wait once more
    # with the remaining bounded budget, then dispose it even if it misbehaves.
    foreach ($capture in @($Pending.ToArray())) {
        if ($null -eq $capture.process) {
            [void]$Pending.Remove($capture)
            if (-not $Completed.Contains($capture)) {
                [void]$Completed.Add($capture)
            }
            continue
        }

        $captureProcess = $capture.process
        $hasExited = $false
        try {
            $hasExited = [bool]$captureProcess.HasExited
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }

        if (-not $hasExited) {
            try {
                & $StopProcessAction ([int]$captureProcess.Id)
            }
            catch {
                [void]$cleanupFailures.Add($_)
                if ($capture.PSObject.Properties["cleanupError"]) {
                    $capture.cleanupError = $_.Exception.Message
                }
            }

            $remainingMilliseconds = [int][Math]::Max(
                0,
                [Math]::Min(1000, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds))
            try {
                $hasExited = [bool]$captureProcess.WaitForExit($remainingMilliseconds)
            }
            catch {
                [void]$cleanupFailures.Add($_)
            }

            if (-not $hasExited) {
                try {
                    $hasExited = [bool]$captureProcess.HasExited
                }
                catch {
                    [void]$cleanupFailures.Add($_)
                }
            }
        }

        if ($hasExited) {
            try {
                [void](Complete-VmMapCapture -Capture $capture -Pending $Pending -Completed $Completed)
            }
            catch {
                [void]$cleanupFailures.Add($_)
            }
            continue
        }

        $completedAt = [DateTimeOffset]::UtcNow
        $capture.captureCompletedAtUtc = $completedAt.ToString("O")
        $capture.captureDurationMilliseconds = [long](
            $completedAt - [DateTimeOffset]::Parse($capture.captureStartedAtUtc)).TotalMilliseconds
        $capture.outputExists = Test-Path -LiteralPath $capture.outputPath -PathType Leaf
        $message = "VMMap PID $($captureProcess.Id) did not terminate within the bounded cleanup timeout."
        if ($capture.PSObject.Properties["cleanupError"]) {
            $capture.cleanupError = $message
        }
        [void]$cleanupFailures.Add([System.TimeoutException]::new($message))

        $capture.process = $null
        try {
            $captureProcess.Dispose()
        }
        catch {
            [void]$cleanupFailures.Add($_)
        }
        [void]$Pending.Remove($capture)
        if (-not $Completed.Contains($capture)) {
            [void]$Completed.Add($capture)
        }
    }

    if ($cleanupFailures.Count -gt 0) {
        $messages = @($cleanupFailures | ForEach-Object { $_.Exception.Message })
        throw "VMMap capture cleanup failed: $($messages -join ' | ')"
    }
}
