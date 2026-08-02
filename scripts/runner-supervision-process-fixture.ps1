# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Authored Windows-only launcher/child fixture for the runner handoff test.
# The named events make the launcher exit and child lifetime deterministic.
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("launcher", "child")]
    [string]$Role,
    [Parameter(Mandatory = $true)]
    [string]$ReadyEventName,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseEventName,
    [string]$ExitEventName = "",
    [string]$Marker = "",
    [switch]$ExitAfterReady
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Role -eq "child") {
    $ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEventName)
    $release = [Threading.EventWaitHandle]::OpenExisting($ReleaseEventName)
    try {
        [void]$ready.Set()
        [void]$release.WaitOne()
    }
    finally {
        $ready.Dispose()
        $release.Dispose()
    }
    exit 0
}

$pwshPath = (Get-Command pwsh -ErrorAction Stop).Source
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $pwshPath
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
[void]$startInfo.ArgumentList.Add("-NoProfile")
[void]$startInfo.ArgumentList.Add("-File")
[void]$startInfo.ArgumentList.Add($PSCommandPath)
[void]$startInfo.ArgumentList.Add("-Role")
[void]$startInfo.ArgumentList.Add("child")
[void]$startInfo.ArgumentList.Add("-ReadyEventName")
[void]$startInfo.ArgumentList.Add($ReadyEventName)
[void]$startInfo.ArgumentList.Add("-ReleaseEventName")
[void]$startInfo.ArgumentList.Add($ReleaseEventName)
[void]$startInfo.ArgumentList.Add("-Marker")
[void]$startInfo.ArgumentList.Add("--sharpemu-mitigated-child")
$childProcess = [System.Diagnostics.Process]::new()
$childProcess.StartInfo = $startInfo
try {
    if (-not $childProcess.Start()) {
        throw "Synthetic mitigated child did not start."
    }

    $ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEventName)
    try {
        if (-not $ready.WaitOne(10000)) {
            throw "Synthetic child did not signal readiness."
        }
    }
    finally {
        $ready.Dispose()
    }
    if ($ExitAfterReady) {
        return
    }
    $exit = [Threading.EventWaitHandle]::OpenExisting($ExitEventName)
    try {
        [void]$exit.WaitOne()
    }
    finally {
        $exit.Dispose()
    }
}
finally {
    $childProcess.Dispose()
}
