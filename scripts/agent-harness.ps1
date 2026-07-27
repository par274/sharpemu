# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $HarnessArguments
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repositoryRoot 'tools/SharpEmu.Tools.AgentHarness/SharpEmu.Tools.AgentHarness.csproj'

Push-Location $repositoryRoot
try {
    & dotnet run --project $project -- @HarnessArguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
