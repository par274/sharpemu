# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param(
    [ValidateSet("Fast", "Shader", "All")]
    [string]$Lane = "Fast",
    [string]$SpirvValidator = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command $($Arguments -join ' ')"
    }
}

function Test-RepositoryInputs {
    Get-Content -LiteralPath (Join-Path $PSScriptRoot "target.example.json") -Raw | ConvertFrom-Json | Out-Null
    Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.ps1 -File | ForEach-Object {
        [void][scriptblock]::Create((Get-Content -LiteralPath $_.FullName -Raw))
    }
}

function Invoke-FastLane {
    Invoke-Checked -Command "pwsh" -Arguments @("-NoProfile", "-File", (Join-Path $PSScriptRoot "test-compare-runs.ps1"))
    Invoke-Checked -Command "pwsh" -Arguments @("-NoProfile", "-File", (Join-Path $PSScriptRoot "test-run-target-memory-safety.ps1"))
    Invoke-Checked -Command "pwsh" -Arguments @("-NoProfile", "-File", (Join-Path $PSScriptRoot "test-run-target-vmmap-threshold.ps1"))
    Invoke-Checked -Command "pwsh" -Arguments @("-NoProfile", "-File", (Join-Path $PSScriptRoot "test-run-target-vmmap-cleanup.ps1"))
    Invoke-Checked -Command "dotnet" -Arguments @("restore", (Join-Path $repositoryRoot "SharpEmu.slnx"))
    Invoke-Checked -Command "dotnet" -Arguments @("build", (Join-Path $repositoryRoot "SharpEmu.slnx"), "-c", "Release", "--no-restore")
    Invoke-Checked -Command "dotnet" -Arguments @("test", (Join-Path $repositoryRoot "SharpEmu.slnx"), "-c", "Release", "--no-build", "--verbosity", "normal")
}

function Invoke-ShaderLane {
    if ([string]::IsNullOrWhiteSpace($SpirvValidator)) {
        throw "The Shader lane requires -SpirvValidator pointing to the pinned SPIRV-Tools v2026.2 spirv-val executable."
    }

    $resolvedValidator = [System.IO.Path]::GetFullPath($SpirvValidator)
    if (-not (Test-Path -LiteralPath $resolvedValidator -PathType Leaf)) {
        throw "SPIR-V validator was not found at '$resolvedValidator'."
    }

    $versionOutput = @(& $resolvedValidator --version)
    if ($LASTEXITCODE -ne 0 -or $versionOutput.Count -eq 0 -or $versionOutput[0] -notlike "*SPIRV-Tools v2026.2*") {
        throw "Expected SPIRV-Tools v2026.2, received: $($versionOutput -join ' ')"
    }

    $moduleDirectory = Join-Path $repositoryRoot "artifacts/shader-dump"
    if (Test-Path -LiteralPath $moduleDirectory) {
        Remove-Item -LiteralPath $moduleDirectory -Recurse -Force
    }

    Invoke-Checked -Command "dotnet" -Arguments @("run", "--project", (Join-Path $repositoryRoot "tools/SharpEmu.Tools.ShaderDump/SharpEmu.Tools.ShaderDump.csproj"), "-c", "Release", "--", $moduleDirectory)
    $modules = @(Get-ChildItem -LiteralPath $moduleDirectory -Filter *.spv -File -Recurse | Sort-Object FullName)
    if ($modules.Count -eq 0) {
        throw "The shader dump produced no SPIR-V modules."
    }

    foreach ($module in $modules) {
        Invoke-Checked -Command $resolvedValidator -Arguments @("--target-env", "vulkan1.2", $module.FullName)
    }

    Write-Host "Validated $($modules.Count) synthetic modules with SPIRV-Tools v2026.2 for Vulkan 1.2."
}

Test-RepositoryInputs
if ($Lane -in @("Fast", "All")) {
    Invoke-FastLane
}
if ($Lane -in @("Shader", "All")) {
    Invoke-ShaderLane
}
