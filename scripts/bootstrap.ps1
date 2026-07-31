# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

#Requires -Version 7.4

[CmdletBinding()]
param(
    [switch]$SkipRestore
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw "The target development environment supports Windows only."
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$requiredSdk = ((Get-Content -LiteralPath (Join-Path $repositoryRoot "global.json") -Raw | ConvertFrom-Json).sdk.version)
$installedSdks = @(& dotnet --list-sdks)
if ($LASTEXITCODE -ne 0 -or -not ($installedSdks | Where-Object { $_ -like "$requiredSdk *" })) {
    throw ".NET SDK $requiredSdk is required. Installed SDKs: $($installedSdks -join ', ')"
}

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
    throw "SharpEmu target work requires an x64 Windows host."
}

$localDirectory = Join-Path $repositoryRoot ".local"
$targetConfig = Join-Path $localDirectory "target.json"
if (-not (Test-Path -LiteralPath $targetConfig)) {
    [System.IO.Directory]::CreateDirectory($localDirectory) | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "target.example.json") -Destination $targetConfig
    Write-Host "Created $targetConfig. Complete it before running the target."
}

if (Get-Command vulkaninfo -ErrorAction SilentlyContinue) {
    Write-Host "Vulkan tools found. Record the runtime and driver versions in .local/target.json."
} else {
    Write-Warning "vulkaninfo was not found. Install the Vulkan SDK or equivalent runtime tools before graphics investigation."
}

if (-not $SkipRestore) {
    & dotnet restore (Join-Path $repositoryRoot "SharpEmu.slnx")
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet restore failed."
    }
}

Write-Host "Windows development environment is ready for repository verification."
