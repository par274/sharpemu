#!/usr/bin/env bash
# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build and run SharpEmu on Apple Silicon macOS through the x64 .NET SDK under
# Rosetta 2.
#
# Why this exists: on some hardened macOS setups (e.g. SIP disabled with strict
# W^X / code-signing enforcement) the *native arm64* .NET runtime cannot start.
# CoreCLR initialization fails with
#     Failed to create CoreCLR, HRESULT: 0x8007000C
# because the runtime's executable-memory allocator calls
#     mprotect(page, PROT_READ | PROT_WRITE)
# and the kernel denies it with EACCES. (The JIT code heap itself is fine —
# the runtime uses pthread_jit_write_protect_np there — so it is only this
# secondary allocator path that trips the enforcement.) The x64 runtime under
# Rosetta 2 uses a permissive executable-memory model and starts normally.
# This also happens to be SharpEmu's intended macOS target: x64 via Rosetta,
# with Vulkan provided by MoltenVK.
#
# Usage:
#   scripts/run-macos-rosetta.sh build                  # build the solution (Release)
#   scripts/run-macos-rosetta.sh run                    # build if needed, then launch the GUI
#   scripts/run-macos-rosetta.sh run /path/to/eboot.bin # build if needed, then run a game
#   scripts/run-macos-rosetta.sh gui                    # launch the already-built GUI
#
# Environment:
#   DOTNET_X64_ROOT   x64 SDK location   (default: $HOME/.dotnet-x64)
#   CONFIG            build configuration (default: Release)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOTNET_X64_ROOT="${DOTNET_X64_ROOT:-$HOME/.dotnet-x64}"
CONFIG="${CONFIG:-Release}"
CMD="${1:-run}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This helper is macOS-only; on Linux/Windows use 'dotnet' directly." >&2
  exit 2
fi

# Rosetta 2 is required to run x64 binaries on Apple Silicon.
if [[ "$(uname -m)" == "arm64" ]] && ! arch -x86_64 /usr/bin/true 2>/dev/null; then
  echo "Rosetta 2 is required. Install it with:" >&2
  echo "    softwareupdate --install-rosetta --agree-to-license" >&2
  exit 1
fi

DOTNET="$DOTNET_X64_ROOT/dotnet"
if [[ ! -x "$DOTNET" ]]; then
  echo "x64 .NET SDK not found at: $DOTNET_X64_ROOT" >&2
  echo "Install it (matches the version in global.json) with:" >&2
  echo "    curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- \\" >&2
  echo "        --channel 10.0 --architecture x64 --install-dir \"$DOTNET_X64_ROOT\"" >&2
  exit 1
fi

export DOTNET_ROOT="$DOTNET_X64_ROOT"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

# The GUI is a library hosted by SharpEmu.CLI: the executable opens the GUI
# when started with no arguments, and runs a game when given an eboot.bin path.
APPHOST="$REPO_ROOT/artifacts/bin/$CONFIG/net10.0/osx-x64/SharpEmu"

build() {
  echo ">> Building SharpEmu.slnx ($CONFIG, x64 under Rosetta)..."
  arch -x86_64 "$DOTNET" build "$REPO_ROOT/SharpEmu.slnx" -c "$CONFIG"
}

case "$CMD" in
  build)
    build
    ;;
  gui)
    [[ -x "$APPHOST" ]] || build
    echo ">> Launching GUI..."
    exec arch -x86_64 "$APPHOST"
    ;;
  run)
    [[ -x "$APPHOST" ]] || build
    shift || true
    if [[ $# -gt 0 ]]; then
      echo ">> Running: $1"
      exec arch -x86_64 "$APPHOST" "$@"
    fi
    echo ">> Launching GUI..."
    exec arch -x86_64 "$APPHOST"
    ;;
  *)
    echo "usage: $0 {build | run [eboot.bin] | gui}" >&2
    exit 2
    ;;
esac
