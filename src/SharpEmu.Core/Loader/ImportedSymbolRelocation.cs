// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Loader;

public readonly record struct ImportedSymbolRelocation(
    ulong TargetAddress,
    long Addend,
    string Nid,
    bool IsData);
