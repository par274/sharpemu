// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Xunit;

namespace SharpEmu.Libs.Tests.Diagnostics;

[CollectionDefinition("MemoryDiagnosticsState", DisableParallelization = true)]
public sealed class MemoryDiagnosticsStateCollection
{
    public const string Name = "MemoryDiagnosticsState";
}
