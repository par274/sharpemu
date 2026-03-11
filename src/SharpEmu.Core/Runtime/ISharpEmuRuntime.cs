// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Loader;
using SharpEmu.HLE;

namespace SharpEmu.Core.Runtime;

public interface ISharpEmuRuntime : IDisposable
{
    string? LastExecutionDiagnostics { get; }

    string? LastExecutionTrace { get; }

    string? LastSessionSummary { get; }

    string? LastBasicBlockTrace { get; }

    string? LastMilestoneLog { get; }

    SelfImage LoadImage(string ebootPath);

    OrbisGen2Result Run(string ebootPath);

    OrbisGen2Result DispatchHleCall(string nid, CpuContext context);
}
