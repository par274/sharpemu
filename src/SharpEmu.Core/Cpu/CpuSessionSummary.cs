// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;

namespace SharpEmu.Core.Cpu;

public readonly struct CpuSessionSummary
{
    public CpuSessionSummary(
        OrbisGen2Result result,
        CpuExitReason reason,
        int? exitCode,
        ulong lastGuestRip,
        ulong lastStubRip,
        int totalInstructions,
        int importsHit,
        int uniqueNidsHit)
    {
        Result = result;
        Reason = reason;
        ExitCode = exitCode;
        LastGuestRip = lastGuestRip;
        LastStubRip = lastStubRip;
        TotalInstructions = totalInstructions;
        ImportsHit = importsHit;
        UniqueNidsHit = uniqueNidsHit;
    }

    public OrbisGen2Result Result { get; }

    public CpuExitReason Reason { get; }

    public int? ExitCode { get; }

    public ulong LastGuestRip { get; }

    public ulong LastStubRip { get; }

    public int TotalInstructions { get; }

    public int ImportsHit { get; }

    public int UniqueNidsHit { get; }
}
