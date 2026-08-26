// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceVideoOut.sprx
// Analyzed provider SHA-256: c1a1b5647a29d5d114fccbfe45487c6712e3f06ebadb78d52e5ccf5604e83412
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class VideoOutLleExports
{
    // Ghidra entry 000111e0; body addresses 170.
    [SysAbiExport(
        Nid = "HuViW4HnrOw",
        ExportName = "sceVideoOutSubmitChangeBufferAttribute2",
        Target = Generation.Gen5,
        LibraryName = "libSceVideoOut",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] VideoOut LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
