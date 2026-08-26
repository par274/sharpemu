// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceAudioOut.sprx
// Analyzed provider SHA-256: 948dfdc30b9c974c5447d9078853beb1555a2e548de6093b05a114e99445ab33
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class AudioOutLleExports
{
    // Ghidra entry 00002080; body addresses 430.
    [SysAbiExport(
        Nid = "wVwPU50pS1c",
        ExportName = "sceAudioOutSetMixLevelPadSpk",
        Target = Generation.Gen5,
        LibraryName = "libSceAudioOut",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] AudioOut LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
