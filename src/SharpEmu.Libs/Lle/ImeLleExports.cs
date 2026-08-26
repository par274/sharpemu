// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceIme.sprx
// Analyzed provider SHA-256: a9fb46b1809ab3f849b82b98b23c273b28e4794a4380185c3dcc472f06ec446e
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class ImeLleExports
{
    // Ghidra entry 00005590; body addresses 377.
    [SysAbiExport(
        Nid = "PMVehSlfZ94",
        ExportName = "sceImeKeyboardClose",
        Target = Generation.Gen5,
        LibraryName = "libSceIme",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] Ime LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
