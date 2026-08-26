// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libScePlayerSelectionDialog.sprx
// Analyzed provider SHA-256: c2e61df112cf0a0b2405de812d7c0d9ae22cd1094a6531d5087703c0f4baacc6
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class PlayerSelectionDialogLleExports
{
    // Ghidra entry 00000720; body addresses 77.
    [SysAbiExport(
        Nid = "CgdJ1PkIsE4",
        ExportName = "scePlayerSelectionDialogTerminate",
        Target = Generation.Gen5,
        LibraryName = "libScePlayerSelectionDialog",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] PlayerSelectionDialog LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
