// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: ulobjmgr.sprx
// Analyzed provider SHA-256: 82ee954d51f7d3eb9015b96bf4afcbb9f00ffff51afd99baaad5d90451f1b2a8
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class UlObjMgrLleExports
{
    // Ghidra entry 00000140; body addresses 114.
    [SysAbiExport(
        Nid = "BG26hBGiNlw",
        ExportName = "_sceUlobjmgrRegisterObject",
        Target = Generation.Gen5,
        LibraryName = "ulobjmgr",
        PreferLle = true)]
    // Ghidra entry 000001c0; body addresses 44.
    [SysAbiExport(
        Nid = "Smf+fUNblPc",
        ExportName = "_sceUlobjmgrUnregisterObject",
        Target = Generation.Gen5,
        LibraryName = "ulobjmgr",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] UlObjMgr LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
