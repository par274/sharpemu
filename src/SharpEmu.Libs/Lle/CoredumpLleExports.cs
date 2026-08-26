// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libkernel.sprx
// Analyzed provider SHA-256: 0d91281f1d2cdcf4d8c2f4b920766b645ea086e679bd95074f30510178a706b0
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class CoredumpLleExports
{
    // Ghidra entry 00013660; body addresses 150.
    [SysAbiExport(
        Nid = "Dbbkj6YHWdo",
        ExportName = "sceCoredumpWriteUserData",
        Target = Generation.Gen5,
        LibraryName = "libSceCoredump",
        PreferLle = true)]
    // Ghidra entry 00013600; body addresses 82.
    [SysAbiExport(
        Nid = "fFkhOgztiCA",
        ExportName = "sceCoredumpUnregisterCoredumpHandler",
        Target = Generation.Gen5,
        LibraryName = "libSceCoredump",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] Coredump LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
