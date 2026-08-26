// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceRazorCpu.sprx
// Analyzed provider SHA-256: 3f7958cd6c115830ebd151ef3d5daf0bdd898dd89e93c5612d8f7546d9254fe9
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class RazorCpuLleExports
{
    // Ghidra entry 00006e00; body addresses 1264.
    [SysAbiExport(
        Nid = "9FowWFMEIM8",
        ExportName = "sceRazorCpuJobManagerSequence",
        Target = Generation.Gen5,
        LibraryName = "libSceRazorCpu",
        PreferLle = true)]
    // Ghidra entry 00007810; body addresses 1206.
    [SysAbiExport(
        Nid = "KP+TBWGHlgs",
        ExportName = "sceRazorCpuJobManagerJob",
        Target = Generation.Gen5,
        LibraryName = "libSceRazorCpu",
        PreferLle = true)]
    // Ghidra entry 000072f0; body addresses 1312.
    [SysAbiExport(
        Nid = "dnEdyY4+klQ",
        ExportName = "sceRazorCpuJobManagerDispatch",
        Target = Generation.Gen5,
        LibraryName = "libSceRazorCpu",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] RazorCpu LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
