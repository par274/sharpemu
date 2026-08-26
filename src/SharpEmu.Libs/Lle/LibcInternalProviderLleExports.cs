// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2 program: gta-v-libc.reconstructed.elf
// Analyzed provider SHA-256: 309cb9031209eb9b838216994d2c39613fcd65ec1eae493c4b784b9dacdd06bb
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class LibcInternalProviderLleExports
{
    // Ghidra entry 0015a570; body addresses 325.
    [SysAbiExport(
        Nid = "3BytPOQgVKc",
        ExportName = "snprintf_s",
        Target = Generation.Gen5,
        LibraryName = "libSceLibcInternal",
        PreferLle = true)]
    // Ghidra entry 0010f5a0; body addresses 69.
    [SysAbiExport(
        Nid = "Vla-Z+eXlxo",
        ExportName = "sceLibcMspaceFree",
        Target = Generation.Gen5,
        LibraryName = "libSceLibcInternal",
        PreferLle = true)]
    // Ghidra entry 0010f670; body addresses 111.
    [SysAbiExport(
        Nid = "gigoVHZvVPE",
        ExportName = "sceLibcMspaceRealloc",
        Target = Generation.Gen5,
        LibraryName = "libSceLibcInternal",
        PreferLle = true)]
    // Ghidra entry 0010f860; body addresses 11.
    [SysAbiExport(
        Nid = "mfHdJTIvhuo",
        ExportName = "sceLibcMspaceMallocStats",
        Target = Generation.Gen5,
        LibraryName = "libSceLibcInternal",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] LibcInternalProvider LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
