// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;

namespace SharpEmu.Libs.LibcInternal;

public static class LibcInternalBacktraceExports
{
    // Ghidra found a provider function, but GTA V never resolved it through the
    // loaded runtime namespace. Keep this on the HLE path until its provider
    // routing or behavioral contract is proven.
    [SysAbiExport(
        Nid = "EHsF2i9FXPM",
        ExportName = "sceLibcInternalBacktraceForGame",
        Target = Generation.Gen5,
        LibraryName = "libSceLibcInternalExt")]
    public static int BacktraceForGameFailClosed(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine(
                "[LIBC][ERROR] sceLibcInternalBacktraceForGame has no proven runtime provider route or HLE contract");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
