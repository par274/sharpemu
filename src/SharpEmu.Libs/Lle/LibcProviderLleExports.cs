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

public static class LibcProviderLleExports
{
    // Ghidra entry 0015add0; body addresses 237.
    [SysAbiExport(
        Nid = "+qitMEbkSWk",
        ExportName = "vsprintf_s",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00102d30; body addresses 8.
    [SysAbiExport(
        Nid = "0hlfW1O4Aa4",
        ExportName = "localeconv",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0014c600; body addresses 1544.
    [SysAbiExport(
        Nid = "1D0H2KNjshE",
        ExportName = "powf",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0015a8b0; body addresses 244.
    [SysAbiExport(
        Nid = "24m4Z4bUaoY",
        ExportName = "sscanf_s",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0015b7c0; body addresses 6611.
    [SysAbiExport(
        Nid = "2vDqwBlpF-o",
        ExportName = "strtod",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00105ca0; body addresses 11.
    [SysAbiExport(
        Nid = "5Lf51jvohTQ",
        ExportName = "_Mtx_destroy",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0016bfd0; body addresses 61.
    [SysAbiExport(
        Nid = "5bBacGLyLOs",
        ExportName = "gmtime_s",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 001c28f0; body addresses 14.
    [SysAbiExport(
        Nid = "802pFCwC9w0",
        ExportName = "__udivti3",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00141010; body addresses 649.
    [SysAbiExport(
        Nid = "EH-x713A99c",
        ExportName = "atan2f",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00140b70; body addresses 460.
    [SysAbiExport(
        Nid = "HUbZmOnT-Dg",
        ExportName = "atan2",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00116890; body addresses 52.
    [SysAbiExport(
        Nid = "MELi-cKqWq0",
        ExportName = "_ZSt19_Xbad_function_callv",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0016aa10; body addresses 236.
    [SysAbiExport(
        Nid = "NFLs+dRJGNg",
        ExportName = "memcpy_s",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0017db50; body addresses 581.
    [SysAbiExport(
        Nid = "O4L+0oCN9zA",
        ExportName = "_FSinh",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0017d700; body addresses 295.
    [SysAbiExport(
        Nid = "PdnFCFqKGqA",
        ExportName = "_FCosh",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0014f9a0; body addresses 238.
    [SysAbiExport(
        Nid = "SAd0Z3wKwLA",
        ExportName = "tanhf",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0015b7b0; body addresses 13.
    [SysAbiExport(
        Nid = "SRI6S9B+-a4",
        ExportName = "atof",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00105c20; body addresses 117.
    [SysAbiExport(
        Nid = "YaHc3GS7y7g",
        ExportName = "_Mtx_init",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00115cc0; body addresses 229.
    [SysAbiExport(
        Nid = "bRujIheWlB0",
        ExportName = "_ZSt14_Throw_C_errori",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 001183a0; body addresses 12.
    [SysAbiExport(
        Nid = "bZx+FFSlkUM",
        ExportName = "_ZdlPvSt11align_val_t",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 001163f0; body addresses 52.
    [SysAbiExport(
        Nid = "eT2UsmTewbU",
        ExportName = "_ZSt11_Xbad_allocv",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0016bf40; body addresses 144.
    [SysAbiExport(
        Nid = "fiiNDnNBKVY",
        ExportName = "localtime_s",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00105cb0; body addresses 13.
    [SysAbiExport(
        Nid = "gTuXQwP9rrs",
        ExportName = "_Mtx_unlock",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00105cc0; body addresses 33.
    [SysAbiExport(
        Nid = "iS4aWbUonl0",
        ExportName = "_Mtx_lock",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0014dc20; body addresses 1196.
    [SysAbiExport(
        Nid = "jMB7EFyu30Y",
        ExportName = "sincos",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00153cd0; body addresses 117.
    [SysAbiExport(
        Nid = "lKEN2IebgJ0",
        ExportName = "longjmp",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00116600; body addresses 58.
    [SysAbiExport(
        Nid = "ozMAr28BwSY",
        ExportName = "_ZSt14_Xout_of_rangePKc",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0013abf0; body addresses 8.
    [SysAbiExport(
        Nid = "rcQCUr0EaRU",
        ExportName = "_Getptoupper",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00116520; body addresses 58.
    [SysAbiExport(
        Nid = "tQIo+GIPklo",
        ExportName = "_ZSt14_Xlength_errorPKc",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 0013d600; body addresses 13.
    [SysAbiExport(
        Nid = "zlfEH8FmyUA",
        ExportName = "_Stoul",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    // Ghidra entry 00134fe0; body addresses 20.
    [SysAbiExport(
        Nid = "zr094EQ39Ww",
        ExportName = "__cxa_pure_virtual",
        Target = Generation.Gen5,
        LibraryName = "libc",
        PreferLle = true)]
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] LibcProvider LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
