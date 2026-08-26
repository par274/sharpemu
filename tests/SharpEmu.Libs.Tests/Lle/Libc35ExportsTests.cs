// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Cpu.Native;
using SharpEmu.HLE;
using SharpEmu.Libs.LibcInternal;
using SharpEmu.Libs.Lle;
using System.Reflection;
using Xunit;

namespace SharpEmu.Libs.Tests.Lle;

public sealed class Libc35ExportsTests
{
    private const string BacktraceNid = "EHsF2i9FXPM";

    private static readonly IReadOnlyDictionary<string, (string ExportName, string LibraryName)> ExpectedPreferLle =
        new Dictionary<string, (string ExportName, string LibraryName)>(StringComparer.Ordinal)
        {
            ["+qitMEbkSWk"] = ("vsprintf_s", "libc"),
            ["0hlfW1O4Aa4"] = ("localeconv", "libc"),
            ["1D0H2KNjshE"] = ("powf", "libc"),
            ["24m4Z4bUaoY"] = ("sscanf_s", "libc"),
            ["2vDqwBlpF-o"] = ("strtod", "libc"),
            ["3BytPOQgVKc"] = ("snprintf_s", "libSceLibcInternal"),
            ["5Lf51jvohTQ"] = ("_Mtx_destroy", "libc"),
            ["5bBacGLyLOs"] = ("gmtime_s", "libc"),
            ["802pFCwC9w0"] = ("__udivti3", "libc"),
            ["EH-x713A99c"] = ("atan2f", "libc"),
            ["HUbZmOnT-Dg"] = ("atan2", "libc"),
            ["MELi-cKqWq0"] = ("_ZSt19_Xbad_function_callv", "libc"),
            ["NFLs+dRJGNg"] = ("memcpy_s", "libc"),
            ["O4L+0oCN9zA"] = ("_FSinh", "libc"),
            ["PdnFCFqKGqA"] = ("_FCosh", "libc"),
            ["SAd0Z3wKwLA"] = ("tanhf", "libc"),
            ["SRI6S9B+-a4"] = ("atof", "libc"),
            ["Vla-Z+eXlxo"] = ("sceLibcMspaceFree", "libSceLibcInternal"),
            ["YaHc3GS7y7g"] = ("_Mtx_init", "libc"),
            ["bRujIheWlB0"] = ("_ZSt14_Throw_C_errori", "libc"),
            ["bZx+FFSlkUM"] = ("_ZdlPvSt11align_val_t", "libc"),
            ["eT2UsmTewbU"] = ("_ZSt11_Xbad_allocv", "libc"),
            ["fiiNDnNBKVY"] = ("localtime_s", "libc"),
            ["gTuXQwP9rrs"] = ("_Mtx_unlock", "libc"),
            ["gigoVHZvVPE"] = ("sceLibcMspaceRealloc", "libSceLibcInternal"),
            ["iS4aWbUonl0"] = ("_Mtx_lock", "libc"),
            ["jMB7EFyu30Y"] = ("sincos", "libc"),
            ["lKEN2IebgJ0"] = ("longjmp", "libc"),
            ["mfHdJTIvhuo"] = ("sceLibcMspaceMallocStats", "libSceLibcInternal"),
            ["ozMAr28BwSY"] = ("_ZSt14_Xout_of_rangePKc", "libc"),
            ["rcQCUr0EaRU"] = ("_Getptoupper", "libc"),
            ["tQIo+GIPklo"] = ("_ZSt14_Xlength_errorPKc", "libc"),
            ["zlfEH8FmyUA"] = ("_Stoul", "libc"),
            ["zr094EQ39Ww"] = ("__cxa_pure_virtual", "libc"),
        };

    private static readonly IReadOnlySet<string> ExplicitlyExcludedNids =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "djxxOmW6-aw", // __progname data
            "H8AprKeZtNg", // _Stderr data
            "2sWzhYqFH4E", // _Stdout data
            "P330P3dFF68", // Need_sceLibc data
            "ZT4ODD2Ts9o", // Need_sceLibcInternal data
            "crb5j7mkk1c", // _is_signal_return
            "NhpspxdjEKU", // _nanosleep
            "hHlZQUnlxSM", // getrusage
            "c7ZnT7V1B98", // rmdir
            "QzB4O+bJQyA", // sceKernelAprResolveFilepathsToIdsAndFileSizesForEach
            "eYAh2vlCY-U", // sceKernelAprResolveFilepathsToIdsForEach
            "i3HWvW35jao", // sceKernelAprResolveFilepathsWithPrefixToIds
            "w5fcCG+t31g", // sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes
            "C+Khtbbx2g8", // sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach
            "VB-BtuIW8Xc", // sceKernelAprResolveFilepathsWithPrefixToIdsForEach
            "uWyW3v98sU4", // sceKernelCheckReachability
            "cfwBSQyr5Ys", // sceKernelDebugWriteCppExceptionInfo
            "-YTW+qXc3CQ", // sceKernelInternalMemoryGetModuleSegmentInfo
            "3k6kx-zOOSQ", // sceKernelMlock
            "0Cq8ipKr9n0", // sceKernelUtimes
            "IafI2PxcPnQ", // scePthreadMutexTimedlock
            "VADc3MNQ3cM", // signal
            "VAzswvTOCzI", // unlink
            "TXFFFiNldU8", // getpeername
            "6O8EwYOgH9Y", // getsockopt
            "5jRCs2axtr4", // inet_ntop
            "Ez8xjo9UF4E", // recv
            "lUk6wrGXyMw", // recvfrom
            "fZOeZIOEmLw", // send
            "oBr313PppNE", // sendto
            "fFxGkxF2bVo", // setsockopt
            "TUuiYS2kE8s", // shutdown
        };

    [Fact]
    public void PreferLleCatalogs_RegisterExact34Gen5NamesAndLibrariesWithoutDuplicates()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5)
            .Where(export => ExpectedPreferLle.ContainsKey(export.Nid))
            .ToArray();

        Assert.Equal(34, exports.Length);
        Assert.Equal(34, exports.Select(export => export.Nid).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(30, exports.Count(export => export.LibraryName == "libc"));
        Assert.Equal(4, exports.Count(export => export.LibraryName == "libSceLibcInternal"));
        foreach (var export in exports)
        {
            var expected = ExpectedPreferLle[export.Nid];
            Assert.Equal(expected.ExportName, export.Name);
            Assert.Equal(expected.LibraryName, export.LibraryName);
            Assert.Equal(Generation.Gen5, export.Target);
            Assert.True(export.PreferLle);
            Assert.True(DirectExecutionBackend.ShouldResolveRegisteredExportViaLle(
                export,
                preferLleForLibc: false));
        }
    }

    [Fact]
    public void BacktraceForGame_RegistersOnceAsGen5FailClosedHleWithoutLlePreference()
    {
        var export = Assert.Single(
            SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5),
            candidate => candidate.Nid == BacktraceNid);

        Assert.Equal("sceLibcInternalBacktraceForGame", export.Name);
        Assert.Equal("libSceLibcInternalExt", export.LibraryName);
        Assert.Equal(Generation.Gen5, export.Target);
        Assert.False(export.PreferLle);
        Assert.False(DirectExecutionBackend.ShouldResolveRegisteredExportViaLle(
            export,
            preferLleForLibc: false));

        var context = new CpuContext(new NullMemory(), Generation.Gen5);
        AssertFailClosed(LibcInternalBacktraceExports.BacktraceForGameFailClosed, context);
    }

    [Fact]
    public void Libc35Registrations_DoNotProjectToGen4OrLeakDeferredDataKernelPosixNids()
    {
        var gen4 = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen4);
        Assert.DoesNotContain(gen4, export => ExpectedPreferLle.ContainsKey(export.Nid));
        Assert.DoesNotContain(gen4, export => export.Nid == BacktraceNid);

        var attributes = new[]
            {
                typeof(LibcProviderLleExports),
                typeof(LibcInternalProviderLleExports),
                typeof(LibcInternalBacktraceExports),
            }
            .SelectMany(type => type
                .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .SelectMany(method => method.GetCustomAttributes<SysAbiExportAttribute>()))
            .ToArray();
        var expectedNids = ExpectedPreferLle.Keys
            .Append(BacktraceNid)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(35, attributes.Length);
        Assert.Equal(expectedNids, attributes.Select(attribute => attribute.Nid).ToHashSet(StringComparer.Ordinal));
        Assert.DoesNotContain(attributes, attribute => ExplicitlyExcludedNids.Contains(attribute.Nid));
    }

    [Fact]
    public void Libc35ProviderFallbacks_AreExplicitlyFailClosed()
    {
        var fallbacks = new Func<CpuContext, int>[]
        {
            LibcProviderLleExports.MissingGuestProvider,
            LibcInternalProviderLleExports.MissingGuestProvider,
        };

        foreach (var fallback in fallbacks)
        {
            var context = new CpuContext(new NullMemory(), Generation.Gen5);
            AssertFailClosed(fallback, context);
        }
    }

    private static void AssertFailClosed(Func<CpuContext, int> fallback, CpuContext context)
    {
        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED,
            fallback(context));
        Assert.Equal(
            unchecked((ulong)(int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED),
            context[CpuRegister.Rax]);
    }

    private sealed class NullMemory : ICpuMemory
    {
        public bool TryRead(ulong virtualAddress, Span<byte> destination) => false;

        public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source) => false;
    }
}
