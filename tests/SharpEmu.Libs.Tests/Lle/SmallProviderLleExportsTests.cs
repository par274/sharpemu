// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Lle;
using Xunit;

namespace SharpEmu.Libs.Tests.Lle;

public sealed class SmallProviderLleExportsTests
{
    private static readonly IReadOnlyDictionary<string, (string ExportName, string LibraryName)> Expected =
        new Dictionary<string, (string ExportName, string LibraryName)>(StringComparer.Ordinal)
        {
            ["9FowWFMEIM8"] = ("sceRazorCpuJobManagerSequence", "libSceRazorCpu"),
            ["BG26hBGiNlw"] = ("_sceUlobjmgrRegisterObject", "ulobjmgr"),
            ["CgdJ1PkIsE4"] = ("scePlayerSelectionDialogTerminate", "libScePlayerSelectionDialog"),
            ["Dbbkj6YHWdo"] = ("sceCoredumpWriteUserData", "libSceCoredump"),
            ["HuViW4HnrOw"] = ("sceVideoOutSubmitChangeBufferAttribute2", "libSceVideoOut"),
            ["KP+TBWGHlgs"] = ("sceRazorCpuJobManagerJob", "libSceRazorCpu"),
            ["PMVehSlfZ94"] = ("sceImeKeyboardClose", "libSceIme"),
            ["Smf+fUNblPc"] = ("_sceUlobjmgrUnregisterObject", "ulobjmgr"),
            ["dnEdyY4+klQ"] = ("sceRazorCpuJobManagerDispatch", "libSceRazorCpu"),
            ["fFkhOgztiCA"] = ("sceCoredumpUnregisterCoredumpHandler", "libSceCoredump"),
            ["rIZnR6eSpvk"] = ("scePadResetOrientation", "libScePad"),
            ["wVwPU50pS1c"] = ("sceAudioOutSetMixLevelPadSpk", "libSceAudioOut"),
        };

    [Fact]
    public void CatalogsRegisterExactGen5NamesAndLibrariesAsLlePreferred()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5)
            .Where(export => Expected.ContainsKey(export.Nid))
            .ToArray();

        Assert.Equal(Expected.Count, exports.Length);
        Assert.Equal(Expected.Count, exports.Select(export => export.Nid).Distinct(StringComparer.Ordinal).Count());
        foreach (var export in exports)
        {
            var expected = Expected[export.Nid];
            Assert.Equal(expected.ExportName, export.Name);
            Assert.Equal(expected.LibraryName, export.LibraryName);
            Assert.True(export.PreferLle);
            Assert.NotEqual(Generation.None, export.Target & Generation.Gen5);
        }
    }

    [Fact]
    public void CatalogsDoNotProjectToGen4()
    {
        Assert.DoesNotContain(
            SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen4),
            export => Expected.ContainsKey(export.Nid));
    }

    [Fact]
    public void MissingGuestProviderFallbacksFailClosed()
    {
        var fallbacks = new Func<CpuContext, int>[]
        {
            AudioOutLleExports.MissingGuestProvider,
            CoredumpLleExports.MissingGuestProvider,
            ImeLleExports.MissingGuestProvider,
            PadLleExports.MissingGuestProvider,
            PlayerSelectionDialogLleExports.MissingGuestProvider,
            RazorCpuLleExports.MissingGuestProvider,
            SysmoduleLleExports.MissingGuestProvider,
            UlObjMgrLleExports.MissingGuestProvider,
            VideoOutLleExports.MissingGuestProvider,
        };

        foreach (var fallback in fallbacks)
        {
            var context = new CpuContext(new NullMemory(), Generation.Gen5);
            Assert.Equal(
                (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED,
                fallback(context));
            Assert.Equal(
                unchecked((ulong)(int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED),
                context[CpuRegister.Rax]);
        }
    }

    private sealed class NullMemory : ICpuMemory
    {
        public bool TryRead(ulong virtualAddress, Span<byte> destination) => false;

        public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source) => false;
    }
}
