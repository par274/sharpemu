// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Lle;
using Xunit;

namespace SharpEmu.Libs.Tests.Lle;

public sealed class ProviderLleExportsTests
{
    private const string SemanticBatchInitializeNid = "MmpF1XsQiHw";
    private static readonly HashSet<string> ForcedHleProviderNids =
        new(StringComparer.Ordinal)
        {
            "Ikfdt-rIqCE",
            "KfGZg2y73oM",
            "w4-d0n60hdo",
        };
    private static readonly HashSet<string> CrossGenerationSemanticProviderNids =
        new(StringComparer.Ordinal)
        {
            "-qLsfDAywIY",
            "39WxhR-ePew",
            "4fU5yvOkVG4",
            "5tOfnaClcqM",
            "MsaFhR+lPE4",
            "S1GkePI17zQ",
            "Z7z6HXWORJY",
            "yKDy8S5yLA0",
        };
    private static readonly string[] SemanticHleReplacementNids =
    [
        "1q1titRBL6o", "b-oySn+G2tE", "e1DFTg+Sd8U", "LHFXRrlTPD8",
        "r98I08t+LOg", "uZW-mqsxkrM", "w1KFAHVqpaU", "ypVBz4uPKcQ",
        "gyTyVn+bXMw", "IADmD4tScBY", "NUeBrN7hzf0", "oBmw4xrmfKs",
        "x01jxu+vxlc",
    ];

    private static readonly IReadOnlyDictionary<string, (string ExportName, string LibraryName)> Provider23Expected =
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

    private static readonly IReadOnlyDictionary<string, int> ExpectedCounts =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["libSceAgc"] = 98,
            ["libSceAgcDriver"] = 22,
            ["libSceAmpr"] = 44,
            ["libSceAudioOut"] = 1,
            ["libSceContentDelete"] = 3,
            ["libSceContentExport"] = 5,
            ["libSceContentSearch"] = 7,
            ["libSceCoredump"] = 2,
            ["libSceGameLiveStreaming"] = 2,
            ["libSceIme"] = 1,
            ["libSceImeDialog"] = 1,
            ["libSceLibcInternal"] = 4,
            ["libSceNet"] = 3,
            ["libSceNetCtl"] = 3,
            ["libSceNpAuth"] = 5,
            ["libSceNpCommerce"] = 7,
            ["libSceNpEntitlementAccess"] = 5,
            ["libSceNpGameIntent"] = 2,
            ["libSceNpManager"] = 3,
            ["libSceNpUniversalDataSystem"] = 4,
            ["libSceNpUtility"] = 5,
            ["libScePad"] = 1,
            ["libScePlayerInvitationDialog"] = 2,
            ["libScePlayerSelectionDialog"] = 1,
            ["libSceRazorCpu"] = 3,
            ["libSceRtc"] = 2,
            ["libSceShare"] = 1,
            ["libSceSharePlay"] = 2,
            ["libSceSigninDialog"] = 4,
            ["libSceSystemService"] = 3,
            ["libSceVideoOut"] = 1,
            ["libSceVideoRecordingP"] = 8,
            ["libSceVoice"] = 15,
            ["libSceWebBrowserDialog"] = 5,
            ["libc"] = 30,
            ["ulobjmgr"] = 2,
        };

    [Fact]
    public void GtaProviderCatalogs_RegisterAll307FallbackNidsAnd13SemanticHleReplacements()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5)
            .Where(IsProviderCatalogExport)
            .ToArray();

        Assert.Equal(307, exports.Length);
        Assert.Equal(307, exports.Select(export => export.Nid).Distinct(StringComparer.Ordinal).Count());
        Assert.All(exports, export =>
        {
            Assert.NotEqual(Generation.None, export.Target & Generation.Gen5);
            Assert.Equal(!ForcedHleProviderNids.Contains(export.Nid), export.PreferLle);
        });

        foreach (var expected in ExpectedCounts)
        {
            Assert.Equal(expected.Value, exports.Count(export => export.LibraryName == expected.Key));
        }

        var allExports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5);
        foreach (var nid in SemanticHleReplacementNids)
        {
            var semanticExport = Assert.Single(
                allExports,
                export => export.Nid == nid);
            Assert.False(semanticExport.PreferLle);
            Assert.NotEqual(typeof(AgcLleExports), semanticExport.Function.Method.DeclaringType);
            Assert.NotEqual(typeof(ImeDialogLleExports), semanticExport.Function.Method.DeclaringType);
        }

        var privateVideoMatches = exports.Where(export => export.Nid == "iQS6DUtLybE").ToArray();
        Assert.True(privateVideoMatches.Length == 1, $"Expected one private-video export, found {privateVideoMatches.Length}.");
        var privateVideoExport = privateVideoMatches[0];
        Assert.Equal("iQS6DUtLybE#L#A", privateVideoExport.Name);
        Assert.Equal("libSceVideoRecordingP", privateVideoExport.LibraryName);

    }

    [Fact]
    public void GtaProvider23Catalogs_RegisterExactGen5NamesAndLibrariesAsLlePreferred()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5)
            .Where(export => Provider23Expected.ContainsKey(export.Nid))
            .ToArray();

        Assert.Equal(12, exports.Length);
        Assert.Equal(12, exports.Select(export => export.Nid).Distinct(StringComparer.Ordinal).Count());
        foreach (var export in exports)
        {
            var expected = Provider23Expected[export.Nid];
            Assert.Equal(expected.ExportName, export.Name);
            Assert.Equal(expected.LibraryName, export.LibraryName);
            Assert.NotEqual(Generation.None, export.Target & Generation.Gen5);
            Assert.True(export.PreferLle, $"Expected provider-preferred routing for {export.Nid} ({export.Name}).");
        }
    }

    [Fact]
    public void GtaProviderCatalogs_DoNotProjectRegistrationsToGen4()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen4)
            .Where(IsProviderCatalogExport)
            .Where(export => !CrossGenerationSemanticProviderNids.Contains(export.Nid))
            .ToArray();

        Assert.Empty(exports);

        Assert.DoesNotContain(
            SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen4),
            export => Provider23Expected.ContainsKey(export.Nid) &&
                export.PreferLle &&
                !CrossGenerationSemanticProviderNids.Contains(export.Nid));
    }

    [Fact]
    public void MissingGuestProviderFallbacks_AreExplicitlyFailClosed()
    {
        var fallbacks = new Func<CpuContext, int>[]
        {
            AgcLleExports.MissingGuestProvider,
            AgcDriverLleExports.MissingGuestProvider,
            AjmLleExports.MissingGuestProvider,
            AmprLleExports.MissingGuestProvider,
            ContentDeleteLleExports.MissingGuestProvider,
            ContentExportLleExports.MissingGuestProvider,
            ContentSearchLleExports.MissingGuestProvider,
            GameLiveStreamingLleExports.MissingGuestProvider,
            ImeDialogLleExports.MissingGuestProvider,
            NetLleExports.MissingGuestProvider,
            NetCtlLleExports.MissingGuestProvider,
            NpAuthLleExports.MissingGuestProvider,
            NpCommerceLleExports.MissingGuestProvider,
            NpEntitlementAccessLleExports.MissingGuestProvider,
            NpGameIntentLleExports.MissingGuestProvider,
            NpManagerLleExports.MissingGuestProvider,
            NpUniversalDataSystemLleExports.MissingGuestProvider,
            NpUtilityLleExports.MissingGuestProvider,
            PlayerInvitationDialogLleExports.MissingGuestProvider,
            RemoteplayLleExports.MissingGuestProvider,
            RtcLleExports.MissingGuestProvider,
            SaveDataNativeLleExports.MissingGuestProvider,
            ShareLleExports.MissingGuestProvider,
            SharePlayLleExports.MissingGuestProvider,
            SigninDialogLleExports.MissingGuestProvider,
            SystemServiceLleExports.MissingGuestProvider,
            VideoRecordingPrivateLleExports.MissingGuestProvider,
            VoiceLleExports.MissingGuestProvider,
            WebBrowserDialogLleExports.MissingGuestProvider,
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

    [Fact]
    public void WebBrowserInitializeUsesExactProviderUnavailableResult()
    {
        var context = new CpuContext(new NullMemory(), Generation.Gen5);

        Assert.Equal(
            unchecked((int)0x80B8000E),
            WebBrowserDialogLleExports.InitializeWithoutGuestProvider(context));
        Assert.Equal(
            unchecked((ulong)unchecked((int)0x80B8000E)),
            context[CpuRegister.Rax]);
    }

    [Fact]
    public void GameLiveStreamingFallbackMatchesProviderLifecycle()
    {
        GameLiveStreamingLleExports.ResetForTests();
        try
        {
            var context = new CpuContext(new NullMemory(), Generation.Gen5);
            context[CpuRegister.Rdi] = 0x3FFF;
            Assert.Equal(
                unchecked((int)0x80A00002),
                GameLiveStreamingLleExports.InitializeWithoutGuestProvider(context));
            Assert.Equal(
                unchecked((ulong)unchecked((int)0x80A00002)),
                context[CpuRegister.Rax]);

            Assert.Equal(
                unchecked((int)0x80A00004),
                GameLiveStreamingLleExports.TerminateWithoutGuestProvider(context));

            context[CpuRegister.Rdi] = 0x4000;
            Assert.Equal(
                (int)OrbisGen2Result.ORBIS_GEN2_OK,
                GameLiveStreamingLleExports.InitializeWithoutGuestProvider(context));
            Assert.Equal(0UL, context[CpuRegister.Rax]);

            Assert.Equal(
                unchecked((int)0x80A00003),
                GameLiveStreamingLleExports.InitializeWithoutGuestProvider(context));

            Assert.Equal(
                (int)OrbisGen2Result.ORBIS_GEN2_OK,
                GameLiveStreamingLleExports.TerminateWithoutGuestProvider(context));
            Assert.Equal(0UL, context[CpuRegister.Rax]);

            Assert.Equal(
                unchecked((int)0x80A00004),
                GameLiveStreamingLleExports.TerminateWithoutGuestProvider(context));
        }
        finally
        {
            GameLiveStreamingLleExports.ResetForTests();
        }
    }

    [Fact]
    public void Provider23MissingGuestProviderFallbacks_AreExplicitlyFailClosed()
    {
        var fallbacks = new Func<CpuContext, int>[]
        {
            AjmNativeLleExports.MissingGuestProvider,
            AppContentLleExports.MissingGuestProvider,
            AudioOutLleExports.MissingGuestProvider,
            AudioOut2LleExports.MissingGuestProvider,
            CoredumpLleExports.MissingGuestProvider,
            ImeLleExports.MissingGuestProvider,
            NpTrophy2LleExports.MissingGuestProvider,
            PadLleExports.MissingGuestProvider,
            PlayerSelectionDialogLleExports.MissingGuestProvider,
            RazorCpuLleExports.MissingGuestProvider,
            SysmoduleLleExports.MissingGuestProvider,
            UlObjMgrLleExports.MissingGuestProvider,
            VideoOutLleExports.MissingGuestProvider,
        };

        Assert.Equal(13, fallbacks.Length);
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

    private static bool IsProviderCatalogExport(ExportedFunction export) =>
        ExpectedCounts.ContainsKey(export.LibraryName) &&
        export.Nid != SemanticBatchInitializeNid &&
        (export.PreferLle || ForcedHleProviderNids.Contains(export.Nid));

    private sealed class NullMemory : ICpuMemory
    {
        public bool TryRead(ulong virtualAddress, Span<byte> destination) => false;

        public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source) => false;
    }
}
