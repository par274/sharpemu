// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.Logging;

[CollectionDefinition("DiagnosticsConfiguration", DisableParallelization = true)]
public sealed class DiagnosticsConfigurationCollection;

[Collection("DiagnosticsConfiguration")]
public sealed class SharpEmuDiagnosticsTests
{
    [Theory]
    [InlineData("Off", DiagnosticProfile.Off)]
    [InlineData("compatibility", DiagnosticProfile.Compatibility)]
    [InlineData("FULL", DiagnosticProfile.Full)]
    [InlineData("custom", DiagnosticProfile.Custom)]
    [InlineData("invalid", DiagnosticProfile.Off)]
    [InlineData(null, DiagnosticProfile.Off)]
    public void ParseProfile_NormalizesKnownValues(string? value, DiagnosticProfile expected) =>
        Assert.Equal(expected, SharpEmuDiagnostics.ParseProfile(value));

    [Fact]
    public void Profiles_EnableOnlyTheirIntendedCategories()
    {
        Assert.Equal(
            DiagnosticCategory.None,
            SharpEmuDiagnostics.ResolveCategories(DiagnosticProfile.Off));
        Assert.Equal(
            DiagnosticCategory.Imports | DiagnosticCategory.AgcUnsupported,
            SharpEmuDiagnostics.ResolveCategories(DiagnosticProfile.Compatibility));
        Assert.Equal(
            DiagnosticCategory.All,
            SharpEmuDiagnostics.ResolveCategories(DiagnosticProfile.Full));
        Assert.Equal(
            DiagnosticCategory.AgcShaders | DiagnosticCategory.Video,
            SharpEmuDiagnostics.ResolveCategories(
                DiagnosticProfile.Custom,
                DiagnosticCategory.AgcShaders | DiagnosticCategory.Video));
    }

    [Fact]
    public void DisabledCategory_DoesNotEvaluateInterpolatedArguments()
    {
        try
        {
            SharpEmuDiagnostics.Configure(DiagnosticProfile.Off);
            var evaluations = 0;

            SharpEmuDiagnostics.Write(
                DiagnosticCategory.AgcPackets,
                $"value={CountEvaluation(ref evaluations)}");

            Assert.Equal(0, evaluations);
            Assert.False(SharpEmuDiagnostics.IsEnabled(DiagnosticCategory.AgcPackets));
        }
        finally
        {
            SharpEmuDiagnostics.Configure(DiagnosticProfile.Off);
        }
    }

    [Fact]
    public void CustomProfile_ParsesIndependentCategories()
    {
        try
        {
            SharpEmuDiagnostics.Configure(
                "Custom",
                ["AgcUnsupported", "Video", "unknown", "None"]);

            Assert.True(SharpEmuDiagnostics.IsEnabled(DiagnosticCategory.AgcUnsupported));
            Assert.True(SharpEmuDiagnostics.IsEnabled(DiagnosticCategory.Video));
            Assert.False(SharpEmuDiagnostics.IsEnabled(DiagnosticCategory.AgcPackets));
        }
        finally
        {
            SharpEmuDiagnostics.Configure(DiagnosticProfile.Off);
        }
    }

    private static int CountEvaluation(ref int count) => ++count;
}
