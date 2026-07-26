// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.GUI;
using Xunit;

namespace SharpEmu.Libs.Tests.GUI;

public sealed class LocalizationTypographyTests
{
    [Theory]
    [InlineData("ja", "Noto Sans JP")]
    [InlineData("ko", "Noto Sans KR")]
    public void AsianLocale_UsesMatchingNotoFontForLauncher(string code, string expectedFamily)
    {
        var localization = Localization.Instance;

        localization.Load(code);

        Assert.Equal(expectedFamily, localization.LauncherFontFamily.FamilyNames[0]);
        Assert.Contains("Google Sans", localization.LauncherFontFamily.FamilyNames);
    }

    [Fact]
    public void NonAsianLocale_UsesGoogleSansForLauncher()
    {
        var localization = Localization.Instance;

        localization.Load("en");

        Assert.Equal(["Google Sans"], localization.LauncherFontFamily.FamilyNames);
    }
}
