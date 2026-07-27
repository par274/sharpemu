// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using Avalonia.Data;
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

    [Fact]
    public void LocalizedIndexerBinding_RefreshesAfterLanguageChange()
    {
        var localization = Localization.Instance;
        var label = new TextBlock();
        using var binding = label.Bind(
            TextBlock.TextProperty,
            new Binding("[Library.AddFolder]")
            {
                Source = localization,
                Mode = BindingMode.OneWay,
            });

        try
        {
            localization.Load("en");
            Assert.Equal("Add folder", label.Text);

            localization.Load("ru");
            Assert.Equal("Добавить папку", label.Text);
        }
        finally
        {
            localization.Load("en");
        }
    }
}
