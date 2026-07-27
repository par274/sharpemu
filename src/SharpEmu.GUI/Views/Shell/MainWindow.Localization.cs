// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI;

/// <summary>Language selection and the per-region localization passes.</summary>
public partial class MainWindow
{
    private void PopulateLanguageBox()
    {
        var languages = Localization.Instance.DiscoverLanguages();
        LanguageBox.ItemsSource = languages;
        LanguageBox.SelectedItem = languages.FirstOrDefault(language =>
            string.Equals(language.Code, _settings.Language, StringComparison.OrdinalIgnoreCase))
            ?? languages.FirstOrDefault();
    }

    private void OnLanguageChanged()
    {
        if (LanguageBox.SelectedItem is not Localization.LanguageInfo language)
        {
            return;
        }

        _settings.Language = language.Code;
        Localization.Instance.Load(language.Code);
        ApplyLocalization();
    }

    /// <summary>
    /// Re-applies every UI string from the current language, so switching
    /// languages in Options takes effect immediately without reopening the
    /// window. Each region applies its own strings; the passes touch disjoint
    /// controls, so their relative order carries no meaning.
    /// </summary>
    private void ApplyLocalization()
    {
        ApplyChromeLocalization();
        ApplyLibraryLocalization();
        ApplyGameOptionsLocalization();
        ApplyOptionsLocalization();
        ApplyConsoleLocalization();
        ApplyGameSurfaceLocalization();
        ApplyAboutLocalization();

        UpdateSelectedGameTexts();
    }

    private static string SectionNavigationLabel(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(char.IsLower))
        {
            return value;
        }

        var lower = value.ToLowerInvariant();
        return char.ToUpperInvariant(lower[0]) + lower[1..];
    }

    private static void ApplyEnvironmentDescription(
        SettingRow globalRow,
        SettingRow perGameRow,
        string localizationKey)
    {
        var description = Localization.Instance.Get(localizationKey);
        globalRow.Description = description;
        perGameRow.Description = description;
    }
}
