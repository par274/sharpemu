// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using SharpEmu.Logging;

namespace SharpEmu.GUI;

public partial class MainWindow
{
    private readonly LocalizedChoice[] _diagnosticProfileChoices =
    [
        LocalizedChoice.FromKey("Off", "Options.Diagnostics.Profile.Off"),
        LocalizedChoice.FromKey("Compatibility", "Options.Diagnostics.Profile.Compatibility"),
        LocalizedChoice.FromKey("Full", "Options.Diagnostics.Profile.Full"),
        LocalizedChoice.FromKey("Custom", "Options.Diagnostics.Profile.Custom"),
    ];

    private bool _isLoadingGlobalDiagnostics;

    private void WireGlobalDiagnostics()
    {
        DiagnosticsProfileBox.SelectionChanged += (_, _) =>
        {
            if (_isLoadingGlobalDiagnostics)
            {
                return;
            }

            _isLoadingGlobalDiagnostics = true;
            try
            {
                var profile = SelectedComboText(DiagnosticsProfileBox, "Off");
                _settings.DiagnosticsProfile = profile;
                var categories = CategoriesForProfile(profile, _settings.DiagnosticCategories);
                _settings.DiagnosticCategories = SharpEmuDiagnostics.CategoryNames(categories);
                SetDiagnosticToggles(GlobalDiagnosticToggles(), profile, categories);
            }
            finally
            {
                _isLoadingGlobalDiagnostics = false;
            }
        };

        foreach (var (_, toggle) in GlobalDiagnosticToggles())
        {
            toggle.IsCheckedChanged += (_, _) =>
            {
                if (_isLoadingGlobalDiagnostics)
                {
                    return;
                }

                _isLoadingGlobalDiagnostics = true;
                try
                {
                    _settings.DiagnosticsProfile = DiagnosticProfile.Custom.ToString();
                    DiagnosticsProfileBox.SelectedItem = FindChoice(
                        _diagnosticProfileChoices,
                        _settings.DiagnosticsProfile,
                        "Off");
                    _settings.DiagnosticCategories = SharpEmuDiagnostics.CategoryNames(
                        ReadDiagnosticToggles(GlobalDiagnosticToggles()));
                    SetDiagnosticToggles(
                        GlobalDiagnosticToggles(),
                        _settings.DiagnosticsProfile,
                        SharpEmuDiagnostics.ParseCategories(_settings.DiagnosticCategories));
                }
                finally
                {
                    _isLoadingGlobalDiagnostics = false;
                }
            };
        }
    }

    private void WireGameDiagnostics()
    {
        GameDiagnosticsProfileBox.ItemsSource = _diagnosticProfileChoices;
        GameDiagnosticsProfileBox.SelectionChanged += (_, _) =>
        {
            if (_isLoadingGameSettings)
            {
                return;
            }

            _isLoadingGameSettings = true;
            try
            {
                var profile = SelectedComboText(GameDiagnosticsProfileBox, "Off");
                var categories = CategoriesForProfile(
                    profile,
                    ReadDiagnosticToggles(GameDiagnosticToggles()));
                SetDiagnosticToggles(GameDiagnosticToggles(), profile, categories);
            }
            finally
            {
                _isLoadingGameSettings = false;
            }

            PersistOpenGameSettings();
        };

        foreach (var (_, toggle) in GameDiagnosticToggles())
        {
            toggle.IsCheckedChanged += (_, _) =>
            {
                if (_isLoadingGameSettings)
                {
                    return;
                }

                _isLoadingGameSettings = true;
                try
                {
                    GameDiagnosticsProfileBox.SelectedItem = FindChoice(
                        _diagnosticProfileChoices,
                        DiagnosticProfile.Custom.ToString(),
                        "Off");
                    SetDiagnosticToggles(
                        GameDiagnosticToggles(),
                        DiagnosticProfile.Custom.ToString(),
                        ReadDiagnosticToggles(GameDiagnosticToggles()));
                }
                finally
                {
                    _isLoadingGameSettings = false;
                }

                PersistOpenGameSettings();
            };
        }
    }

    private void ApplyGlobalDiagnosticSettings()
    {
        _isLoadingGlobalDiagnostics = true;
        try
        {
            DiagnosticsProfileBox.SelectedItem = FindChoice(
                _diagnosticProfileChoices,
                _settings.DiagnosticsProfile,
                "Off");
            var categories = CategoriesForProfile(
                _settings.DiagnosticsProfile,
                _settings.DiagnosticCategories);
            SetDiagnosticToggles(
                GlobalDiagnosticToggles(),
                _settings.DiagnosticsProfile,
                categories);
        }
        finally
        {
            _isLoadingGlobalDiagnostics = false;
        }
    }

    private void ApplyGameDiagnosticSettings(EffectiveLaunchSettings settings)
    {
        GameDiagnosticsProfileBox.SelectedItem = FindChoice(
            _diagnosticProfileChoices,
            settings.DiagnosticsProfile,
            "Off");
        SetDiagnosticToggles(
            GameDiagnosticToggles(),
            settings.DiagnosticsProfile,
            CategoriesForProfile(settings.DiagnosticsProfile, settings.DiagnosticCategories));
    }

    private static DiagnosticCategory CategoriesForProfile(
        string profileValue,
        IEnumerable<string> customCategories) =>
        CategoriesForProfile(
            profileValue,
            SharpEmuDiagnostics.ParseCategories(customCategories));

    private static DiagnosticCategory CategoriesForProfile(
        string profileValue,
        DiagnosticCategory customCategories)
    {
        var profile = SharpEmuDiagnostics.ParseProfile(profileValue);
        return SharpEmuDiagnostics.ResolveCategories(profile, customCategories);
    }

    private static void SetDiagnosticToggles(
        IEnumerable<(DiagnosticCategory Category, ToggleSwitch Toggle)> controls,
        string profileValue,
        DiagnosticCategory categories)
    {
        var custom = SharpEmuDiagnostics.ParseProfile(profileValue) == DiagnosticProfile.Custom;
        foreach (var (category, toggle) in controls)
        {
            toggle.IsChecked = (categories & category) != 0;
            toggle.IsEnabled = custom;
        }
    }

    private static DiagnosticCategory ReadDiagnosticToggles(
        IEnumerable<(DiagnosticCategory Category, ToggleSwitch Toggle)> controls)
    {
        var categories = DiagnosticCategory.None;
        foreach (var (category, toggle) in controls)
        {
            if (toggle.IsChecked == true)
            {
                categories |= category;
            }
        }

        return categories;
    }

    private (DiagnosticCategory Category, ToggleSwitch Toggle)[] GlobalDiagnosticToggles() =>
    [
        (DiagnosticCategory.Imports, DiagImportsToggle),
        (DiagnosticCategory.AgcUnsupported, DiagAgcUnsupportedToggle),
        (DiagnosticCategory.AgcShaders, DiagAgcShadersToggle),
        (DiagnosticCategory.AgcPackets, DiagAgcPacketsToggle),
        (DiagnosticCategory.AgcDraws, DiagAgcDrawsToggle),
        (DiagnosticCategory.Memory, DiagMemoryToggle),
        (DiagnosticCategory.Video, DiagVideoToggle),
    ];

    private (DiagnosticCategory Category, ToggleSwitch Toggle)[] GameDiagnosticToggles() =>
    [
        (DiagnosticCategory.Imports, GameDiagImportsToggle),
        (DiagnosticCategory.AgcUnsupported, GameDiagAgcUnsupportedToggle),
        (DiagnosticCategory.AgcShaders, GameDiagAgcShadersToggle),
        (DiagnosticCategory.AgcPackets, GameDiagAgcPacketsToggle),
        (DiagnosticCategory.AgcDraws, GameDiagAgcDrawsToggle),
        (DiagnosticCategory.Memory, GameDiagMemoryToggle),
        (DiagnosticCategory.Video, GameDiagVideoToggle),
    ];
}
