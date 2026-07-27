// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace SharpEmu.GUI;

/// <summary>Per-game options overlay: open/close, persistence and sections.</summary>
public partial class MainWindow
{
    private void WireGameOptions()
    {
        ConsoleToggle.Click += (_, _) => OpenSelectedGameSettings();

        var navButtons = GameOptionsNavButtons();
        for (var index = 0; index < navButtons.Length; index++)
        {
            var section = index;
            var button = navButtons[index];
            // The trailing button leaves the overlay instead of selecting a
            // section.
            if (section < 3)
            {
                button.Click += (_, _) => SetGameOptionsSection(section);
            }
            else
            {
                button.Click += (_, _) => CloseGameSettings();
            }

            button.PointerEntered += (_, _) =>
            {
                if (_isGameSettingsOpen)
                {
                    SetGameOptionsNavIndicator(section);
                }
            };
            button.GotFocus += (_, _) => SetGameOptionsNavIndicator(section);
        }
        GameOptionsNavHost.PointerExited += (_, _) =>
        {
            if (_isGameSettingsOpen)
            {
                SetGameOptionsNavIndicator(_gameOptionsSectionIndex);
            }
        };

        GameOptionsLaunchButton.Click += (_, _) =>
        {
            CloseGameSettings();
            LaunchSelected();
        };
        GameOptionsOpenFolderButton.Click += (_, _) => OpenSelectedGameFolder();
        GameOptionsCopyPathButton.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.Path, "Clipboard.Path");
        GameOptionsCopyTitleIdButton.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.TitleId, "Clipboard.TitleId");
        GameOptionsRemoveButton.Click += (_, _) =>
        {
            CloseGameSettings();
            RemoveSelectedFromLibrary();
        };

        GameLogLevelBox.SelectionChanged += (_, _) => PersistOpenGameSettings();
        GameTraceBox.ValueChanged += (_, _) => PersistOpenGameSettings();
        GameStrictToggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        GameLogToFileToggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        foreach (var (_, toggle) in GameEnvironmentToggles())
        {
            toggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        }
    }

    /// <summary>
    /// Applies the overlay's own strings. The per-game log-level list is filled
    /// by <see cref="ApplyOptionsLocalization"/>, which builds the localized
    /// level names once and shares them with the global page.
    /// </summary>
    private void ApplyGameOptionsLocalization()
    {
        var loc = Localization.Instance;

        GameOptionsLastPlayedLabel.Text = loc.Get("Library.Stat.LastPlayed");
        GameOptionsVersionLabel.Text = loc.Get("Library.Stat.Version");
        GameOptionsInstalledLabel.Text = loc.Get("Library.Stat.Installed");
        GameOptionsTitleIdLabel.Text = loc.Get("Library.Stat.TitleId");
        GameOptionsLastPlayedValue.Text = loc.Get("Library.Stat.NotPlayed");
        GameOptionsGeneralNavLabel.Text = loc.Get("Options.General");
        GameOptionsLoggingNavLabel.Text = loc.Get("Options.Logging");
        GameOptionsEnvironmentNavLabel.Text = loc.Get("Options.Env.Tab");
        GameOptionsBackNavLabel.Text = loc.Get("Common.Back");
        GameOptionsLaunchLabel.Text = loc.Get("Library.Context.Launch");
        GameOptionsOpenFolderLabel.Text = loc.Get("Library.Context.OpenFolder");
        GameOptionsCopyPathLabel.Text = loc.Get("Library.Context.CopyPath");
        GameOptionsCopyTitleIdLabel.Text = loc.Get("Library.Context.CopyTitleId");
        GameOptionsRemoveLabel.Text = loc.Get("Library.Context.Remove");

        GameStrictRow.Label = loc.Get("Options.Strict.Label");
        GameStrictRow.Description = loc.Get("Options.Strict.Desc");
        GameLogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        GameLogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        GameTraceRow.Label = loc.Get("Options.TraceImports.Label");
        GameTraceRow.Description = loc.Get("Options.TraceImports.Desc");
        GameLogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        GameLogToFileRow.Description = loc.Get("Options.LogToFile.Desc");
    }

    private void OpenSelectedGameSettings()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(game.TitleId))
        {
            AppendConsoleLine(
                "[GUI][WARN] Per-game settings require a title ID, which this game does not have.",
                WarningLineBrush);
            return;
        }

        var vm = new ViewModels.PerGameSettingsViewModel(game.TitleId, game.Name, _settings);
        _gameSettingsViewModel = vm;
        LoadGameSettings(vm);
        GameOptionsOverlay.DataContext = game;
        SetGameOptionsSection(0);
        GameOptionsLaunchButton.IsEnabled = !_isRunning;
        GameOptionsCopyTitleIdButton.IsEnabled = !string.IsNullOrWhiteSpace(game.TitleId);

        _selectedDetailsAnimationGeneration++;
        SelectedDetailsHost.Classes.Remove("detailsOut");
        SelectedDetailsHost.Classes.Remove("detailsInStart");
        SetStateClass(BackdropLayer, "gameOptionsOpen", active: true);
        SetStateClass(CarouselHost, "gameOptionsOpen", active: true);
        SetStateClass(SelectedDetailsHost, "gameOptionsOpen", active: true);
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: true);

        _isGameSettingsOpen = true;
        ConsoleToggle.IsChecked = true;
        GameList.IsHitTestVisible = false;
        GameOptionsOverlay.IsHitTestVisible = true;
        GameOptionsGeneralNav.Focus();
    }

    private void CloseGameSettings()
    {
        if (!_isGameSettingsOpen)
        {
            return;
        }

        _isGameSettingsOpen = false;
        SetStateClass(BackdropLayer, "gameOptionsOpen", active: false);
        SetStateClass(CarouselHost, "gameOptionsOpen", active: false);
        SetStateClass(SelectedDetailsHost, "gameOptionsOpen", active: false);
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: false);
        GameOptionsOverlay.IsHitTestVisible = false;
        GameList.IsHitTestVisible = true;
        ConsoleToggle.IsChecked = false;
        GameList.Focus();
    }

    private void LoadGameSettings(ViewModels.PerGameSettingsViewModel vm)
    {
        _isLoadingGameSettings = true;
        try
        {
            GameLogLevelBox.SelectedIndex = LogLevelIndex(vm.SelectedLogLevel);
            GameTraceBox.Value = vm.ImportTraceLimit;
            GameStrictToggle.IsChecked = vm.IsStrictDynlibResolution;
            GameLogToFileToggle.IsChecked = vm.IsLogToFile;

            foreach (var (name, toggle) in GameEnvironmentToggles())
            {
                toggle.IsChecked = vm.GetEnvironment(name);
            }
        }
        finally
        {
            _isLoadingGameSettings = false;
        }
    }

    private void PersistOpenGameSettings()
    {
        if (_isGameSettingsOpen &&
            !_isLoadingGameSettings &&
            _gameSettingsViewModel is { } vm)
        {
            PersistGameSettings(vm);
        }
    }

    private void PersistGameSettings(ViewModels.PerGameSettingsViewModel vm)
    {
        vm.SelectedLogLevel = LogLevelAt(GameLogLevelBox.SelectedIndex);
        vm.IsLogLevelOverridden =
            !string.Equals(vm.SelectedLogLevel, _settings.LogLevel, StringComparison.Ordinal);
        vm.ImportTraceLimit = (int)(GameTraceBox.Value ?? 0);
        vm.IsImportTraceOverridden = vm.ImportTraceLimit != _settings.ImportTraceLimit;
        vm.IsStrictDynlibResolution = GameStrictToggle.IsChecked == true;
        vm.IsStrictOverridden =
            vm.IsStrictDynlibResolution != _settings.StrictDynlibResolution;
        vm.IsLogToFile = GameLogToFileToggle.IsChecked == true;
        vm.IsLogToFileOverridden = vm.IsLogToFile != _settings.LogToFile;

        var selectedEnvironment = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, toggle) in GameEnvironmentToggles())
        {
            var isEnabled = toggle.IsChecked == true;
            vm.SetEnvironment(name, isEnabled);
            if (isEnabled)
            {
                selectedEnvironment.Add(name);
            }
        }

        vm.IsEnvironmentOverridden =
            !_settings.EnvironmentToggles.ToHashSet(StringComparer.Ordinal).SetEquals(selectedEnvironment);
        vm.Save();
    }

    private void SetGameOptionsSection(int section)
    {
        var buttons = GameOptionsNavButtons();
        var panels = GameOptionsSectionPanels();

        section = Math.Clamp(section, 0, panels.Length - 1);
        _gameOptionsSectionIndex = section;
        SetGameOptionsNavIndicator(section);
        for (var index = 0; index < panels.Length; index++)
        {
            SetStateClass(buttons[index], "active", index == section);
            SetStateClass(panels[index], "active", index == section);
            SetPanelInteraction(panels[index], index == section);
        }

        SetStateClass(GameOptionsBackNav, "active", active: false);
    }

    private void SetGameOptionsNavIndicator(int section)
    {
        if (GameOptionsNavIndicator.RenderTransform is TranslateTransform transform)
        {
            var buttons = GameOptionsNavButtons();
            var index = Math.Clamp(section, 0, buttons.Length - 1);
            var button = buttons[index];
            transform.Y = button.TranslatePoint(default, GameOptionsNavHost)?.Y
                ?? index * button.Bounds.Height;
        }
    }

    private Button[] GameOptionsNavButtons() =>
    [
        GameOptionsGeneralNav,
        GameOptionsLoggingNav,
        GameOptionsEnvironmentNav,
        GameOptionsBackNav,
    ];

    private Control[] GameOptionsSectionPanels() =>
    [
        GameOptionsGeneralPanel,
        GameOptionsLoggingPanel,
        GameOptionsEnvironmentPanel,
    ];

    private (string Name, ToggleSwitch Toggle)[] GameEnvironmentToggles() =>
    [
        ("SHARPEMU_BTHID_UNAVAILABLE", GameEnvBthidToggle),
        ("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD", GameEnvLoopGuardToggle),
        ("SHARPEMU_WRITABLE_APP0", GameEnvWritableApp0Toggle),
        ("SHARPEMU_VK_VALIDATION", GameEnvVkValidationToggle),
        ("SHARPEMU_DUMP_SPIRV", GameEnvDumpSpirvToggle),
        ("SHARPEMU_LOG_DIRECT_MEMORY", GameEnvLogDirectMemoryToggle),
        ("SHARPEMU_LOG_IO", GameEnvLogIoToggle),
        ("SHARPEMU_LOG_NP", GameEnvLogNpToggle),
    ];
}
