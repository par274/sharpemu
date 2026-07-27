// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Platform.Storage;

namespace SharpEmu.GUI;

/// <summary>Global options page: settings binding, sections and value mapping.</summary>
public partial class MainWindow
{
    private void WireOptions()
    {
        var navButtons = OptionsNavButtons();
        for (var index = 0; index < navButtons.Length; index++)
        {
            var section = index;
            var button = navButtons[index];
            button.Click += (_, _) => SetOptionsSection(section);
            button.PointerEntered += (_, _) => SetOptionsNavIndicator(section);
            button.GotFocus += (_, _) => SetOptionsNavIndicator(section);
        }
        OptionsNavHost.PointerExited += (_, _) => SetOptionsNavIndicator(_optionsSectionIndex);
        SetOptionsSection(0);

        // The settings page edits _settings live, so a launch started while
        // it is open already uses the new values.
        LogLevelBox.SelectionChanged += (_, _) => _settings.LogLevel = SelectedLogLevel();
        TraceImportsBox.ValueChanged += (_, _) => _settings.ImportTraceLimit = (int)(TraceImportsBox.Value ?? 0);
        RenderResolutionBox.SelectionChanged += (_, _) =>
            _settings.RenderResolutionScale = RenderResolutionScaleAt(RenderResolutionBox.SelectedIndex);
        StrictToggle.IsCheckedChanged += (_, _) => _settings.StrictDynlibResolution = StrictToggle.IsChecked == true;
        LogToFileToggle.IsCheckedChanged += (_, _) => _settings.LogToFile = LogToFileToggle.IsChecked == true;
        OverrideLogFileToggle.IsCheckedChanged += (_, _) =>
            _settings.OverrideLogFile = OverrideLogFileToggle.IsChecked == true;
        TitleMusicToggle.IsCheckedChanged += (_, _) =>
        {
            _settings.PlayTitleMusic = TitleMusicToggle.IsChecked == true;
            OnTitleMusicSettingChanged();
        };
        DiscordToggle.IsCheckedChanged += (_, _) =>
        {
            _settings.DiscordRichPresence = DiscordToggle.IsChecked == true;
            UpdateDiscordPresence();
        };
        AutoUpdateToggle.IsCheckedChanged += (_, _) =>
            _settings.CheckForUpdatesOnStartup = AutoUpdateToggle.IsChecked == true;
        SelectLogFilePathButton.Click += async (_, _) => await SelectLogFilePathAsync();

        EnvBthidToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_BTHID_UNAVAILABLE", EnvBthidToggle.IsChecked == true);
        EnvLoopGuardToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD", EnvLoopGuardToggle.IsChecked == true);
        EnvWritableApp0Toggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_WRITABLE_APP0", EnvWritableApp0Toggle.IsChecked == true);
        EnvVkValidationToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_VK_VALIDATION", EnvVkValidationToggle.IsChecked == true);
        EnvDumpSpirvToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_DUMP_SPIRV", EnvDumpSpirvToggle.IsChecked == true);
        EnvLogDirectMemoryToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_DIRECT_MEMORY", EnvLogDirectMemoryToggle.IsChecked == true);
        EnvLogIoToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_IO", EnvLogIoToggle.IsChecked == true);
        EnvLogNpToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_NP", EnvLogNpToggle.IsChecked == true);

        LanguageBox.SelectionChanged += (_, _) => OnLanguageChanged();
    }

    /// <summary>
    /// Applies the options page strings. Environment descriptions and the
    /// log-level list are shared with the per-game overlay: both are built once
    /// here and written to both rows, so the two pages cannot drift apart.
    /// </summary>
    private void ApplyOptionsLocalization()
    {
        var loc = Localization.Instance;

        OptionsGeneralNavLabel.Text = SectionNavigationLabel(loc.Get("Options.General"));
        OptionsLoggingNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Logging"));
        OptionsLauncherNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Section.Launcher"));
        OptionsRenderingNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Graphics.Rendering"));
        OptionsEnvironmentNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Env.Tab"));
        OptionsAboutNavLabel.Text = SectionNavigationLabel(loc.Get("Options.About"));

        ApplyEnvironmentDescription(EnvBthidRow, GameEnvBthidRow, "Options.Env.Bthid.Desc");
        ApplyEnvironmentDescription(EnvLoopGuardRow, GameEnvLoopGuardRow, "Options.Env.LoopGuard.Desc");
        ApplyEnvironmentDescription(EnvWritableApp0Row, GameEnvWritableApp0Row, "Options.Env.WritableApp0.Desc");
        ApplyEnvironmentDescription(EnvVkValidationRow, GameEnvVkValidationRow, "Options.Env.VkValidation.Desc");
        ApplyEnvironmentDescription(EnvDumpSpirvRow, GameEnvDumpSpirvRow, "Options.Env.DumpSpirv.Desc");
        ApplyEnvironmentDescription(
            EnvLogDirectMemoryRow,
            GameEnvLogDirectMemoryRow,
            "Options.Env.LogDirectMemory.Desc");
        ApplyEnvironmentDescription(EnvLogIoRow, GameEnvLogIoRow, "Options.Env.LogIo.Desc");
        ApplyEnvironmentDescription(EnvLogNpRow, GameEnvLogNpRow, "Options.Env.LogNp.Desc");
        CpuEngineRow.Label = loc.Get("Options.CpuEngine.Label");
        CpuEngineRow.Description = loc.Get("Options.CpuEngine.Desc");
        CpuEngineBox.ItemsSource = new[] { loc.Get("Options.CpuEngine.Native") };
        CpuEngineBox.SelectedIndex = 0;

        StrictRow.Label = loc.Get("Options.Strict.Label");
        StrictRow.Description = loc.Get("Options.Strict.Desc");

        LogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        LogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        var globalLogLevel = _settings.LogLevel;
        var gameLogLevel = _gameSettingsViewModel?.SelectedLogLevel ?? globalLogLevel;
        var localizedLogLevels = new[]
        {
            loc.Get("Options.LogLevel.Trace"),
            loc.Get("Options.LogLevel.Debug"),
            loc.Get("Options.LogLevel.Info"),
            loc.Get("Options.LogLevel.Warning"),
            loc.Get("Options.LogLevel.Error"),
            loc.Get("Options.LogLevel.Critical"),
        };

        LogLevelBox.ItemsSource = localizedLogLevels;
        LogLevelBox.SelectedIndex = LogLevelIndex(globalLogLevel);

        var wasLoadingGameSettings = _isLoadingGameSettings;
        _isLoadingGameSettings = true;
        try
        {
            GameLogLevelBox.ItemsSource = localizedLogLevels;
            GameLogLevelBox.SelectedIndex = LogLevelIndex(gameLogLevel);
        }
        finally
        {
            _isLoadingGameSettings = wasLoadingGameSettings;
        }

        TraceImportsRow.Label = loc.Get("Options.TraceImports.Label");
        TraceImportsRow.Description = loc.Get("Options.TraceImports.Desc");

        LogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        LogToFileRow.Description = loc.Get("Options.LogToFile.Desc");

        LogFilePathRow.Label = loc.Get("Options.LogFilePath.Label");
        SelectLogFilePathButtonLabel.Text = loc.Get("Options.LogFilePath.Select");
        UpdateLogFilePathText();

        OverrideLogFileRow.Label = loc.Get("Options.OverrideLogFile.Label");
        OverrideLogFileRow.Description = loc.Get("Options.OverrideLogFile.Desc");

        LanguageRow.Label = loc.Get("Options.Language.Label");
        LanguageRow.Description = loc.Get("Options.Language.Desc");

        RenderResolutionRow.Label = loc.Get("Options.RenderResolution.Label");
        RenderResolutionRow.Description = loc.Get("Options.RenderResolution.Desc");
        var renderResolutionScale = _settings.RenderResolutionScale;
        RenderResolutionBox.ItemsSource = new[]
        {
            loc.Get("Options.RenderResolution.Native"),
            "75%",
            "50%",
            "25%",
        };
        RenderResolutionBox.SelectedIndex = RenderResolutionIndex(renderResolutionScale);

        TitleMusicRow.Label = loc.Get("Options.TitleMusic.Label");
        TitleMusicRow.Description = loc.Get("Options.TitleMusic.Desc");

        DiscordRow.Label = loc.Get("Options.Discord.Label");
        DiscordRow.Description = loc.Get("Options.Discord.Desc");
        AutoUpdateRow.Label = loc.Get("Updater.Auto.Label");
        AutoUpdateRow.Description = loc.Get("Updater.Auto.Desc");
    }

    // ---- Settings ----

    private void ApplySettingsToControls()
    {
        LogLevelBox.SelectedIndex = _settings.LogLevel.ToLowerInvariant() switch
        {
            "trace" => 0,
            "debug" => 1,
            "info" => 2,
            "warning" or "warn" => 3,
            "error" => 4,
            "critical" or "fatal" => 5,
            _ => 2,
        };
        TraceImportsBox.Value = Math.Clamp(_settings.ImportTraceLimit, 0, 4096);
        RenderResolutionBox.SelectedIndex = RenderResolutionIndex(_settings.RenderResolutionScale);
        StrictToggle.IsChecked = _settings.StrictDynlibResolution;
        LogToFileToggle.IsChecked = _settings.LogToFile;
        OverrideLogFileToggle.IsChecked = _settings.OverrideLogFile;
        TitleMusicToggle.IsChecked = _settings.PlayTitleMusic;
        DiscordToggle.IsChecked = _settings.DiscordRichPresence;
        AutoUpdateToggle.IsChecked = _settings.CheckForUpdatesOnStartup;
        EnvBthidToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_BTHID_UNAVAILABLE");
        EnvLoopGuardToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD");
        EnvWritableApp0Toggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_WRITABLE_APP0");
        EnvVkValidationToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_VK_VALIDATION");
        EnvDumpSpirvToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_DUMP_SPIRV");
        EnvLogDirectMemoryToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_DIRECT_MEMORY");
        EnvLogIoToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_IO");
        EnvLogNpToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_NP");
        UpdateLogFilePathText();
    }

    private void SetEnvironmentToggle(string name, bool enabled)
    {
        if (enabled)
        {
            if (!_settings.EnvironmentToggles.Contains(name))
            {
                _settings.EnvironmentToggles.Add(name);
            }
        }
        else
        {
            _settings.EnvironmentToggles.Remove(name);
        }
    }

    private string SelectedLogLevel()
    {
        return LogLevelAt(LogLevelBox.SelectedIndex);
    }

    private static string LogLevelAt(int index)
    {
        return index switch
        {
            0 => "Trace",
            1 => "Debug",
            2 => "Info",
            3 => "Warning",
            4 => "Error",
            5 => "Critical",
            _ => "Info",
        };
    }

    private static int LogLevelIndex(string? logLevel)
    {
        return logLevel?.ToLowerInvariant() switch
        {
            "trace" => 0,
            "debug" => 1,
            "warning" or "warn" => 3,
            "error" => 4,
            "critical" or "fatal" => 5,
            _ => 2,
        };
    }

    private static int RenderResolutionIndex(double scale)
    {
        return scale switch
        {
            >= 0.875 => 0,
            >= 0.625 => 1,
            >= 0.375 => 2,
            _ => 3,
        };
    }

    private static double RenderResolutionScaleAt(int index)
    {
        return index switch
        {
            1 => 0.75,
            2 => 0.5,
            3 => 0.25,
            _ => 1.0,
        };
    }

    private void UpdateLogFilePathText()
    {
        LogFilePathRow.Description = string.IsNullOrWhiteSpace(_settings.LogFilePath)
            ? Localization.Instance.Get("Options.LogFilePath.Default")
            : _settings.LogFilePath;
    }

    private async Task SelectLogFilePathAsync()
    {
        var loc = Localization.Instance;
        SaveFilePickerResult result = await StorageProvider.SaveFilePickerWithResultAsync(new FilePickerSaveOptions
        {
            Title = loc.Get("Dialog.SaveLogFile"),
            SuggestedFileName = "SharpEmuLog",
            DefaultExtension = "log",
            FileTypeChoices =
                [
                    new FilePickerFileType(loc.Get("Dialog.PlainTextFiles")) { Patterns = ["*.txt"] },
                    new FilePickerFileType(loc.Get("Dialog.LogFiles")) { Patterns = ["*.log"] }
                ]
        });

        if (result.File is not null)
        {
            _settings.LogFilePath = result.File.Path.LocalPath;
            UpdateLogFilePathText();
        }
    }

    private Button[] OptionsNavButtons() =>
    [
        OptionsGeneralNav,
        OptionsLoggingNav,
        OptionsLauncherNav,
        OptionsRenderingNav,
        OptionsEnvironmentNav,
        OptionsAboutNav,
    ];

    private Control[] OptionsSectionPanels() =>
    [
        OptionsGeneralPanel,
        OptionsLoggingPanel,
        OptionsLauncherPanel,
        OptionsRenderingPanel,
        OptionsEnvironmentPanel,
        OptionsAboutPanel,
    ];

    private void SetOptionsSection(int section, bool focusNavigation = false)
    {
        var buttons = OptionsNavButtons();
        var panels = OptionsSectionPanels();
        section = Math.Clamp(section, 0, buttons.Length - 1);
        _optionsSectionIndex = section;
        SetOptionsNavIndicator(section);

        for (var index = 0; index < buttons.Length; index++)
        {
            var active = index == section;
            SetStateClass(buttons[index], "active", active);
            SetStateClass(panels[index], "active", active);
            SetPanelInteraction(panels[index], active);
        }

        if (focusNavigation)
        {
            buttons[section].BringIntoView();
            buttons[section].Focus(NavigationMethod.Directional);
        }
    }

    private static void SetPanelInteraction(Control panel, bool isActive)
    {
        // Keep the visual tree enabled while it fades. IsEnabled propagates to
        // every descendant and activates Fluent's :disabled colors before the
        // transition has finished, which appears as a one-frame color flash.
        panel.IsHitTestVisible = isActive;
        KeyboardNavigation.SetTabNavigation(
            panel,
            isActive ? KeyboardNavigationMode.Continue : KeyboardNavigationMode.None);
    }

    private void SetOptionsNavIndicator(int section)
    {
        if (OptionsNavIndicator.RenderTransform is TranslateTransform transform)
        {
            var buttons = OptionsNavButtons();
            var index = Math.Clamp(section, 0, buttons.Length - 1);
            var button = buttons[index];

            // The navigation rows are contiguous hit targets. The 7 px visual
            // gap lives inside each 61 px row, so pointer traversal never
            // enters an ownerless area. Resolve the indicator position from
            // the arranged button instead of duplicating the row pitch here.
            transform.Y = button.TranslatePoint(default, OptionsNavHost)?.Y
                ?? index * button.Bounds.Height;
        }
    }

    private Control[] ActiveOptionsControls() => _optionsSectionIndex switch
    {
        0 => [CpuEngineBox, StrictToggle],
        1 => [LogLevelBox, TraceImportsBox, LogToFileToggle, SelectLogFilePathButton, OverrideLogFileToggle],
        2 => [LanguageBox, TitleMusicToggle, DiscordToggle, AutoUpdateToggle],
        3 => [RenderResolutionBox],
        4 =>
        [
            EnvBthidToggle,
            EnvLoopGuardToggle,
            EnvWritableApp0Toggle,
            EnvVkValidationToggle,
            EnvDumpSpirvToggle,
            EnvLogDirectMemoryToggle,
            EnvLogIoToggle,
            EnvLogNpToggle,
        ],
        5 => [UpdateButton, LatestCommitButton, GithubButton, DiscordButton],
        _ => [],
    };

    private static void SetStateClass(StyledElement element, string className, bool active)
    {
        if (active)
        {
            if (!element.Classes.Contains(className))
            {
                element.Classes.Add(className);
            }
        }
        else
        {
            element.Classes.Remove(className);
        }
    }
}
