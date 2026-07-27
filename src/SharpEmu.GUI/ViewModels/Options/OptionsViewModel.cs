// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using System.Globalization;
using System.Reactive.Linq;
using Avalonia.Controls;
using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Backs the Options page. Each toggle/selector is a reactive property that
/// writes through to <see cref="ISettingsService"/> and persists automatically.
/// Previously the MainWindow hand-wired ~20 IsCheckedChanged handlers; this
/// view-model replaces that with data bindings plus a single save subscription.
/// </summary>
public partial class OptionsViewModel : ReactiveObject
{
    private readonly ISettingsService _settings;

    public OptionsViewModel(ISettingsService settings)
    {
        _settings = settings;
        var s = settings.Settings;

        // Seed reactive state from the persisted settings.
        _logLevel = MapLogLevelToIndex(s.LogLevel);
        _importTraceLimit = Math.Clamp(s.ImportTraceLimit, 0, 4096);
        _renderResolutionIndex = MapRenderScaleToIndex(s.RenderResolutionScale);
        _strictDynlibResolution = s.StrictDynlibResolution;
        _logToFile = s.LogToFile;
        _overrideLogFile = s.OverrideLogFile;
        _playTitleMusic = s.PlayTitleMusic;
        _discordRichPresence = s.DiscordRichPresence;
        _checkForUpdatesOnStartup = s.CheckForUpdatesOnStartup;
        _envBthid = s.EnvironmentToggles.Contains("SHARPEMU_BTHID_UNAVAILABLE");
        _envLoopGuard = s.EnvironmentToggles.Contains("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD");
        _envWritableApp0 = s.EnvironmentToggles.Contains("SHARPEMU_WRITABLE_APP0");
        _envVkValidation = s.EnvironmentToggles.Contains("SHARPEMU_VK_VALIDATION");
        _envDumpSpirv = s.EnvironmentToggles.Contains("SHARPEMU_DUMP_SPIRV");
        _envLogDirectMemory = s.EnvironmentToggles.Contains("SHARPEMU_LOG_DIRECT_MEMORY");
        _envLogIo = s.EnvironmentToggles.Contains("SHARPEMU_LOG_IO");
        _envLogNp = s.EnvironmentToggles.Contains("SHARPEMU_LOG_NP");
        _logFilePath = s.LogFilePath ?? string.Empty;

        // Persist on change. Debounced so a render-scale spin or fast toggling
        // does not hit disk per tick. Each watched property feeds a single
        // merged stream to avoid the multi-parameter WhenAnyValue overload
        // limits.
        IObservable<bool> Watch(params System.Linq.Expressions.Expression<Func<OptionsViewModel, object?>>[] selectors)
            => selectors.Select(s => this.WhenAnyValue(s).Select(_ => true)).Merge();

        Watch(
            x => x.LogLevel, x => x.ImportTraceLimit, x => x.RenderResolutionIndex,
            x => x.StrictDynlibResolution, x => x.LogToFile, x => x.OverrideLogFile,
            x => x.PlayTitleMusic, x => x.DiscordRichPresence, x => x.CheckForUpdatesOnStartup,
            x => x.EnvBthid, x => x.EnvLoopGuard, x => x.EnvWritableApp0,
            x => x.EnvVkValidation, x => x.EnvDumpSpirv, x => x.EnvLogDirectMemory,
            x => x.EnvLogIo, x => x.EnvLogNp, x => x.LogFilePath)
            .Throttle(TimeSpan.FromMilliseconds(250))
            .Subscribe(_ => Persist());
    }

    // --- Emulation ---
    [Reactive] private int _logLevel;
    [Reactive] private int _importTraceLimit;
    [Reactive] private int _renderResolutionIndex;
    [Reactive] private bool _strictDynlibResolution;

    // --- Logging ---
    [Reactive] private bool _logToFile;
    [Reactive] private bool _overrideLogFile;
    [Reactive] private string _logFilePath;

    // --- Launcher ---
    [Reactive] private bool _playTitleMusic;
    [Reactive] private bool _discordRichPresence;
    [Reactive] private bool _checkForUpdatesOnStartup;

    // --- Environment toggles ---
    [Reactive] private bool _envBthid;
    [Reactive] private bool _envLoopGuard;
    [Reactive] private bool _envWritableApp0;
    [Reactive] private bool _envVkValidation;
    [Reactive] private bool _envDumpSpirv;
    [Reactive] private bool _envLogDirectMemory;
    [Reactive] private bool _envLogIo;
    [Reactive] private bool _envLogNp;

    /// <summary>Writes the current reactive state back into settings and saves.</summary>
    public void Persist()
    {
        var s = _settings.Settings;
        s.LogLevel = MapIndexToLogLevel(LogLevel);
        s.ImportTraceLimit = ImportTraceLimit;
        s.StrictDynlibResolution = StrictDynlibResolution;
        s.LogToFile = LogToFile;
        s.OverrideLogFile = OverrideLogFile;
        s.PlayTitleMusic = PlayTitleMusic;
        s.DiscordRichPresence = DiscordRichPresence;
        s.CheckForUpdatesOnStartup = CheckForUpdatesOnStartup;
        _settings.SetEnvironmentToggle("SHARPEMU_BTHID_UNAVAILABLE", EnvBthid);
        _settings.SetEnvironmentToggle("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD", EnvLoopGuard);
        _settings.SetEnvironmentToggle("SHARPEMU_WRITABLE_APP0", EnvWritableApp0);
        _settings.SetEnvironmentToggle("SHARPEMU_VK_VALIDATION", EnvVkValidation);
        _settings.SetEnvironmentToggle("SHARPEMU_DUMP_SPIRV", EnvDumpSpirv);
        _settings.SetEnvironmentToggle("SHARPEMU_LOG_DIRECT_MEMORY", EnvLogDirectMemory);
        _settings.SetEnvironmentToggle("SHARPEMU_LOG_IO", EnvLogIo);
        _settings.SetEnvironmentToggle("SHARPEMU_LOG_NP", EnvLogNp);
        _settings.Save();
    }

    /// <summary>Applies a render-resolution scale parsed from a ComboBox item's Tag.</summary>
    public void ApplyRenderResolutionScale(double scale)
    {
        RenderResolutionIndex = MapRenderScaleToIndex(scale);
        // Persist takes RenderResolutionIndex; but the DTO stores the raw scale.
        _settings.Settings.RenderResolutionScale = scale;
        _settings.Save();
    }

    private static int MapLogLevelToIndex(string level)
        => level.ToLowerInvariant() switch
        {
            "trace" => 0,
            "debug" => 1,
            "info" => 2,
            "warning" or "warn" => 3,
            "error" => 4,
            "critical" or "fatal" => 5,
            _ => 2,
        };

    private static string MapIndexToLogLevel(int index)
        => index switch
        {
            0 => "Trace",
            1 => "Debug",
            2 => "Info",
            3 => "Warning",
            4 => "Error",
            5 => "Critical",
            _ => "Info",
        };

    private static int MapRenderScaleToIndex(double scale)
        => scale switch
        {
            >= 0.875 => 0,
            >= 0.625 => 1,
            >= 0.375 => 2,
            _ => 3,
        };
}
