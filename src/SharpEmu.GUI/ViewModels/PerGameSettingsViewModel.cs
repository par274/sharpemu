// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using ReactiveUI;
using ReactiveUI.SourceGenerators;

/// <summary>
/// Backs the per-game settings dialog. Each setting carries an "override"
/// flag (whether it diverges from the global defaults); only overridden values
/// are persisted. Previously the dialog window edited controls and wrote to
/// PerGameSettings.Save inline; this view-model owns the editable state so the
/// window can be reduced to pure binding.
/// </summary>
public partial class PerGameSettingsViewModel : ReactiveObject
{
    private readonly string _titleId;

    public static IReadOnlyList<string> LogLevels { get; } =
        new[] { "Trace", "Debug", "Info", "Warning", "Error", "Critical" };

    public static IReadOnlyList<string> EnvironmentToggleNames { get; } =
    [
        "SHARPEMU_BTHID_UNAVAILABLE",
        "SHARPEMU_DISABLE_IMPORT_LOOP_GUARD",
        "SHARPEMU_WRITABLE_APP0",
        "SHARPEMU_VK_VALIDATION",
        "SHARPEMU_DUMP_SPIRV",
        "SHARPEMU_LOG_DIRECT_MEMORY",
        "SHARPEMU_LOG_IO",
        "SHARPEMU_LOG_NP",
    ];

    public PerGameSettingsViewModel(string titleId, string displayName, GuiSettings global)
    {
        _titleId = titleId;
        Title = Localization.Instance.Format("PerGame.Title", displayName, titleId);

        // Seed from global defaults.
        SelectedLogLevel = Array.IndexOf(LogLevels.ToArray(), global.LogLevel) >= 0 ? global.LogLevel : "Info";
        ImportTraceLimit = global.ImportTraceLimit;
        IsStrictDynlibResolution = global.StrictDynlibResolution;
        IsLogToFile = global.LogToFile;
        foreach (var name in EnvironmentToggleNames)
        {
            _environmentStates[name] = global.EnvironmentToggles.Contains(name);
        }

        // Apply per-game overrides on top, marking which fields are overridden.
        var existing = PerGameSettings.Load(titleId);
        if (existing is not null)
        {
            if (existing.LogLevel is { } level && Array.IndexOf(LogLevels.ToArray(), level) >= 0)
            {
                IsLogLevelOverridden = true;
                SelectedLogLevel = level;
            }

            if (existing.ImportTraceLimit is { } t) { IsImportTraceOverridden = true; ImportTraceLimit = t; }
            if (existing.StrictDynlibResolution is { } s) { IsStrictOverridden = true; IsStrictDynlibResolution = s; }
            if (existing.LogToFile is { } l) { IsLogToFileOverridden = true; IsLogToFile = l; }
            if (existing.EnvironmentToggles is { } env)
            {
                IsEnvironmentOverridden = true;
                foreach (var name in EnvironmentToggleNames)
                {
                    _environmentStates[name] = env.Contains(name);
                }
            }
        }
    }

    public string Title { get; }

    [Reactive] private string _selectedLogLevel = "Info";
    [Reactive] private bool _isLogLevelOverridden;
    [Reactive] private int _importTraceLimit;
    [Reactive] private bool _isImportTraceOverridden;
    [Reactive] private bool _isStrictDynlibResolution;
    [Reactive] private bool _isStrictOverridden;
    [Reactive] private bool _isLogToFile;
    [Reactive] private bool _isLogToFileOverridden;
    [Reactive] private bool _isEnvironmentOverridden;

    private readonly Dictionary<string, bool> _environmentStates = new();

    /// <summary>Reads a per-toggle on/off state.</summary>
    public bool GetEnvironment(string name) =>
        _environmentStates.TryGetValue(name, out var v) && v;

    /// <summary>Sets a per-toggle on/off state.</summary>
    public void SetEnvironment(string name, bool value) => _environmentStates[name] = value;

    /// <summary>Persists the overridden fields to the per-title config file.</summary>
    public void Save()
    {
        var settings = new PerGameSettings
        {
            LogLevel = IsLogLevelOverridden ? SelectedLogLevel : null,
            ImportTraceLimit = IsImportTraceOverridden ? ImportTraceLimit : null,
            StrictDynlibResolution = IsStrictOverridden ? IsStrictDynlibResolution : null,
            LogToFile = IsLogToFileOverridden ? IsLogToFile : null,
            EnvironmentToggles = IsEnvironmentOverridden
                ? EnvironmentToggleNames.Where(GetEnvironment).ToList()
                : null,
        };
        settings.Save(_titleId);
    }
}
