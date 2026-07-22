// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Owns the launcher's persistent settings. Wraps the <see cref="GuiSettings"/>
/// DTO so ViewModels and the window resolve a single shared instance instead
/// of each holding their own copy. Persists to gui-settings.json next to the
/// executable.
/// </summary>
public interface ISettingsService
{
    /// <summary>The live settings object; mutate in place then call <see cref="Save"/>.</summary>
    GuiSettings Settings { get; }

    /// <summary>Reloads settings from disk, replacing <see cref="Settings"/>.</summary>
    void Load();

    /// <summary>Persists the current <see cref="Settings"/> to disk.</summary>
    void Save();

    /// <summary>
    /// Toggles a named environment-variable flag in settings. The actual
    /// environment is mutated at launch time from this list.
    /// </summary>
    void SetEnvironmentToggle(string name, bool enabled);
}
