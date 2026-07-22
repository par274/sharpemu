// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Single source of truth for <see cref="GuiSettings"/>. Previously the
/// MainWindow owned the DTO and saved it ad-hoc from a dozen click handlers;
/// the save cadence is unchanged (callers call <see cref="Save"/> when a
/// setting changes), but there is now one shared instance behind a service.
/// </summary>
internal sealed class SettingsService : ISettingsService
{
    public GuiSettings Settings { get; private set; } = GuiSettings.Load();

    public void Load() => Settings = GuiSettings.Load();

    public void Save() => Settings.Save();

    public void SetEnvironmentToggle(string name, bool enabled)
    {
        if (enabled)
        {
            if (!Settings.EnvironmentToggles.Contains(name))
            {
                Settings.EnvironmentToggles.Add(name);
            }
        }
        else
        {
            Settings.EnvironmentToggles.Remove(name);
        }
    }
}
