// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Thin adapter over the <see cref="Localization"/> singleton. The singleton
/// stays the single source of truth (embedded resources, loose overrides);
/// this just makes it injectable for ViewModels and tests.
/// </summary>
internal sealed class LocalizationService : ILocalizationService
{
    public string CurrentCode => Localization.Instance.CurrentCode;

    public int Revision => Localization.Instance.Revision;

    public Localization Source => Localization.Instance;

    public IReadOnlyList<Localization.LanguageInfo> DiscoverLanguages()
        => Localization.Instance.DiscoverLanguages();

    public void Load(string code) => Localization.Instance.Load(code);

    public string Get(string key) => Localization.Instance.Get(key);

    public string Format(string key, params object?[] args)
        => Localization.Instance.Format(key, args);
}
