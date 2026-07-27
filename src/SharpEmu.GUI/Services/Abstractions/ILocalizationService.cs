// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Loads and resolves localized UI strings. Abstraction over the
/// <see cref="Localization"/> singleton so ViewModels can be fed a string
/// provider without depending on a static.
/// </summary>
public interface ILocalizationService
{
    /// <summary>The language code currently active (e.g. "en").</summary>
    string CurrentCode { get; }

    /// <summary>A token that changes whenever the active language changes.</summary>
    int Revision { get; }

    /// <summary>The underlying singleton, for indexer-style XAML bindings.</summary>
    Localization Source { get; }

    /// <summary>Languages discoverable as embedded or loose overrides.</summary>
    IReadOnlyList<Localization.LanguageInfo> DiscoverLanguages();

    /// <summary>Loads a language by code.</summary>
    void Load(string code);

    /// <summary>Resolves a key to its localized value, falling back to the key.</summary>
    string Get(string key);

    /// <summary>Resolves and formats a key.</summary>
    string Format(string key, params object?[] args);
}
