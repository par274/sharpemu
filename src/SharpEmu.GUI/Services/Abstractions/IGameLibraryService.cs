// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Scans the filesystem for installed games and reads the metadata Sony ships
/// beside each eboot (sce_sys/param.json, icon0.png, pic0.png). Extracted from
/// the MainWindow god-class so the library scan is testable and UI-free.
/// </summary>
public interface IGameLibraryService
{
    /// <summary>
    /// Recursively finds every eboot.bin under the given folders, skipping
    /// duplicates and explicitly excluded paths, and reads each game's metadata.
    /// Returns games sorted by display name.
    /// </summary>
    IReadOnlyList<GameEntry> ScanFolders(IReadOnlyList<string> folders, IReadOnlySet<string> excludedPaths);

    /// <summary>Decodes cover art for a game off the UI thread.</summary>
    /// <returns>A pinned-size bitmap, or null if the cover is missing or unreadable.</returns>
    Avalonia.Media.Imaging.Bitmap? LoadCover(string? coverPath);

    /// <summary>Totals the size of the directory holding the eboot.</summary>
    long ComputeInstallSize(string ebootPath);

    /// <summary>
    /// Watches the given folders for changes that could alter the library — a
    /// game being added, removed or having its metadata rewritten. The raise is
    /// debounced, so a burst of filesystem events surfaces as a single
    /// <see cref="LibraryChanged"/>. Call again whenever the watched set changes.
    /// </summary>
    void Watch(IReadOnlyList<string> folders);

    /// <summary>
    /// Raised (on a background thread) when the watcher detects a library-affecting
    /// change. Subscribers must marshal to the UI thread themselves.
    /// </summary>
    event EventHandler? LibraryChanged;
}
