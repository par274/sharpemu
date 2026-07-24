// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using System.Text.Json;
using Avalonia.Media.Imaging;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Filesystem-backed game library. The scan and metadata-parsing logic lived as
/// private statics inside <c>MainWindow</c>; moved here unchanged so it can run
/// on a background thread without any dependency on UI controls.
/// </summary>
internal sealed class GameLibraryService : IGameLibraryService, IDisposable
{
    // OS-aware path comparison shared with the window's own settings lookups.
    internal static StringComparer PathComparer => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    internal static StringComparison PathComparison => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private const int CoverDecodeWidth = 312;

    private readonly List<FileSystemWatcher> _watchers = new();
    private Timer? _debounce;
    private readonly object _watchLock = new();
    private bool _disposed;

    /// <inheritdoc />
    public event EventHandler? LibraryChanged;

    /// <inheritdoc />
    public void Watch(IReadOnlyList<string> folders)
    {
        lock (_watchLock)
        {
            if (_disposed)
            {
                return;
            }

            foreach (var watcher in _watchers)
            {
                watcher.Dispose();
            }
            _watchers.Clear();

            foreach (var folder in folders)
            {
                if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                {
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName
                                       | NotifyFilters.DirectoryName
                                       | NotifyFilters.Size
                                       | NotifyFilters.LastWrite,
                        EnableRaisingEvents = true,
                    };
                    watcher.Created += OnWatcherEvent;
                    watcher.Deleted += OnWatcherEvent;
                    watcher.Changed += OnWatcherEvent;
                    watcher.Renamed += OnWatcherEvent;
                    watcher.Error += OnWatcherError;
                    _watchers.Add(watcher);
                }
                catch (Exception)
                {
                }
            }
        }
    }

    private void OnWatcherEvent(object? sender, FileSystemEventArgs e)
    {
        // Any change could matter; the debounce collapses the noise. A cheap name
        // filter avoids raising for unrelated files, but metadata lives next to the
        // eboot in sce_sys, so keep the filter permissive.
        ScheduleDebouncedChange();
    }

    private void OnWatcherError(object? sender, ErrorEventArgs e)
    {
        // Watchers can drop (e.g. a watched folder is renamed/removed). Surface it
        // so the UI re-scans rather than going stale; the next Watch() call rebuilds.
        ScheduleDebouncedChange();
    }

    private void ScheduleDebouncedChange()
    {
        lock (_watchLock)
        {
            if (_disposed)
            {
                return;
            }

            // (Re)start a one-shot timer: only after filesystem activity settles for
            // the full interval do we raise, collapsing bursts into one rescan.
            if (_debounce is null)
            {
                _debounce = new Timer(_ => RaiseLibraryChanged(), null, LibraryChangedDebounceMs, Timeout.Infinite);
            }
            else
            {
                _debounce.Change(LibraryChangedDebounceMs, Timeout.Infinite);
            }
        }
    }

    private void RaiseLibraryChanged()
    {
        // Raised on a threadpool thread; subscribers marshal to the UI thread.
        LibraryChanged?.Invoke(this, EventArgs.Empty);
    }

    private const int LibraryChangedDebounceMs = 600;

    public IReadOnlyList<GameEntry> ScanFolders(IReadOnlyList<string> folders, IReadOnlySet<string> excludedPaths)
    {
        var games = new List<GameEntry>();
        var seen = new HashSet<string>(PathComparer);
        var enumeration = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            MaxRecursionDepth = 8,
        };

        foreach (var folder in folders)
        {
            if (!Directory.Exists(folder))
            {
                continue;
            }

            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "eboot.bin", enumeration))
                {
                    var fullPath = Path.GetFullPath(file);
                    if (!seen.Add(fullPath) || excludedPaths.Contains(fullPath))
                    {
                        continue;
                    }

                    long size = 0;
                    try
                    {
                        size = new FileInfo(fullPath).Length;
                    }
                    catch (IOException)
                    {
                    }

                    var (title, titleId, version) = TryReadParamJson(fullPath);
                    games.Add(new GameEntry(
                        title ?? GameNameFor(fullPath), titleId, version, fullPath, size,
                        FindCoverFor(fullPath), FindBackgroundFor(fullPath)));
                }
            }
            catch (Exception)
            {
                // Skip folders that fail to enumerate.
            }
        }

        games.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return games;
    }

    public Bitmap? LoadCover(string? coverPath)
    {
        if (coverPath is null)
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(coverPath);
            return Bitmap.DecodeToWidth(stream, CoverDecodeWidth);
        }
        catch (Exception)
        {
            // A missing or undecodable image keeps the placeholder.
            return null;
        }
    }

    public long ComputeInstallSize(string ebootPath)
    {
        var directory = Path.GetDirectoryName(ebootPath);
        if (directory is null)
        {
            return 0;
        }

        long total = 0;
        try
        {
            var enumeration = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
            };
            foreach (var file in new DirectoryInfo(directory).EnumerateFiles("*", enumeration))
            {
                total += file.Length;
            }
        }
        catch (Exception)
        {
            // Fall back to whatever was accumulated so far.
        }

        return total;
    }

    /// <summary>
    /// Reads the game title, title id and content version from
    /// sce_sys/param.json next to the executable, when present.
    /// </summary>
    private static (string? Title, string? TitleId, string? Version) TryReadParamJson(string ebootPath)
    {
        try
        {
            var directory = Path.GetDirectoryName(ebootPath);
            if (directory is null)
            {
                return (null, null, null);
            }

            var paramPath = Path.Combine(directory, "sce_sys", "param.json");
            if (!File.Exists(paramPath))
            {
                return (null, null, null);
            }

            // ReadAllText handles a UTF-8 BOM, which JsonDocument rejects in
            // raw bytes.
            using var document = JsonDocument.Parse(File.ReadAllText(paramPath));
            var root = document.RootElement;

            string? titleId = null;
            if (root.TryGetProperty("titleId", out var idElement) && idElement.ValueKind == JsonValueKind.String)
            {
                titleId = idElement.GetString();
            }

            // contentVersion carries the installed app version
            // ("01.000.000"); masterVersion is the fallback on older dumps.
            string? version = null;
            if (root.TryGetProperty("contentVersion", out var versionElement) &&
                versionElement.ValueKind == JsonValueKind.String)
            {
                version = versionElement.GetString();
            }
            else if (root.TryGetProperty("masterVersion", out var masterElement) &&
                     masterElement.ValueKind == JsonValueKind.String)
            {
                version = masterElement.GetString();
            }

            string? title = null;
            if (root.TryGetProperty("localizedParameters", out var localized) &&
                localized.ValueKind == JsonValueKind.Object)
            {
                if (localized.TryGetProperty("defaultLanguage", out var language) &&
                    language.ValueKind == JsonValueKind.String &&
                    localized.TryGetProperty(language.GetString()!, out var defaultBlock) &&
                    defaultBlock.ValueKind == JsonValueKind.Object &&
                    defaultBlock.TryGetProperty("titleName", out var titleName) &&
                    titleName.ValueKind == JsonValueKind.String)
                {
                    title = titleName.GetString();
                }
                else
                {
                    foreach (var property in localized.EnumerateObject())
                    {
                        if (property.Value.ValueKind == JsonValueKind.Object &&
                            property.Value.TryGetProperty("titleName", out var anyTitleName) &&
                            anyTitleName.ValueKind == JsonValueKind.String)
                        {
                            title = anyTitleName.GetString();
                            break;
                        }
                    }
                }
            }

            return (
                string.IsNullOrWhiteSpace(title) ? null : title,
                string.IsNullOrWhiteSpace(titleId) ? null : titleId,
                string.IsNullOrWhiteSpace(version) ? null : version.Trim());
        }
        catch (Exception)
        {
            return (null, null, null);
        }
    }

    /// <summary>
    /// Finds the cover art shipped with the game: sce_sys/icon0.png next to
    /// the executable (falling back to pic0.png).
    /// </summary>
    private static string? FindCoverFor(string ebootPath)
    {
        var directory = Path.GetDirectoryName(ebootPath);
        if (directory is null)
        {
            return null;
        }

        var sceSys = Path.Combine(directory, "sce_sys");
        foreach (var candidate in new[] { "icon0.png", "pic0.png" })
        {
            var coverPath = Path.Combine(sceSys, candidate);
            if (File.Exists(coverPath))
            {
                return coverPath;
            }
        }

        return null;
    }

    /// <summary>
    /// Finds the key art shipped with the game (sce_sys/pic0.png, falling
    /// back to pic1.png), used as the window backdrop when selected.
    /// </summary>
    private static string? FindBackgroundFor(string ebootPath)
    {
        var directory = Path.GetDirectoryName(ebootPath);
        if (directory is null)
        {
            return null;
        }

        var sceSys = Path.Combine(directory, "sce_sys");
        foreach (var candidate in new[] { "pic0.png", "pic1.png" })
        {
            var backgroundPath = Path.Combine(sceSys, candidate);
            if (File.Exists(backgroundPath))
            {
                return backgroundPath;
            }
        }

        return null;
    }

    private static string GameNameFor(string ebootPath)
    {
        var directory = Path.GetDirectoryName(ebootPath);
        var name = directory is not null ? Path.GetFileName(directory) : null;
        return string.IsNullOrEmpty(name) ? Path.GetFileName(ebootPath) : name;
    }

    /// <summary>
    /// Stops watching and releases the watchers. The service is a DI singleton,
    /// so this runs once at application shutdown; safe to call even if
    /// <see cref="Watch"/> was never invoked.
    /// </summary>
    public void Dispose()
    {
        lock (_watchLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _debounce?.Dispose();
            _debounce = null;
            foreach (var watcher in _watchers)
            {
                watcher.Dispose();
            }
            _watchers.Clear();
        }
    }
}
