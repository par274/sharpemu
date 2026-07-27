// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using System.Collections.ObjectModel;
using System.Reactive.Linq;
using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Backs the game library page: the full collection of scanned games, the
/// search filter, and the currently selected tile. The scan itself runs in
/// <see cref="IGameLibraryService"/>; this view-model owns the observable
/// state that the ListBox, search box and launch bar bind to.
/// </summary>
public partial class LibraryViewModel : ReactiveObject
{
    private readonly IGameLibraryService _library;
    private readonly SemaphoreSlim _detailLoadGate = new(2);
    private readonly HashSet<GameEntry> _enrichmentInFlight = new();

    /// <summary>All scanned games, before the search filter is applied.</summary>
    private readonly List<GameEntry> _allGames = new();

    public LibraryViewModel(IGameLibraryService library)
    {
        _library = library;

        // Re-apply the search filter whenever the query changes. Throttle so
        // fast typing does not reconcile the filtered list per keystroke.
        this.WhenAnyValue(x => x.SearchText)
            .Throttle(TimeSpan.FromMilliseconds(120))
            .Subscribe(_ => Avalonia.Threading.Dispatcher.UIThread.Post(RefreshVisibleGames));
    }

    /// <summary>
    /// Carousel items matching the current search: real games followed by the
    /// trailing <see cref="AddFolderTile"/> action card. The action tile is
    /// always appended last so the launcher keeps a single, consistent entry
    /// point for adding a folder even when the library is empty.
    /// </summary>
    public ObservableCollection<LibraryTile> Games { get; } = new();

    /// <summary>
    /// Raised once after a logical visible-list update. The window uses this
    /// consolidated notification instead of reacting to each diff operation.
    /// </summary>
    public event EventHandler? VisibleGamesChanged;

    [Reactive]
    private string _searchText = string.Empty;

    [Reactive]
    private GameEntry? _selectedGame;

    [Reactive]
    private bool _isEmpty;

    /// <summary>
    /// Reconciles the in-memory library with a background scan while preserving
    /// existing card instances, then enriches only new or changed entries.
    /// </summary>
    public void ApplyScannedGames(IReadOnlyList<GameEntry> games)
    {
        var existingByPath = _allGames.ToDictionary(
            game => game.Path,
            GameLibraryService.PathComparer);
        var merged = new List<GameEntry>(games.Count);
        var added = new List<GameEntry>();
        var toEnrich = new List<GameEntry>();
        foreach (var scanned in games)
        {
            if (existingByPath.TryGetValue(scanned.Path, out var existing))
            {
                if (existing.UpdateFrom(scanned) || existing.IsLoading)
                {
                    toEnrich.Add(existing);
                }

                merged.Add(existing);
            }
            else
            {
                merged.Add(scanned);
                added.Add(scanned);
                toEnrich.Add(scanned);
            }
        }

        _allGames.Clear();
        _allGames.AddRange(merged);
        RefreshVisibleGames();
        foreach (var game in added)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(
                () => game.IsCardVisible = true,
                Avalonia.Threading.DispatcherPriority.Render);
        }

        EnrichDetailsInBackground(toEnrich);
    }

    /// <summary>The raw list of scanned games (pre-filter); used by the window for remove/exclude.</summary>
    public IReadOnlyList<GameEntry> AllGames => _allGames;

    /// <summary>
    /// Drops a game from the in-memory list (the caller persists it to the
    /// excluded set in settings) and re-applies the filter.
    /// </summary>
    public void Remove(GameEntry game)
    {
        _allGames.RemoveAll(g => string.Equals(g.Path, game.Path, GameLibraryService.PathComparison));
        if (ReferenceEquals(SelectedGame, game))
        {
            SelectedGame = null;
        }

        RefreshVisibleGames();
    }

    /// <summary>Re-applies the search filter against <see cref="AllGames"/>.</summary>
    public void RefreshVisibleGames()
    {
        var query = (SearchText ?? string.Empty).Trim();
        var selectedPath = SelectedGame?.Path;

        var desired = new List<LibraryTile>();
        var gameCount = 0;
        foreach (var game in _allGames)
        {
            if (query.Length == 0 ||
                game.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                game.Path.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                (game.TitleId?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            {
                desired.Add(game);
                gameCount++;
            }
        }

        // The "add folder" action is the trailing carousel tile, shown whenever
        // the library (or the filtered view) would otherwise be empty too.
        if (query.Length == 0 || gameCount > 0)
        {
            desired.Add(AddFolderTile.Instance);
        }

        ReconcileVisibleGames(desired);

        if (selectedPath is not null &&
            Games.OfType<GameEntry>().FirstOrDefault(g => g.Path.Equals(selectedPath, GameLibraryService.PathComparison))
                is { } reselected)
        {
            SelectedGame = reselected;
        }

        IsEmpty = gameCount == 0;
        VisibleGamesChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Decodes cover art and totals each game's install size off the UI thread,
    /// posting results back as they become ready. Repeated watcher scans reuse
    /// an in-flight load instead of restarting it.
    /// </summary>
    private void EnrichDetailsInBackground(IReadOnlyList<GameEntry> games)
    {
        if (games.Count == 0)
        {
            return;
        }

        foreach (var game in games)
        {
            if (_enrichmentInFlight.Add(game))
            {
                _ = EnrichGameAsync(game, game.CoverPath);
            }
        }
    }

    private async Task EnrichGameAsync(GameEntry game, string? requestedCoverPath)
    {
        await _detailLoadGate.WaitAsync();
        Avalonia.Media.Imaging.Bitmap? cover = null;
        long size = 0;
        try
        {
            (cover, size) = await Task.Run(() => (
                _library.LoadCover(requestedCoverPath),
                _library.ComputeInstallSize(game.Path)));
        }
        finally
        {
            _detailLoadGate.Release();
        }

        await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            _enrichmentInFlight.Remove(game);
            if (!_allGames.Contains(game))
            {
                cover?.Dispose();
                return;
            }

            if (!string.Equals(game.CoverPath, requestedCoverPath, StringComparison.Ordinal))
            {
                cover?.Dispose();
                EnrichDetailsInBackground([game]);
                return;
            }

            game.Cover = cover;
            if (size > 0)
            {
                game.SizeBytes = size;
            }

            game.IsLoading = false;
        });
    }

    private void ReconcileVisibleGames(IReadOnlyList<LibraryTile> desired)
    {
        for (var index = 0; index < desired.Count; index++)
        {
            var item = desired[index];
            if (index < Games.Count && ReferenceEquals(Games[index], item))
            {
                continue;
            }

            var existingIndex = -1;
            for (var candidate = index + 1; candidate < Games.Count; candidate++)
            {
                if (ReferenceEquals(Games[candidate], item))
                {
                    existingIndex = candidate;
                    break;
                }
            }

            if (existingIndex >= 0)
            {
                Games.Move(existingIndex, index);
            }
            else
            {
                Games.Insert(index, item);
            }
        }

        while (Games.Count > desired.Count)
        {
            Games.RemoveAt(Games.Count - 1);
        }
    }
}
