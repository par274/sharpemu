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

    /// <summary>All scanned games, before the search filter is applied.</summary>
    private readonly List<GameEntry> _allGames = new();

    /// <summary>
    /// Generation counter for background cover/size enrichment; bumped on each
    /// rescan so a stale load can abandon its post-back to the UI thread.
    /// </summary>
    private int _detailLoadGeneration;

    public LibraryViewModel(IGameLibraryService library)
    {
        _library = library;

        // Re-apply the search filter whenever the query changes. Throttle so
        // fast typing does not rebuild the filtered list per keystroke.
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

    [Reactive]
    private string _searchText = string.Empty;

    [Reactive]
    private GameEntry? _selectedGame;

    [Reactive]
    private bool _isEmpty;

    [Reactive]
    private bool _isScanning;

    /// <summary>
    /// Replaces the in-memory library with the result of a background scan and
    /// kicks off cover/size enrichment. Called by the window after it has
    /// resolved folders/exclusions from settings.
    /// </summary>
    public void ApplyScannedGames(IReadOnlyList<GameEntry> games)
    {
        _allGames.Clear();
        _allGames.AddRange(games);
        RefreshVisibleGames();
        EnrichDetailsInBackground(games);
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
        SelectedGame = null;
        RefreshVisibleGames();
    }

    /// <summary>Re-applies the search filter against <see cref="AllGames"/>.</summary>
    public void RefreshVisibleGames()
    {
        var query = (SearchText ?? string.Empty).Trim();
        var selectedPath = SelectedGame?.Path;

        Games.Clear();
        var gameCount = 0;
        foreach (var game in _allGames)
        {
            if (query.Length == 0 ||
                game.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                game.Path.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                (game.TitleId?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            {
                Games.Add(game);
                gameCount++;
            }
        }

        // The "add folder" action is the trailing carousel tile, shown whenever
        // the library (or the filtered view) would otherwise be empty too.
        if (query.Length == 0 || gameCount > 0)
        {
            Games.Add(AddFolderTile.Instance);
        }

        if (selectedPath is not null &&
            Games.OfType<GameEntry>().FirstOrDefault(g => g.Path.Equals(selectedPath, GameLibraryService.PathComparison))
                is { } reselected)
        {
            SelectedGame = reselected;
        }

        IsEmpty = gameCount == 0;
    }

    /// <summary>
    /// Decodes cover art and totals each game's install size off the UI thread,
    /// posting results back as they become ready. A newer scan invalidates
    /// older loads via the generation counter.
    /// </summary>
    private void EnrichDetailsInBackground(IReadOnlyList<GameEntry> games)
    {
        var generation = ++_detailLoadGeneration;
        _ = Task.Run(() =>
        {
            // Covers first: they are cheap and the most visible, so the grid
            // fills with art before the (potentially slow) size pass runs.
            foreach (var game in games)
            {
                if (generation != _detailLoadGeneration)
                {
                    return;
                }

                if (game.CoverPath is null)
                {
                    continue;
                }

                var cover = _library.LoadCover(game.CoverPath);
                if (cover is not null && generation == _detailLoadGeneration)
                {
                    game.Cover = cover;
                }
            }

            foreach (var game in games)
            {
                if (generation != _detailLoadGeneration)
                {
                    return;
                }

                var size = _library.ComputeInstallSize(game.Path);
                if (size > 0 && generation == _detailLoadGeneration)
                {
                    game.SizeBytes = size;
                }
            }
        });
    }
}
