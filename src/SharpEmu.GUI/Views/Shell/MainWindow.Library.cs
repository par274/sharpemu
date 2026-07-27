// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System.Diagnostics;
using System.Globalization;

namespace SharpEmu.GUI;

/// <summary>Game library: folders, scanning, selection, details and backdrop.</summary>
public partial class MainWindow
{
    private void WireLibrary()
    {
        // The library watcher raises from a background thread when a game is
        // added/removed on disk; re-scan on the UI thread so the carousel updates
        // without a manual refresh.
        _libraryService.LibraryChanged += (_, _) =>
            Dispatcher.UIThread.Post(() => _ = RescanLibraryAsync());
        _library.VisibleGamesChanged += (_, _) => SynchronizeLibrarySelection();

        try
        {
            _defaultBackdrop = new Bitmap(
                AssetLoader.Open(new Uri("avares://SharpEmu.GUI/Assets/pic0.png")));
            BackdropImage.Source = _defaultBackdrop;
            BackdropImage.Opacity = 1.0;
        }
        catch (Exception)
        {
            _defaultBackdrop = null; // color background remains the fallback
        }

        // Assign the item source before attaching SelectionChanged so the
        // initial population cannot raise into a half-initialized window.
        GameList.ItemsSource = _visibleGames;
        GameList.SelectionChanged += (_, _) =>
        {
            // A re-entrant raise from cancelling a selection below must not
            // reset the visible game.
            if (_suppressSelectionChanged)
            {
                return;
            }

            // The trailing "add folder" card is an action, not a selectable
            // game: it must never become active. Cancel the selection (keeping
            // any previously selected game highlighted) and open the picker.
            if (GameList.SelectedItem is AddFolderTile)
            {
                var previous = _library.SelectedGame;
                _suppressSelectionChanged = true;
                try
                {
                    GameList.SelectedItem = previous;
                }
                finally
                {
                    _suppressSelectionChanged = false;
                }

                if (!_addFolderInProgress)
                {
                    _addFolderInProgress = true;
                    _ = AddFolderAsync().ContinueWith(_ => _addFolderInProgress = false);
                }
                return;
            }

            var current = GameList.SelectedItem as GameEntry;
            // A collection diff can temporarily clear the ListBox selection on
            // its next layout pass. The consolidated synchronization step below
            // restores the intended entry, so never mirror that transient null
            // into the details panel here.
            if (current is null)
            {
                return;
            }

            _library.SelectedGame = current;
            UpdateSelectedGame(current);
        };
        GameList.DoubleTapped += (_, _) =>
        {
            if (GameList.SelectedItem is AddFolderTile)
            {
                if (!_addFolderInProgress)
                {
                    _addFolderInProgress = true;
                    _ = AddFolderAsync().ContinueWith(_ => _addFolderInProgress = false);
                }
                return;
            }

            LaunchSelected();
        };
        SearchBox.TextChanged += (_, _) =>
        {
            _library.SearchText = SearchBox.Text ?? string.Empty;
        };
        LaunchButton.Click += (_, _) => LaunchSelected();

        GameList.AddHandler(ContextRequestedEvent, OnGameContextRequested, RoutingStrategies.Tunnel);
        CtxLaunch.Click += (_, _) => LaunchSelected();
        CtxOpenFolder.Click += (_, _) => OpenSelectedGameFolder();
        CtxCopyPath.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.Path, "Clipboard.Path");
        CtxCopyTitleId.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.TitleId, "Clipboard.TitleId");
        CtxGameSettings.Click += (_, _) => OpenSelectedGameSettings();
        CtxRemove.Click += (_, _) => RemoveSelectedFromLibrary();
    }

    private void ApplyLibraryLocalization()
    {
        var loc = Localization.Instance;

        CtxLaunch.Header = loc.Get("Library.Context.Launch");
        CtxOpenFolder.Header = loc.Get("Library.Context.OpenFolder");
        CtxCopyPath.Header = loc.Get("Library.Context.CopyPath");
        CtxCopyTitleId.Header = loc.Get("Library.Context.CopyTitleId");
        CtxGameSettings.Header = loc.Get("Library.Context.GameSettings");
        CtxRemove.Header = loc.Get("Library.Context.Remove");

        LastPlayedLabel.Text = loc.Get("Library.Stat.LastPlayed");
        VersionLabel.Text = loc.Get("Library.Stat.Version");
        InstalledLabel.Text = loc.Get("Library.Stat.Installed");
        TitleIdLabel.Text = loc.Get("Library.Stat.TitleId");
        LastPlayedValue.Text = loc.Get("Library.Stat.NotPlayed");

        LaunchButtonLabel.Text = loc.Get("Launch.Launch");
    }

    // ---- Game library ----

    private async Task AddFolderAsync()
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = Localization.Instance.Get("Dialog.ChooseGameFolder"),
            AllowMultiple = false,
        });

        var path = folders.FirstOrDefault()?.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var changed = false;
        if (!_settings.GameFolders.Contains(path, FilePathComparer))
        {
            _settings.GameFolders.Add(path);
            changed = true;
        }

        // Adding (or re-adding) a folder is an explicit signal to restore any
        // games beneath it that were removed from the library earlier.
        var prefix = Path.TrimEndingDirectorySeparator(path) + Path.DirectorySeparatorChar;
        changed |= _settings.ExcludedGames.RemoveAll(excluded =>
            excluded.StartsWith(prefix, FilePathComparison)) > 0;

        if (changed)
        {
            _settings.Save();
            // Keep the filesystem watcher aligned with the new folder set so
            // future changes (games installed/removed on disk) are picked up.
            _libraryService.Watch(_settings.GameFolders);
        }

        await RescanLibraryAsync();
    }

    private async Task RescanLibraryAsync()
    {
        var generation = Interlocked.Increment(ref _libraryScanGeneration);
        var folders = _settings.GameFolders.ToArray();
        var excluded = new HashSet<string>(_settings.ExcludedGames, FilePathComparer);
        StatusBarRight.Text = Localization.Instance.Get("Status.ScanningLibrary");

        // The scan runs in the injected library service; the view-model owns
        // the resulting collection and kicks off cover/size enrichment.
        var games = await Task.Run(() => _libraryService.ScanFolders(folders, excluded));
        if (generation != _libraryScanGeneration)
        {
            return;
        }

        _library.ApplyScannedGames(games);
        UpdateDiscordPresence();
        StatusBarRight.Text = folders.Length == 0
            ? Localization.Instance.Get("Status.AddFolderPrompt")
            : Localization.Instance.Format("Status.LibraryScanned", games.Count, folders.Length);
    }

    // Library scan and metadata parsing live in GameLibraryService now;
    // the legacy static helpers (ScanFolders, TryReadParamJson, FindCoverFor,
    // FindBackgroundFor, GameNameFor, ComputeInstallSize) were removed when
    // the logic moved behind IGameLibraryService.

    // ---- Game context menu ----

    /// <summary>
    /// Selects the tile under the pointer before its context menu opens, and
    /// suppresses the menu on empty grid space.
    /// </summary>
    private void OnGameContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        var item = (e.Source as Visual)?.FindAncestorOfType<ListBoxItem>(includeSelf: true);
        if (item?.DataContext is not GameEntry game)
        {
            e.Handled = true;
            return;
        }

        GameList.SelectedItem = game;
        CtxLaunch.IsEnabled = !_isRunning;
        CtxCopyTitleId.IsEnabled = game.TitleId is not null;
        CtxGameSettings.IsEnabled = !string.IsNullOrWhiteSpace(game.TitleId);
    }

    private void OpenSelectedGameFolder()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{game.Path}\"",
                    UseShellExecute = false,
                });
            }
            else if (Path.GetDirectoryName(game.Path) is { } directory)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = OperatingSystem.IsMacOS() ? "open" : "xdg-open",
                    Arguments = $"\"{directory}\"",
                    UseShellExecute = false,
                });
            }
        }
        catch (Exception ex)
        {
            StatusBarRight.Text = Localization.Instance.Format("Status.CouldNotOpenFolder", ex.Message);
        }
    }

    /// <summary>Copies <paramref name="text"/> and reports it via <paramref name="whatKey"/>, e.g. "Clipboard.Path".</summary>
    private async Task CopyToClipboardAsync(string? text, string whatKey)
    {
        if (string.IsNullOrEmpty(text) || Clipboard is null)
        {
            return;
        }

        await Clipboard.SetTextAsync(text);
        StatusBarRight.Text = Localization.Instance.Format("Status.CopiedToClipboard", Localization.Instance.Get(whatKey));
    }

    private void RemoveSelectedFromLibrary()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        if (!_settings.ExcludedGames.Contains(game.Path, FilePathComparer))
        {
            _settings.ExcludedGames.Add(game.Path);
            _settings.Save();
        }

        _library.Remove(game);
        StatusBarRight.Text = Localization.Instance.Format("Status.RemovedFromLibrary", game.Name);
    }

    private void SynchronizeLibrarySelection()
    {
        var selectedPath = _library.SelectedGame?.Path;
        GameEntry? toSelect;
        if (selectedPath is not null &&
            _visibleGames.OfType<GameEntry>().FirstOrDefault(g => g.Path.Equals(selectedPath, FilePathComparison))
                is { } reselected)
        {
            toSelect = reselected;
        }
        else if (_visibleGames.OfType<GameEntry>().FirstOrDefault() is { } first)
        {
            toSelect = first;
        }
        else
        {
            toSelect = null;
        }

        var current = GameList.SelectedItem as GameEntry;
        if (ReferenceEquals(current, toSelect))
        {
            var modelSelectionChanged = !ReferenceEquals(_library.SelectedGame, toSelect);
            _library.SelectedGame = toSelect;
            if (modelSelectionChanged)
            {
                UpdateSelectedGame(toSelect);
            }
            else
            {
                ApplySelectedGameDetails(toSelect);
                UpdateRunButtons();
            }

            return;
        }

        _suppressSelectionChanged = true;
        try
        {
            GameList.SelectedItem = toSelect;
        }
        finally
        {
            _suppressSelectionChanged = false;
        }

        _library.SelectedGame = toSelect;
        UpdateSelectedGame(toSelect);
    }

    private void UpdateSelectedGame()
    {
        UpdateSelectedGame(GameList.SelectedItem as GameEntry);
    }

    /// <summary>
    /// Applies the selected game to the details panel, backdrop and preview.
    /// Takes the game explicitly (rather than re-reading <see cref="GameList"/>'s
    /// <see cref="SelectingItemsControl.SelectedItem"/>) because ListBox applies
    /// selection asynchronously on its next layout pass — reading it back right
    /// after assigning it can return the stale value, leaving the initial load
    /// showing the welcome state instead of the first game.
    /// </summary>
    private void UpdateSelectedGame(GameEntry? game)
    {
        _ = AnimateSelectedGameDetailsAsync(game);

        if (game is not null)
        {
            _ = UpdateBackdropAsync(game);
            PlaySelectedGamePreview(game);
        }
        else
        {
            _ = UpdateBackdropAsync(null);
            _sndPreview.Stop();
        }

        UpdateRunButtons();
    }

    private async Task AnimateSelectedGameDetailsAsync(GameEntry? game)
    {
        var generation = ++_selectedDetailsAnimationGeneration;
        SelectedDetailsHost.Classes.Remove("detailsInStart");
        SelectedDetailsHost.Classes.Add("detailsOut");
        await Task.Delay(110);

        if (generation != _selectedDetailsAnimationGeneration)
        {
            return;
        }

        ApplySelectedGameDetails(game);
        SelectedDetailsHost.Classes.Remove("detailsOut");
        SelectedDetailsHost.Classes.Add("detailsInStart");
        await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Render);

        if (generation != _selectedDetailsAnimationGeneration)
        {
            return;
        }

        SelectedDetailsHost.Classes.Remove("detailsInStart");
    }

    private void ApplySelectedGameDetails(GameEntry? game)
    {
        if (game is not null)
        {
            SelectedGameTitle.Text = game.Name;
            SelectedGamePath.Text = game.Path;
            SelectedEmptyHint.IsVisible = false;
            SelectedActionsHost.IsVisible = true;
            SelectedCoverPanel.DataContext = game;
            SelectedBadgesRow.DataContext = game;
            SelectedBadgesRow.IsVisible = true;
            UpdateLastPlayedValues(game);
        }
        else
        {
            // Empty library: a welcome state rather than "no game selected".
            // The launch/options actions have nothing to act on, so they stay hidden.
            SelectedGameTitle.Text = Localization.Instance.Get("Library.Welcome.Title");
            SelectedGamePath.Text = Localization.Instance.Get("Library.Welcome.Hint");
            SelectedEmptyHint.Text = Localization.Instance.Get("Library.Welcome.Hint");
            SelectedEmptyHint.IsVisible = true;
            SelectedActionsHost.IsVisible = false;
            SelectedCoverPanel.DataContext = null;
            SelectedBadgesRow.DataContext = null;
            SelectedBadgesRow.IsVisible = false;
            UpdateLastPlayedValues(null);
        }
    }

    private void UpdateLastPlayedValues(GameEntry? game)
    {
        var text = Localization.Instance.Get("Library.Stat.NotPlayed");
        if (game is not null)
        {
            var gameKey = game.TitleId ?? game.Name;
            if (_gameActivity.GetLastPlayedAt(gameKey) is { } lastPlayedAt)
            {
                text = lastPlayedAt
                    .ToLocalTime()
                    .ToString("g", CurrentLocalizationCulture());
            }
        }

        LastPlayedValue.Text = text;
        GameOptionsLastPlayedValue.Text = text;
    }

    private static CultureInfo CurrentLocalizationCulture()
    {
        var cultureName = Localization.Instance.CurrentCode.ToLowerInvariant() switch
        {
            "ar" => "ar-SA",
            "br" => "pt-BR",
            "de" => "de-DE",
            "dk" => "da-DK",
            "en" => "en-GB",
            "es" => "es-ES",
            "fr" => "fr-FR",
            "hu" => "hu-HU",
            "it" => "it-IT",
            "ja" => "ja-JP",
            "ko" => "ko-KR",
            "nl" => "nl-NL",
            "pt" => "pt-PT",
            "ru" => "ru-RU",
            "tr" => "tr-TR",
            _ => CultureInfo.CurrentCulture.Name,
        };

        return CultureInfo.GetCultureInfo(cultureName);
    }

    /// <summary>
    /// Text-only refresh of the launch bar's title/path, split out of
    /// <see cref="UpdateSelectedGame"/> so a language change can re-apply it
    /// without restarting the backdrop fade or preview music.
    /// </summary>
    private void UpdateSelectedGameTexts()
    {
        ApplySelectedGameDetails(GameList.SelectedItem as GameEntry);
    }

    /// <summary>
    /// Loops the selected game's sce_sys/snd0.at9 preview music, console
    /// home screen style. Silent while a game is running or when disabled
    /// in the options.
    /// </summary>
    private void PlaySelectedGamePreview(GameEntry game)
    {
        if (_isRunning || !_settings.PlayTitleMusic)
        {
            return;
        }

        var directory = Path.GetDirectoryName(game.Path);
        var sndPath = directory is null ? null : Path.Combine(directory, "sce_sys", "snd0.at9");
        if (sndPath is not null && File.Exists(sndPath))
        {
            _sndPreview.Play(sndPath);
        }
        else
        {
            _sndPreview.Stop();
        }
    }

    private void OnTitleMusicSettingChanged()
    {
        if (!_settings.PlayTitleMusic)
        {
            _sndPreview.Stop();
        }
        else if (GameList.SelectedItem is GameEntry game)
        {
            PlaySelectedGamePreview(game);
        }
    }

    /// <summary>
    /// Fades the window backdrop to the selected game's key art. The image
    /// decodes off the UI thread and is cached on the entry; a newer
    /// selection cancels the fade-in of an older one.
    /// </summary>
    private async Task UpdateBackdropAsync(GameEntry? game)
    {
        var generation = ++_backdropGeneration;
        BackdropImage.Opacity = 0;
        CoverFallbackImage.Opacity = 0;

        // The bundled key art is the primary backdrop whenever the selection
        // has no art of its own; the window color stays as the last fallback.
        void ShowDefaultBackdrop()
        {
            if (generation == _backdropGeneration && _defaultBackdrop is not null)
            {
                BackdropImage.Source = _defaultBackdrop;
                BackdropImage.Opacity = 1.0;
            }
        }

        if (game is null)
        {
            ShowDefaultBackdrop();
            return;
        }

        if (game.BackgroundPath is null)
        {
            ShowDefaultBackdrop();
            if (game.CoverPath is null)
            {
                return;
            }

            if (game.Cover is null)
            {
                try
                {
                    var coverPath = game.CoverPath;
                    game.Cover = await Task.Run(() =>
                    {
                        using var stream = File.OpenRead(coverPath);
                        return Bitmap.DecodeToWidth(stream, 720);
                    });
                }
                catch (Exception)
                {
                    return;
                }
            }

            if (generation == _backdropGeneration)
            {
                CoverFallbackImage.Source = game.Cover;
                CoverFallbackImage.Opacity = 1.0;
            }

            return;
        }

        if (game.Background is null)
        {
            try
            {
                var path = game.BackgroundPath;
                game.Background = await Task.Run(() =>
                {
                    using var stream = File.OpenRead(path);
                    return Bitmap.DecodeToWidth(stream, 1600);
                });
            }
            catch (Exception)
            {
                ShowDefaultBackdrop(); // undecodable key art
                return;
            }
        }

        if (generation == _backdropGeneration)
        {
            BackdropImage.Source = game.Background;
            BackdropImage.Opacity = 1.0;
        }
    }
}
