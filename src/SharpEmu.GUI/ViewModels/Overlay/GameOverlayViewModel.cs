// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using System.Globalization;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Presentation state for the persistent in-game overlay. The window samples
/// time once per second while visible, but republishes pixels only when one of
/// the displayed minute/hour values changes. Duration calculation and
/// localization stay out of its visual code.
/// </summary>
public partial class GameOverlayViewModel : ReactiveObject
{
    private static readonly TimeSpan RecentWindow = TimeSpan.FromDays(14);

    private readonly SessionViewModel _session;
    private readonly IGameActivityService _activity;

    public GameOverlayViewModel(
        SessionViewModel session,
        IGameActivityService activity)
    {
        _session = session;
        _activity = activity;
        UpdateLocalization();
        Refresh(DateTimeOffset.Now);
    }

    [Reactive] private string _gameTitle = string.Empty;
    [Reactive] private string _gameMetadata = string.Empty;
    [Reactive] private bool _hasGameMetadata;
    [Reactive] private Bitmap? _gamePoster;
    [Reactive] private IBrush _posterPlaceholderBrush = Brushes.Transparent;
    [Reactive] private string _gameInitials = string.Empty;
    [Reactive] private bool _hasPoster;
    [Reactive] private string _sessionDuration = "0.0 h";
    [Reactive] private string _recentDuration = "0.0 h";
    [Reactive] private string _currentTime = "--:--";
    [Reactive] private string _sessionLabel = string.Empty;
    [Reactive] private string _recentLabel = string.Empty;
    [Reactive] private string _consoleLabel = string.Empty;
    [Reactive] private string _exitLabel = string.Empty;
    [Reactive] private string _selectHint = string.Empty;
    [Reactive] private string _closeHint = string.Empty;
    [Reactive] private string _toggleHint = string.Empty;
    [Reactive] private bool _canExit;

    public void Refresh(DateTimeOffset now)
    {
        GameTitle = _session.RunningGameTitle;
        GameMetadata = string.Join(
            "  •  ",
            new[] { _session.RunningTitleId, _session.RunningGameVersion }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
        HasGameMetadata = GameMetadata.Length > 0;
        GamePoster = _session.RunningGamePoster;
        PosterPlaceholderBrush = _session.RunningGamePlaceholderBrush;
        GameInitials = _session.RunningGameInitials;
        HasPoster = GamePoster is not null;
        CurrentTime = now.ToString("HH:mm", CultureInfo.CurrentCulture);
        CanExit = _session.IsRunning && !_session.IsStopping;

        if (!_session.IsRunning || _session.RunningSinceUnixSeconds <= 0)
        {
            SessionDuration = FormatHours(TimeSpan.Zero);
            RecentDuration = FormatHours(TimeSpan.Zero);
            return;
        }

        var startedAt = DateTimeOffset.FromUnixTimeSeconds(_session.RunningSinceUnixSeconds);
        var gameKey = _session.RunningTitleId ?? _session.RunningGameTitle;
        SessionDuration = FormatHours(now - startedAt);
        RecentDuration = FormatHours(
            _activity.GetPlayedSince(gameKey, now - RecentWindow, now));
    }

    public void UpdateLocalization()
    {
        var loc = Localization.Instance;
        SessionLabel = loc.Get("Overlay.Session");
        RecentLabel = loc.Get("Overlay.LastTwoWeeks");
        ConsoleLabel = loc.Get("Launch.Console");
        ExitLabel = loc.Get("Overlay.Exit");
        SelectHint = loc.Get("Overlay.Hint.Select");
        CloseHint = loc.Get("Overlay.Hint.Close");
        ToggleHint = loc.Get("Overlay.Hint.Toggle");
    }

    private static string FormatHours(TimeSpan duration) =>
        $"{Math.Max(0, duration.TotalHours):0.0} h";
}
