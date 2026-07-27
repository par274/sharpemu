// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using Avalonia.Media;
using Avalonia.Media.Imaging;
using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Tracks the running emulation session independently of the shell view:
/// running/stopping state, title, and exit status. Subscribes to <see cref="IEmulatorService"/>
/// so the window (session bar popup, run buttons, Discord presence) binds to a
/// single source of truth instead of scattered bool flags.
/// </summary>
public partial class SessionViewModel : ReactiveObject
{
    private readonly IEmulatorService _emulator;
    private readonly IGameActivityService _activity;

    public SessionViewModel(
        IEmulatorService emulator,
        IGameActivityService activity)
    {
        _emulator = emulator;
        _activity = activity;
        _emulator.Exited += OnExited;
    }

    [Reactive] private bool _isRunning;
    [Reactive] private bool _isStopping;
    [Reactive] private string _runningGameTitle = string.Empty;
    [Reactive] private string? _runningTitleId;
    [Reactive] private string? _runningGameVersion;
    [Reactive] private Bitmap? _runningGamePoster;
    [Reactive] private IBrush _runningGamePlaceholderBrush = Brushes.Transparent;
    [Reactive] private string _runningGameInitials = string.Empty;
    [Reactive] private long _runningSinceUnixSeconds;
    [Reactive] private int _lastExitCode;

    /// <summary>Called by the window when a launch is prepared.</summary>
    public void OnLaunchPrepared(
        string displayName,
        string? titleId,
        string? version,
        Bitmap? poster,
        IBrush placeholderBrush,
        string initials)
    {
        var startedAt = DateTimeOffset.UtcNow;
        RunningGameTitle = displayName;
        RunningTitleId = titleId;
        RunningGameVersion = version;
        RunningGamePoster = poster;
        RunningGamePlaceholderBrush = placeholderBrush;
        RunningGameInitials = initials;
        RunningSinceUnixSeconds = startedAt.ToUnixTimeSeconds();
        _activity.BeginSession(titleId ?? displayName, startedAt);
        IsRunning = true;
        IsStopping = false;
    }

    /// <summary>Called by the window when the user requests a stop.</summary>
    public void OnStopRequested()
    {
        IsStopping = true;
    }

    /// <summary>Clears a prepared launch that was cancelled before a process started.</summary>
    public void OnLaunchCancelled()
    {
        _activity.CompleteSession(DateTimeOffset.UtcNow);
        IsRunning = false;
        IsStopping = false;
    }

    public void OnApplicationClosing()
    {
        _activity.CompleteSession(DateTimeOffset.UtcNow);
    }

    private void OnExited(int exitCode)
    {
        _activity.CompleteSession(DateTimeOffset.UtcNow);
        LastExitCode = exitCode;
        IsRunning = false;
        IsStopping = false;
    }
}
