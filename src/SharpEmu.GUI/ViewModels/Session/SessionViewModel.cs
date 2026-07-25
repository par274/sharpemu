// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

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

    public SessionViewModel(IEmulatorService emulator)
    {
        _emulator = emulator;
        _emulator.Exited += OnExited;
    }

    [Reactive] private bool _isRunning;
    [Reactive] private bool _isStopping;
    [Reactive] private string _runningGameTitle = string.Empty;
    [Reactive] private string? _runningTitleId;
    [Reactive] private long _runningSinceUnixSeconds;
    [Reactive] private int _lastExitCode;

    /// <summary>Called by the window when a launch is prepared.</summary>
    public void OnLaunchPrepared(string displayName, string? titleId)
    {
        RunningGameTitle = displayName;
        RunningTitleId = titleId;
        RunningSinceUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        IsRunning = true;
        IsStopping = false;
    }

    /// <summary>Called by the window when the user requests a stop.</summary>
    public void OnStopRequested()
    {
        IsStopping = true;
    }

    private void OnExited(int exitCode)
    {
        LastExitCode = exitCode;
        IsRunning = false;
        IsStopping = false;
    }
}
