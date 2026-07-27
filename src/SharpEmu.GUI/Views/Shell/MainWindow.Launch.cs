// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using SharpEmu.Libs.VideoOut;

namespace SharpEmu.GUI;

/// <summary>Emulator discovery, launch, stop and process output.</summary>
public partial class MainWindow
{
    // ---- Emulator discovery ----

    private void LocateEmulator()
    {
        _emulatorService.LocateEmulator();
        _emulatorExePath = _emulatorService.EmulatorExePath;
        _logService.SetEmulatorExePath(_emulatorExePath);

        EmulatorPathText.Text = _emulatorExePath is not null
            ? Localization.Instance.Format("Status.EmulatorPath", _emulatorExePath)
            : Localization.Instance.Get("Status.EmulatorNotFound");
    }

    // ---- Launching ----

    private void LaunchSelected()
    {
        if (GameList.SelectedItem is GameEntry game)
        {
            Launch(
                game.Path,
                game.Name,
                game.TitleId,
                game.VersionText,
                game.Cover,
                game.PlaceholderBrush,
                game.Initials);
        }
    }

    private void Launch(
        string ebootPath,
        string displayName,
        string? titleId = null,
        string? version = null,
        Bitmap? poster = null,
        IBrush? placeholderBrush = null,
        string? initials = null)
    {
        if (_isRunning)
        {
            return;
        }

        var resolvedTitleId = string.IsNullOrWhiteSpace(titleId)
            ? _library.AllGames.FirstOrDefault(game => game.Path.Equals(ebootPath, FilePathComparison))?.TitleId
            : titleId;
        var effective = EffectiveLaunchSettings.Resolve(_settings, PerGameSettings.Load(resolvedTitleId));

        _sndPreview.Stop();
        _logService.Clear();

        _logService.DropFileLog();
        if (effective.LogToFile)
        {
            _logService.OpenFileLog(resolvedTitleId);
        }

        // Effective settings, env vars and runtime options now live in the
        // emulator service; only the UI reaction remains here.
        _emulatorService.PrepareLaunch(ebootPath, displayName, resolvedTitleId);

        _isRunning = true;
        _runningGameName = displayName;
        _runningGameTitleId = resolvedTitleId;
        _runningSinceUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _session.OnLaunchPrepared(
            displayName,
            resolvedTitleId,
            version,
            poster,
            placeholderBrush ?? Brushes.Transparent,
            initials ?? "?");
        StatusText.Text = Localization.Instance.Format("Launch.Running", displayName);
        StatusBarRight.Text = Localization.Instance.Format("Status.Running", displayName);
        BeginLaunchPresentation();
        UpdateRunButtons();
        UpdateDiscordPresence();

        ShowGameView();

        if (_gameSurfaceHost?.Surface is { } surface)
        {
            StartPendingSession(surface);
        }
    }

    /// <summary>
    /// Stops the running game and updates status/presence immediately. The
    /// process-exit path still runs when the corpse is collected, but a game
    /// wedged in a GPU driver call can keep its process alive for a long
    /// time after termination — the launcher should not look (or tell
    /// Discord it is) "playing" during that window.
    /// </summary>
    private void StopEmulator()
    {
        if (!_isRunning || _isStopping)
        {
            return;
        }

        // If a launch is still pending (surface not yet attached), cancel it
        // instead of letting the delayed callback start a session the user
        // already cancelled.
        if (_emulatorService.CancelPendingLaunch())
        {
            _session.OnLaunchCancelled();
            OnEmulatorExited(0);
            return;
        }

        _isStopping = true;
        _session.OnStopRequested();
        _gameOverlay.HideOverlay(activateOwner: false);
        _emulatorService.Stop();
        _runningGameName = null;
        _runningGameTitleId = null;
        StatusText.Text = Localization.Instance.Get("Launch.Stopping");
        StatusBarRight.Text = Localization.Instance.Get("Status.Stopping");
        UpdateDiscordPresence();
        ReturnToLibraryWhileStopping();
    }

    /// <summary>
    /// Builds "user/logs/&lt;titleId&gt;-&lt;timestamp&gt;.log" next to the emulator
    /// executable, following the same portable-data convention as savedata.
    /// </summary>
    private void OnEmulatorExited(int exitCode)
    {
        _logService.Flush();
        _isRunning = false;
        _isStopping = false;
        // The emulator service disposes its own process; the window only owns
        // the native surface host and view state.
        DisposeGameSurfaceHost();
        HideGameView();

        var meaningKey = exitCode switch
        {
            0 => "Exit.Ok",
            1 => "Exit.InvalidArguments",
            2 => "Exit.EbootNotFound",
            3 => "Exit.RuntimeException",
            4 => "Exit.EmulationError",
            -1073741819 => "Exit.EmulationError",
            _ => "Exit.Unknown",
        };
        var stoppedByUser = exitCode == EmulatorProcess.HostStopExitCode;
        var meaning = Localization.Instance.Get(meaningKey);
        var brush = exitCode == 0 || stoppedByUser ? SuccessLineBrush : ErrorLineBrush;
        AppendConsoleLine(
            stoppedByUser
                ? "Game closed by the user."
                : Localization.Instance.Format("Launch.ProcessExited", exitCode, meaning),
            brush);
        CloseFileLogSoon();

        StatusText.Text = stoppedByUser
            ? "Game closed by the user."
            : Localization.Instance.Format("Launch.Exited", exitCode, meaning);
        StatusBarRight.Text = Localization.Instance.Get("Status.Idle");
        _runningGameName = null;
        _runningGameTitleId = null;
        UpdateLastPlayedValues(GameList.SelectedItem as GameEntry);
        UpdateRunButtons();
        UpdateDiscordPresence();
    }

    private void StartPendingSession(VulkanHostSurface surface)
    {
        // Resolve the child-process descriptor here (the surface is a UI-bound
        // native handle) and hand it to the service, which owns the process.
        string? descriptor = null;
        if (surface.TryGetChildProcessDescriptor(out var d))
        {
            descriptor = d;
        }
        else
        {
            AppendConsoleLine(
                "[GUI][WARN] Embedded child surfaces are unavailable on this platform; opening a game window instead.",
                WarningLineBrush);
        }

        _emulatorService.StartPendingSession(
            descriptor,
            descriptor is null ? null : _gameOverlay.FrameDescriptor);
    }

    private void OnEmulatorOutput(string line, bool isError)
    {
        _logService.Enqueue(line, isError);
        if (!line.Contains("[VIDEOOUT][INFO] Hosted splash ready.", StringComparison.Ordinal) &&
            !line.Contains("[VIDEOOUT][INFO] Hosted first frame presented.", StringComparison.Ordinal))
        {
            return;
        }

        Dispatcher.UIThread.Post(() =>
        {
            if (_isRunning &&
                !_isStopping &&
                _awaitingFirstFrame &&
                !_isGameSurfaceTransitioning)
            {
                _isGameSurfaceTransitioning = true;
                _ = TransitionToGameSurfaceAsync(_launchPresentationGeneration);
            }
        });
    }

    private void UpdateRunButtons()
    {
        LaunchButton.IsEnabled = !_isRunning && GameList.SelectedItem is GameEntry;
    }
}
