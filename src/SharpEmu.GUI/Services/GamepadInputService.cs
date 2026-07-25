// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using SharpEmu.GUI.Services.Abstractions;
using SharpEmu.HLE.Host;
using SharpEmu.HLE.Host.Windows;

/// <summary>
/// Polls DualSense/XInput controllers and raises navigation intents. The
/// hold-to-repeat timing (first fire on press, then 400ms delay, then 130ms
/// cadence) is lifted unchanged from the former PollGamepad in the window.
/// </summary>
internal sealed class GamepadInputService : IGamepadInputService
{
    private HostGamepadButtons _previousButtons;
    private long _navLeftNextAt;
    private long _navRightNextAt;
    private long _navUpNextAt;
    private long _navDownNextAt;

    public event Action<int>? MoveHorizontal;
    public event Action<int>? MoveVertical;
    public event Action? Activate;
    public event Action<int>? PageRequested;

    /// <summary>
    /// Polls the controller once. UI context (active page, whether a game is
    /// running) is passed in so the service stays free of window state.
    /// </summary>
    /// <param name="isActive">Whether the launcher window is foreground.</param>
    /// <param name="isRunning">Whether a game session is active (controller goes to the game).</param>
    /// <param name="activePage">0 = Library, 1 = Options, 2 = Console.</param>
    public bool Poll(bool isActive, bool isRunning, int activePage)
    {
        // DualSense wins when both are connected; XInput covers Xbox pads.
        if (!WindowsDualSenseReader.TryGetState(out var pad) && !WindowsXInputReader.TryGetState(out pad))
        {
            _previousButtons = HostGamepadButtons.None;
            return false;
        }

        if (!isActive)
        {
            _previousButtons = pad.Buttons;
            return false;
        }

        if (isRunning)
        {
            _previousButtons = pad.Buttons;
            return false;
        }

        var shoulderPressed = pad.Buttons & ~_previousButtons;
        if ((shoulderPressed & HostGamepadButtons.L1) != 0)
        {
            PageRequested?.Invoke(Math.Max(activePage - 1, 0));
        }

        if ((shoulderPressed & HostGamepadButtons.R1) != 0)
        {
            PageRequested?.Invoke(Math.Min(activePage + 1, 2));
        }

        var now = Environment.TickCount64;
        var left = (pad.Buttons & HostGamepadButtons.Left) != 0 || pad.LeftX < 64;
        var right = (pad.Buttons & HostGamepadButtons.Right) != 0 || pad.LeftX > 192;
        var up = (pad.Buttons & HostGamepadButtons.Up) != 0 || pad.LeftY < 64;
        var down = (pad.Buttons & HostGamepadButtons.Down) != 0 || pad.LeftY > 192;

        if (ShouldNavigate(left, ref _navLeftNextAt, now))
        {
            MoveHorizontal?.Invoke(-1);
        }

        if (ShouldNavigate(right, ref _navRightNextAt, now))
        {
            MoveHorizontal?.Invoke(1);
        }

        if (ShouldNavigate(up, ref _navUpNextAt, now))
        {
            MoveVertical?.Invoke(-1);
        }

        if (ShouldNavigate(down, ref _navDownNextAt, now))
        {
            MoveVertical?.Invoke(1);
        }

        var pressed = pad.Buttons & ~_previousButtons;
        if ((pressed & HostGamepadButtons.Cross) != 0)
        {
            Activate?.Invoke();
        }

        _previousButtons = pad.Buttons;
        return true;
    }

    /// <summary>
    /// Edge-triggered with hold-to-repeat: fires on press, then repeats
    /// after 400ms at 130ms intervals while held.
    /// </summary>
    private static bool ShouldNavigate(bool held, ref long nextAt, long now)
    {
        if (!held)
        {
            nextAt = 0;
            return false;
        }

        if (nextAt == 0)
        {
            nextAt = now + 400;
            return true;
        }

        if (now >= nextAt)
        {
            nextAt = now + 130;
            return true;
        }

        return false;
    }
}
