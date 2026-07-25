// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Polls a connected DualSense/Xbox controller and raises navigation intents.
/// Extracted from the MainWindow god-class so the gamepad no longer needs to
/// reach into ListBox selection and page switching directly: the window
/// subscribes to these events and translates them into focus/VM actions.
/// </summary>
internal interface IGamepadInputService
{
    /// <summary>Raised on a horizontal navigation intent; -1 = left, +1 = right.</summary>
    event Action<int>? MoveHorizontal;

    /// <summary>Raised on a vertical navigation intent; -1 = up, +1 = down.</summary>
    event Action<int>? MoveVertical;

    /// <summary>Raised when the user activates the selected item (Cross).</summary>
    event Action? Activate;

    /// <summary>Raised when L1/R1 requests the previous or next shell page.</summary>
    event Action<int>? PageRequested;

    /// <summary>
    /// Polls the controller once. The window drives this from its 50ms timer.
    /// Returns false when no controller is connected or the launcher should
    /// ignore input (backgrounded, or a game is running).
    /// </summary>
    /// <param name="isActive">Whether the launcher window is foreground.</param>
    /// <param name="isRunning">Whether a game session is active (controller goes to the game).</param>
    /// <param name="activePage">0 = Library, 1 = Options, 2 = Console.</param>
    bool Poll(bool isActive, bool isRunning, int activePage);
}
