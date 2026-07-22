// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

using SharpEmu.Core.Runtime;

/// <summary>
/// Owns the isolated emulator process and the launch options applied to it.
/// Extracted from the MainWindow god-class so the launch pipeline (effective
/// settings, environment variables, argument building, process lifecycle) is
/// UI-free and the SessionViewModel only reacts to state changes.
/// </summary>
public interface IEmulatorService
{
    /// <summary>Whether a game process is currently running.</summary>
    bool IsRunning { get; }

    /// <summary>The emulator executable path resolved at startup, or null if not found.</summary>
    string? EmulatorExePath { get; }

    /// <summary>Raised on the UI thread when the emulator process exits.</summary>
    event Action<int>? Exited;

    /// <summary>Raised for each line the emulator writes to stdout/stderr.</summary>
    event Action<string, bool>? OutputReceived;

    /// <summary>Resolves and stores the emulator executable path. Returns false if not found.</summary>
    bool LocateEmulator();

    /// <summary>
    /// Prepares the launch: resolves effective settings (global + per-game),
    /// applies environment variables, builds runtime options, and records the
    /// pending launch. The session actually starts once a native surface is
    /// available via <see cref="StartPendingSession"/>.
    /// </summary>
    /// <param name="ebootPath">Absolute path to the game's eboot.bin.</param>
    /// <param name="displayName">Game title shown in the session bar / Discord.</param>
    /// <param name="titleId">Title id for per-game settings and the log file name.</param>
    void PrepareLaunch(string ebootPath, string displayName, string? titleId);

    /// <summary>
    /// Starts the emulator process against a native surface, using the launch
    /// prepared by <see cref="PrepareLaunch"/>. No-op if no launch is pending.
    /// </summary>
    /// <param name="childProcessDescriptor">The serialized surface handle, or
    /// null when embedded child surfaces are unavailable on this platform
    /// (e.g. macOS Metal): the emulator then opens its own window.</param>
    void StartPendingSession(string? childProcessDescriptor);

    /// <summary>Requests the running emulator to stop and records the stop intent.</summary>
    void Stop();

    /// <summary>
    /// Drops the pending launch without starting it (used when the user cancels
    /// before the surface arrives). Returns whether a pending launch was dropped.
    /// </summary>
    bool CancelPendingLaunch();
}

/// <summary>
/// Resolved launch options shared between the window and the emulator service.
/// Kept here (not in a runtime project) because it carries UI-facing metadata
/// alongside the core runtime options.
/// </summary>
public sealed record EmulatorLaunchOptions(
    string EbootPath,
    string DisplayName,
    string? TitleId,
    string LogLevel,
    SharpEmuRuntimeOptions RuntimeOptions);
