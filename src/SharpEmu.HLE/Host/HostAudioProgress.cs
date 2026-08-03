// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// State reported by one host audio stream. The seconds value is an estimate
/// derived from the stream's own submitted/dequeued input, not a measurement
/// of physical or audible playback.
/// </summary>
public enum HostAudioProgressState
{
    Unavailable,
    Starting,
    Running,
    TemporaryUnderrun,
    Completed,
    Failed,
    Disposed,
}

/// <summary>
/// Per-stream progress used by an owning movie or guest audio port.
/// </summary>
public readonly record struct HostAudioProgress(
    HostAudioProgressState State,
    double EstimatedPlayedSeconds)
{
    public static HostAudioProgress Unavailable =>
        new(HostAudioProgressState.Unavailable, 0);
}
