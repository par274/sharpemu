// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Persists completed play sessions and exposes rolling activity totals for
/// the game overlay. The active session is included in live queries but is
/// written only once when the emulator exits.
/// </summary>
public interface IGameActivityService
{
    void BeginSession(string gameKey, DateTimeOffset startedAt);

    void CompleteSession(DateTimeOffset endedAt);

    TimeSpan GetPlayedSince(string gameKey, DateTimeOffset since, DateTimeOffset now);

    DateTimeOffset? GetLastPlayedAt(string gameKey);
}
