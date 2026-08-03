// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;

namespace SharpEmu.HLE.Host;

/// <summary>
/// Estimated guest audio progress, in seconds.
///
/// The estimate is derived from accepted input submitted to an SDL audio stream
/// minus the input-format bytes still queued for conversion. SDL queue state
/// does not expose all conversion, device, or hardware buffering, so this is
/// not a direct measurement of samples physically played or heard by the user.
/// Wall clock may run ahead of it when the guest cannot feed the device. This
/// remains an ordinary guest-audio diagnostic; host movies use their owning
/// stream's progress instead of this process-wide value.
///
/// Reported per stream and kept as the furthest-along value: the guest's ports
/// all carry one mix, and the leading port is the one whose position the
/// listener perceives.
/// </summary>
public static class GuestAudioClock
{
    private static long _playedMicroseconds;
    private static long _lastAdvanceTimestamp;

    /// <summary>Monotonic seconds of estimated guest audio progress.</summary>
    public static double PlayedSeconds =>
        Interlocked.Read(ref _playedMicroseconds) / 1_000_000.0;

    /// <summary>
    /// True while a stream has reported progress recently. False means no guest
    /// audio is playing, and callers must fall back to wall clock rather than
    /// stalling on a clock that will never advance.
    /// </summary>
    public static bool IsRunning
    {
        get
        {
            var last = Interlocked.Read(ref _lastAdvanceTimestamp);
            return last != 0 &&
                   Stopwatch.GetElapsedTime(last) < TimeSpan.FromMilliseconds(250);
        }
    }

    public static bool Report(double playedSeconds)
    {
        if (double.IsNaN(playedSeconds) || playedSeconds < 0)
        {
            return false;
        }

        var microseconds = (long)(playedSeconds * 1_000_000.0);
        var current = Interlocked.Read(ref _playedMicroseconds);
        while (microseconds > current)
        {
            var seen = Interlocked.CompareExchange(
                ref _playedMicroseconds,
                microseconds,
                current);
            if (seen == current)
            {
                Interlocked.Exchange(ref _lastAdvanceTimestamp, Stopwatch.GetTimestamp());
                return true;
            }

            current = seen;
        }

        return false;
    }
}
