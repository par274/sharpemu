// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-only

using System.Diagnostics;
using System.Threading;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Tracks the most recent vk.flip_retired event so the native-execution stall
/// watchdog (SharpEmu.Core) can tell "no import progress" apart from "imports
/// are advancing but no new frame has presented" — the latter is a distinct
/// symptom class (GPU/AGC sync gap) that the import-count watchdog alone
/// cannot see. Deliberately dependency-free of AGC/CPU types so both
/// SharpEmu.Libs (VulkanVideoPresenter, the writer) and SharpEmu.Core
/// (DirectExecutionBackend, the reader) can reference it without a cycle.
/// </summary>
public static class FlipProgressTracker
{
    private static long _lastFlipTimestamp;
    private static long _lastFlipVersion;
    private static int _hasFlipped;

    public static void RecordFlip(long version)
    {
        Volatile.Write(ref _lastFlipVersion, version);
        Volatile.Write(ref _lastFlipTimestamp, Stopwatch.GetTimestamp());
        Volatile.Write(ref _hasFlipped, 1);
    }

    public static bool HasFlipped => Volatile.Read(ref _hasFlipped) != 0;

    public static long LastFlipVersion => Volatile.Read(ref _lastFlipVersion);

    /// <summary>
    /// Seconds since the last recorded flip, or null if no flip has ever been
    /// recorded (still in pre-render boot — a different, already-diagnosed
    /// stage, not the flip-stall symptom this tracker exists for).
    /// </summary>
    public static double? SecondsSinceLastFlip()
    {
        if (Volatile.Read(ref _hasFlipped) == 0)
        {
            return null;
        }

        var elapsedTicks = Stopwatch.GetTimestamp() - Volatile.Read(ref _lastFlipTimestamp);
        return elapsedTicks / (double)Stopwatch.Frequency;
    }
}
