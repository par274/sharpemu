// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Collections.Concurrent;
using System.Diagnostics;
using SharpEmu.Logging;

namespace SharpEmu.HLE.Host;

/// <summary>
/// Optional metadata and aggregate counters for host audio streams. The
/// disabled path is a single environment/session/budget check; it does not
/// construct diagnostic payloads or take a diagnostic lock.
/// </summary>
public static class HostAudioDiagnostics
{
    internal const int MaximumEvents = 4096;

    private static readonly bool Requested = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_AUDIO_DIAGNOSTICS"),
        "1",
        StringComparison.Ordinal);
    private static readonly AudioDiagnosticEventBudget EventBudget =
        new(MaximumEvents);
    private static readonly ConcurrentDictionary<string, OpenFailureState> OpenFailures =
        new(StringComparer.Ordinal);

    public static bool Enabled =>
        Requested &&
        MemoryDiagnostics.IsEnabled &&
        EventBudget.HasCapacity;

    internal static bool TryReserveEvent() =>
        Enabled && EventBudget.TryReserve();

    internal static string Identity(string? source) => AudioIdentity(source);

    public static void RecordOpenFailure(
        string owner,
        string source,
        uint sampleRate,
        int channels,
        string format,
        int maximumQueuedBytes,
        Exception exception)
    {
        if (!Enabled)
        {
            return;
        }

        ArgumentNullException.ThrowIfNull(exception);
        var sourceIdentity = AudioIdentity(source);
        var key = owner + "|" + sourceIdentity;
        var state = OpenFailures.GetOrAdd(key, static _ => new OpenFailureState());
        var attempt = Interlocked.Increment(ref state.Attempts);
        var now = Stopwatch.GetTimestamp();
        var last = Volatile.Read(ref state.LastEventTimestamp);
        if (attempt != 1 &&
            last != 0 &&
            Stopwatch.GetElapsedTime(last) < TimeSpan.FromSeconds(1))
        {
            return;
        }

        if (Interlocked.CompareExchange(
                ref state.LastEventTimestamp,
                now,
                last) != last ||
            !TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.stream-open-failure",
            new
            {
                hostMonotonicTicks = now,
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                owner,
                source = sourceIdentity,
                attempt,
                sampleRate,
                channels,
                format,
                maximumQueuedBytes,
                exceptionType = exception.GetType().Name,
                message = exception.Message,
            });
    }

    internal static void RecordStreamOpen(HostAudioStreamDiagnosticSnapshot snapshot)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.stream-open",
            new
            {
                hostMonotonicTicks = Stopwatch.GetTimestamp(),
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                stream = snapshot,
            });
    }

    internal static void RecordStreamSummary(HostAudioStreamDiagnosticSnapshot snapshot)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.stream-summary",
            new
            {
                hostMonotonicTicks = Stopwatch.GetTimestamp(),
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                stream = snapshot,
            });
    }

    internal static void RecordStreamPhase(HostAudioStreamDiagnosticSnapshot snapshot)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.stream-phase",
            new
            {
                hostMonotonicTicks = Stopwatch.GetTimestamp(),
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                stream = snapshot,
            });
    }

    public static void RecordMovieDecoderIdentity(
        string source,
        long movieInstanceId,
        long hostMovieGeneration,
        double declaredAudioDurationSeconds,
        int sourceSampleRate,
        int sourceChannels,
        string sourceSampleFormat,
        int outputSampleRate,
        int outputChannels,
        string outputSampleFormat)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.movie-decoder-open",
            new
            {
                hostMonotonicTicks = Stopwatch.GetTimestamp(),
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                source = AudioIdentity(source),
                movieInstanceId,
                hostMovieGeneration,
                declaredAudioDurationSeconds,
                sourceSampleRate,
                sourceChannels,
                sourceSampleFormat,
                outputSampleRate,
                outputChannels,
                outputSampleFormat,
            });
    }

    public static void RecordMovieDecoderSummary(
        string source,
        long movieInstanceId,
        long hostMovieGeneration,
        double declaredAudioDurationSeconds,
        long decodedSourceFrames,
        long convertedOutputFrames,
        long submittedOutputFrames,
        long failedSubmissionFrames,
        long resamplerInputFrames,
        long resamplerOutputFrames,
        double lastSourceTimestampSeconds,
        HostAudioStreamDiagnosticSnapshot stream)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        MemoryDiagnostics.RecordEvent(
            "audio.movie-decoder-summary",
            new
            {
                hostMonotonicTicks = Stopwatch.GetTimestamp(),
                stopwatchFrequency = Stopwatch.Frequency,
                threadId = Environment.CurrentManagedThreadId,
                threadName = Thread.CurrentThread.Name,
                source = AudioIdentity(source),
                movieInstanceId,
                hostMovieGeneration,
                declaredAudioDurationSeconds,
                decodedSourceFrames,
                convertedOutputFrames,
                submittedOutputFrames,
                unsubmittedOutputFrames = Math.Max(
                    0,
                    convertedOutputFrames - submittedOutputFrames),
                failedSubmissionFrames,
                resamplerInputFrames,
                resamplerOutputFrames,
                lastSourceTimestampSeconds,
                stream,
            });
    }

    private static string AudioIdentity(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var lastSeparator = -1;
        for (var index = 0; index < path.Length; index++)
        {
            if (path[index] is '/' or '\\')
            {
                lastSeparator = index;
            }
        }

        return lastSeparator >= 0 ? path[(lastSeparator + 1)..] : path;
    }

    private sealed class OpenFailureState
    {
        internal long Attempts;
        internal long LastEventTimestamp;
    }
}

public interface IHostAudioStreamDiagnostics
{
    void SetDiagnosticContext(
        string owner,
        string source,
        long movieInstanceId,
        long hostMovieGeneration);

    void SetDiagnosticPhase(string phase);

    HostAudioStreamDiagnosticSnapshot GetDiagnosticSnapshot();
}

public readonly record struct HostAudioStreamDiagnosticSnapshot
{
    public HostAudioStreamDiagnosticSnapshot()
    {
    }

    public int StreamId { get; init; }
    public string Owner { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public long MovieInstanceId { get; init; }
    public long HostMovieGeneration { get; init; }
    public string Phase { get; init; } = string.Empty;
    public uint InputSampleRate { get; init; }
    public int InputChannels { get; init; }
    public int InputBytesPerFrame { get; init; }
    public int StreamInputFrequency { get; init; }
    public int StreamInputChannels { get; init; }
    public string StreamInputFormat { get; init; } = string.Empty;
    public int StreamOutputFrequency { get; init; }
    public int StreamOutputChannels { get; init; }
    public string StreamOutputFormat { get; init; } = string.Empty;
    public int MaximumQueuedBytes { get; init; }
    public int MaximumQueuedFrames { get; init; }
    public double MaximumQueuedMilliseconds { get; init; }
    public int QueuedInputBytes { get; init; }
    public int QueuedInputFrames { get; init; }
    public double QueuedInputMilliseconds { get; init; }
    public int ConvertedAvailableBytes { get; init; }
    public long SubmittedInputBytes { get; init; }
    public long SubmittedInputFrames { get; init; }
    public long ConsumedInputBytes { get; init; }
    public long ConsumedInputFrames { get; init; }
    public long FailedSubmissionBytes { get; init; }
    public long FailedSubmissionFrames { get; init; }
    public long SubmissionCount { get; init; }
    public long FailedSubmissionCount { get; init; }
    public long OverTargetSubmissionCount { get; init; }
    public long EmptyQueueObservations { get; init; }
    public long UnderrunCount { get; init; }
    public double UnderrunDurationMilliseconds { get; init; }
    public long QueueQueryFailureCount { get; init; }
    public uint DeviceId { get; init; }
    public string DeviceName { get; init; } = string.Empty;
    public string DeviceState { get; init; } = string.Empty;
    public bool DevicePaused { get; init; }
    public int DeviceFrequency { get; init; }
    public int DeviceChannels { get; init; }
    public string DeviceFormat { get; init; } = string.Empty;
    public int DeviceBufferFrames { get; init; }
    public long DeviceStateTransitionCount { get; init; }
    public double StreamFrequencyRatio { get; init; }
    public bool CallbackAvailable { get; init; }
    public int CallbackRequestedFrames { get; init; }
    public int CallbackSuppliedFrames { get; init; }
    public long ClockReportAcceptedCount { get; init; }
    public long ClockReportRejectedCount { get; init; }
    public double LastStreamPlayedSeconds { get; init; }
    public double GlobalGuestAudioClockSeconds { get; init; }
}

internal sealed class AudioDiagnosticEventBudget
{
    private readonly int _maximum;
    private int _accepted;

    internal AudioDiagnosticEventBudget(int maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        _maximum = maximum;
    }

    internal bool HasCapacity => Volatile.Read(ref _accepted) < _maximum;

    internal int AcceptedCount => Volatile.Read(ref _accepted);

    internal bool TryReserve()
    {
        while (true)
        {
            var accepted = Volatile.Read(ref _accepted);
            if (accepted >= _maximum)
            {
                return false;
            }

            if (Interlocked.CompareExchange(
                    ref _accepted,
                    accepted + 1,
                    accepted) == accepted)
            {
                return true;
            }
        }
    }
}
