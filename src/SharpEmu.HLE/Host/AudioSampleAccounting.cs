// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// Exact byte and sample accounting for one host PCM stream. The class has no
/// clock or device dependency, which keeps reconciliation tests deterministic.
/// The caller serializes access when it is used by a live stream.
/// </summary>
internal sealed class AudioSampleAccounting
{
    private readonly int _bytesPerOutputFrame;
    private long _decodedSourceFrames;
    private long _convertedOutputFrames;
    private long _convertedOutputBytes;
    private long _submittedOutputBytes;
    private long _failedSubmissionBytes;
    private long _resamplerInputFrames;
    private long _resamplerOutputFrames;

    internal AudioSampleAccounting(int bytesPerOutputFrame)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytesPerOutputFrame);
        _bytesPerOutputFrame = bytesPerOutputFrame;
    }

    internal void RecordDecodedAndConverted(long sourceFrames, long outputFrames)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sourceFrames);
        ArgumentOutOfRangeException.ThrowIfNegative(outputFrames);
        _decodedSourceFrames = checked(_decodedSourceFrames + sourceFrames);
        _convertedOutputFrames = checked(_convertedOutputFrames + outputFrames);
        _convertedOutputBytes = checked(
            _convertedOutputBytes + outputFrames * (long)_bytesPerOutputFrame);
        _resamplerInputFrames = checked(_resamplerInputFrames + sourceFrames);
        _resamplerOutputFrames = checked(_resamplerOutputFrames + outputFrames);
    }

    internal void RecordSubmission(int bytes, bool accepted)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        if (accepted)
        {
            _submittedOutputBytes = checked(_submittedOutputBytes + bytes);
        }
        else
        {
            _failedSubmissionBytes = checked(_failedSubmissionBytes + bytes);
        }
    }

    internal AudioSampleAccountingSnapshot Snapshot(long queuedOutputBytes)
    {
        var consumedOutputBytes = queuedOutputBytes < 0
            ? -1
            : Math.Clamp(
                _submittedOutputBytes - queuedOutputBytes,
                0,
                _submittedOutputBytes);
        var missingOutputBytes = Math.Max(
            0,
            _convertedOutputBytes - _submittedOutputBytes);

        return new AudioSampleAccountingSnapshot
        {
            BytesPerOutputFrame = _bytesPerOutputFrame,
            DecodedSourceFrames = _decodedSourceFrames,
            ConvertedOutputFrames = _convertedOutputFrames,
            ConvertedOutputBytes = _convertedOutputBytes,
            SubmittedOutputFrames = _submittedOutputBytes / _bytesPerOutputFrame,
            SubmittedOutputBytes = _submittedOutputBytes,
            FailedSubmissionFrames = _failedSubmissionBytes / _bytesPerOutputFrame,
            FailedSubmissionBytes = _failedSubmissionBytes,
            QueuedOutputFrames = queuedOutputBytes < 0
                ? -1
                : queuedOutputBytes / _bytesPerOutputFrame,
            QueuedOutputBytes = queuedOutputBytes,
            ConsumedOutputFrames = consumedOutputBytes < 0
                ? -1
                : consumedOutputBytes / _bytesPerOutputFrame,
            ConsumedOutputBytes = consumedOutputBytes,
            MissingOutputFrames = missingOutputBytes / _bytesPerOutputFrame,
            MissingOutputBytes = missingOutputBytes,
            ResamplerInputFrames = _resamplerInputFrames,
            ResamplerOutputFrames = _resamplerOutputFrames,
        };
    }

    internal void Reset()
    {
        _decodedSourceFrames = 0;
        _convertedOutputFrames = 0;
        _convertedOutputBytes = 0;
        _submittedOutputBytes = 0;
        _failedSubmissionBytes = 0;
        _resamplerInputFrames = 0;
        _resamplerOutputFrames = 0;
    }

    /// <summary>
    /// Calculates a delta for a monotonic counter that may have been reset or
    /// wrapped. A decrease is interpreted as a reset at zero; callers that
    /// need modular rollover can use the overload with an explicit maximum.
    /// </summary>
    internal static long CounterDelta(long previous, long current) =>
        current >= previous ? current - previous : current;

    internal static ulong CounterDelta(
        ulong previous,
        ulong current,
        ulong counterMaximum)
    {
        return current >= previous
            ? current - previous
            : counterMaximum - previous + 1UL + current;
    }
}

internal readonly record struct AudioSampleAccountingSnapshot
{
    internal int BytesPerOutputFrame { get; init; }
    internal long DecodedSourceFrames { get; init; }
    internal long ConvertedOutputFrames { get; init; }
    internal long ConvertedOutputBytes { get; init; }
    internal long SubmittedOutputFrames { get; init; }
    internal long SubmittedOutputBytes { get; init; }
    internal long FailedSubmissionFrames { get; init; }
    internal long FailedSubmissionBytes { get; init; }
    internal long QueuedOutputFrames { get; init; }
    internal long QueuedOutputBytes { get; init; }
    internal long ConsumedOutputFrames { get; init; }
    internal long ConsumedOutputBytes { get; init; }
    internal long MissingOutputFrames { get; init; }
    internal long MissingOutputBytes { get; init; }
    internal long ResamplerInputFrames { get; init; }
    internal long ResamplerOutputFrames { get; init; }
}
