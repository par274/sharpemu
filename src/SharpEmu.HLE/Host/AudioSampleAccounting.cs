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
    private readonly int _bytesPerStreamFrame;
    private long _decodedSourceFrames;
    private long _convertedOutputFrames;
    private long _convertedOutputBytes;
    private long _submittedInputBytes;
    private long _failedSubmissionBytes;
    private long _resamplerInputFrames;
    private long _resamplerOutputFrames;

    internal AudioSampleAccounting(int bytesPerStreamFrame)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytesPerStreamFrame);
        _bytesPerStreamFrame = bytesPerStreamFrame;
    }

    internal void RecordDecodedAndConverted(long sourceFrames, long outputFrames)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sourceFrames);
        ArgumentOutOfRangeException.ThrowIfNegative(outputFrames);
        _decodedSourceFrames = checked(_decodedSourceFrames + sourceFrames);
        _convertedOutputFrames = checked(_convertedOutputFrames + outputFrames);
        _convertedOutputBytes = checked(
            _convertedOutputBytes + outputFrames * (long)_bytesPerStreamFrame);
        _resamplerInputFrames = checked(_resamplerInputFrames + sourceFrames);
        _resamplerOutputFrames = checked(_resamplerOutputFrames + outputFrames);
    }

    internal void RecordSubmission(int bytes, bool accepted)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        if (accepted)
        {
            _submittedInputBytes = checked(_submittedInputBytes + bytes);
        }
        else
        {
            _failedSubmissionBytes = checked(_failedSubmissionBytes + bytes);
        }
    }

    internal AudioSampleAccountingSnapshot Snapshot(long queuedInputBytes)
    {
        var dequeuedInputBytes = queuedInputBytes < 0
            ? -1
            : Math.Clamp(
                _submittedInputBytes - queuedInputBytes,
                0,
                _submittedInputBytes);
        var missingOutputBytes = Math.Max(
            0, _convertedOutputBytes - _submittedInputBytes);

        return new AudioSampleAccountingSnapshot
        {
            BytesPerStreamFrame = _bytesPerStreamFrame,
            DecodedSourceFrames = _decodedSourceFrames,
            ConvertedOutputFrames = _convertedOutputFrames,
            ConvertedOutputBytes = _convertedOutputBytes,
            SubmittedInputFrames = _submittedInputBytes / _bytesPerStreamFrame,
            SubmittedInputBytes = _submittedInputBytes,
            FailedSubmissionFrames = _failedSubmissionBytes / _bytesPerStreamFrame,
            FailedSubmissionBytes = _failedSubmissionBytes,
            QueuedInputFrames = queuedInputBytes < 0
                ? -1
                : queuedInputBytes / _bytesPerStreamFrame,
            QueuedInputBytes = queuedInputBytes,
            DequeuedInputFrames = dequeuedInputBytes < 0
                ? -1
                : dequeuedInputBytes / _bytesPerStreamFrame,
            DequeuedInputBytes = dequeuedInputBytes,
            MissingOutputFrames = missingOutputBytes / _bytesPerStreamFrame,
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
        _submittedInputBytes = 0;
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
    internal int BytesPerStreamFrame { get; init; }
    internal long DecodedSourceFrames { get; init; }
    internal long ConvertedOutputFrames { get; init; }
    internal long ConvertedOutputBytes { get; init; }
    internal long SubmittedInputFrames { get; init; }
    internal long SubmittedInputBytes { get; init; }
    internal long FailedSubmissionFrames { get; init; }
    internal long FailedSubmissionBytes { get; init; }
    internal long QueuedInputFrames { get; init; }
    internal long QueuedInputBytes { get; init; }
    internal long DequeuedInputFrames { get; init; }
    internal long DequeuedInputBytes { get; init; }
    internal long MissingOutputFrames { get; init; }
    internal long MissingOutputBytes { get; init; }
    internal long ResamplerInputFrames { get; init; }
    internal long ResamplerOutputFrames { get; init; }
}
