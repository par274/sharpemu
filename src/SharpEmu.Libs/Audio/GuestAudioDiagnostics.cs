// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE.Host;

namespace SharpEmu.Libs.Audio;

/// <summary>
/// Opt-in, bounded observations for guest audio producer boundaries. The
/// caller owns the enabled check around every payload-producing operation.
/// </summary>
internal static class GuestAudioDiagnostics
{
    internal static bool Enabled => HostAudioDiagnostics.Enabled;

    internal static bool ShouldEmit(long sequence) =>
        sequence is > 0 and <= 16 ||
        (sequence > 16 && (sequence & (sequence - 1)) == 0);

    internal static void Record(string eventName, object data)
    {
        HostAudioDiagnostics.RecordGuestAudioEvent(eventName, data);
    }

    /// <summary>
    /// Returns a bounded equality fingerprint, never the PCM payload. This is
    /// called only on the explicitly enabled diagnostic path.
    /// </summary>
    internal static ulong Fingerprint(ReadOnlySpan<byte> bytes)
    {
        const ulong offset = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;
        var hash = offset ^ (ulong)bytes.Length;
        foreach (var value in bytes)
        {
            hash ^= value;
            hash *= prime;
        }

        return hash;
    }

    internal static GuestPcmMetrics MeasureInterleaved(
        ReadOnlySpan<byte> source,
        int frames,
        int channels,
        int bytesPerSample,
        bool isFloat)
    {
        if (frames <= 0 || channels <= 0 || bytesPerSample <= 0)
        {
            return default;
        }

        var frameBytes = checked(channels * bytesPerSample);
        if (source.Length < checked(frames * frameBytes))
        {
            return default;
        }

        var leftPeak = 0.0;
        var rightPeak = 0.0;
        var otherPeak = 0.0;
        var leftSquares = 0.0;
        var rightSquares = 0.0;
        var leftSamples = 0;
        var rightSamples = 0;
        for (var frame = 0; frame < frames; frame++)
        {
            var frameData = source.Slice(frame * frameBytes, frameBytes);
            var left = ReadNormalized(frameData, 0, bytesPerSample, isFloat);
            var right = channels == 1
                ? left
                : ReadNormalized(frameData, 1, bytesPerSample, isFloat);
            leftPeak = Math.Max(leftPeak, Math.Abs(left));
            rightPeak = Math.Max(rightPeak, Math.Abs(right));
            leftSquares += left * left;
            rightSquares += right * right;
            leftSamples++;
            rightSamples++;

            for (var channel = 2; channel < channels; channel++)
            {
                otherPeak = Math.Max(
                    otherPeak,
                    Math.Abs(ReadNormalized(frameData, channel, bytesPerSample, isFloat)));
            }
        }

        return new GuestPcmMetrics(
            frames,
            leftPeak,
            rightPeak,
            leftSamples == 0 ? 0 : Math.Sqrt(leftSquares / leftSamples),
            rightSamples == 0 ? 0 : Math.Sqrt(rightSquares / rightSamples),
            otherPeak);
    }

    internal static GuestPcmMetrics MeasureStereoFloat(ReadOnlySpan<float> stereo, int frames)
    {
        if (frames <= 0 || stereo.Length < checked(frames * 2))
        {
            return default;
        }

        var leftPeak = 0.0;
        var rightPeak = 0.0;
        var leftSquares = 0.0;
        var rightSquares = 0.0;
        for (var frame = 0; frame < frames; frame++)
        {
            var left = Normalize(stereo[frame * 2]);
            var right = Normalize(stereo[(frame * 2) + 1]);
            leftPeak = Math.Max(leftPeak, Math.Abs(left));
            rightPeak = Math.Max(rightPeak, Math.Abs(right));
            leftSquares += left * left;
            rightSquares += right * right;
        }

        return new GuestPcmMetrics(
            frames,
            leftPeak,
            rightPeak,
            Math.Sqrt(leftSquares / frames),
            Math.Sqrt(rightSquares / frames),
            0);
    }

    private static double ReadNormalized(
        ReadOnlySpan<byte> frame,
        int channel,
        int bytesPerSample,
        bool isFloat)
    {
        var sample = frame.Slice(channel * bytesPerSample, bytesPerSample);
        if (isFloat)
        {
            var bits = BinaryPrimitives.ReadInt32LittleEndian(sample);
            return Normalize(BitConverter.Int32BitsToSingle(bits));
        }

        return BinaryPrimitives.ReadInt16LittleEndian(sample) / 32768.0;
    }

    private static double Normalize(float value) =>
        float.IsFinite(value) ? value : 0.0;
}

internal readonly record struct GuestPcmMetrics(
    int Frames,
    double LeftPeak,
    double RightPeak,
    double LeftRms,
    double RightRms,
    double OtherPeak);

internal sealed class GuestAudioCallTrace
{
    private long _sequence;

    internal long Next() => Interlocked.Increment(ref _sequence);

    internal long Sequence => Volatile.Read(ref _sequence);
}

internal readonly record struct GuestAudioBufferObservation(
    long Sequence,
    ulong Address,
    int ByteLength,
    ulong Fingerprint,
    bool SameAddressAsPrevious,
    bool SameContentAsPrevious,
    long SameAddressCount,
    long SameContentCount,
    GuestPcmMetrics Metrics,
    bool Emit);

internal readonly record struct GuestAudioSkipObservation(
    long Sequence,
    ulong Address,
    int ByteLength,
    int PendingBefore,
    bool Emit);

/// <summary>
/// Tracks only the previous submitted identity and bounded equality counts.
/// No instance is created by the normal, diagnostics-disabled path.
/// </summary>
internal sealed class GuestAudioBufferTrace
{
    private readonly object _gate = new();
    private long _sequence;
    private ulong _lastAddress;
    private int _lastByteLength;
    private ulong _lastFingerprint;
    private bool _hasLast;
    private long _sameAddressCount;
    private long _sameContentCount;

    internal GuestAudioBufferObservation Observe(
        ulong address,
        ReadOnlySpan<byte> source,
        int frames,
        int channels,
        int bytesPerSample,
        bool isFloat)
    {
        var fingerprint = GuestAudioDiagnostics.Fingerprint(source);
        var metrics = GuestAudioDiagnostics.MeasureInterleaved(
            source,
            frames,
            channels,
            bytesPerSample,
            isFloat);

        lock (_gate)
        {
            var sequence = ++_sequence;
            var sameAddress = _hasLast && address == _lastAddress;
            var sameContent = _hasLast &&
                              source.Length == _lastByteLength &&
                              fingerprint == _lastFingerprint;
            if (sameAddress)
            {
                _sameAddressCount++;
            }

            if (sameContent)
            {
                _sameContentCount++;
            }

            _lastAddress = address;
            _lastByteLength = source.Length;
            _lastFingerprint = fingerprint;
            _hasLast = true;
            return new GuestAudioBufferObservation(
                sequence,
                address,
                source.Length,
                fingerprint,
                sameAddress,
                sameContent,
                _sameAddressCount,
                _sameContentCount,
                metrics,
                GuestAudioDiagnostics.ShouldEmit(sequence));
        }
    }

    internal GuestAudioSkipObservation ObserveSkipped(ulong address, int byteLength, int pendingBefore)
    {
        lock (_gate)
        {
            var sequence = ++_sequence;
            return new GuestAudioSkipObservation(
                sequence,
                address,
                byteLength,
                pendingBefore,
                GuestAudioDiagnostics.ShouldEmit(sequence));
        }
    }
}
