// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;

namespace SharpEmu.HLE.Host;

/// <summary>
/// Bounded scalar statistics for one diagnostic window of interleaved host
/// PCM. It never retains samples or builds a payload until a snapshot is
/// requested.
/// </summary>
public sealed class AudioPcmStatistics
{
    private readonly HostPcmFormat _format;
    private readonly int _channels;
    private readonly double[] _previousSamples;
    private readonly bool[] _hasPreviousSamples;
    private double _peak;
    private double _sumSquares;
    private long _sampleCount;
    private long _frameCount;
    private long _clippingCount;
    private long _zeroCrossingCount;

    public AudioPcmStatistics(HostPcmFormat format, int channels)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(channels);
        _format = format;
        _channels = channels;
        _previousSamples = new double[channels];
        _hasPreviousSamples = new bool[channels];
    }

    public void Record(ReadOnlySpan<byte> pcm)
    {
        var bytesPerSample = _format == HostPcmFormat.Float32
            ? sizeof(float)
            : sizeof(short);
        var bytesPerFrame = checked(bytesPerSample * _channels);
        if (pcm.Length % bytesPerFrame != 0)
        {
            return;
        }

        _frameCount = checked(_frameCount + pcm.Length / bytesPerFrame);
        var sampleIndex = 0;
        for (var offset = 0; offset < pcm.Length; offset += bytesPerSample)
        {
            var sample = _format == HostPcmFormat.Float32
                ? BitConverter.Int32BitsToSingle(
                    BinaryPrimitives.ReadInt32LittleEndian(pcm[offset..]))
                : BinaryPrimitives.ReadInt16LittleEndian(pcm[offset..]) / 32768.0;
            if (!double.IsFinite(sample))
            {
                continue;
            }

            var magnitude = Math.Abs(sample);
            _peak = Math.Max(_peak, magnitude);
            _sumSquares += sample * sample;
            _sampleCount = checked(_sampleCount + 1);
            if (magnitude >= 0.99999)
            {
                _clippingCount = checked(_clippingCount + 1);
            }

            var channel = sampleIndex % _channels;
            if (_hasPreviousSamples[channel] &&
                ((_previousSamples[channel] < 0 && sample >= 0) ||
                 (_previousSamples[channel] >= 0 && sample < 0)))
            {
                _zeroCrossingCount = checked(_zeroCrossingCount + 1);
            }

            _previousSamples[channel] = sample;
            _hasPreviousSamples[channel] = true;
            sampleIndex++;
        }
    }

    public AudioPcmStatisticsSnapshot SnapshotAndReset()
    {
        var snapshot = new AudioPcmStatisticsSnapshot
        {
            Format = _format.ToString(),
            Channels = _channels,
            FrameCount = _frameCount,
            SampleCount = _sampleCount,
            Peak = _peak,
            Rms = _sampleCount == 0
                ? 0
                : Math.Sqrt(_sumSquares / _sampleCount),
            ClippingCount = _clippingCount,
            ZeroCrossingCount = _zeroCrossingCount,
        };

        _peak = 0;
        _sumSquares = 0;
        _sampleCount = 0;
        _frameCount = 0;
        _clippingCount = 0;
        _zeroCrossingCount = 0;
        Array.Clear(_previousSamples);
        Array.Clear(_hasPreviousSamples);
        return snapshot;
    }
}

public readonly record struct AudioPcmStatisticsSnapshot
{
    public AudioPcmStatisticsSnapshot()
    {
    }

    public string Format { get; init; } = string.Empty;
    public int Channels { get; init; }
    public long FrameCount { get; init; }
    public long SampleCount { get; init; }
    public double Peak { get; init; }
    public double Rms { get; init; }
    public long ClippingCount { get; init; }
    public long ZeroCrossingCount { get; init; }
}
