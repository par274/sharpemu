// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.Libs.Audio;
using Xunit;

namespace SharpEmu.Libs.Tests.Audio;

public sealed class GuestAudioProducerDiagnosticsTests
{
    [Fact]
    public void StereoMetricsKeepLeftAndRightSeparate()
    {
        Span<byte> pcm = stackalloc byte[4 * 2];
        WriteS16(pcm, 0, -32768);
        WriteS16(pcm, 1, 16384);
        WriteS16(pcm, 2, 0);
        WriteS16(pcm, 3, -32768);

        var metrics = GuestAudioDiagnostics.MeasureInterleaved(
            pcm,
            frames: 2,
            channels: 2,
            bytesPerSample: sizeof(short),
            isFloat: false);

        Assert.Equal(1.0, metrics.LeftPeak, precision: 12);
        Assert.Equal(1.0, metrics.RightPeak, precision: 12);
        Assert.Equal(Math.Sqrt(0.5), metrics.LeftRms, precision: 12);
        Assert.Equal(Math.Sqrt(0.625), metrics.RightRms, precision: 12);
        Assert.Equal(0.0, metrics.OtherPeak);
    }

    [Fact]
    public void MonoMetricsMirrorTheSingleGuestChannel()
    {
        Span<byte> pcm = stackalloc byte[sizeof(short) * 2];
        WriteS16(pcm, 0, 8192);
        WriteS16(pcm, 1, -16384);

        var metrics = GuestAudioDiagnostics.MeasureInterleaved(
            pcm,
            frames: 2,
            channels: 1,
            bytesPerSample: sizeof(short),
            isFloat: false);

        Assert.Equal(metrics.LeftPeak, metrics.RightPeak);
        Assert.Equal(metrics.LeftRms, metrics.RightRms);
    }

    [Fact]
    public void EightChannelMetricsExposeFrontAndOtherEnergy()
    {
        Span<byte> pcm = stackalloc byte[8 * sizeof(short)];
        WriteS16(pcm, 0, 4096);
        WriteS16(pcm, 1, -8192);
        WriteS16(pcm, 2, 12288);
        WriteS16(pcm, 3, 0);
        WriteS16(pcm, 4, 16384);
        WriteS16(pcm, 5, -2048);
        WriteS16(pcm, 6, 0);
        WriteS16(pcm, 7, -24576);

        var metrics = GuestAudioDiagnostics.MeasureInterleaved(
            pcm,
            frames: 1,
            channels: 8,
            bytesPerSample: sizeof(short),
            isFloat: false);

        Assert.Equal(4096 / 32768.0, metrics.LeftPeak, precision: 12);
        Assert.Equal(8192 / 32768.0, metrics.RightPeak, precision: 12);
        Assert.Equal(24576 / 32768.0, metrics.OtherPeak, precision: 12);
    }

    [Fact]
    public void FloatAndMixedMetricsRemainFinite()
    {
        Span<byte> pcm = stackalloc byte[sizeof(float) * 2];
        BinaryPrimitives.WriteSingleLittleEndian(pcm, 0.25f);
        BinaryPrimitives.WriteSingleLittleEndian(pcm[sizeof(float)..], float.NaN);

        var input = GuestAudioDiagnostics.MeasureInterleaved(
            pcm,
            frames: 1,
            channels: 2,
            bytesPerSample: sizeof(float),
            isFloat: true);
        var mixed = GuestAudioDiagnostics.MeasureStereoFloat([0.5f, -0.25f], frames: 1);

        Assert.Equal(0.25, input.LeftPeak, precision: 12);
        Assert.Equal(0.0, input.RightPeak);
        Assert.Equal(0.5, mixed.LeftPeak, precision: 12);
        Assert.Equal(0.25, mixed.RightPeak, precision: 12);
    }

    [Fact]
    public void BufferTraceDistinguishesAddressReuseFromContentChange()
    {
        var trace = new GuestAudioBufferTrace();
        byte[] first = [1, 2, 3, 4];
        byte[] changed = [1, 2, 3, 5];

        var initial = trace.Observe(0x1000, first, 1, 2, 2, isFloat: false);
        var repeated = trace.Observe(0x1000, first, 1, 2, 2, isFloat: false);
        var mutated = trace.Observe(0x1000, changed, 1, 2, 2, isFloat: false);
        var moved = trace.Observe(0x2000, changed, 1, 2, 2, isFloat: false);

        Assert.Equal(1, initial.Sequence);
        Assert.False(initial.SameAddressAsPrevious);
        Assert.True(repeated.SameAddressAsPrevious);
        Assert.True(repeated.SameContentAsPrevious);
        Assert.Equal(1, repeated.SameAddressCount);
        Assert.Equal(1, repeated.SameContentCount);
        Assert.True(mutated.SameAddressAsPrevious);
        Assert.False(mutated.SameContentAsPrevious);
        Assert.Equal(2, mutated.SameAddressCount);
        Assert.Equal(1, mutated.SameContentCount);
        Assert.False(moved.SameAddressAsPrevious);
        Assert.True(moved.SameContentAsPrevious);
        Assert.Equal(2, moved.SameContentCount);
    }

    [Fact]
    public void SkippedObservationPreservesPendingStateWithoutFingerprinting()
    {
        var trace = new GuestAudioBufferTrace();

        var skipped = trace.ObserveSkipped(0x4000, byteLength: 1024, pendingBefore: 0);

        Assert.Equal(1, skipped.Sequence);
        Assert.Equal(0x4000UL, skipped.Address);
        Assert.Equal(1024, skipped.ByteLength);
        Assert.Equal(0, skipped.PendingBefore);
    }

    [Fact]
    public void SamplingRuleIsBoundedAndDeterministic()
    {
        Assert.True(GuestAudioDiagnostics.ShouldEmit(1));
        Assert.True(GuestAudioDiagnostics.ShouldEmit(4));
        Assert.False(GuestAudioDiagnostics.ShouldEmit(5));
        Assert.True(GuestAudioDiagnostics.ShouldEmit(8));
        Assert.False(GuestAudioDiagnostics.ShouldEmit(9));
        Assert.True(GuestAudioDiagnostics.ShouldEmit(16));

        Assert.NotEqual(
            GuestAudioDiagnostics.Fingerprint([1, 2, 3]),
            GuestAudioDiagnostics.Fingerprint([1, 2, 4]));
    }

    private static void WriteS16(Span<byte> destination, int sample, short value) =>
        BinaryPrimitives.WriteInt16LittleEndian(
            destination[(sample * sizeof(short))..],
            value);
}
