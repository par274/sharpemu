// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MediaFramePlaybackTests
{
    [Fact]
    public void FramesAdvanceAccordingToTheMovieClock()
    {
        var time = new FakeMonotonicClock();
        var decoder = new SequenceDecoder(1, 2, 3);
        using var playback = new MediaFramePlayback(decoder, monotonicClock: time);

        decoder.WaitForDecodedCount(3);
        Assert.True(playback.TryGetFrame(true, out var frame, out var advanced));
        Assert.True(advanced);
        Assert.Equal(1, frame[0]);

        Assert.True(playback.TryGetFrame(true, out frame, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, frame[0]);

        time.Advance(0.5);
        Assert.True(playback.TryGetFrame(true, out frame, out advanced));
        Assert.True(advanced);
        Assert.Equal(2, frame[0]);

        time.Advance(0.5);
        Assert.True(playback.TryGetFrame(true, out frame, out advanced));
        Assert.True(advanced);
        Assert.Equal(3, frame[0]);
    }

    [Fact]
    public void FirstFrameWaitsUntilPresentationStarts()
    {
        var time = new FakeMonotonicClock();
        var decoder = new SequenceDecoder(1, 2);
        using var playback = new MediaFramePlayback(decoder, monotonicClock: time);

        decoder.WaitForDecodedCount(2);
        Assert.True(playback.TryGetFrame(false, out var first, out var advanced));
        Assert.True(advanced);
        Assert.Equal(1, first[0]);

        time.Advance(100);
        Assert.True(playback.TryGetFrame(false, out var held, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, held[0]);

        Assert.True(playback.TryGetFrame(true, out held, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, held[0]);

        time.Advance(0.5);
        Assert.True(playback.TryGetFrame(true, out var second, out advanced));
        Assert.True(advanced);
        Assert.Equal(2, second[0]);
    }

    [Fact]
    public void PresentationGatePauseHoldsAndResumeRebasesMovieTime()
    {
        var time = new FakeMonotonicClock();
        var decoder = new SequenceDecoder(1, 2, 3);
        using var playback = new MediaFramePlayback(decoder, monotonicClock: time);

        decoder.WaitForDecodedCount(3);
        Assert.True(playback.TryGetFrame(true, out var frame, out _));
        Assert.Equal(1, frame[0]);

        time.Advance(0.1);
        Assert.True(playback.TryGetFrame(false, out frame, out var advanced));
        Assert.False(advanced);
        Assert.Equal(1, frame[0]);

        time.Advance(5);
        Assert.True(playback.TryGetFrame(false, out frame, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, frame[0]);

        Assert.True(playback.TryGetFrame(true, out frame, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, frame[0]);

        time.Advance(0.4);
        Assert.True(playback.TryGetFrame(true, out frame, out advanced));
        Assert.True(advanced);
        Assert.Equal(2, frame[0]);
    }

    private sealed class SequenceDecoder(params byte[] values) : IMediaFrameDecoder
    {
        private readonly ManualResetEventSlim _decoded = new();
        private int _index;

        internal int DecodedCount => Volatile.Read(ref _index);

        public uint Width => 1;

        public uint Height => 1;

        public uint FramesPerSecondNumerator => 2;

        public uint FramesPerSecondDenominator => 1;

        public bool HasAudioTrack => false;

        public bool TryDecodeNextFrame(Span<byte> destination, double movieSeconds)
        {
            var index = Interlocked.Increment(ref _index) - 1;
            if (index >= values.Length)
            {
                return false;
            }

            destination.Fill(values[index]);
            _decoded.Set();
            return true;
        }

        public MediaPumpResult PumpAudioWhileVideoBackpressured(double movieSeconds) =>
            MediaPumpResult.Backpressure;

        internal void WaitForDecodedCount(int count)
        {
            Assert.True(
                SpinWait.SpinUntil(
                    () => DecodedCount >= count,
                    TimeSpan.FromSeconds(2)),
                $"The decoder produced {DecodedCount} frames, expected {count}.");
        }

        public void Dispose() => _decoded.Dispose();
    }

    private sealed class FakeMonotonicClock : IMovieMonotonicClock
    {
        public double Seconds { get; private set; }

        internal void Advance(double seconds) => Seconds += seconds;
    }
}
