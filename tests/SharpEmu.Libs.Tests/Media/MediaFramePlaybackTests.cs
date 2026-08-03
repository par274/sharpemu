// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MediaFramePlaybackTests
{
    [Fact]
    public void FramesAdvanceAccordingToMovieClock()
    {
        using var playback = new MediaFramePlayback(new SequenceDecoder(1, 2, 3));

        Assert.Equal(1, WaitForAdvancedFrame(playback)[0]);
        Assert.True(playback.TryGetFrame(true, out var heldFrame, out var advanced));
        Assert.False(advanced);
        Assert.Equal(1, heldFrame[0]);

        Assert.Equal(2, WaitForAdvancedFrame(playback)[0]);
        Assert.Equal(3, WaitForAdvancedFrame(playback)[0]);
    }

    private static byte[] WaitForAdvancedFrame(MediaFramePlayback playback)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
            if (playback.TryGetFrame(true, out var frame, out var advanced) && advanced)
            {
                return frame;
            }

            Thread.Sleep(1);
        }

        throw new TimeoutException("The decoder did not produce a frame.");
    }

    [Fact]
    public void FirstFrameWaitsUntilPresentationStarts()
    {
        using var playback = new MediaFramePlayback(new SequenceDecoder(1, 2));

        var first = WaitForFrame(playback, advanceClock: false);
        Assert.Equal(1, first[0]);
        Thread.Sleep(100);

        Assert.True(playback.TryGetFrame(false, out var held, out var advanced));
        Assert.False(advanced);
        Assert.Equal(1, held[0]);

        Assert.True(playback.TryGetFrame(true, out held, out advanced));
        Assert.False(advanced);
        Assert.Equal(1, held[0]);
        Assert.Equal(2, WaitForAdvancedFrame(playback)[0]);
    }

    [Fact]
    public void IndependentMovieAudioStartsWhileFiveVideoDestinationsAreOwned()
    {
        var decoder = new SaturatedVideoDecoder();
        using var playback = new MediaFramePlayback(decoder);

        Assert.True(
            decoder.FiveDestinationsOwned.Wait(TimeSpan.FromSeconds(2)),
            "The video decoder did not reach the five-destination boundary.");
        Assert.True(playback.TryGetFrame(true, out _, out _));
        Assert.True(
            SpinWait.SpinUntil(
                () => decoder.AudioPumpCount > 0,
                TimeSpan.FromSeconds(2)),
            "The independent audio pump did not run after video backpressure.");
        Assert.Equal(5, decoder.VideoFramesProduced);
    }

    private static byte[] WaitForFrame(
        MediaFramePlayback playback,
        bool advanceClock)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
            if (playback.TryGetFrame(advanceClock, out var frame, out _))
            {
                return frame;
            }

            Thread.Sleep(1);
        }

        throw new TimeoutException("The decoder did not produce a frame.");
    }

    private sealed class SequenceDecoder(params byte[] values) : IMediaFrameDecoder
    {
        private int _index;

        public uint Width => 1;

        public uint Height => 1;

        // Keep frame boundaries far enough apart that a loaded CI runner cannot
        // skip an expected frame between polling iterations.
        public uint FramesPerSecondNumerator => 2;

        public uint FramesPerSecondDenominator => 1;

        public bool TryDecodeNextFrame(Span<byte> destination)
        {
            if (_index >= values.Length)
            {
                return false;
            }

            destination.Fill(values[_index++]);
            return true;
        }

        public void Dispose()
        {
        }
    }

    private sealed class SaturatedVideoDecoder :
        IMediaFrameDecoder,
        IMediaMovieAudio
    {
        private readonly ManualResetEventSlim _audioStop = new();
        private Thread? _audioThread;
        private int _disposed;
        private int _audioPumpCount;

        internal ManualResetEventSlim FiveDestinationsOwned { get; } = new();

        internal int VideoFramesProduced { get; private set; }

        internal int AudioPumpCount => Volatile.Read(ref _audioPumpCount);

        public uint Width => 1;

        public uint Height => 1;

        public uint FramesPerSecondNumerator => 30;

        public uint FramesPerSecondDenominator => 1;

        public bool HasAudioTrack => true;

        public bool TryDecodeNextFrame(Span<byte> destination)
        {
            destination[0] = checked((byte)(VideoFramesProduced + 1));
            VideoFramesProduced++;
            if (VideoFramesProduced == 5)
            {
                FiveDestinationsOwned.Set();
            }

            return true;
        }

        public void Start()
        {
            _audioThread = new Thread(() =>
            {
                while (!_audioStop.IsSet)
                {
                    Interlocked.Increment(ref _audioPumpCount);
                    Thread.SpinWait(256);
                }
            })
            {
                IsBackground = true,
                Name = "synthetic movie audio pump",
            };
            _audioThread.Start();
        }

        public MovieAudioProgress GetMovieAudioProgress() =>
            new(MovieAudioProgressState.Running, 0, false, string.Empty);

        public void Pause() => _audioStop.Reset();

        public void Resume()
        {
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _audioStop.Set();
            if (_audioThread is not null && Thread.CurrentThread != _audioThread)
            {
                _audioThread.Join();
            }

            FiveDestinationsOwned.Dispose();
            _audioStop.Dispose();
        }
    }
}
