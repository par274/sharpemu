// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieAudioPumpContractTests
{
    [Fact]
    public void AudioPumpsWhenAllFiveExternalDestinationsAreOwned()
    {
        var decoder = new SyntheticMovieDecoder(
        [
            Video(1), Video(2), Video(3), Video(4), Video(5),
            Audio(6), Video(7), Audio(8), Video(9), Audio(10),
        ],
        hasAudioTrack: true,
        videoGate: 5,
        audioGate: 3);

        using var playback = new MediaFramePlayback(decoder);

        decoder.WaitForVideoOutput(5);
        decoder.WaitForAudioPackets(3);

        Assert.Equal([1, 2, 3, 4, 5], decoder.ExternalVideoPackets);
        Assert.Equal([6, 8, 10], decoder.SubmittedAudioPackets);
        Assert.Equal(1, decoder.RetainedNextFrameCount);
        Assert.Equal(0, decoder.RetainedPacketCount);
        Assert.Equal(0, decoder.RetainedPacketBytes);
        Assert.True(decoder.PumpCalls > 0);
    }

    [Fact]
    public void SlowConsumerAcrossCompleteMovieKeepsRetainedStateBounded()
    {
        var packets = new List<SyntheticPacket>();
        for (var index = 0; index < 180; index++)
        {
            packets.Add(Video(index, index / 30.0));
            if (index % 6 == 5)
            {
                packets.Add(Audio(10_000 + index / 6));
            }
        }

        var decoder = new SyntheticMovieDecoder(packets, hasAudioTrack: true);
        var time = new FakeMonotonicClock();
        using var playback = new MediaFramePlayback(decoder, monotonicClock: time);

        decoder.WaitForVideoOutput(5);
        decoder.WaitForEndOfInput();

        // One presentation every 500 ms models the measured 2 FPS consumer.
        if (!playback.TryGetFrame(true, out _, out _))
        {
            throw new InvalidOperationException(
                $"video={decoder.ExternalVideoPackets.Count} remaining={decoder.RemainingPackets} " +
                $"pump={decoder.PumpCalls} state={decoder.PumpState}");
        }
        for (var index = 1; index <= 8; index++)
        {
            time.Advance(0.5);
            decoder.SetAudioProgress(index * 0.5);
            _ = playback.TryGetFrame(true, out _, out _);
        }

        Assert.Equal(
            180,
            decoder.PumpedVideoPackets.Count + decoder.ExternalVideoPackets.Count);
        Assert.Equal(30, decoder.SubmittedAudioPackets.Count);
        Assert.Equal(
            decoder.SubmittedAudioPackets.OrderBy(sequence => sequence),
            decoder.SubmittedAudioPackets);
        Assert.InRange(decoder.MaximumRetainedNextFrameCount, 0, 1);
        Assert.Equal(0, decoder.RetainedPacketCount);
        Assert.Equal(0, decoder.RetainedPacketBytes);
    }

    [Fact]
    public void LateDecodedVideoIsDiscardedUsingPacketTimestamp()
    {
        var decoder = new SyntheticMovieDecoder(
            [Video(1, 0), Video(2, 1.0 / 30), Audio(3)],
            hasAudioTrack: true);

        Assert.Equal(
            MediaPumpResult.EndOfInput,
            decoder.PumpAudioWhileVideoBackpressured(movieSeconds: 1.0));
        Assert.Equal([1, 2], decoder.PumpedVideoPackets);
        Assert.Equal(2, decoder.LateVideoFrameCount);
        Assert.Equal(0, decoder.RetainedNextFrameCount);
        Assert.Equal([3], decoder.SubmittedAudioPackets);
    }

    [Fact]
    public void NoAudioMovieDoesNotInvokeAudioPumpWhenDestinationsAreFull()
    {
        var decoder = new SyntheticMovieDecoder(
            [Video(1), Video(2), Video(3), Video(4), Video(5), Video(6)],
            hasAudioTrack: false,
            videoGate: 5);

        using var playback = new MediaFramePlayback(decoder);
        decoder.WaitForVideoOutput(5);

        Assert.Equal(0, decoder.PumpCalls);
        Assert.Equal(0, decoder.RetainedPacketCount);
        Assert.Equal(0, decoder.RetainedPacketBytes);
    }

    [Fact]
    public void DisposalDuringAudioPumpTerminatesTheOldDecoderIdentity()
    {
        var decoder = new SyntheticMovieDecoder(
            [Video(1), Video(2), Video(3), Video(4), Video(5), Audio(6)],
            hasAudioTrack: true,
            videoGate: 5,
            pausePumpUntilDisposed: true);

        var playback = new MediaFramePlayback(decoder);
        decoder.WaitForVideoOutput(5);
        decoder.WaitForPumpEntry();

        playback.Dispose();

        Assert.True(decoder.IsDisposed);
        Assert.Equal(0, decoder.RetainedPacketCount);
        Assert.Equal(0, decoder.RetainedPacketBytes);
    }

    private static SyntheticPacket Video(int sequence, double timestamp = 0) =>
        new(sequence, SyntheticPacketKind.Video, timestamp, 1.0 / 30.0);

    private static SyntheticPacket Audio(int sequence) =>
        new(sequence, SyntheticPacketKind.Audio, 0, 0);

    private sealed class SyntheticMovieDecoder :
        IMediaFrameDecoder,
        IMovieAudioProgressSource,
        IMediaPumpDiagnostics
    {
        private readonly Queue<SyntheticPacket> _packets;
        private readonly object _gate = new();
        private readonly int _videoGate;
        private readonly int _audioGate;
        private readonly bool _pausePumpUntilDisposed;
        private readonly ManualResetEventSlim _videoOutputReached = new();
        private readonly ManualResetEventSlim _audioPacketsReached = new();
        private readonly ManualResetEventSlim _endOfInputReached = new();
        private readonly ManualResetEventSlim _pumpEntered = new();
        private SyntheticPacket? _retainedNextFrame;
        private MovieAudioProgress _audioProgress =
            new(MovieAudioProgressState.Running, 0);
        private string _pumpState = "video-decode";
        private int _disposed;
        private int _videoOutputCount;

        internal SyntheticMovieDecoder(
            IEnumerable<SyntheticPacket> packets,
            bool hasAudioTrack,
            int videoGate = 0,
            int audioGate = 0,
            bool pausePumpUntilDisposed = false)
        {
            _packets = new Queue<SyntheticPacket>(packets);
            HasAudioTrack = hasAudioTrack;
            _videoGate = videoGate;
            _audioGate = audioGate;
            _pausePumpUntilDisposed = pausePumpUntilDisposed;
        }

        internal List<int> ExternalVideoPackets { get; } = [];

        internal List<int> PumpedVideoPackets { get; } = [];

        internal List<int> SubmittedAudioPackets { get; } = [];

        internal int PumpCalls { get; private set; }

        public long LateVideoFrameCount { get; private set; }

        internal int MaximumRetainedNextFrameCount { get; private set; }

        internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        internal void SetAudioProgress(double seconds) =>
            _audioProgress = new(MovieAudioProgressState.Running, seconds);

        internal int RemainingPackets
        {
            get
            {
                lock (_gate)
                {
                    return _packets.Count;
                }
            }
        }

        public uint Width => 1;

        public uint Height => 1;

        public uint FramesPerSecondNumerator => 30;

        public uint FramesPerSecondDenominator => 1;

        public bool HasAudioTrack { get; }

        public double? NextVideoWakeupSeconds =>
            _retainedNextFrame is { } frame
                ? frame.TimestampSeconds + frame.DurationSeconds
                : null;

        public string PumpState => Volatile.Read(ref _pumpState);

        public long RetainedNextFrameCount => _retainedNextFrame is null ? 0 : 1;

        public long RetainedPacketCount => 0;

        public long RetainedPacketBytes => 0;

        public MovieAudioProgress GetMovieAudioProgress() => _audioProgress;

        public bool TryDecodeNextFrame(Span<byte> destination, double movieSeconds)
        {
            lock (_gate)
            {
                if (IsDisposed)
                {
                    return false;
                }

                Volatile.Write(ref _pumpState, "video-decode");
                while (true)
                {
                    var packet = TakeNextVideoPacket(movieSeconds);
                    if (packet is null)
                    {
                        return false;
                    }

                    destination.Fill((byte)packet.Value.Sequence);
                    ExternalVideoPackets.Add(packet.Value.Sequence);
                    _videoOutputCount++;
                    if (_videoGate > 0 && _videoOutputCount >= _videoGate)
                    {
                        _videoOutputReached.Set();
                    }

                    return true;
                }
            }
        }

        public MediaPumpResult PumpAudioWhileVideoBackpressured(double movieSeconds)
        {
            lock (_gate)
            {
                if (IsDisposed)
                {
                    return MediaPumpResult.Disposed;
                }

                _pumpEntered.Set();
                PumpCalls++;
                Volatile.Write(ref _pumpState, "audio-pump");

                if (_pausePumpUntilDisposed)
                {
                    SpinWait.SpinUntil(() => IsDisposed, TimeSpan.FromSeconds(2));
                    return MediaPumpResult.Disposed;
                }

                while (_packets.TryDequeue(out var packet))
                {
                    if (packet.Kind == SyntheticPacketKind.Audio)
                    {
                        SubmittedAudioPackets.Add(packet.Sequence);
                        if (_audioGate > 0 && SubmittedAudioPackets.Count >= _audioGate)
                        {
                            _audioPacketsReached.Set();
                        }

                        continue;
                    }

                    if (packet.Kind != SyntheticPacketKind.Video)
                    {
                        continue;
                    }

                    PumpedVideoPackets.Add(packet.Sequence);
                    if (IsLate(packet, movieSeconds))
                    {
                        LateVideoFrameCount++;
                        continue;
                    }

                    if (_retainedNextFrame is null)
                    {
                        _retainedNextFrame = packet;
                        MaximumRetainedNextFrameCount = Math.Max(
                            MaximumRetainedNextFrameCount,
                            1);
                    }
                }

                _endOfInputReached.Set();
                Volatile.Write(ref _pumpState, "drain");
                return _retainedNextFrame is null
                    ? MediaPumpResult.EndOfInput
                    : MediaPumpResult.Backpressure;
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            lock (_gate)
            {
                _packets.Clear();
                _retainedNextFrame = null;
                Volatile.Write(ref _pumpState, "disposed");
            }

            _videoOutputReached.Dispose();
            _audioPacketsReached.Dispose();
            _endOfInputReached.Dispose();
            _pumpEntered.Dispose();
        }

        internal void WaitForVideoOutput(int count)
        {
            if (_videoGate >= count && _videoGate > 0)
            {
                Assert.True(_videoOutputReached.Wait(TimeSpan.FromSeconds(2)));
                return;
            }

            if (!SpinWait.SpinUntil(
                    () => ExternalVideoPackets.Count >= count,
                    TimeSpan.FromSeconds(2)))
            {
                throw new InvalidOperationException(
                    $"video={ExternalVideoPackets.Count} remaining={RemainingPackets} " +
                    $"pump={PumpCalls} state={PumpState}");
            }
        }

        internal void WaitForAudioPackets(int count)
        {
            if (_audioGate >= count && _audioGate > 0)
            {
                Assert.True(_audioPacketsReached.Wait(TimeSpan.FromSeconds(2)));
                return;
            }

            Assert.True(
                SpinWait.SpinUntil(
                    () => SubmittedAudioPackets.Count >= count,
                    TimeSpan.FromSeconds(2)));
        }

        internal void WaitForEndOfInput()
        {
            if (!_endOfInputReached.Wait(TimeSpan.FromSeconds(2)))
            {
                throw new InvalidOperationException(
                    $"video={ExternalVideoPackets.Count} pumped={PumpedVideoPackets.Count} " +
                    $"remaining={RemainingPackets} pump={PumpCalls} state={PumpState}");
            }
        }

        internal void WaitForPumpEntry() =>
            Assert.True(_pumpEntered.Wait(TimeSpan.FromSeconds(2)));

        private SyntheticPacket? TakeNextVideoPacket(double movieSeconds)
        {
            while (true)
            {
                SyntheticPacket packet;
                if (_retainedNextFrame is { } retained)
                {
                    _retainedNextFrame = null;
                    packet = retained;
                }
                else if (!_packets.TryDequeue(out packet))
                {
                    _endOfInputReached.Set();
                    return null;
                }

                if (packet.Kind == SyntheticPacketKind.Audio)
                {
                    SubmittedAudioPackets.Add(packet.Sequence);
                    continue;
                }

                if (packet.Kind != SyntheticPacketKind.Video)
                {
                    continue;
                }

                if (IsLate(packet, movieSeconds))
                {
                    LateVideoFrameCount++;
                    continue;
                }

                return packet;
            }
        }

        private static bool IsLate(SyntheticPacket packet, double movieSeconds) =>
            packet.TimestampSeconds + packet.DurationSeconds <= movieSeconds;
    }

    private readonly record struct SyntheticPacket(
        int Sequence,
        SyntheticPacketKind Kind,
        double TimestampSeconds,
        double DurationSeconds);

    private enum SyntheticPacketKind
    {
        Video,
        Audio,
    }

    private sealed class FakeMonotonicClock : IMovieMonotonicClock
    {
        public double Seconds { get; private set; }

        internal void Advance(double seconds) => Seconds += seconds;
    }
}
