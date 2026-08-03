// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieAudioPumpContractTests
{
    [Fact]
    public void CurrentMediaFramePlaybackStopsCallingDecoderWhenFiveBuffersAreOwned()
    {
        var decoder = new InterleavedDecoder(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Audio(6),
            Video(7),
            Audio(8),
        ]);

        using (var playback = new MediaFramePlayback(decoder))
        {
            Assert.True(
                decoder.FiveBuffersOwned.Wait(TimeSpan.FromSeconds(2)),
                "The current decoder contract did not fill all five destinations.");
            Assert.Equal(5, decoder.DecodedVideoPacketSequences.Count);
            Assert.Empty(decoder.SubmittedAudioPacketSequences);
            Assert.Equal(3, decoder.RemainingPacketCount);
            Assert.Equal(5, decoder.TryDecodeNextFrameCalls);
        }

        Assert.True(decoder.IsDisposed);
    }

    [Fact]
    public void CurrentContractLeavesLaterInterleavedAudioBehindFrameBufferWait()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        var playback = new CurrentMediaFramePlaybackContract(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Audio(6),
            Video(7),
            Audio(8),
        ],
        audio);

        for (var index = 0; index < CurrentMediaFramePlaybackContract.VideoBufferCount; index++)
        {
            Assert.Equal(AuthoredPumpResult.Progress, playback.PumpOneFrame());
        }

        Assert.Equal(AuthoredPumpResult.Backpressure, playback.PumpOneFrame());
        Assert.True(playback.IsBlockedOnFrameBuffers);
        Assert.Equal(5, playback.OwnedVideoBufferCount);
        Assert.Equal(5, playback.DecoderCalls);
        Assert.Empty(audio.SubmittedPacketSequences);
        Assert.Equal(3, playback.RemainingPacketCount);
    }

    [Fact]
    public void BoundedPumpSubmitsAudioAfterAllVideoDestinationsAreOwned()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        using var pump = new BoundedPacketPumpExperiment(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Audio(6),
            Video(7, bytes: 3),
            Audio(8),
            Video(9, bytes: 3),
            Audio(10),
        ],
        audio,
        maximumDeferredPacketCount: 2,
        maximumDeferredBytes: 8);

        var result = pump.PumpUntilBlocked();

        Assert.Equal(AuthoredPumpResult.Backpressure, result);
        Assert.Equal(5, pump.OwnedVideoBufferCount);
        Assert.Equal([6, 8, 10], audio.SubmittedPacketSequences);
        Assert.Equal([7, 9], pump.DeferredVideoPackets.Select(packet => packet.Sequence));
        Assert.Equal(2, pump.DeferredPacketCount);
        Assert.Equal(6, pump.DeferredBytes);
        Assert.Equal(0, pump.RetainedDecodedFrameQueueCount);
    }

    [Fact]
    public void BoundedPacketDeferralPreservesVideoOrderAndBackpressuresAtBothBounds()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        using var pump = new BoundedPacketPumpExperiment(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Video(6, bytes: 4),
            Video(7, bytes: 4),
            Video(8, bytes: 5),
            Audio(9),
        ],
        audio,
        maximumDeferredPacketCount: 2,
        maximumDeferredBytes: 8);

        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.Equal([6, 7], pump.DeferredVideoPackets.Select(packet => packet.Sequence));
        Assert.Equal(2, pump.MaximumObservedDeferredPacketCount);
        Assert.Equal(8, pump.MaximumObservedDeferredBytes);
        Assert.Equal(8, pump.DeferredBytes);
        Assert.Equal(2, pump.RemainingPacketCount);
        Assert.Empty(audio.SubmittedPacketSequences);

        Assert.True(pump.TryGetOwnedBufferForPacket(1, out var firstBuffer), "packet 1 owned");
        Assert.True(pump.ReleaseVideoBuffer(firstBuffer), "release packet 1");
        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.True(pump.TryGetOwnedBufferForPacket(6, out var decodedSixBuffer), "packet 6 decoded");
        Assert.Equal(firstBuffer, decodedSixBuffer);
        Assert.Equal([7], pump.DeferredVideoPackets.Select(packet => packet.Sequence));

        Assert.True(pump.TryGetOwnedBufferForPacket(2, out var secondBuffer), "packet 2 owned");
        Assert.True(pump.ReleaseVideoBuffer(secondBuffer), "release packet 2");
        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.True(pump.TryGetOwnedBufferForPacket(7, out var decodedSevenBuffer), "packet 7 decoded");
        Assert.Equal(secondBuffer, decodedSevenBuffer);

        Assert.True(pump.TryGetOwnedBufferForPacket(3, out var thirdBuffer), "packet 3 owned");
        Assert.True(pump.ReleaseVideoBuffer(thirdBuffer), "release packet 3");
        Assert.Equal(AuthoredPumpResult.EndOfInput, pump.PumpUntilBlocked());
        Assert.True(pump.TryGetOwnedBufferForPacket(8, out var decodedEightBuffer), "packet 8 decoded");
        Assert.Equal(thirdBuffer, decodedEightBuffer);
        Assert.Equal([9], audio.SubmittedPacketSequences);
        Assert.Empty(pump.DeferredVideoPackets);
        Assert.True(pump.DemuxReachedEof, "demux EOF");
        Assert.True(pump.IsCompleted, "pump completed");

        var decodedVideoSequences = pump.Events
            .Where(pumpEvent => pumpEvent.Kind == "video-decoded")
            .Select(pumpEvent => pumpEvent.PacketSequence);
        Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8], decodedVideoSequences);
    }

    [Fact]
    public void SlowVideoConsumerDoesNotPermitOwnedBufferReuseWhileAudioPumps()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        using var pump = new BoundedPacketPumpExperiment(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Audio(6),
            Audio(7),
            Audio(8),
            Video(9),
        ],
        audio,
        maximumDeferredPacketCount: 1,
        maximumDeferredBytes: 4);

        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.Equal([6, 7, 8], audio.SubmittedPacketSequences);
        Assert.Equal(5, pump.OwnedVideoBufferCount);
        Assert.Equal(0, pump.RetainedDecodedFrameQueueCount);

        var ownedBeforeRelease = pump.OwnedFrames.Values
            .ToDictionary(frame => frame.PacketSequence, frame => frame.BufferId);
        Assert.True(pump.TryGetOwnedBufferForPacket(1, out var releasedBuffer));
        Assert.True(pump.ReleaseVideoBuffer(releasedBuffer));
        Assert.Equal(AuthoredPumpResult.EndOfInput, pump.PumpUntilBlocked());
        Assert.True(pump.TryGetOwnedBufferForPacket(9, out var newBuffer));
        Assert.Equal(releasedBuffer, newBuffer);

        foreach (var sequence in new[] { 2, 3, 4, 5 })
        {
            var currentBuffer = pump.OwnedFrames
                .Single(frame => frame.Value.PacketSequence == sequence)
                .Key;
            Assert.Equal(ownedBeforeRelease[sequence], currentBuffer);
        }
    }

    [Fact]
    public void AudioDeviceFailureDoesNotTurnTheVideoPumpIntoAnUnboundedQueue()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: false);
        using var pump = new BoundedPacketPumpExperiment(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Audio(6),
            Video(7),
            Audio(8),
        ],
        audio,
        maximumDeferredPacketCount: 1,
        maximumDeferredBytes: 4);

        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.True(pump.AudioFailed);
        Assert.Equal(2, audio.FailedSubmissions);
        Assert.Equal(1, pump.DeferredPacketCount);
        Assert.Equal(5, pump.OwnedVideoBufferCount);

        Assert.True(pump.TryGetOwnedBufferForPacket(1, out var buffer));
        Assert.True(pump.ReleaseVideoBuffer(buffer));
        Assert.Equal(AuthoredPumpResult.EndOfInput, pump.PumpUntilBlocked());
        Assert.True(pump.TryGetOwnedBufferForPacket(7, out _));
        Assert.Equal(0, pump.RetainedDecodedFrameQueueCount);
    }

    [Fact]
    public void NoAudioMovieReachesEofWithoutInventingAudioWork()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        using var pump = new BoundedPacketPumpExperiment(
        [Video(1), Video(2)],
        audio,
        maximumDeferredPacketCount: 1,
        maximumDeferredBytes: 4);

        Assert.Equal(AuthoredPumpResult.EndOfInput, pump.PumpUntilBlocked());
        Assert.True(pump.DemuxReachedEof);
        Assert.True(pump.IsCompleted);
        Assert.Empty(audio.SubmittedPacketSequences);
        Assert.Empty(pump.DeferredVideoPackets);
    }

    [Fact]
    public void DisposalReleasesDeferredPacketsAndStopsAnActivePump()
    {
        var audio = new AuthoredAudioSink(acceptsSubmissions: true);
        var pump = new BoundedPacketPumpExperiment(
        [
            Video(1),
            Video(2),
            Video(3),
            Video(4),
            Video(5),
            Video(6),
            Audio(7),
        ],
        audio,
        maximumDeferredPacketCount: 1,
        maximumDeferredBytes: 4);

        Assert.Equal(AuthoredPumpResult.Backpressure, pump.PumpUntilBlocked());
        Assert.Equal(1, pump.DeferredPacketCount);
        Assert.Equal(1, pump.DeferredBytes);
        var ownedBeforeDispose = pump.OwnedVideoBufferCount;

        pump.Dispose();

        Assert.True(pump.IsDisposed);
        Assert.Equal(1, pump.ReleasedDeferredPacketCount);
        Assert.Equal(0, pump.DeferredPacketCount);
        Assert.Equal(0, pump.DeferredBytes);
        Assert.Equal(ownedBeforeDispose, pump.OwnedVideoBufferCount);
        Assert.True(audio.IsDisposed);
        Assert.Equal(1, audio.DisposeCount);
        Assert.Equal(AuthoredPumpResult.Disposed, pump.PumpOne());
        pump.Dispose();
        Assert.Equal(1, audio.DisposeCount);
    }

    private static AuthoredPacket Video(int sequence, int bytes = 1) =>
        new(sequence, AuthoredPacketKind.Video, bytes);

    private static AuthoredPacket Audio(int sequence, double seconds = 0.1) =>
        new(sequence, AuthoredPacketKind.Audio, 1, seconds);

    private sealed class InterleavedDecoder(IEnumerable<AuthoredPacket> packets) :
        IMediaFrameDecoder
    {
        private readonly Queue<AuthoredPacket> _packets = new(packets);

        internal ManualResetEventSlim FiveBuffersOwned { get; } = new();

        internal List<int> DecodedVideoPacketSequences { get; } = [];

        internal List<int> SubmittedAudioPacketSequences { get; } = [];

        internal int TryDecodeNextFrameCalls { get; private set; }

        internal int RemainingPacketCount
        {
            get
            {
                lock (_packets)
                {
                    return _packets.Count;
                }
            }
        }

        internal bool IsDisposed { get; private set; }

        public uint Width => 1;

        public uint Height => 1;

        public uint FramesPerSecondNumerator => 30;

        public uint FramesPerSecondDenominator => 1;

        public bool TryDecodeNextFrame(Span<byte> destination)
        {
            TryDecodeNextFrameCalls++;
            while (true)
            {
                AuthoredPacket packet;
                lock (_packets)
                {
                    if (_packets.Count == 0)
                    {
                        return false;
                    }

                    packet = _packets.Dequeue();
                }

                if (packet.Kind == AuthoredPacketKind.Audio)
                {
                    SubmittedAudioPacketSequences.Add(packet.Sequence);
                    continue;
                }

                if (packet.Kind != AuthoredPacketKind.Video)
                {
                    continue;
                }

                destination.Fill((byte)packet.Sequence);
                DecodedVideoPacketSequences.Add(packet.Sequence);
                if (DecodedVideoPacketSequences.Count == CurrentMediaFramePlaybackContract.VideoBufferCount)
                {
                    FiveBuffersOwned.Set();
                }

                return true;
            }
        }

        public void Dispose()
        {
            IsDisposed = true;
            FiveBuffersOwned.Dispose();
        }
    }
}
