// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Tests.Media;

internal enum AuthoredPacketKind
{
    Video,
    Audio,
    Other,
}

internal readonly record struct AuthoredPacket(
    int Sequence,
    AuthoredPacketKind Kind,
    int PayloadBytes,
    double AudioSeconds = 0);

internal readonly record struct AuthoredDecodedFrame(
    int PacketSequence,
    int BufferId);

internal enum AuthoredPumpResult
{
    Progress,
    Backpressure,
    EndOfInput,
    Disposed,
}

internal sealed class AuthoredAudioSink(bool acceptsSubmissions) : IDisposable
{
    private readonly bool _acceptsSubmissions = acceptsSubmissions;

    public List<int> SubmittedPacketSequences { get; } = [];

    public int FailedSubmissions { get; private set; }

    public bool IsDisposed { get; private set; }

    public int DisposeCount { get; private set; }

    public bool Submit(AuthoredPacket packet)
    {
        if (IsDisposed)
        {
            return false;
        }

        if (!_acceptsSubmissions)
        {
            FailedSubmissions++;
            return false;
        }

        SubmittedPacketSequences.Add(packet.Sequence);
        return true;
    }

    public void Dispose()
    {
        if (IsDisposed)
        {
            return;
        }

        IsDisposed = true;
        DisposeCount++;
    }
}

/// <summary>
/// Test-only replay of the current MediaFramePlayback/IMediaFrameDecoder
/// boundary. The real playback thread waits before calling TryDecodeNextFrame
/// when all five destinations are owned; this model makes that ordering
/// deterministic without changing production code.
/// </summary>
internal sealed class CurrentMediaFramePlaybackContract
{
    internal const int VideoBufferCount = 5;

    private readonly Queue<AuthoredPacket> _packets;
    private readonly Queue<int> _freeBuffers = new(Enumerable.Range(0, VideoBufferCount));
    private readonly Dictionary<int, AuthoredDecodedFrame> _ownedFrames = [];
    private readonly AuthoredAudioSink _audioSink;

    internal CurrentMediaFramePlaybackContract(
        IEnumerable<AuthoredPacket> packets,
        AuthoredAudioSink audioSink)
    {
        _packets = new Queue<AuthoredPacket>(packets);
        _audioSink = audioSink;
    }

    internal int DecoderCalls { get; private set; }

    internal int RemainingPacketCount => _packets.Count;

    internal int OwnedVideoBufferCount => _ownedFrames.Count;

    internal bool IsBlockedOnFrameBuffers { get; private set; }

    internal IReadOnlyDictionary<int, AuthoredDecodedFrame> OwnedFrames => _ownedFrames;

    internal AuthoredPumpResult PumpOneFrame()
    {
        if (_freeBuffers.Count == 0)
        {
            IsBlockedOnFrameBuffers = true;
            return AuthoredPumpResult.Backpressure;
        }

        IsBlockedOnFrameBuffers = false;
        var bufferId = _freeBuffers.Dequeue();
        DecoderCalls++;

        while (_packets.Count > 0)
        {
            var packet = _packets.Dequeue();
            if (packet.Kind == AuthoredPacketKind.Audio)
            {
                _audioSink.Submit(packet);
                continue;
            }

            if (packet.Kind != AuthoredPacketKind.Video)
            {
                continue;
            }

            _ownedFrames.Add(
                bufferId,
                new AuthoredDecodedFrame(packet.Sequence, bufferId));
            return AuthoredPumpResult.Progress;
        }

        _freeBuffers.Enqueue(bufferId);
        return AuthoredPumpResult.EndOfInput;
    }

    internal bool ReleaseVideoBuffer(int bufferId)
    {
        if (!_ownedFrames.Remove(bufferId))
        {
            return false;
        }

        _freeBuffers.Enqueue(bufferId);
        IsBlockedOnFrameBuffers = false;
        return true;
    }
}

internal readonly record struct AuthoredPumpEvent(
    string Kind,
    int PacketSequence,
    int BufferId = -1);

/// <summary>
/// Dormant, test-only candidate for one demux context with bounded compressed
/// video-packet deferral. It deliberately models no decoded-frame queue: each
/// decoded video packet owns one of the five external destinations until the
/// test consumer releases that exact buffer.
/// </summary>
internal sealed class BoundedPacketPumpExperiment : IDisposable
{
    internal const int VideoBufferCount = 5;

    private readonly Queue<AuthoredPacket> _packets;
    private readonly Queue<AuthoredPacket> _deferredVideoPackets = [];
    private readonly Queue<int> _freeBuffers = new(Enumerable.Range(0, VideoBufferCount));
    private readonly Dictionary<int, AuthoredDecodedFrame> _ownedFrames = [];
    private readonly List<AuthoredPumpEvent> _events = [];
    private readonly AuthoredAudioSink _audioSink;
    private readonly int _maximumDeferredPacketCount;
    private readonly int _maximumDeferredBytes;
    private bool _demuxReachedEof;
    private bool _disposed;
    private int _deferredBytes;

    internal BoundedPacketPumpExperiment(
        IEnumerable<AuthoredPacket> packets,
        AuthoredAudioSink audioSink,
        int maximumDeferredPacketCount,
        int maximumDeferredBytes)
    {
        if (maximumDeferredPacketCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDeferredPacketCount));
        }

        if (maximumDeferredBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDeferredBytes));
        }

        _packets = new Queue<AuthoredPacket>(packets);
        _audioSink = audioSink;
        _maximumDeferredPacketCount = maximumDeferredPacketCount;
        _maximumDeferredBytes = maximumDeferredBytes;
    }

    internal IReadOnlyList<AuthoredPumpEvent> Events => _events;

    internal IReadOnlyDictionary<int, AuthoredDecodedFrame> OwnedFrames => _ownedFrames;

    internal IReadOnlyList<AuthoredPacket> DeferredVideoPackets =>
        _deferredVideoPackets.ToArray();

    internal int DeferredPacketCount => _deferredVideoPackets.Count;

    internal int DeferredBytes => _deferredBytes;

    internal int MaximumObservedDeferredPacketCount { get; private set; }

    internal int MaximumObservedDeferredBytes { get; private set; }

    internal int RetainedDecodedFrameQueueCount => 0;

    internal int OwnedVideoBufferCount => _ownedFrames.Count;

    internal int RemainingPacketCount => _packets.Count;

    internal bool DemuxReachedEof => _demuxReachedEof;

    internal bool IsCompleted { get; private set; }

    internal bool IsDisposed => _disposed;

    internal bool AudioFailed { get; private set; }

    internal int ReleasedDeferredPacketCount { get; private set; }

    internal AuthoredPumpResult PumpOne()
    {
        if (_disposed)
        {
            return AuthoredPumpResult.Disposed;
        }

        if (_freeBuffers.Count > 0)
        {
            if (_deferredVideoPackets.Count > 0)
            {
                var deferred = _deferredVideoPackets.Dequeue();
                _deferredBytes -= deferred.PayloadBytes;
                DecodeVideo(deferred);
                if (_demuxReachedEof && _deferredVideoPackets.Count == 0)
                {
                    IsCompleted = true;
                }
                return AuthoredPumpResult.Progress;
            }

            if (!TryDequeuePacket(out var packet))
            {
                _demuxReachedEof = true;
                IsCompleted = true;
                return AuthoredPumpResult.EndOfInput;
            }

            return ProcessPacketWithVideoDestination(packet);
        }

        if (_demuxReachedEof)
        {
            // A deferred packet is still a live compressed input, not an EOF.
            // The consumer must release a destination before it can be decoded.
            return _deferredVideoPackets.Count == 0
                ? AuthoredPumpResult.EndOfInput
                : AuthoredPumpResult.Backpressure;
        }

        if (!TryPeekPacket(out var nextPacket))
        {
            _demuxReachedEof = true;
            IsCompleted = _deferredVideoPackets.Count == 0;
            return _deferredVideoPackets.Count == 0
                ? AuthoredPumpResult.EndOfInput
                : AuthoredPumpResult.Backpressure;
        }

        if (nextPacket.Kind == AuthoredPacketKind.Video)
        {
            if (_deferredVideoPackets.Count >= _maximumDeferredPacketCount ||
                _deferredBytes > _maximumDeferredBytes - nextPacket.PayloadBytes)
            {
                return AuthoredPumpResult.Backpressure;
            }

            _ = TryDequeuePacket(out var deferredPacket);
            _deferredVideoPackets.Enqueue(deferredPacket);
            _deferredBytes += deferredPacket.PayloadBytes;
            MaximumObservedDeferredPacketCount = Math.Max(
                MaximumObservedDeferredPacketCount,
                _deferredVideoPackets.Count);
            MaximumObservedDeferredBytes = Math.Max(
                MaximumObservedDeferredBytes,
                _deferredBytes);
            AddEvent(new AuthoredPumpEvent("video-deferred", deferredPacket.Sequence));
            return AuthoredPumpResult.Progress;
        }

        _ = TryDequeuePacket(out var packetWithoutVideoDestination);
        return ProcessAudioOrOther(packetWithoutVideoDestination);
    }

    internal AuthoredPumpResult PumpUntilBlocked()
    {
        while (true)
        {
            var result = PumpOne();
            if (result != AuthoredPumpResult.Progress)
            {
                return result;
            }
        }
    }

    internal bool ReleaseVideoBuffer(int bufferId)
    {
        if (_disposed || !_ownedFrames.Remove(bufferId))
        {
            return false;
        }

        _freeBuffers.Enqueue(bufferId);
        return true;
    }

    internal bool TryGetOwnedBufferForPacket(
        int packetSequence,
        out int bufferId)
    {
        foreach (var pair in _ownedFrames)
        {
            if (pair.Value.PacketSequence == packetSequence)
            {
                bufferId = pair.Key;
                return true;
            }
        }

        bufferId = -1;
        return false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ReleasedDeferredPacketCount += _deferredVideoPackets.Count;
        _deferredVideoPackets.Clear();
        _deferredBytes = 0;
        _packets.Clear();
        _audioSink.Dispose();
    }

    private AuthoredPumpResult ProcessPacketWithVideoDestination(AuthoredPacket packet)
    {
        return packet.Kind switch
        {
            AuthoredPacketKind.Video => DecodeVideo(packet),
            AuthoredPacketKind.Audio or AuthoredPacketKind.Other =>
                ProcessAudioOrOther(packet),
            _ => throw new ArgumentOutOfRangeException(),
        };
    }

    private AuthoredPumpResult ProcessAudioOrOther(AuthoredPacket packet)
    {
        if (packet.Kind != AuthoredPacketKind.Audio)
        {
            AddEvent(new AuthoredPumpEvent("packet-discarded", packet.Sequence));
            return AuthoredPumpResult.Progress;
        }

        var submitted = _audioSink.Submit(packet);
        if (!submitted)
        {
            AudioFailed = true;
            AddEvent(new AuthoredPumpEvent("audio-failed", packet.Sequence));
        }
        else
        {
            AddEvent(new AuthoredPumpEvent("audio-submitted", packet.Sequence));
        }

        return AuthoredPumpResult.Progress;
    }

    private AuthoredPumpResult DecodeVideo(AuthoredPacket packet)
    {
        if (_freeBuffers.Count == 0)
        {
            throw new InvalidOperationException(
                "The experiment attempted to decode into an owned buffer.");
        }

        var bufferId = _freeBuffers.Dequeue();
        _ownedFrames.Add(
            bufferId,
            new AuthoredDecodedFrame(packet.Sequence, bufferId));
        AddEvent(new AuthoredPumpEvent("video-decoded", packet.Sequence, bufferId));
        return AuthoredPumpResult.Progress;
    }

    private bool TryPeekPacket(out AuthoredPacket packet)
    {
        if (_packets.Count == 0)
        {
            packet = default;
            return false;
        }

        packet = _packets.Peek();
        return true;
    }

    private bool TryDequeuePacket(out AuthoredPacket packet)
    {
        if (_packets.Count == 0)
        {
            packet = default;
            return false;
        }

        packet = _packets.Dequeue();
        return true;
    }

    private void AddEvent(AuthoredPumpEvent pumpEvent) => _events.Add(pumpEvent);
}
