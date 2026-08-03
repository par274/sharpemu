// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Tests.Media;

internal enum SyntheticMovieAudioState
{
    NoTrack,
    NotStarted,
    Running,
    TemporaryUnderrun,
    Paused,
    Completed,
    Failed,
    Disposed,
}

public enum SyntheticAudioFailure
{
    None,
    Open,
    Decoder,
    Submission,
    Device,
}

internal sealed class SyntheticNativeResource : IDisposable
{
    internal SyntheticNativeResource(string name) => Name = name;

    internal string Name { get; }

    internal int DisposeCount { get; private set; }

    internal bool IsDisposed => DisposeCount != 0;

    public void Dispose()
    {
        if (DisposeCount == 0)
        {
            DisposeCount = 1;
        }
    }
}

/// <summary>
/// Scalar ownership model for one independent media input. The model has one
/// live packet and frame slot, a bounded PCM submission buffer, and a bounded
/// host queue. It intentionally contains no media payloads.
/// </summary>
internal sealed class SyntheticMediaContext : IDisposable
{
    internal SyntheticMediaContext(string owner)
    {
        Input = new(owner + ".format");
        Codec = new(owner + ".codec");
        Packet = new(owner + ".packet");
        Frame = new(owner + ".frame");
        Resampler = new(owner + ".resampler");
        HostStream = new(owner + ".host-audio");
    }

    internal SyntheticNativeResource Input { get; }

    internal SyntheticNativeResource Codec { get; }

    internal SyntheticNativeResource Packet { get; }

    internal SyntheticNativeResource Frame { get; }

    internal SyntheticNativeResource Resampler { get; }

    internal SyntheticNativeResource HostStream { get; }

    internal IEnumerable<SyntheticNativeResource> Resources =>
        [Input, Codec, Packet, Frame, Resampler, HostStream];

    public void Dispose()
    {
        foreach (var resource in Resources)
        {
            resource.Dispose();
        }
    }
}

/// <summary>
/// Deterministic contract model for the production independent movie-audio
/// boundary. It covers ownership and lifecycle semantics without opening a
/// target asset or retaining packet/sample payloads in the test repository.
/// </summary>
internal sealed class IndependentMovieAudioContextExperiment : IDisposable
{
    internal const int VideoDestinationCount = 5;
    internal const int MaximumAudioPacketBytes = 4 * 1024;
    internal const int MaximumDecodedFrameBytes = 4 * 1024;
    internal const int MaximumSubmissionBytes = 4 * 1024;
    internal const int MaximumQueuedPcmBytes = 16 * 1024;
    internal const int MaximumDiagnosticEvents = 32;

    private const int SamplesPerSubmission = 1_024;
    private const int BytesPerSample = 4;

    private readonly SyntheticAudioFailure _failure;
    private readonly bool _diagnosticsEnabled;
    private readonly bool _hasAudioTrack;
    private int _audioPacketsRemaining = 4;
    private int _videoFramesRemaining = 8;
    private int _videoBuffersOwned;
    private int _queuedPcmBytes;
    private int _submittedPcmBytes;
    private double _lastClockSeconds;
    private double _fallbackBaseSeconds;
    private double _fallbackStartSeconds;
    private bool _fallbackClockStarted;
    private bool _paused;
    private bool _disposed;

    internal IndependentMovieAudioContextExperiment(
        long generation,
        bool hasAudioTrack,
        SyntheticAudioFailure failure = SyntheticAudioFailure.None,
        bool diagnosticsEnabled = false)
    {
        Generation = generation;
        _hasAudioTrack = hasAudioTrack;
        _failure = failure;
        _diagnosticsEnabled = diagnosticsEnabled;
        VideoContext = new SyntheticMediaContext("video");

        if (!hasAudioTrack)
        {
            State = SyntheticMovieAudioState.NoTrack;
            return;
        }

        if (failure == SyntheticAudioFailure.Open)
        {
            OpenAttemptContext = new SyntheticMediaContext("audio-open-attempt");
            OpenAttemptContext.Dispose();
            State = SyntheticMovieAudioState.Failed;
            FailureReason = "audio input open failed";
            return;
        }

        AudioContext = new SyntheticMediaContext("audio");
        State = SyntheticMovieAudioState.NotStarted;
    }

    internal long Generation { get; }

    internal SyntheticMediaContext VideoContext { get; }

    internal SyntheticMediaContext? AudioContext { get; }

    internal SyntheticMediaContext? OpenAttemptContext { get; }

    internal bool HasAudioTrack => _hasAudioTrack;

    internal SyntheticMovieAudioState State { get; private set; }

    internal string FailureReason { get; private set; } = string.Empty;

    internal bool AudioDemuxEof { get; private set; }

    internal bool AudioDecoderEof { get; private set; }

    internal bool AudioResamplerEof { get; private set; }

    internal bool HostAudioDrainComplete { get; private set; }

    internal bool VideoEof { get; private set; }

    internal int AudioPumpCount { get; private set; }

    internal int AudioPacketsDecoded { get; private set; }

    internal int AudioFramesDecoded { get; private set; }

    internal int AudioSubmissions { get; private set; }

    internal int VideoPumpCount { get; private set; }

    internal int VideoBuffersOwned => _videoBuffersOwned;

    internal int MaximumObservedLivePackets { get; private set; }

    internal int MaximumObservedLiveFrames { get; private set; }

    internal int MaximumObservedQueuedPcmBytes { get; private set; }

    internal int DiagnosticPayloadsBuilt { get; private set; }

    internal int SubmittedPcmBytes => _submittedPcmBytes;

    internal int QueuedPcmBytes => _queuedPcmBytes;

    internal double AudioSeconds =>
        Math.Max(0, _submittedPcmBytes - _queuedPcmBytes) /
        (48_000.0 * BytesPerSample);

    internal int RetainedBoundBytes =>
        VideoDestinationCount +
        (_hasAudioTrack
            ? MaximumAudioPacketBytes +
              MaximumDecodedFrameBytes +
              MaximumSubmissionBytes +
              MaximumQueuedPcmBytes
            : 0);

    internal bool IsMovieComplete =>
        VideoEof &&
        (_videoBuffersOwned == 0) &&
        (!_hasAudioTrack ||
         State == SyntheticMovieAudioState.Completed ||
         State == SyntheticMovieAudioState.Failed);

    internal bool PumpVideo()
    {
        if (_disposed || _videoBuffersOwned == VideoDestinationCount)
        {
            return false;
        }

        if (_videoFramesRemaining == 0)
        {
            VideoEof = true;
            return false;
        }

        _videoFramesRemaining--;
        _videoBuffersOwned++;
        VideoPumpCount++;
        return true;
    }

    internal void ReleaseVideoBuffer()
    {
        if (_videoBuffersOwned == 0)
        {
            throw new InvalidOperationException("No video destination is owned.");
        }

        _videoBuffersOwned--;
    }

    internal void ExhaustVideo()
    {
        _videoFramesRemaining = 0;
        VideoEof = true;
    }

    internal bool PumpAudio()
    {
        if (_disposed || !_hasAudioTrack || _paused || IsAudioTerminal)
        {
            return false;
        }

        AudioPumpCount++;
        if (_failure == SyntheticAudioFailure.Decoder)
        {
            Fail("audio decoder failed");
            return false;
        }

        if (_audioPacketsRemaining == 0)
        {
            AudioDemuxEof = true;
            AudioDecoderEof = true;
            AudioResamplerEof = true;
            TryCompleteAudio();
            return false;
        }

        if (_queuedPcmBytes + MaximumSubmissionBytes > MaximumQueuedPcmBytes)
        {
            State = SyntheticMovieAudioState.TemporaryUnderrun;
            return false;
        }

        var livePacket = 1;
        MaximumObservedLivePackets = Math.Max(MaximumObservedLivePackets, livePacket);
        _audioPacketsRemaining--;
        AudioPacketsDecoded++;

        var liveFrame = 1;
        MaximumObservedLiveFrames = Math.Max(MaximumObservedLiveFrames, liveFrame);
        AudioFramesDecoded++;

        if (_failure == SyntheticAudioFailure.Submission)
        {
            Fail("host audio submission failed");
            return false;
        }

        _submittedPcmBytes += MaximumSubmissionBytes;
        _queuedPcmBytes += MaximumSubmissionBytes;
        MaximumObservedQueuedPcmBytes = Math.Max(
            MaximumObservedQueuedPcmBytes,
            _queuedPcmBytes);
        AudioSubmissions++;
        State = SyntheticMovieAudioState.Running;
        if (_diagnosticsEnabled && DiagnosticPayloadsBuilt < MaximumDiagnosticEvents)
        {
            DiagnosticPayloadsBuilt++;
        }

        return true;
    }

    internal void DrainHostAudio(int bytes)
    {
        if (_disposed || !_hasAudioTrack || bytes < 0)
        {
            return;
        }

        if (_failure == SyntheticAudioFailure.Device)
        {
            Fail("host audio device failed");
            return;
        }

        _queuedPcmBytes = Math.Max(0, _queuedPcmBytes - bytes);
        if (_queuedPcmBytes == 0)
        {
            TryCompleteAudio();
            if (!HostAudioDrainComplete)
            {
                State = SyntheticMovieAudioState.TemporaryUnderrun;
            }
        }
        else if (!IsAudioTerminal && !_paused)
        {
            State = SyntheticMovieAudioState.Running;
        }
    }

    internal void ExhaustAudio()
    {
        _audioPacketsRemaining = 0;
        PumpAudio();
    }

    internal double ReadMovieClock(double wallSeconds)
    {
        if (wallSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(wallSeconds));
        }

        if (_disposed || _paused)
        {
            return _lastClockSeconds;
        }

        double selected;
        if (!_hasAudioTrack)
        {
            selected = wallSeconds;
        }
        else if (State is SyntheticMovieAudioState.Failed or
                 SyntheticMovieAudioState.Completed)
        {
            if (!_fallbackClockStarted)
            {
                _fallbackClockStarted = true;
                _fallbackStartSeconds = wallSeconds;
                _fallbackBaseSeconds = _lastClockSeconds;
            }

            selected = _fallbackBaseSeconds +
                Math.Max(0, wallSeconds - _fallbackStartSeconds);
        }
        else if (State is SyntheticMovieAudioState.TemporaryUnderrun or
                 SyntheticMovieAudioState.NotStarted or
                 SyntheticMovieAudioState.Paused)
        {
            selected = _lastClockSeconds;
        }
        else
        {
            selected = Math.Min(wallSeconds, AudioSeconds);
        }

        _lastClockSeconds = Math.Max(_lastClockSeconds, selected);
        return _lastClockSeconds;
    }

    internal void Pause()
    {
        if (_disposed || IsAudioTerminal || !_hasAudioTrack)
        {
            return;
        }

        _paused = true;
        State = SyntheticMovieAudioState.Paused;
    }

    internal void Resume()
    {
        if (_disposed || State == SyntheticMovieAudioState.Failed)
        {
            return;
        }

        _paused = false;
        State = SyntheticMovieAudioState.Running;
    }

    internal void Cancel() => Dispose();

    internal void Skip() => Dispose();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        AudioContext?.Dispose();
        VideoContext.Dispose();
        State = SyntheticMovieAudioState.Disposed;
    }

    private bool IsAudioTerminal =>
        State is SyntheticMovieAudioState.Failed or
        SyntheticMovieAudioState.Completed or
        SyntheticMovieAudioState.Disposed;

    private void TryCompleteAudio()
    {
        if (AudioDemuxEof && AudioDecoderEof && AudioResamplerEof &&
            _queuedPcmBytes == 0)
        {
            HostAudioDrainComplete = true;
            State = SyntheticMovieAudioState.Completed;
        }
    }

    private void Fail(string reason)
    {
        FailureReason = reason;
        State = SyntheticMovieAudioState.Failed;
        AudioContext?.HostStream.Dispose();
    }
}

internal sealed class SyntheticMovieGenerationHost : IDisposable
{
    private long _nextGeneration;

    internal IndependentMovieAudioContextExperiment? Current { get; private set; }

    internal IndependentMovieAudioContextExperiment Attach(
        bool hasAudioTrack,
        SyntheticAudioFailure failure = SyntheticAudioFailure.None)
    {
        Current?.Dispose();
        Current = new IndependentMovieAudioContextExperiment(
            ++_nextGeneration,
            hasAudioTrack,
            failure);
        return Current;
    }

    internal bool ApplyAudioCallback(
        long generation,
        Action<IndependentMovieAudioContextExperiment> callback)
    {
        var current = Current;
        if (current is null || current.Generation != generation ||
            current.State == SyntheticMovieAudioState.Disposed)
        {
            return false;
        }

        callback(current);
        return true;
    }

    internal void SkipCurrent() => Current?.Skip();

    public void Dispose() => Current?.Dispose();
}
