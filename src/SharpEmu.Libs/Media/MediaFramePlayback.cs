// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using SharpEmu.HLE.Host;

namespace SharpEmu.Libs.Media;

internal interface IMediaFrameDecoder : IDisposable
{
    uint Width { get; }

    uint Height { get; }

    uint FramesPerSecondNumerator { get; }

    uint FramesPerSecondDenominator { get; }

    bool HasAudioTrack { get; }

    bool TryDecodeNextFrame(Span<byte> destination, double movieSeconds);

    MediaPumpResult PumpAudioWhileVideoBackpressured(double movieSeconds);
}

internal enum MediaPumpResult
{
    Progress,
    Backpressure,
    EndOfInput,
    Failed,
    Disposed,
}

internal interface IMediaAudioDiagnostics
{
    void SetMovieDiagnosticIdentity(
        string source,
        long movieInstanceId,
        long hostMovieGeneration);

    void SetDiagnosticPhase(string phase);
}

internal interface IMediaPumpDiagnostics
{
    string PumpState { get; }

    long LateVideoFrameCount { get; }

    long RetainedNextFrameCount { get; }

    long RetainedPacketCount { get; }

    long RetainedPacketBytes { get; }
}

/// <summary>
/// Keeps blocking codec work away from the Vulkan presentation thread and
/// releases decoded frames according to the movie time base.
/// </summary>
internal sealed class MediaFramePlayback : IDisposable
{
    private const int BufferCount = 5;

    private readonly object _gate = new();
    private readonly IMediaFrameDecoder _decoder;
    private readonly IMediaAudioDiagnostics? _audioDiagnostics;
    private readonly IMovieAudioProgressSource? _audioProgress;
    private readonly IMediaPumpDiagnostics? _pumpDiagnostics;
    private readonly MovieTimeline _timeline;
    private readonly long _diagnosticMovieInstanceId;
    private readonly Queue<byte[]> _freeBuffers = new();
    private readonly Queue<DecodedFrame> _decodedFrames = new();
    private readonly Thread _decoderThread;
    private byte[]? _currentFrame;
    private byte[]? _retiredFrame;
    private long _currentFrameIndex = -1;
    private long _nextDecodedFrameIndex;
    private long _playbackStartTimestamp;
    private long _lastSkewTraceTimestamp;
    private long _diagnosticFramesAdvanced;
    private long _diagnosticFramesHeld;
    private long _diagnosticFramesSkipped;
    private long _diagnosticFramesRetired;
    private long _diagnosticFramesDiscarded;
    private bool _playbackClockStarted;
    private bool _decoderCompleted;
    private bool _stopRequested;
    private bool _finished;
    private int _disposed;

    internal MediaFramePlayback(
        IMediaFrameDecoder decoder,
        long diagnosticMovieInstanceId = 0,
        long movieGeneration = 0,
        IMovieMonotonicClock? monotonicClock = null)
    {
        _decoder = decoder;
        _audioDiagnostics = HostAudioDiagnostics.Enabled
            ? decoder as IMediaAudioDiagnostics
            : null;
        _audioProgress = decoder as IMovieAudioProgressSource;
        _pumpDiagnostics = decoder as IMediaPumpDiagnostics;
        _timeline = new MovieTimeline(
            movieGeneration,
            decoder.HasAudioTrack,
            monotonicClock);
        _diagnosticMovieInstanceId = diagnosticMovieInstanceId;
        Width = decoder.Width;
        Height = decoder.Height;
        FramesPerSecondNumerator = decoder.FramesPerSecondNumerator;
        FramesPerSecondDenominator = decoder.FramesPerSecondDenominator;

        var frameBytes = checked((int)((ulong)Width * Height * 4));
        for (var index = 0; index < BufferCount; index++)
        {
            _freeBuffers.Enqueue(GC.AllocateUninitializedArray<byte>(frameBytes));
        }

        _decoderThread = new Thread(DecodeLoop)
        {
            IsBackground = true,
            Name = "SharpEmu Bink video decoder",
        };
        _decoderThread.Start();
    }

    internal uint Width { get; }

    internal uint Height { get; }

    internal uint FramesPerSecondNumerator { get; }

    internal uint FramesPerSecondDenominator { get; }

    internal bool IsFinished
    {
        get
        {
            lock (_gate)
            {
                return _finished;
            }
        }
    }

    /// <summary>
    /// Movie-local seconds since the first frame was presented, and the index of
    /// the last frame shown. The selected source belongs to this movie
    /// generation, not to the process-wide guest audio clock.
    /// </summary>
    internal (double Seconds, long FrameIndex) PlaybackProgress
    {
        get
        {
            lock (_gate)
            {
                return (
                    _playbackClockStarted
                        ? CurrentPlaybackSecondsLocked()
                        : 0,
                    _currentFrameIndex);
            }
        }
    }

    internal bool TryGetFrame(
        bool advanceClock,
        out byte[] pixels,
        out bool advanced)
    {
        lock (_gate)
        {
            pixels = [];
            advanced = false;
            if (_finished)
            {
                return false;
            }

            if (_currentFrame is null)
            {
                if (_decodedFrames.Count == 0)
                {
                    if (_decoderCompleted)
                    {
                        _finished = true;
                    }
                    return false;
                }

                var first = _decodedFrames.Dequeue();
                _currentFrame = first.Pixels;
                _currentFrameIndex = first.Index;
                advanced = true;
                Monitor.PulseAll(_gate);
            }

            if (advanceClock)
            {
                var audioProgress = CurrentMovieAudioProgressLocked();
                if (!_playbackClockStarted)
                {
                    _playbackStartTimestamp = Stopwatch.GetTimestamp();
                    _timeline.Start(audioProgress);
                    _playbackClockStarted = true;
                    MovieDiagnostics.Start(
                        _diagnosticMovieInstanceId,
                        audioProgress,
                        _timeline.Mode);
                }
                else
                {
                    _timeline.Resume(audioProgress);
                }
            }
            else if (_playbackClockStarted)
            {
                _timeline.Pause(CurrentMovieAudioProgressLocked());
            }

            var elapsedSeconds = CurrentPlaybackSecondsLocked();
            TraceClockSkewLocked();
            var targetFrameIndex = CurrentTargetFrameIndexLocked();
            DecodedFrame? replacement = null;
            while (_decodedFrames.Count > 0 &&
                   _decodedFrames.Peek().Index <= targetFrameIndex)
            {
                if (replacement is { } skipped)
                {
                    _freeBuffers.Enqueue(skipped.Pixels);
                    if (MovieDiagnostics.Enabled)
                    {
                        _diagnosticFramesSkipped++;
                    }
                }
                replacement = _decodedFrames.Dequeue();
            }

            if (replacement is { } next)
            {
                if (_retiredFrame is not null)
                {
                    _freeBuffers.Enqueue(_retiredFrame);
                }
                _retiredFrame = _currentFrame;
                _currentFrame = next.Pixels;
                _currentFrameIndex = next.Index;
                advanced = true;
                if (MovieDiagnostics.Enabled)
                {
                    _diagnosticFramesRetired++;
                }
                Monitor.PulseAll(_gate);
            }

            var frameDurationSeconds =
                (double)FramesPerSecondDenominator / FramesPerSecondNumerator;
            if (_playbackClockStarted &&
                _decoderCompleted &&
                _decodedFrames.Count == 0 &&
                elapsedSeconds >= (_currentFrameIndex + 1) * frameDurationSeconds)
            {
                _finished = true;
                return false;
            }

            pixels = _currentFrame;
            if (MovieDiagnostics.Enabled)
            {
                if (advanced)
                {
                    _diagnosticFramesAdvanced++;
                }
                else
                {
                    _diagnosticFramesHeld++;
                }
            }
            return true;
        }
    }

    internal void Pause()
    {
        lock (_gate)
        {
            _timeline.Pause(CurrentMovieAudioProgressLocked());
            Monitor.PulseAll(_gate);
        }
    }

    internal void Resume()
    {
        lock (_gate)
        {
            _timeline.Resume(CurrentMovieAudioProgressLocked());
            Monitor.PulseAll(_gate);
        }
    }

    private double CurrentPlaybackSecondsLocked()
    {
        if (!_playbackClockStarted)
        {
            return 0;
        }

        return _timeline.Read(CurrentMovieAudioProgressLocked());
    }

    private MovieAudioProgress CurrentMovieAudioProgressLocked() =>
        _audioProgress?.GetMovieAudioProgress() ??
        new(
            _decoder.HasAudioTrack
                ? MovieAudioProgressState.Unavailable
                : MovieAudioProgressState.NoTrack,
            0);

    private static readonly bool _traceClockSkew = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_LOG_MOVIE_SYNC"),
        "1",
        StringComparison.Ordinal);

    /// <summary>
    /// Logs how far the movie's wall clock has drifted from its owning audio
    /// estimate. A skew that is flat across playback is a late audio start; one
    /// that grows is a rate mismatch, and the two need different fixes. Caller
    /// holds <see cref="_gate"/>.
    /// </summary>
    private void TraceClockSkewLocked()
    {
        if ((!_traceClockSkew && !MovieDiagnostics.Enabled) ||
            !_playbackClockStarted)
        {
            return;
        }

        var now = Stopwatch.GetTimestamp();
        if (_lastSkewTraceTimestamp != 0 &&
            Stopwatch.GetElapsedTime(_lastSkewTraceTimestamp) < TimeSpan.FromSeconds(1))
        {
            return;
        }

        _lastSkewTraceTimestamp = now;
        var wallSeconds = Stopwatch.GetElapsedTime(_playbackStartTimestamp).TotalSeconds;
        var audioProgress = CurrentMovieAudioProgressLocked();
        var audioSeconds = audioProgress.EstimatedPlayedSeconds;
        var selectedPlaybackSeconds = CurrentPlaybackSecondsLocked();
        var targetFrameIndex = CurrentTargetFrameIndexLocked();
        var audioRunning = audioProgress.State == MovieAudioProgressState.Running;
        if (_traceClockSkew)
        {
            Console.Error.WriteLine(
                $"[PERF][MOVIE] wall_s={wallSeconds:F2} audio_s={audioSeconds:F2} " +
                $"playback_s={selectedPlaybackSeconds:F2} " +
                $"skew_s={wallSeconds - audioSeconds:F2} frame={_currentFrameIndex} " +
                $"audio_running={audioRunning}");
        }

        MovieDiagnostics.Clock(
            _diagnosticMovieInstanceId,
            wallSeconds,
            audioProgress,
            selectedPlaybackSeconds,
            _timeline.Mode,
            _currentFrameIndex,
            _currentFrameIndex < 0
                ? -1
                : _currentFrameIndex *
                    (double)FramesPerSecondDenominator / FramesPerSecondNumerator,
            targetFrameIndex,
            _nextDecodedFrameIndex,
            _decodedFrames.Count,
            _diagnosticFramesAdvanced,
            _diagnosticFramesHeld,
            _diagnosticFramesSkipped,
            _diagnosticFramesRetired,
            _diagnosticFramesDiscarded,
            _pumpDiagnostics?.PumpState ?? "unavailable",
            _pumpDiagnostics?.LateVideoFrameCount ?? 0,
            _pumpDiagnostics?.RetainedNextFrameCount ?? 0,
            _pumpDiagnostics?.RetainedPacketCount ?? 0,
            _pumpDiagnostics?.RetainedPacketBytes ?? 0);
        _diagnosticFramesAdvanced = 0;
        _diagnosticFramesHeld = 0;
        _diagnosticFramesSkipped = 0;
        _diagnosticFramesRetired = 0;
        _diagnosticFramesDiscarded = 0;
    }

    /// <summary>
    /// The frame the movie's own time base says should be on screen right now.
    /// Returns -1 until the first frame is presented, so the queue prefills
    /// instead of instantly declaring everything late.
    /// </summary>
    private long CurrentTargetFrameIndexLocked() =>
        _playbackClockStarted
            ? (long)Math.Floor(
                CurrentPlaybackSecondsLocked() *
                FramesPerSecondNumerator / FramesPerSecondDenominator)
            : -1;

    private void DecodeLoop()
    {
        try
        {
            while (true)
            {
                byte[]? destination = null;
                var pumpAudio = false;
                var movieSeconds = 0d;
                lock (_gate)
                {
                    while (!_stopRequested && _freeBuffers.Count == 0)
                    {
                        if (_audioDiagnostics is not null)
                        {
                            _audioDiagnostics.SetDiagnosticPhase(
                                _decoder.HasAudioTrack
                                    ? "frame-buffer-pump"
                                    : "frame-buffer-wait");
                        }

                        if (!_decoder.HasAudioTrack)
                        {
                            Monitor.Wait(_gate);
                            continue;
                        }

                        movieSeconds = CurrentPlaybackSecondsLocked();
                        pumpAudio = true;
                        break;
                    }
                    if (_stopRequested)
                    {
                        return;
                    }

                    if (!pumpAudio)
                    {
                        if (_audioDiagnostics is not null)
                        {
                            _audioDiagnostics.SetDiagnosticPhase("video-decode");
                        }
                        destination = _freeBuffers.Dequeue();
                    }
                }

                if (pumpAudio)
                {
                    var pumpResult = _decoder.PumpAudioWhileVideoBackpressured(movieSeconds);
                    lock (_gate)
                    {
                        if (_stopRequested)
                        {
                            return;
                        }

                        switch (pumpResult)
                        {
                            case MediaPumpResult.Progress:
                                Monitor.PulseAll(_gate);
                                break;
                            case MediaPumpResult.Backpressure:
                                if (_freeBuffers.Count == 0)
                                {
                                    if (_audioDiagnostics is not null)
                                    {
                                        _audioDiagnostics.SetDiagnosticPhase(
                                            "frame-buffer-wait");
                                    }
                                    Monitor.Wait(_gate);
                                }
                                break;
                            case MediaPumpResult.EndOfInput:
                            case MediaPumpResult.Failed:
                            case MediaPumpResult.Disposed:
                                _decoderCompleted = true;
                                Monitor.PulseAll(_gate);
                                return;
                            default:
                                throw new ArgumentOutOfRangeException();
                        }
                    }

                    continue;
                }

                if (destination is null ||
                    !_decoder.TryDecodeNextFrame(destination, movieSeconds))
                {
                    lock (_gate)
                    {
                        if (destination is not null)
                        {
                            _freeBuffers.Enqueue(destination);
                        }
                        _decoderCompleted = true;
                        Monitor.PulseAll(_gate);
                    }
                    return;
                }

                lock (_gate)
                {
                    var frameIndex = _nextDecodedFrameIndex++;

                    // Frames are pulled once per guest flip, so a title running
                    // well under the movie's frame rate cannot drain a queue
                    // this shallow fast enough and the movie stretches past its
                    // real duration — audio finishes while the last picture sits
                    // on screen and the next movie starts late. Once the clock
                    // has passed a queued frame it can never be shown, so retire
                    // it in favour of this newer one. Only superseded frames are
                    // dropped, never the newest, so a decoder that cannot keep
                    // up still advances the picture instead of freezing it.
                    var targetFrameIndex = CurrentTargetFrameIndexLocked();
                    if (frameIndex <= targetFrameIndex)
                    {
                        while (_decodedFrames.Count > 0 &&
                               _decodedFrames.Peek().Index <= targetFrameIndex)
                        {
                            _freeBuffers.Enqueue(_decodedFrames.Dequeue().Pixels);
                            if (MovieDiagnostics.Enabled)
                            {
                                _diagnosticFramesDiscarded++;
                            }
                        }
                    }

                    _decodedFrames.Enqueue(new DecodedFrame(frameIndex, destination));
                    Monitor.PulseAll(_gate);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or
                                             InvalidOperationException)
        {
            Console.Error.WriteLine(
                $"[LOADER][WARN] Bink decoder stopped: {exception.Message}");
            lock (_gate)
            {
                _decoderCompleted = true;
                Monitor.PulseAll(_gate);
            }
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
            _stopRequested = true;
            _timeline.Dispose();
            Monitor.PulseAll(_gate);
        }
        _decoder.Dispose();
        if (Thread.CurrentThread != _decoderThread &&
            !_decoderThread.Join(TimeSpan.FromSeconds(2)))
        {
            Console.Error.WriteLine(
                "[LOADER][WARN] Bink decoder thread did not stop during disposal.");
        }
    }

    private readonly record struct DecodedFrame(long Index, byte[] Pixels);
}
