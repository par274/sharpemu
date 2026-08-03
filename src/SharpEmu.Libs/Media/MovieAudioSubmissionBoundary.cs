// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE.Host;

namespace SharpEmu.Libs.Media;

internal enum MovieAudioSubmissionResult
{
    Accepted,
    Cancelled,
    HostFailure,
    ProgressUnavailable,
}

internal enum MovieAudioDrainResult
{
    Completed,
    Cancelled,
    HostFailure,
    Unsupported,
}

internal readonly record struct MovieAudioProgressSample(
    long SubmittedFrames,
    long PlayedFrames,
    double Seconds,
    bool HasProgress,
    bool TemporaryUnderrun,
    bool HostDrainComplete);

/// <summary>
/// Reconciles the bounded PCM frontier with the host queue. The exact path is
/// deliberately arithmetic-only: accepted output frames minus the currently
/// queued frames is the playback estimate, clamped to the submitted frontier.
/// </summary>
internal sealed class MovieAudioProgressTracker
{
    private readonly int _bytesPerFrame;
    private readonly int _sampleRate;
    private readonly HostAudioProgressSource _source;
    private long _submittedFrames;
    private long _playedFrames;
    private bool _hostDrainComplete;

    internal MovieAudioProgressTracker(
        int bytesPerFrame,
        int sampleRate,
        HostAudioProgressSource source)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytesPerFrame);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sampleRate);
        _bytesPerFrame = bytesPerFrame;
        _sampleRate = sampleRate;
        _source = source;
    }

    internal long SubmittedFrames => _submittedFrames;

    internal void RecordSubmitted(long frames)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(frames);
        _submittedFrames = checked(_submittedFrames + frames);
    }

    internal MovieAudioProgressSample ObserveQueuedPcmBytes(int queuedBytes)
    {
        if (queuedBytes < 0 || _source != HostAudioProgressSource.ExactQueueDepth)
        {
            return ObserveWithoutQueue();
        }

        var queuedFrames = queuedBytes / _bytesPerFrame;
        _playedFrames = Math.Clamp(
            _submittedFrames - queuedFrames,
            0,
            _submittedFrames);
        return CreateSample(
            hasProgress: true,
            temporaryUnderrun: queuedBytes == 0 && _submittedFrames > 0);
    }

    internal MovieAudioProgressSample ObserveWithoutQueue()
    {
        // A calibrated submission-paced backend explicitly promises that an
        // accepted submission has reached its playback frontier. An entirely
        // unavailable backend exposes no invented clock or drain claim.
        var calibrated = _source == HostAudioProgressSource.CalibratedSubmissionPaced;
        if (calibrated)
        {
            _playedFrames = _submittedFrames;
        }

        return CreateSample(
            hasProgress: calibrated,
            temporaryUnderrun: false);
    }

    internal MovieAudioProgressSample MarkHostDrainComplete()
    {
        _playedFrames = _submittedFrames;
        _hostDrainComplete = true;
        return CreateSample(
            hasProgress: _source != HostAudioProgressSource.Unavailable,
            temporaryUnderrun: false);
    }

    private MovieAudioProgressSample CreateSample(
        bool hasProgress,
        bool temporaryUnderrun) =>
        new(
            _submittedFrames,
            _playedFrames,
            _playedFrames / (double)_sampleRate,
            hasProgress,
            temporaryUnderrun && !_hostDrainComplete,
            _hostDrainComplete);
}

/// <summary>
/// The production seam between movie conversion and a host stream. It owns
/// the stream, applies the backend capability contract, and gives the decoder
/// a single disposal and drain boundary to exercise in deterministic tests.
/// </summary>
internal sealed class MovieAudioSubmissionBoundary : IDisposable
{
    private readonly IHostAudioStream _stream;
    private readonly IHostAudioStreamControl? _control;
    private readonly MovieAudioProgressTracker _progress;
    private readonly int _outputBytesPerFrame;
    private MovieAudioProgressSample _lastProgress;
    private int _disposed;

    internal MovieAudioSubmissionBoundary(
        IHostAudioStream stream,
        int outputBytesPerFrame,
        int outputSampleRate)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _control = stream as IHostAudioStreamControl;
        _outputBytesPerFrame = outputBytesPerFrame;
        ProgressSource = _control?.ProgressSource ?? stream.ProgressSource;
        _progress = new MovieAudioProgressTracker(
            outputBytesPerFrame,
            outputSampleRate,
            ProgressSource);
    }

    internal HostAudioProgressSource ProgressSource { get; }

    internal bool SupportsPause => _control?.SupportsPause == true;

    internal IHostAudioStreamDiagnostics? Diagnostics =>
        _stream as IHostAudioStreamDiagnostics;

    internal MovieAudioProgressSample LastProgress => _lastProgress;

    internal MovieAudioSubmissionResult Submit(
        ReadOnlySpan<byte> pcm,
        long outputFrames,
        CancellationToken cancellationToken,
        out MovieAudioProgressSample progress)
    {
        progress = default;
        if (Volatile.Read(ref _disposed) != 0 ||
            cancellationToken.IsCancellationRequested)
        {
            return MovieAudioSubmissionResult.Cancelled;
        }

        bool accepted;
        try
        {
            accepted = _control is not null
                ? _control.Submit(pcm, cancellationToken)
                : _stream.Submit(pcm);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return MovieAudioSubmissionResult.Cancelled;
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidOperationException or
            ObjectDisposedException or
            NotSupportedException)
        {
            return MovieAudioSubmissionResult.HostFailure;
        }

        if (!accepted)
        {
            return cancellationToken.IsCancellationRequested
                ? MovieAudioSubmissionResult.Cancelled
                : MovieAudioSubmissionResult.HostFailure;
        }

        _progress.RecordSubmitted(outputFrames);
        if (ProgressSource == HostAudioProgressSource.ExactQueueDepth)
        {
            if (!TryGetQueuedPcmBytes(out var queuedBytes))
            {
                progress = _progress.ObserveWithoutQueue();
                _lastProgress = progress;
                return MovieAudioSubmissionResult.ProgressUnavailable;
            }

            progress = _progress.ObserveQueuedPcmBytes(queuedBytes);
        }
        else
        {
            progress = _progress.ObserveWithoutQueue();
        }

        _lastProgress = progress;

        return MovieAudioSubmissionResult.Accepted;
    }

    internal MovieAudioProgressSample ObserveProgress()
    {
        if (ProgressSource == HostAudioProgressSource.ExactQueueDepth &&
            TryGetQueuedPcmBytes(out var queuedBytes))
        {
            _lastProgress = _progress.ObserveQueuedPcmBytes(queuedBytes);
            return _lastProgress;
        }

        _lastProgress = _progress.ObserveWithoutQueue();
        return _lastProgress;
    }

    internal MovieAudioDrainResult WaitForDrain(CancellationToken cancellationToken)
    {
        if (ProgressSource == HostAudioProgressSource.Unavailable)
        {
            return MovieAudioDrainResult.Unsupported;
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            if (ProgressSource == HostAudioProgressSource.CalibratedSubmissionPaced)
            {
                _lastProgress = _progress.MarkHostDrainComplete();
                return MovieAudioDrainResult.Completed;
            }

            if (!TryGetQueuedPcmBytes(out var queuedBytes))
            {
                return MovieAudioDrainResult.HostFailure;
            }

            if (queuedBytes == 0)
            {
                _lastProgress = _progress.MarkHostDrainComplete();
                return MovieAudioDrainResult.Completed;
            }

            try
            {
                cancellationToken.WaitHandle.WaitOne(1);
            }
            catch (ObjectDisposedException)
            {
                return MovieAudioDrainResult.Cancelled;
            }
        }

        return MovieAudioDrainResult.Cancelled;
    }

    internal void SetPaused(bool paused)
    {
        if (_control is null || !SupportsPause || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _control.SetPaused(paused);
    }

    private bool TryGetQueuedPcmBytes(out int queuedBytes)
    {
        queuedBytes = _stream.QueuedPcmBytes;
        if (queuedBytes >= 0)
        {
            return true;
        }

        var queuedMilliseconds = _stream.QueuedMilliseconds;
        if (queuedMilliseconds < 0)
        {
            return false;
        }

        queuedBytes = checked((int)Math.Round(
            queuedMilliseconds * (_outputBytesPerFrame * 48_000.0) / 1_000.0));
        return queuedBytes >= 0;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stream.Dispose();
    }
}

internal enum MovieDemuxReadDisposition
{
    Packet,
    EndOfInput,
    Failure,
}

internal static class MovieDemuxReadBoundary
{
    internal static MovieDemuxReadDisposition Classify(
        int readResult,
        int eofResult)
    {
        if (readResult >= 0)
        {
            return MovieDemuxReadDisposition.Packet;
        }

        return readResult == eofResult
            ? MovieDemuxReadDisposition.EndOfInput
            : MovieDemuxReadDisposition.Failure;
    }
}

/// <summary>
/// The finite decoder-side drain state. EOF on one stage is not completion:
/// every stage and the host stream must cross its own boundary exactly once.
/// </summary>
internal sealed class MovieAudioDrainLifecycle
{
    internal bool DemuxEof { get; private set; }
    internal bool CodecDrainSent { get; private set; }
    internal bool DecoderEof { get; private set; }
    internal bool ResamplerEof { get; private set; }
    internal bool HostDrainComplete { get; private set; }
    internal bool Failed { get; private set; }
    internal bool Disposed { get; private set; }

    internal bool IsComplete =>
        DemuxEof && DecoderEof && ResamplerEof && HostDrainComplete;

    internal void MarkDemuxEof() => DemuxEof = true;

    internal void MarkCodecDrainSent() => CodecDrainSent = true;

    internal void MarkDecoderEof() => DecoderEof = true;

    internal void MarkResamplerEof() => ResamplerEof = true;

    internal void MarkHostDrainComplete() => HostDrainComplete = true;

    internal void MarkFailed() => Failed = true;

    internal void MarkDisposed() => Disposed = true;
}
