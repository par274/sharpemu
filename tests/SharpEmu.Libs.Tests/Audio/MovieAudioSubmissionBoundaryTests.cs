// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE.Host;
using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Audio;

public sealed class MovieAudioSubmissionBoundaryTests
{
    [Fact]
    public void StrictAdmissionAllowsExactCapAndRejectsOverflowWithoutArithmeticWrap()
    {
        Assert.True(HostAudioQueueAdmission.Fits(4, 4, 8));
        Assert.False(HostAudioQueueAdmission.Fits(4, 5, 8));
        Assert.False(HostAudioQueueAdmission.Fits(9, 0, 8));
        Assert.True(HostAudioQueueAdmission.Fits(
            int.MaxValue - 2,
            2,
            int.MaxValue));
        Assert.False(HostAudioQueueAdmission.Fits(
            int.MaxValue - 2,
            3,
            int.MaxValue));
    }

    [Fact]
    public async Task ExactQueueSubmissionRecoversAfterDeviceDrainWithoutAnExtraSubmission()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 8,
            HostAudioProgressSource.ExactQueueDepth);
        stream.SetStrictQueueBound(true);
        using var boundary = new MovieAudioSubmissionBoundary(
            stream,
            outputBytesPerFrame: 4,
            outputSampleRate: 48_000);

        var first = boundary.Submit(
            new byte[8],
            outputFrames: 2,
            CancellationToken.None,
            out var firstProgress);
        Assert.Equal(MovieAudioSubmissionResult.Accepted, first);
        Assert.Equal(2, firstProgress.SubmittedFrames);
        Assert.Equal(8, stream.QueuedPcmBytes);
        Assert.Equal(1, stream.SubmissionCount);
        stream.SubmissionEntered.Reset();

        using var cancellation = new CancellationTokenSource();
        var second = Task.Run(() => boundary.Submit(
            new byte[4],
            outputFrames: 1,
            cancellation.Token,
            out _));

        Assert.True(stream.SubmissionEntered.Wait(TimeSpan.FromSeconds(1)));
        Assert.NotSame(second, await Task.WhenAny(
            second,
            Task.Delay(TimeSpan.FromMilliseconds(50))));
        Assert.Equal(1, stream.SubmissionCount);
        Assert.InRange(stream.MaximumObservedQueuedBytes, 0, 8);

        stream.Drain(8);
        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            await second);
        Assert.Equal(2, stream.SubmissionCount);
        Assert.InRange(stream.MaximumObservedQueuedBytes, 0, 8);
        Assert.Equal(4, stream.QueuedPcmBytes);
    }

    [Fact]
    public async Task CancellationWhileStrictSubmissionWaitsDoesNotAdmitAnotherBuffer()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 8,
            HostAudioProgressSource.ExactQueueDepth);
        stream.SetStrictQueueBound(true);
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            boundary.Submit(new byte[8], 2, CancellationToken.None, out _));
        stream.SubmissionEntered.Reset();

        using var cancellation = new CancellationTokenSource();
        var pending = Task.Run(() => boundary.Submit(
            new byte[4],
            1,
            cancellation.Token,
            out _));
        Assert.True(stream.SubmissionEntered.Wait(TimeSpan.FromSeconds(1)));

        cancellation.Cancel();

        Assert.Equal(
            MovieAudioSubmissionResult.Cancelled,
            await pending);
        Assert.Equal(1, stream.SubmissionCount);
        Assert.InRange(stream.MaximumObservedQueuedBytes, 0, 8);
    }

    [Fact]
    public void NonStrictSubmissionRetainsGuestOverTargetAdmissionBehavior()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 8,
            HostAudioProgressSource.ExactQueueDepth);

        Assert.True(stream.Submit(new byte[4]));
        Assert.True(stream.Submit(new byte[8]));
        Assert.Equal(12, stream.QueuedPcmBytes);
        Assert.Equal(2, stream.SubmissionCount);
    }

    [Fact]
    public void ExactProgressTracksSubmittedMinusQueuedAndHostDrain()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 32,
            HostAudioProgressSource.ExactQueueDepth);
        stream.SetStrictQueueBound(true);
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            boundary.Submit(new byte[16], 4, CancellationToken.None, out _));
        stream.Drain(8);
        var progress = boundary.ObserveProgress();
        Assert.Equal(4, progress.SubmittedFrames);
        Assert.Equal(2, progress.PlayedFrames);
        Assert.False(progress.TemporaryUnderrun);

        stream.Drain(8);
        progress = boundary.ObserveProgress();
        Assert.Equal(4, progress.PlayedFrames);
        Assert.True(progress.TemporaryUnderrun);

        Assert.Equal(
            MovieAudioDrainResult.Completed,
            boundary.WaitForDrain(CancellationToken.None));
        Assert.True(boundary.LastProgress.HostDrainComplete);
    }

    [Fact]
    public void UnavailableProgressContinuesAcceptedSubmissionsAndReportsUnsupportedDrain()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 16,
            HostAudioProgressSource.Unavailable);
        stream.SetStrictQueueBound(true);
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        for (var index = 0; index < 3; index++)
        {
            var result = boundary.Submit(
                new byte[4],
                1,
                CancellationToken.None,
                out var progress);
            Assert.Equal(MovieAudioSubmissionResult.Accepted, result);
            Assert.False(progress.HasProgress);
        }

        Assert.Equal(3, stream.SubmissionCount);
        Assert.Equal(MovieAudioDrainResult.Unsupported,
            boundary.WaitForDrain(CancellationToken.None));
        Assert.False(boundary.SupportsPause);
    }

    [Fact]
    public void CalibratedSubmissionPacingProvidesAClockAndDrainBoundary()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 16,
            HostAudioProgressSource.CalibratedSubmissionPaced);
        stream.SetStrictQueueBound(true);
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            boundary.Submit(new byte[8], 2, CancellationToken.None, out var progress));
        Assert.True(progress.HasProgress);
        Assert.Equal(2, progress.PlayedFrames);
        Assert.Equal(MovieAudioDrainResult.Completed,
            boundary.WaitForDrain(CancellationToken.None));
    }

    [Fact]
    public void SupportedBackendPauseAndResumeAreExposedThroughTheProductionBoundary()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 16,
            HostAudioProgressSource.ExactQueueDepth,
            supportsPause: true);
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        Assert.True(boundary.SupportsPause);
        boundary.SetPaused(true);
        Assert.True(stream.IsPaused);
        boundary.SetPaused(false);
        Assert.False(stream.IsPaused);
        Assert.Equal(2, stream.PauseCallCount);
    }

    [Fact]
    public void ExplicitHostFailureIsNotConfusedWithTemporaryBackpressure()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 16,
            HostAudioProgressSource.ExactQueueDepth)
        {
            AcceptSubmissions = false,
        };
        using var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);

        Assert.Equal(
            MovieAudioSubmissionResult.HostFailure,
            boundary.Submit(new byte[4], 1, CancellationToken.None, out _));
        Assert.Equal(0, stream.SubmissionCount);
    }

    [Fact]
    public void DemuxReadBoundaryOnlyTreatsOfficialEofAsNormalExhaustion()
    {
        Assert.Equal(
            MovieDemuxReadDisposition.Packet,
            MovieDemuxReadBoundary.Classify(0, -541));
        Assert.Equal(
            MovieDemuxReadDisposition.EndOfInput,
            MovieDemuxReadBoundary.Classify(-541, -541));
        Assert.Equal(
            MovieDemuxReadDisposition.Failure,
            MovieDemuxReadBoundary.Classify(-5, -541));
    }

    [Fact]
    public void DecoderDrainLifecycleRequiresEveryStageAndHostDrain()
    {
        var lifecycle = new MovieAudioDrainLifecycle();
        Assert.False(lifecycle.IsComplete);

        lifecycle.MarkDemuxEof();
        lifecycle.MarkCodecDrainSent();
        lifecycle.MarkDecoderEof();
        lifecycle.MarkResamplerEof();
        Assert.False(lifecycle.IsComplete);

        lifecycle.MarkHostDrainComplete();
        Assert.True(lifecycle.IsComplete);
        lifecycle.MarkFailed();
        lifecycle.MarkDisposed();
        Assert.True(lifecycle.Failed);
        Assert.True(lifecycle.Disposed);
    }

    [Fact]
    public async Task CancellationThenDisposalReleasesABlockedBackendExactlyOnce()
    {
        using var stream = new DeterministicHostAudioStream(
            maximumQueuedBytes: 4,
            HostAudioProgressSource.ExactQueueDepth);
        stream.SetStrictQueueBound(true);
        var boundary = new MovieAudioSubmissionBoundary(stream, 4, 48_000);
        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            boundary.Submit(new byte[4], 1, CancellationToken.None, out _));
        stream.SubmissionEntered.Reset();

        using var cancellation = new CancellationTokenSource();
        var pending = Task.Run(() => boundary.Submit(
            new byte[4],
            1,
            cancellation.Token,
            out _));
        Assert.True(stream.SubmissionEntered.Wait(TimeSpan.FromSeconds(1)));
        cancellation.Cancel();
        Assert.Equal(MovieAudioSubmissionResult.Cancelled,
            await pending);

        boundary.Dispose();
        boundary.Dispose();
        Assert.Equal(1, stream.DisposeCount);
    }

    private sealed class DeterministicHostAudioStream :
        IHostAudioStream,
        IHostAudioStreamControl
    {
        private readonly object _gate = new();
        private readonly int _maximumQueuedBytes;
        private readonly HostAudioProgressSource _progressSource;
        private readonly ManualResetEventSlim _drained = new(false);
        private readonly bool _supportsPause;
        private bool _strictQueueBound;
        private bool _disposed;
        private int _queuedPcmBytes;

        internal DeterministicHostAudioStream(
            int maximumQueuedBytes,
            HostAudioProgressSource progressSource,
            bool supportsPause = false)
        {
            _maximumQueuedBytes = maximumQueuedBytes;
            _progressSource = progressSource;
            _supportsPause = supportsPause;
        }

        internal bool AcceptSubmissions { get; set; } = true;

        internal ManualResetEventSlim SubmissionEntered { get; } = new();

        internal int SubmissionCount { get; private set; }

        internal int MaximumObservedQueuedBytes { get; private set; }

        internal int DisposeCount { get; private set; }

        internal int PauseCallCount { get; private set; }

        internal bool IsPaused { get; private set; }

        public int QueuedPcmBytes
        {
            get
            {
                lock (_gate)
                {
                    return _progressSource == HostAudioProgressSource.ExactQueueDepth
                        ? _queuedPcmBytes
                        : -1;
                }
            }
        }

        public HostAudioProgressSource ProgressSource => _progressSource;

        public bool Submit(ReadOnlySpan<byte> stereoPcm16) =>
            Submit(stereoPcm16, CancellationToken.None);

        public bool Submit(
            ReadOnlySpan<byte> stereoPcm16,
            CancellationToken cancellationToken)
        {
            while (true)
            {
                lock (_gate)
                {
                    if (_disposed || !AcceptSubmissions)
                    {
                        return false;
                    }

                    SubmissionEntered.Set();
                    if (!_strictQueueBound || HostAudioQueueAdmission.Fits(
                            _queuedPcmBytes,
                            stereoPcm16.Length,
                            _maximumQueuedBytes))
                    {
                        _queuedPcmBytes = checked(_queuedPcmBytes + stereoPcm16.Length);
                        SubmissionCount++;
                        MaximumObservedQueuedBytes = Math.Max(
                            MaximumObservedQueuedBytes,
                            _queuedPcmBytes);
                        return true;
                    }
                }

                try
                {
                    _drained.Wait(cancellationToken);
                    _drained.Reset();
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
            }
        }

        public void SetPaused(bool paused)
        {
            if (!SupportsPause)
            {
                throw new NotSupportedException();
            }

            IsPaused = paused;
            PauseCallCount++;
        }

        public bool SupportsPause => _supportsPause;

        public void SetGuestClockReporting(bool enabled)
        {
        }

        public void SetStrictQueueBound(bool enabled) =>
            _strictQueueBound = enabled;

        internal void Drain(int bytes)
        {
            lock (_gate)
            {
                _queuedPcmBytes = Math.Max(0, _queuedPcmBytes - bytes);
            }

            _drained.Set();
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                DisposeCount++;
            }

            _drained.Set();
        }
    }
}
