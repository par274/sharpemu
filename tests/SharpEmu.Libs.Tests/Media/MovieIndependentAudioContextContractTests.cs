// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieIndependentAudioContextContractTests
{
    [Fact]
    public void AudioContinuesWhenAllFiveVideoDestinationsAreOwned()
    {
        using var movie = new IndependentMovieAudioContextExperiment(
            generation: 1,
            hasAudioTrack: true);

        for (var index = 0; index <
             IndependentMovieAudioContextExperiment.VideoDestinationCount;
             index++)
        {
            Assert.True(movie.PumpVideo());
        }

        Assert.False(movie.PumpVideo());
        Assert.Equal(5, movie.VideoBuffersOwned);

        Assert.True(movie.PumpAudio());
        Assert.True(movie.PumpAudio());
        Assert.Equal(2, movie.AudioSubmissions);
        Assert.Equal(2, movie.AudioPacketsDecoded);
        Assert.Equal(5, movie.VideoBuffersOwned);
    }

    [Fact]
    public void AudioAndVideoEofDrainIndependentlyInEitherOrder()
    {
        using var audioFirst = new IndependentMovieAudioContextExperiment(1, true);
        audioFirst.ExhaustAudio();
        while (audioFirst.PumpAudio())
        {
        }

        audioFirst.DrainHostAudio(
            IndependentMovieAudioContextExperiment.MaximumQueuedPcmBytes);
        Assert.Equal(SyntheticMovieAudioState.Completed, audioFirst.State);
        Assert.False(audioFirst.VideoEof);
        Assert.False(audioFirst.IsMovieComplete);

        using var videoFirst = new IndependentMovieAudioContextExperiment(2, true);
        Assert.True(videoFirst.PumpAudio());
        videoFirst.ExhaustVideo();
        videoFirst.ExhaustAudio();
        while (videoFirst.PumpAudio())
        {
        }

        Assert.True(videoFirst.VideoEof);
        Assert.False(videoFirst.HostAudioDrainComplete);
        Assert.False(videoFirst.IsMovieComplete);
        videoFirst.DrainHostAudio(
            IndependentMovieAudioContextExperiment.MaximumQueuedPcmBytes);
        Assert.Equal(SyntheticMovieAudioState.Completed, videoFirst.State);
        Assert.True(videoFirst.IsMovieComplete);
    }

    [Fact]
    public void TemporaryUnderrunHoldsTheMovieClockAndRecoversOnSubmission()
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, true);

        Assert.True(movie.PumpAudio());
        Assert.Equal(0, movie.ReadMovieClock(1.0));
        movie.DrainHostAudio(
            IndependentMovieAudioContextExperiment.MaximumSubmissionBytes);

        Assert.Equal(SyntheticMovieAudioState.TemporaryUnderrun, movie.State);
        Assert.Equal(0, movie.ReadMovieClock(2.0));
        Assert.True(movie.PumpAudio());
        Assert.Equal(SyntheticMovieAudioState.Running, movie.State);
        Assert.True(movie.AudioSeconds > 0);
    }

    [Fact]
    public void NormalAudioCompletionFallsBackToMovieLocalClockWhileVideoRemains()
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, true);

        movie.PumpAudio();
        movie.ExhaustAudio();
        while (movie.PumpAudio())
        {
        }

        movie.DrainHostAudio(
            IndependentMovieAudioContextExperiment.MaximumQueuedPcmBytes);
        Assert.Equal(SyntheticMovieAudioState.Completed, movie.State);
        Assert.False(movie.VideoEof);

        var before = movie.ReadMovieClock(0.5);
        var after = movie.ReadMovieClock(1.0);
        Assert.True(after > before);
        Assert.False(movie.IsMovieComplete);
    }

    [Fact]
    public void NoAudioMovieDoesNotOpenOrDrainAnAudioContext()
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, false);

        Assert.Null(movie.AudioContext);
        Assert.Equal(SyntheticMovieAudioState.NoTrack, movie.State);
        Assert.Equal(1.0, movie.ReadMovieClock(1.0));
        Assert.Equal(0, movie.AudioPumpCount);
        Assert.Equal(0, movie.AudioSubmissions);
    }

    [Theory]
    [InlineData(SyntheticAudioFailure.Decoder, "audio decoder failed")]
    [InlineData(SyntheticAudioFailure.Submission, "host audio submission failed")]
    [InlineData(SyntheticAudioFailure.Device, "host audio device failed")]
    public void RuntimeAudioFailuresAreTerminalAndVisible(
        SyntheticAudioFailure failure,
        string reason)
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, true, failure);

        if (failure == SyntheticAudioFailure.Device)
        {
            Assert.True(movie.PumpAudio());
            movie.DrainHostAudio(1);
        }
        else
        {
            Assert.False(movie.PumpAudio());
        }

        Assert.Equal(SyntheticMovieAudioState.Failed, movie.State);
        Assert.Equal(reason, movie.FailureReason);
        Assert.False(movie.HostAudioDrainComplete);
        Assert.True(movie.AudioContext!.HostStream.IsDisposed);
    }

    [Fact]
    public void OpenFailureReleasesThePartiallyCreatedIndependentContext()
    {
        using var movie = new IndependentMovieAudioContextExperiment(
            1,
            hasAudioTrack: true,
            failure: SyntheticAudioFailure.Open);

        Assert.Equal(SyntheticMovieAudioState.Failed, movie.State);
        Assert.Null(movie.AudioContext);
        Assert.NotNull(movie.OpenAttemptContext);
        Assert.All(movie.OpenAttemptContext!.Resources, resource =>
            Assert.Equal(1, resource.DisposeCount));
    }

    [Fact]
    public void PauseAndResumeDoNotConsumeAudioOrAdvanceTheClock()
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, true);

        Assert.True(movie.PumpAudio());
        var queued = movie.QueuedPcmBytes;
        movie.Pause();
        Assert.Equal(SyntheticMovieAudioState.Paused, movie.State);
        Assert.False(movie.PumpAudio());
        Assert.Equal(queued, movie.QueuedPcmBytes);
        Assert.Equal(0, movie.ReadMovieClock(10));

        movie.Resume();
        Assert.Equal(SyntheticMovieAudioState.Running, movie.State);
        Assert.True(movie.PumpAudio());
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("skip")]
    [InlineData("dispose")]
    public void CancellationSkipAndDisposalReleaseEveryOwnedResourceOnce(string action)
    {
        var movie = new IndependentMovieAudioContextExperiment(1, true);
        movie.PumpAudio();

        switch (action)
        {
            case "cancel":
                movie.Cancel();
                break;
            case "skip":
                movie.Skip();
                break;
            case "dispose":
                movie.Dispose();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(action));
        }

        movie.Dispose();
        Assert.Equal(SyntheticMovieAudioState.Disposed, movie.State);
        Assert.All(movie.VideoContext.Resources, resource =>
            Assert.Equal(1, resource.DisposeCount));
        Assert.All(movie.AudioContext!.Resources, resource =>
            Assert.Equal(1, resource.DisposeCount));
    }

    [Fact]
    public void SamePathReplacementGetsASeparateGeneration()
    {
        using var host = new SyntheticMovieGenerationHost();
        var first = host.Attach(hasAudioTrack: true);
        var second = host.Attach(hasAudioTrack: true);

        Assert.NotEqual(first.Generation, second.Generation);
        Assert.Equal(SyntheticMovieAudioState.Disposed, first.State);
        Assert.False(host.ApplyAudioCallback(
            first.Generation,
            current => current.PumpAudio()));
        Assert.Equal(0, second.AudioPumpCount);
    }

    [Fact]
    public void StaleAudioCallbackCannotAffectTheReplacementGeneration()
    {
        using var host = new SyntheticMovieGenerationHost();
        var oldMovie = host.Attach(hasAudioTrack: true);
        var oldGeneration = oldMovie.Generation;
        var newMovie = host.Attach(hasAudioTrack: true);

        Assert.False(host.ApplyAudioCallback(
            oldGeneration,
            current => current.PumpAudio()));
        Assert.Equal(0, newMovie.AudioPumpCount);
        Assert.True(host.ApplyAudioCallback(
            newMovie.Generation,
            current => current.PumpAudio()));
        Assert.Equal(1, newMovie.AudioPumpCount);
    }

    [Fact]
    public void NativeOwnershipAndRetainedStateHaveFiniteBounds()
    {
        using var movie = new IndependentMovieAudioContextExperiment(1, true);

        for (var index = 0; index < 20; index++)
        {
            movie.PumpAudio();
            movie.DrainHostAudio(
                IndependentMovieAudioContextExperiment.MaximumSubmissionBytes);
        }

        Assert.InRange(movie.MaximumObservedLivePackets, 0, 1);
        Assert.InRange(movie.MaximumObservedLiveFrames, 0, 1);
        Assert.InRange(
            movie.MaximumObservedQueuedPcmBytes,
            0,
            IndependentMovieAudioContextExperiment.MaximumQueuedPcmBytes);
        Assert.InRange(
            movie.MaximumObservedQueuedPcmBytes,
            0,
            movie.RetainedBoundBytes);
        Assert.NotSame(movie.VideoContext, movie.AudioContext);
        Assert.All(movie.VideoContext.Resources, resource =>
            Assert.False(resource.IsDisposed));
        Assert.All(movie.AudioContext!.Resources, resource =>
            Assert.False(resource.IsDisposed));
    }

    [Fact]
    public void DiagnosticsDisabledBuildsNoPayloadsAndRemainsBoundedWhenEnabled()
    {
        using var disabled = new IndependentMovieAudioContextExperiment(1, true);
        for (var index = 0; index < 20; index++)
        {
            disabled.PumpAudio();
            disabled.DrainHostAudio(
                IndependentMovieAudioContextExperiment.MaximumSubmissionBytes);
        }

        Assert.Equal(0, disabled.DiagnosticPayloadsBuilt);

        using var enabled = new IndependentMovieAudioContextExperiment(
            2,
            hasAudioTrack: true,
            diagnosticsEnabled: true);
        for (var index = 0; index < 40; index++)
        {
            enabled.PumpAudio();
            enabled.DrainHostAudio(
                IndependentMovieAudioContextExperiment.MaximumSubmissionBytes);
        }

        Assert.InRange(
            enabled.DiagnosticPayloadsBuilt,
            0,
            IndependentMovieAudioContextExperiment.MaximumDiagnosticEvents);
    }

    [Fact]
    public void RepeatedInitializationAndTeardownIsIdempotent()
    {
        for (var index = 0; index < 100; index++)
        {
            using var movie = new IndependentMovieAudioContextExperiment(index + 1, true);
            movie.PumpAudio();
            movie.Dispose();
            movie.Dispose();
            Assert.All(movie.AudioContext!.Resources, resource =>
                Assert.Equal(1, resource.DisposeCount));
        }
    }
}
