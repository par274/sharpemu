// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieTimelineContractTests
{
    [Fact]
    public void CurrentSharedClockAllowsUnrelatedAudioToAdvanceMovieSelection()
    {
        var currentSelection = CurrentSharedGuestAudioClockContract.Select(
            wallSeconds: 1.0,
            sharedClockAtStart: 100.0,
            sharedClockSeconds: 101.0,
            isRunning: true);

        // The movie's own authored audio has progressed only 0.2 seconds, but
        // the current shared clock selects the unrelated stream's full second.
        Assert.Equal(1.0, currentSelection);
        Assert.True(currentSelection > 0.2);
    }

    [Fact]
    public void CurrentSharedClockCanStretchMovieWhenUnrelatedAudioLags()
    {
        var currentSelection = CurrentSharedGuestAudioClockContract.Select(
            wallSeconds: 1.0,
            sharedClockAtStart: 50.0,
            sharedClockSeconds: 50.2,
            isRunning: true);

        // The movie's own authored audio has progressed 0.8 seconds, while a
        // slow unrelated stream limits the current shared selection to 0.2.
        Assert.Equal(0.2, currentSelection, precision: 10);
        Assert.True(currentSelection < 0.8);
    }

    [Fact]
    public void MovieAudioAdvancesWhileUnrelatedAudioOut2IsAhead()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("with-audio.bk2", hasAudio: true);
        time.Advance(0.75);

        var selected = movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.Running,
            Seconds: 0.60));

        Assert.Equal(0.60, selected);
        Assert.Equal(AuthoredMovieTimelineMode.MovieAudio, movie.Mode);
    }

    [Fact]
    public void UnrelatedAudioOut2ProgressCannotAdvanceMovieLocalClock()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("with-audio.bk2", hasAudio: true);
        time.Advance(1.0);

        // The unrelated stream is deliberately far ahead. It is not passed to
        // MovieTimelineExperiment.Read, matching the proposed ownership rule.
        var unrelatedAudioOut2Seconds = 90.0;
        _ = unrelatedAudioOut2Seconds;
        var selected = movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.Running,
            Seconds: 0.20));

        Assert.Equal(0.20, selected);
        Assert.NotEqual(unrelatedAudioOut2Seconds, selected);
    }

    [Fact]
    public void AudioLessMovieUsesItsOwnMonotonicWallTime()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("silent.bk2", hasAudio: false);
        time.Advance(0.75);

        var selected = movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.Failed,
            Seconds: 50));

        Assert.Equal(0.75, selected);
        Assert.Equal(AuthoredMovieTimelineMode.MovieWall, movie.Mode);
        time.Advance(0.25);
        Assert.Equal(1.0, movie.Read(default));
    }

    [Fact]
    public void MovieAudioUnderrunHoldsVideoToMovieLocalAudio()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("with-audio.bk2", hasAudio: true);
        time.Advance(0.5);
        Assert.Equal(0.4, movie.Read(Running(0.4)));

        time.Advance(0.5);
        Assert.Equal(0.4, movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.TemporaryUnderrun,
            Seconds: 12.0)));
        Assert.Equal(AuthoredMovieTimelineMode.HeldDuringUnderrun, movie.Mode);
    }

    [Fact]
    public void PermanentMovieAudioFailureFallsBackToLocalWallTime()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("with-audio.bk2", hasAudio: true);
        time.Advance(0.5);
        Assert.Equal(0.3, movie.Read(Running(0.3)));

        time.Advance(0.2);
        Assert.Equal(0.3, movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.Failed,
            Seconds: 0.3)));
        Assert.Equal(AuthoredMovieTimelineMode.FallbackWall, movie.Mode);

        time.Advance(0.7);
        Assert.Equal(1.0, movie.Read(Running(0.3)));
    }

    [Fact]
    public void TemporaryUnderrunDoesNotSilentlySwitchTimelinesOrJumpForward()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("with-audio.bk2", hasAudio: true);
        time.Advance(0.2);
        Assert.Equal(0.2, movie.Read(Running(0.2)));

        time.Advance(1.0);
        var held = movie.Read(new AuthoredMovieAudioProgress(
            AuthoredMovieAudioState.TemporaryUnderrun,
            Seconds: 40.0));
        Assert.Equal(0.2, held);
        Assert.False(movie.IsFallback);

        time.Advance(0.1);
        Assert.Equal(0.3, movie.Read(Running(0.3)));
    }

    [Fact]
    public void CompletionAndReplacementTerminateTheOldClock()
    {
        var time = new FakeMonotonicTime();
        var factory = new MovieTimelineFactory(time);
        var first = factory.Start("first.bk2", hasAudio: false);
        time.Advance(1.0);
        Assert.Equal(1.0, first.Read(default));

        first.Complete();
        time.Advance(5.0);
        Assert.Equal(1.0, first.Read(default));
        Assert.True(first.IsTerminal);

        var replacement = factory.Replace(first, "second.bk2", hasAudio: false);
        Assert.NotEqual(first.Generation, replacement.Generation);
        Assert.Equal(0.0, replacement.Read(default));
    }

    [Fact]
    public void SamePathReplacementReceivesANewClockIdentity()
    {
        var time = new FakeMonotonicTime();
        var factory = new MovieTimelineFactory(time);
        var first = factory.Start("same-path.bk2", hasAudio: true);
        time.Advance(0.4);
        Assert.Equal(0.4, first.Read(Running(0.4)));

        var replacement = factory.Replace(first, "same-path.bk2", hasAudio: true);

        Assert.Equal(first.Path, replacement.Path);
        Assert.NotEqual(first.Generation, replacement.Generation);
        Assert.Equal(0.0, replacement.Read(Running(0.0)));
    }

    [Fact]
    public void MovieClockValuesRemainMonotonicWithinOneGeneration()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("monotonic.bk2", hasAudio: true);
        var values = new List<double>();

        time.Advance(0.4);
        values.Add(movie.Read(Running(0.4)));
        time.Advance(0.2);
        values.Add(movie.Read(Running(0.1)));
        time.Advance(0.2);
        values.Add(movie.Read(Running(0.8)));

        Assert.Equal([0.4, 0.4, 0.8], values);
        Assert.True(values.Zip(values.Skip(1)).All(pair => pair.First <= pair.Second));
    }

    [Fact]
    public void DiagnosticsDisabledDoesNoPayloadConstructionOrEventWork()
    {
        var time = new FakeMonotonicTime();
        var diagnostics = new AuthoredTimelineDiagnostics(enabled: false);
        var movie = new MovieTimelineFactory(time).Start(
            "diagnostics-off.bk2",
            hasAudio: true,
            diagnostics: diagnostics);

        for (var index = 0; index < 8; index++)
        {
            time.Advance(0.1);
            _ = movie.Read(Running(index * 0.1));
        }

        Assert.Equal(0, diagnostics.PayloadsBuilt);
        Assert.Empty(diagnostics.Events);
    }

    [Fact]
    public void PauseSkipAndDisposeKeepLifecycleStateLocalAndTerminal()
    {
        var time = new FakeMonotonicTime();
        var movie = new MovieTimelineFactory(time).Start("lifecycle.bk2", hasAudio: false);
        time.Advance(0.5);
        Assert.Equal(0.5, movie.Read(default));

        movie.Pause(default);
        time.Advance(5.0);
        Assert.Equal(0.5, movie.Read(default));
        movie.Resume();
        time.Advance(0.5);
        Assert.Equal(1.0, movie.Read(default));

        movie.Skip();
        time.Advance(5.0);
        Assert.Equal(1.0, movie.Read(default));
        Assert.True(movie.IsTerminal);

        movie.Dispose();
        Assert.Equal(1.0, movie.Read(default));
        Assert.True(movie.IsTerminal);
    }

    private static AuthoredMovieAudioProgress Running(double seconds) =>
        new(AuthoredMovieAudioState.Running, seconds);
}
