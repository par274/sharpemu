// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieTimelineContractTests
{
    [Fact]
    public void MovieUsesOnlyItsOwnAudioProgressAndCapsItToLocalWallTime()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(time, generation: 1, hasAudio: true, Running(0));

        time.Advance(0.75);
        Assert.Equal(0.60, movie.Read(Running(0.60)));
        Assert.Equal(MovieTimelineMode.MovieAudio, movie.Mode);
    }

    [Fact]
    public void AudioLessMovieUsesLocalMonotonicWallTime()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(time, generation: 1, hasAudio: false, default);

        time.Advance(0.75);
        Assert.Equal(0.75, movie.Read(default));
        Assert.Equal(MovieTimelineMode.MovieWall, movie.Mode);
    }

    [Fact]
    public void StartingAndTemporaryUnderrunHoldUntilAudioRunsAgain()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(
            time,
            generation: 1,
            hasAudio: true,
            new MovieAudioProgress(MovieAudioProgressState.Starting, 0));

        time.Advance(0.5);
        Assert.Equal(0, movie.Read(new MovieAudioProgress(
            MovieAudioProgressState.Starting,
            0)));

        time.Advance(0.1);
        Assert.Equal(0.4, movie.Read(Running(0.4)));

        time.Advance(0.5);
        Assert.Equal(0.4, movie.Read(new MovieAudioProgress(
            MovieAudioProgressState.TemporaryUnderrun,
            0.8)));
        Assert.Equal(MovieTimelineMode.HeldDuringUnderrun, movie.Mode);

        time.Advance(0.2);
        Assert.Equal(0.6, movie.Read(Running(0.6)));
    }

    [Fact]
    public void CompletionAndPermanentFailureAnchorWallContinuation()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(time, generation: 1, hasAudio: true, Running(0));

        time.Advance(0.5);
        Assert.Equal(0.5, movie.Read(Running(0.5)));

        time.Advance(0.2);
        Assert.Equal(0.5, movie.Read(new MovieAudioProgress(
            MovieAudioProgressState.Completed,
            0.5)));
        Assert.Equal(MovieTimelineMode.FallbackWall, movie.Mode);

        time.Advance(0.7);
        Assert.Equal(1.2, movie.Read(Running(0.5)));
    }

    [Fact]
    public void PauseAndResumeRebasesWithoutAnAudioJump()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(time, generation: 1, hasAudio: true, Running(0));

        time.Advance(0.5);
        Assert.Equal(0.5, movie.Read(Running(0.5)));
        movie.Pause(Running(0.5));

        time.Advance(5.0);
        Assert.Equal(0.5, movie.Read(Running(0.9)));

        movie.Resume(Running(0.9));
        Assert.Equal(0.5, movie.Read(Running(0.9)));

        time.Advance(0.2);
        Assert.Equal(0.7, movie.Read(Running(1.1)), precision: 10);
    }

    [Fact]
    public void TerminalGenerationCannotAdvanceAndReplacementStartsAtZero()
    {
        var time = new FakeMonotonicClock();
        var first = Start(time, generation: 7, hasAudio: false, default);
        time.Advance(1.0);
        Assert.Equal(1.0, first.Read(default));

        first.Skip();
        time.Advance(5.0);
        Assert.Equal(1.0, first.Read(default));
        Assert.True(first.IsTerminal);

        var replacement = Start(time, generation: 8, hasAudio: false, default);
        Assert.NotEqual(first.Generation, replacement.Generation);
        Assert.Equal(0.0, replacement.Read(default));
    }

    [Fact]
    public void MovieValuesRemainMonotonicWhenAudioEstimateRegresses()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(time, generation: 1, hasAudio: true, Running(0));
        var values = new List<double>();

        time.Advance(0.4);
        values.Add(movie.Read(Running(0.4)));
        time.Advance(0.2);
        values.Add(movie.Read(Running(0.1)));
        time.Advance(0.2);
        values.Add(movie.Read(Running(0.8)));

        Assert.Equal([0.4, 0.4, 0.8], values);
    }

    [Fact]
    public void AudioFailureBeforeFirstFrameUsesWallFallback()
    {
        var time = new FakeMonotonicClock();
        var movie = Start(
            time,
            generation: 1,
            hasAudio: true,
            new MovieAudioProgress(MovieAudioProgressState.Failed, 0));

        time.Advance(0.25);
        Assert.Equal(0.25, movie.Read(new MovieAudioProgress(
            MovieAudioProgressState.Failed,
            0)));
        Assert.Equal(MovieTimelineMode.FallbackWall, movie.Mode);
    }

    private static MovieTimeline Start(
        FakeMonotonicClock time,
        long generation,
        bool hasAudio,
        MovieAudioProgress initial)
    {
        var movie = new MovieTimeline(generation, hasAudio, time);
        movie.Start(initial);
        return movie;
    }

    private static MovieAudioProgress Running(double seconds) =>
        new(MovieAudioProgressState.Running, seconds);

    private sealed class FakeMonotonicClock : IMovieMonotonicClock
    {
        public double Seconds { get; private set; }

        internal void Advance(double seconds) => Seconds += seconds;
    }
}
