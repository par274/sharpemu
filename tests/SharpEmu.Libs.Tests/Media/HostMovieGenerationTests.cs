// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class HostMovieGenerationTests
{
    [Fact]
    public void ActiveGenerationWithFrameIsEligible()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();

        Assert.True(frame.Publish(generation));
        Assert.True(frame.IsEligible(tracker.ActiveGeneration));
    }

    [Fact]
    public void CompletionInvalidatesTheCompletedGeneration()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(generation);

        Assert.True(tracker.Invalidate(generation));
        Assert.True(frame.Invalidate(generation));
        Assert.False(frame.IsEligible(tracker.ActiveGeneration));
    }

    [Fact]
    public void GuestCloseInvalidatesTheClosedGeneration()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(generation);

        Assert.True(tracker.Invalidate(generation));
        Assert.True(frame.Invalidate(generation));
        Assert.False(frame.HasFrame);
        Assert.False(frame.IsEligible(generation));
    }

    [Fact]
    public void ReplacementMakesThePreviousGenerationInactive()
    {
        var tracker = new HostMovieGenerationTracker();
        var previousGeneration = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(previousGeneration);

        Assert.True(tracker.Invalidate(previousGeneration));
        var nextGeneration = tracker.Activate();

        Assert.NotEqual(previousGeneration, nextGeneration);
        Assert.False(tracker.IsActive(previousGeneration));
        Assert.False(frame.IsEligible(nextGeneration));
    }

    [Fact]
    public void QueuedNextGenerationDoesNotExposeThePreviousFrameBeforeDecode()
    {
        var tracker = new HostMovieGenerationTracker();
        var previousGeneration = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(previousGeneration);
        tracker.Invalidate(previousGeneration);
        frame.Invalidate(previousGeneration);

        var nextGeneration = tracker.Activate();

        Assert.False(frame.IsEligible(nextGeneration));
        Assert.False(frame.HasFrame);
    }

    [Fact]
    public void SamePathStartedAgainGetsASeparateGeneration()
    {
        var tracker = new HostMovieGenerationTracker();
        var firstGeneration = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(firstGeneration);
        tracker.Invalidate(firstGeneration);
        frame.Invalidate(firstGeneration);

        var secondGeneration = tracker.Activate();

        Assert.NotEqual(firstGeneration, secondGeneration);
        Assert.False(frame.IsEligible(secondGeneration));
        Assert.True(frame.Publish(secondGeneration));
        Assert.True(frame.IsEligible(secondGeneration));
    }

    [Fact]
    public void HeldFrameRemainsEligibleWhileItsGenerationIsActive()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();

        Assert.True(frame.Publish(generation));
        Assert.False(frame.Publish(generation));
        Assert.True(frame.IsEligible(generation));
    }

    [Fact]
    public void InvalidationMakesHostSelectionFallBackToGuestTextureResolution()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(generation);
        tracker.Invalidate(generation);
        frame.Invalidate(generation);

        // The presenter represents this false result as no host binding; the
        // ordinary guest texture resolver then receives the original draw.
        Assert.False(frame.IsEligible(tracker.ActiveGeneration));
    }

    [Fact]
    public void LateInvalidationCannotInvalidateTheReplacementGeneration()
    {
        var tracker = new HostMovieGenerationTracker();
        var previousGeneration = tracker.Activate();
        var nextGeneration = tracker.Activate();

        Assert.False(tracker.Invalidate(previousGeneration));
        Assert.True(tracker.IsActive(nextGeneration));
    }

    [Fact]
    public void PresenterShutdownResetsRetainedFrameEligibility()
    {
        var tracker = new HostMovieGenerationTracker();
        var generation = tracker.Activate();
        var frame = new HostMovieFrameLifetime();
        frame.Publish(generation);

        frame.Reset();

        Assert.False(frame.HasFrame);
        Assert.Equal(0, frame.Generation);
        Assert.False(frame.IsEligible(tracker.ActiveGeneration));
    }

    [Fact]
    public void GenerationIdentityIsIndependentOfMoviePathAndDiagnostics()
    {
        var tracker = new HostMovieGenerationTracker();
        var firstGeneration = tracker.Activate();
        tracker.Invalidate(firstGeneration);
        var secondGeneration = tracker.Activate();

        Assert.True(firstGeneration > 0);
        Assert.True(secondGeneration > firstGeneration);
        Assert.False(MovieDiagnostics.Enabled);
        Assert.Equal(0, MovieDiagnostics.NewMovieInstanceId());
    }
}
