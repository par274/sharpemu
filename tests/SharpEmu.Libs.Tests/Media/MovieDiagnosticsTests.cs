// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using SharpEmu.Logging;
using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Media;

public sealed class MovieDiagnosticsTests
{
    [Fact]
    public void PresenterRateLimiterSamplesUnchangedStateOncePerSecond()
    {
        var limiter = new MovieDiagnosticRateLimiter();
        var start = 100L;

        Assert.True(limiter.ShouldEmit(start, instanceId: 4, state: 5));
        Assert.False(limiter.ShouldEmit(
            start + Stopwatch.Frequency / 2,
            instanceId: 4,
            state: 5));
        Assert.True(limiter.ShouldEmit(
            start + Stopwatch.Frequency,
            instanceId: 4,
            state: 5));
        Assert.True(limiter.ShouldEmit(
            start + Stopwatch.Frequency + 1,
            instanceId: 5,
            state: 5));
        Assert.True(limiter.ShouldEmit(
            start + Stopwatch.Frequency + 2,
            instanceId: 5,
            state: 1));
    }

    [Fact]
    public void EventBudgetAcceptsExactlyItsConfiguredMaximum()
    {
        var budget = new MovieDiagnosticEventBudget(MovieDiagnostics.MaximumEvents);

        for (var index = 0; index < MovieDiagnostics.MaximumEvents; index++)
        {
            Assert.True(budget.TryReserve());
        }

        Assert.False(budget.TryReserve());
        Assert.Equal(MovieDiagnostics.MaximumEvents, budget.AcceptedCount);
        Assert.False(budget.HasCapacity);
    }

    [Fact]
    public void ExhaustedEventBudgetDoesNotRunPayloadWork()
    {
        var budget = new MovieDiagnosticEventBudget(3);
        var payloadWork = 0;

        for (var index = 0; index < 100; index++)
        {
            if (budget.TryReserve())
            {
                payloadWork++;
                _ = new { index };
            }
        }

        Assert.Equal(3, payloadWork);
        Assert.Equal(3, budget.AcceptedCount);
    }

    [Fact]
    public void ConcurrentEventBudgetReservationsStayWithinAllowance()
    {
        const int maximum = 257;
        var budget = new MovieDiagnosticEventBudget(maximum);
        var accepted = 0;

        Parallel.For(
            0,
            32_768,
            _ =>
            {
                if (budget.TryReserve())
                {
                    Interlocked.Increment(ref accepted);
                }
            });

        Assert.Equal(maximum, accepted);
        Assert.Equal(maximum, budget.AcceptedCount);
        Assert.False(budget.TryReserve());
    }

    [Fact]
    public void DiagnosticsDisabledPathStillReturnsNoMovieInstanceId()
    {
        Assert.False(MemoryDiagnostics.IsEnabled);
        Assert.False(MovieDiagnostics.Enabled);
        Assert.Equal(0, MovieDiagnostics.NewMovieInstanceId());
    }
}
