// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
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
}
