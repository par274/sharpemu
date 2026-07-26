// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.GUI.Services;
using Xunit;

namespace SharpEmu.Libs.Tests.GUI;

public sealed class GameActivityServiceTests
{
    [Fact]
    public void GetPlayedSince_ClipsCompletedSessionToRequestedWindow()
    {
        using var storage = new ActivityStorage();
        var activity = new GameActivityService(storage.Path);
        var start = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

        activity.BeginSession("PPSA00001", start);
        activity.CompleteSession(start.AddDays(9));

        var played = activity.GetPlayedSince(
            "PPSA00001",
            start.AddDays(7),
            start.AddDays(11));

        Assert.Equal(TimeSpan.FromDays(2), played);
    }

    [Fact]
    public void GetPlayedSince_IncludesCurrentActiveSession()
    {
        using var storage = new ActivityStorage();
        var activity = new GameActivityService(storage.Path);
        var now = new DateTimeOffset(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

        activity.BeginSession("PPSA00002", now.AddHours(-2));

        Assert.Equal(
            TimeSpan.FromHours(2),
            activity.GetPlayedSince("PPSA00002", now.AddDays(-14), now));
    }

    [Fact]
    public void CompleteSession_PersistsHistoryForNextLauncherRun()
    {
        using var storage = new ActivityStorage();
        var startedAt = new DateTimeOffset(2026, 7, 20, 9, 0, 0, TimeSpan.Zero);
        var firstRun = new GameActivityService(storage.Path);

        firstRun.BeginSession("PPSA00003", startedAt);
        firstRun.CompleteSession(startedAt.AddHours(3));

        var nextRun = new GameActivityService(storage.Path);
        Assert.Equal(
            TimeSpan.FromHours(3),
            nextRun.GetPlayedSince(
                "PPSA00003",
                startedAt.AddDays(-14),
                startedAt.AddHours(4)));
        Assert.Equal(startedAt, nextRun.GetLastPlayedAt("PPSA00003"));
    }

    [Fact]
    public void BeginSession_PersistsLatestLaunchImmediately()
    {
        using var storage = new ActivityStorage();
        var firstLaunch = new DateTimeOffset(2026, 7, 20, 9, 0, 0, TimeSpan.Zero);
        var latestLaunch = firstLaunch.AddDays(2);
        var activity = new GameActivityService(storage.Path);

        activity.BeginSession("PPSA00004", firstLaunch);
        activity.CompleteSession(firstLaunch.AddHours(1));
        activity.BeginSession("ppsa00004", latestLaunch);

        var nextRun = new GameActivityService(storage.Path);
        Assert.Equal(latestLaunch, nextRun.GetLastPlayedAt("PPSA00004"));
    }

    private sealed class ActivityStorage : IDisposable
    {
        private readonly string _directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"sharpemu-activity-tests-{Guid.NewGuid():N}");

        public string Path => System.IO.Path.Combine(_directory, "activity.json");

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
