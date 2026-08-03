// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Tests.Media;

internal enum AuthoredMovieAudioState
{
    NoTrack,
    Running,
    TemporaryUnderrun,
    Failed,
    Completed,
}

internal readonly record struct AuthoredMovieAudioProgress(
    AuthoredMovieAudioState State,
    double Seconds);

internal enum AuthoredMovieTimelineMode
{
    MovieAudio,
    MovieWall,
    HeldDuringUnderrun,
    FallbackWall,
    Terminal,
}

internal sealed class FakeMonotonicTime
{
    internal double Seconds { get; private set; }

    internal void Advance(double seconds)
    {
        if (seconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(seconds));
        }

        Seconds += seconds;
    }
}

internal readonly record struct AuthoredTimelineEvent(
    long Generation,
    AuthoredMovieTimelineMode Mode,
    double Seconds);

internal sealed class AuthoredTimelineDiagnostics(bool enabled)
{
    internal bool Enabled { get; } = enabled;

    internal int PayloadsBuilt { get; private set; }

    internal List<AuthoredTimelineEvent> Events { get; } = [];

    internal void Record(AuthoredTimelineEvent timelineEvent)
    {
        PayloadsBuilt++;
        Events.Add(timelineEvent);
    }
}

/// <summary>
/// Test-only movie-local clock policy. Its only time input is FakeMonotonicTime;
/// an unrelated guest-audio value is intentionally not an input to Read.
/// </summary>
internal sealed class MovieTimelineExperiment
{
    private readonly FakeMonotonicTime _time;
    private readonly bool _hasAudio;
    private readonly AuthoredTimelineDiagnostics? _diagnostics;
    private double _startedAt;
    private double _lastSeconds;
    private double _fallbackStartedAt;
    private double _fallbackBaseSeconds;
    private bool _fallback;
    private bool _paused;
    private bool _terminal;

    internal MovieTimelineExperiment(
        long generation,
        string path,
        bool hasAudio,
        FakeMonotonicTime time,
        AuthoredTimelineDiagnostics? diagnostics = null)
    {
        Generation = generation;
        Path = path;
        _hasAudio = hasAudio;
        _time = time;
        _diagnostics = diagnostics;
        _startedAt = time.Seconds;
        Mode = hasAudio
            ? AuthoredMovieTimelineMode.MovieAudio
            : AuthoredMovieTimelineMode.MovieWall;
    }

    internal long Generation { get; }

    internal string Path { get; }

    internal AuthoredMovieTimelineMode Mode { get; private set; }

    internal bool IsTerminal => _terminal;

    internal bool IsPaused => _paused;

    internal bool IsFallback => _fallback;

    internal double Read(AuthoredMovieAudioProgress audio)
    {
        if (_terminal || _paused)
        {
            return _lastSeconds;
        }

        var wallSeconds = Math.Max(0, _time.Seconds - _startedAt);
        var selectedSeconds = _lastSeconds;
        if (!_hasAudio)
        {
            Mode = AuthoredMovieTimelineMode.MovieWall;
            selectedSeconds = wallSeconds;
        }
        else if (_fallback)
        {
            Mode = AuthoredMovieTimelineMode.FallbackWall;
            selectedSeconds = _fallbackBaseSeconds +
                Math.Max(0, _time.Seconds - _fallbackStartedAt);
        }
        else
        {
            switch (audio.State)
            {
                case AuthoredMovieAudioState.Running:
                    Mode = AuthoredMovieTimelineMode.MovieAudio;
                    // Do not select an audio estimate from the future. The
                    // production policy caps this movie-owned estimate by wall
                    // time without sharing the clock with another stream.
                    selectedSeconds = Math.Min(
                        wallSeconds,
                        Math.Max(0, audio.Seconds));
                    break;
                case AuthoredMovieAudioState.TemporaryUnderrun:
                    Mode = AuthoredMovieTimelineMode.HeldDuringUnderrun;
                    selectedSeconds = _lastSeconds;
                    break;
                case AuthoredMovieAudioState.Failed:
                case AuthoredMovieAudioState.Completed:
                    BeginFallback();
                    Mode = AuthoredMovieTimelineMode.FallbackWall;
                    selectedSeconds = _lastSeconds;
                    break;
                case AuthoredMovieAudioState.NoTrack:
                    BeginFallback();
                    Mode = AuthoredMovieTimelineMode.FallbackWall;
                    selectedSeconds = _lastSeconds;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        _lastSeconds = Math.Max(_lastSeconds, selectedSeconds);
        Emit();
        return _lastSeconds;
    }

    internal void Pause(AuthoredMovieAudioProgress audio)
    {
        if (_terminal || _paused)
        {
            return;
        }

        _ = Read(audio);
        _paused = true;
    }

    internal void Resume()
    {
        if (_terminal)
        {
            return;
        }

        _paused = false;
        if (!_hasAudio && !_fallback)
        {
            RebaseWallClock();
        }
        else if (_fallback)
        {
            _fallbackStartedAt = _time.Seconds;
            _fallbackBaseSeconds = _lastSeconds;
        }
    }

    internal void Complete() => End();

    internal void Skip() => End();

    internal void Dispose() => End();

    private void BeginFallback()
    {
        if (_fallback)
        {
            return;
        }

        _fallback = true;
        _fallbackStartedAt = _time.Seconds;
        _fallbackBaseSeconds = _lastSeconds;
    }

    private void RebaseWallClock()
    {
        // Keep a paused wall-clock movie exactly at its last selected position
        // when the host resumes it.
        _startedAt = _time.Seconds - _lastSeconds;
    }

    private void End()
    {
        _terminal = true;
        _paused = false;
        Mode = AuthoredMovieTimelineMode.Terminal;
    }

    private void Emit()
    {
        if (_diagnostics is not { Enabled: true } diagnostics)
        {
            return;
        }

        diagnostics.Record(new AuthoredTimelineEvent(Generation, Mode, _lastSeconds));
    }
}

internal sealed class MovieTimelineFactory(FakeMonotonicTime time)
{
    private long _nextGeneration;

    internal MovieTimelineExperiment Start(
        string path,
        bool hasAudio,
        AuthoredTimelineDiagnostics? diagnostics = null) =>
        new(++_nextGeneration, path, hasAudio, time, diagnostics);

    internal MovieTimelineExperiment Replace(
        MovieTimelineExperiment current,
        string path,
        bool hasAudio,
        AuthoredTimelineDiagnostics? diagnostics = null)
    {
        current.Dispose();
        return Start(path, hasAudio, diagnostics);
    }
}

/// <summary>
/// Test-only replay of the current MediaFramePlayback clock expression. It is
/// intentionally global/furthest-stream shaped so the tests pin the behavior
/// that the selected movie-local policy is meant to remove.
/// </summary>
internal static class CurrentSharedGuestAudioClockContract
{
    internal static double Select(
        double wallSeconds,
        double sharedClockAtStart,
        double sharedClockSeconds,
        bool isRunning)
    {
        if (!isRunning)
        {
            return wallSeconds;
        }

        return Math.Clamp(
            sharedClockSeconds - sharedClockAtStart,
            0,
            wallSeconds);
    }
}
