// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Media;

internal enum MovieAudioProgressState
{
    NoTrack,
    Starting,
    Running,
    TemporaryUnderrun,
    Completed,
    Failed,
    Unavailable,
    Disposed,
}

internal readonly record struct MovieAudioProgress(
    MovieAudioProgressState State,
    double EstimatedPlayedSeconds);

internal interface IMovieAudioProgressSource
{
    bool HasAudioTrack { get; }

    MovieAudioProgress GetMovieAudioProgress();
}

internal interface IMovieMonotonicClock
{
    double Seconds { get; }
}

internal sealed class StopwatchMovieMonotonicClock : IMovieMonotonicClock
{
    private readonly long _started = System.Diagnostics.Stopwatch.GetTimestamp();

    public double Seconds =>
        System.Diagnostics.Stopwatch.GetElapsedTime(_started).TotalSeconds;
}

internal enum MovieTimelineMode
{
    MovieAudio,
    MovieWall,
    HeldDuringUnderrun,
    FallbackWall,
    Paused,
    Terminal,
}

/// <summary>
/// Generation-owned movie time selection. This type has no dependency on the
/// process-wide guest audio clock; its only audio input is the active movie's
/// progress source.
/// </summary>
internal sealed class MovieTimeline
{
    private readonly IMovieMonotonicClock _clock;
    private readonly bool _hasAudioTrack;
    private double _wallOriginSeconds;
    private double _fallbackOriginSeconds;
    private double _fallbackBaseSeconds;
    private double _audioOffsetSeconds;
    private double _lastSeconds;
    private bool _fallback;
    private bool _started;
    private bool _paused;
    private bool _terminal;

    internal MovieTimeline(
        long generation,
        bool hasAudioTrack,
        IMovieMonotonicClock? clock = null)
    {
        Generation = generation;
        _hasAudioTrack = hasAudioTrack;
        _clock = clock ?? new StopwatchMovieMonotonicClock();
        _wallOriginSeconds = _clock.Seconds;
        Mode = hasAudioTrack
            ? MovieTimelineMode.MovieAudio
            : MovieTimelineMode.MovieWall;
    }

    internal long Generation { get; }

    internal MovieTimelineMode Mode { get; private set; }

    internal bool IsTerminal => _terminal;

    internal bool IsPaused => _paused;

    internal void Start(MovieAudioProgress progress)
    {
        if (_terminal || _started)
        {
            return;
        }

        _started = true;
        _wallOriginSeconds = _clock.Seconds;
        if (_hasAudioTrack)
        {
            if (progress.State is MovieAudioProgressState.Completed or
                MovieAudioProgressState.Failed or
                MovieAudioProgressState.Unavailable or
                MovieAudioProgressState.Disposed)
            {
                BeginFallback();
                Mode = MovieTimelineMode.FallbackWall;
            }
            else if (progress.State == MovieAudioProgressState.Running)
            {
                _audioOffsetSeconds = Math.Max(0, progress.EstimatedPlayedSeconds);
            }
        }
    }

    internal double Read(MovieAudioProgress progress)
    {
        if (_terminal || _paused)
        {
            return _lastSeconds;
        }

        var wallSeconds = Math.Max(0, _clock.Seconds - _wallOriginSeconds);
        var selectedSeconds = _lastSeconds;
        if (!_hasAudioTrack || progress.State == MovieAudioProgressState.NoTrack)
        {
            Mode = MovieTimelineMode.MovieWall;
            selectedSeconds = wallSeconds;
        }
        else if (_fallback)
        {
            Mode = MovieTimelineMode.FallbackWall;
            selectedSeconds = _fallbackBaseSeconds +
                Math.Max(0, _clock.Seconds - _fallbackOriginSeconds);
        }
        else
        {
            switch (progress.State)
            {
                case MovieAudioProgressState.Starting:
                case MovieAudioProgressState.TemporaryUnderrun:
                    Mode = MovieTimelineMode.HeldDuringUnderrun;
                    selectedSeconds = _lastSeconds;
                    break;
                case MovieAudioProgressState.Running:
                    Mode = MovieTimelineMode.MovieAudio;
                    selectedSeconds = Math.Min(
                        wallSeconds,
                        Math.Max(0, progress.EstimatedPlayedSeconds - _audioOffsetSeconds));
                    break;
                case MovieAudioProgressState.Completed:
                case MovieAudioProgressState.Failed:
                case MovieAudioProgressState.Unavailable:
                case MovieAudioProgressState.Disposed:
                    BeginFallback();
                    Mode = MovieTimelineMode.FallbackWall;
                    selectedSeconds = _lastSeconds;
                    break;
                case MovieAudioProgressState.NoTrack:
                    Mode = MovieTimelineMode.MovieWall;
                    selectedSeconds = wallSeconds;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        _lastSeconds = Math.Max(_lastSeconds, selectedSeconds);
        return _lastSeconds;
    }

    internal void Pause(MovieAudioProgress progress)
    {
        if (_terminal || _paused)
        {
            return;
        }

        _ = Read(progress);
        _paused = true;
        Mode = MovieTimelineMode.Paused;
    }

    internal void Resume(MovieAudioProgress progress)
    {
        if (_terminal)
        {
            return;
        }

        if (!_paused)
        {
            return;
        }

        _paused = false;
        if (_fallback)
        {
            _fallbackOriginSeconds = _clock.Seconds;
            _fallbackBaseSeconds = _lastSeconds;
        }
        else if (!_hasAudioTrack || progress.State == MovieAudioProgressState.NoTrack)
        {
            _wallOriginSeconds = _clock.Seconds - _lastSeconds;
        }
        else if (progress.State is not MovieAudioProgressState.NoTrack)
        {
            _audioOffsetSeconds = Math.Max(
                _audioOffsetSeconds,
                progress.EstimatedPlayedSeconds - _lastSeconds);
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
        _fallbackOriginSeconds = _clock.Seconds;
        _fallbackBaseSeconds = _lastSeconds;
    }

    private void End()
    {
        _terminal = true;
        _paused = false;
        Mode = MovieTimelineMode.Terminal;
    }
}
