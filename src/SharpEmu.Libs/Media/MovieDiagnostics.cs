// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using SharpEmu.Logging;

namespace SharpEmu.Libs.Media;

/// <summary>
/// Bounded, opt-in movie lifecycle diagnostics written to the existing JSONL
/// memory-diagnostics stream. The default path is a single volatile read and
/// does not allocate, format text, take a lock, or retain diagnostic state.
/// </summary>
internal static class MovieDiagnostics
{
    private const int MaximumEvents = 4096;
    private static readonly bool Requested = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_MOVIE_DIAGNOSTICS"),
        "1",
        StringComparison.Ordinal);
    private static long _nextMovieInstanceId;
    private static int _eventCount;
    private static readonly MovieDiagnosticRateLimiter PresenterPumpLimiter =
        new();
    private static readonly MovieDiagnosticRateLimiter PresenterSelectionLimiter =
        new();
    private static bool _hasPresenterSelection;
    private static bool _lastPresenterFrameAvailable;
    private static bool _lastPresenterPlaybackActive;
    private static long _lastPresenterInstanceId;
    private static string _lastPresenterMovie = string.Empty;
    private static readonly MovieDiagnosticRateLimiter PresenterPresentationLimiter =
        new();
    private static bool _hasPresenterPresentation;
    private static bool _lastPresenterPresentedHost;
    private static long _lastPresenterPresentedInstanceId;
    private static string _lastPresenterPresentedMovie = string.Empty;

    internal static bool Enabled =>
        Requested && MemoryDiagnostics.IsEnabled;

    internal static long NewMovieInstanceId()
    {
        return Enabled ? Interlocked.Increment(ref _nextMovieInstanceId) : 0;
    }

    internal static void Observe(
        string path,
        string state,
        long instanceId,
        long activeInstanceId,
        bool pending)
    {
        if (!Enabled)
        {
            return;
        }

        Write("observe", new
        {
            movie = MovieIdentity(path),
            state,
            movieInstanceId = instanceId,
            activeMovieInstanceId = activeInstanceId,
            pending,
        });
    }

    internal static void Queue(
        string path,
        long activeInstanceId,
        bool duplicate)
    {
        if (!Enabled)
        {
            return;
        }

        Write("queue", new
        {
            movie = MovieIdentity(path),
            activeMovieInstanceId = activeInstanceId,
            duplicate,
        });
    }

    internal static void Attach(
        string path,
        long instanceId,
        uint width,
        uint height,
        uint framesPerSecondNumerator,
        uint framesPerSecondDenominator,
        string mode)
    {
        if (!Enabled)
        {
            return;
        }

        Write("attach", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            width,
            height,
            framesPerSecondNumerator,
            framesPerSecondDenominator,
            mode,
        });
    }

    internal static void Reattach(
        string? previousPath,
        long previousInstanceId,
        string nextPath,
        long nextInstanceId)
    {
        if (!Enabled)
        {
            return;
        }

        Write("reattach", new
        {
            previousMovie = MovieIdentity(previousPath),
            previousMovieInstanceId = previousInstanceId,
            movie = MovieIdentity(nextPath),
            movieInstanceId = nextInstanceId,
        });
    }

    internal static void Start(
        long instanceId,
        double audioStartSeconds,
        double audioSeconds,
        bool audioRunning,
        bool followGuestAudioClock)
    {
        if (!Enabled)
        {
            return;
        }

        Write("start", new
        {
            movieInstanceId = instanceId,
            wallSeconds = 0d,
            audioStartSeconds,
            audioSeconds,
            selectedPlaybackSeconds = 0d,
            audioRunning,
            followGuestAudioClock,
        });
    }

    internal static void Clock(
        long instanceId,
        double wallSeconds,
        double audioSeconds,
        double selectedPlaybackSeconds,
        bool audioRunning,
        bool followGuestAudioClock,
        long currentFrameIndex,
        long targetFrameIndex,
        long decodedFrameCount,
        int decodedQueueCount,
        long framesAdvanced,
        long framesHeld,
        long framesSkipped,
        long framesRetired,
        long framesDiscarded)
    {
        if (!Enabled)
        {
            return;
        }

        Write("clock", new
        {
            movieInstanceId = instanceId,
            wallSeconds,
            audioSeconds,
            selectedPlaybackSeconds,
            audioRunning,
            followGuestAudioClock,
            currentFrameIndex,
            targetFrameIndex,
            decodedFrameCount,
            decodedQueueCount,
            framesAdvanced,
            framesHeld,
            framesSkipped,
            framesRetired,
            framesDiscarded,
        });
    }

    internal static void Complete(
        string path,
        long instanceId,
        double wallSeconds,
        long frameIndex)
    {
        if (!Enabled)
        {
            return;
        }

        Write("complete", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            wallSeconds,
            frameIndex,
        });
    }

    internal static void Stop(string path, long instanceId, string reason)
    {
        if (!Enabled)
        {
            return;
        }

        Write("stop", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            reason,
        });
    }

    internal static void Dispose(string path, long instanceId, string reason)
    {
        if (!Enabled)
        {
            return;
        }

        Write("dispose", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            reason,
        });
    }

    internal static void GuestOpen(
        int fileDescriptor,
        string path,
        long instanceId,
        bool completionShim)
    {
        if (!Enabled)
        {
            return;
        }

        Write("guest-open", new
        {
            fileDescriptor,
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            completionShim,
        });
    }

    internal static void GuestClose(
        int fileDescriptor,
        string path,
        long instanceId,
        bool notifiedBridge)
    {
        if (!Enabled)
        {
            return;
        }

        Write("guest-close", new
        {
            fileDescriptor,
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            notifiedBridge,
        });
    }

    internal static void PresenterPump(
        string? path,
        long instanceId,
        bool hostFrameAvailable,
        bool hostPlaybackActive,
        bool advanced,
        long frameSerial,
        uint width,
        uint height)
    {
        if (!Enabled)
        {
            return;
        }

        var state = (hostFrameAvailable ? 1 : 0) |
            (hostPlaybackActive ? 2 : 0);
        var now = Stopwatch.GetTimestamp();
        if (!PresenterPumpLimiter.ShouldEmit(now, instanceId, state))
        {
            return;
        }

        Write("presenter-pump", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostFrameAvailable,
            hostPlaybackActive,
            advanced,
            frameSerial,
            width,
            height,
        });
    }

    internal static void PresenterSelection(
        string? path,
        long instanceId,
        bool hostFrameAvailable,
        bool hostPlaybackActive,
        bool selectedHostMovie,
        long frameSerial,
        long lumaUploadedFrameSerial,
        long chromaUploadedFrameSerial,
        int lumaTextureIndex,
        int chromaTextureIndex)
    {
        if (!Enabled)
        {
            return;
        }

        var movie = MovieIdentity(path);
        var state = (hostFrameAvailable ? 1 : 0) |
            (hostPlaybackActive ? 2 : 0);
        var now = Stopwatch.GetTimestamp();
        var changed = !_hasPresenterSelection ||
            _lastPresenterFrameAvailable != hostFrameAvailable ||
            _lastPresenterPlaybackActive != hostPlaybackActive ||
            _lastPresenterInstanceId != instanceId ||
            !string.Equals(_lastPresenterMovie, movie, StringComparison.Ordinal);

        if (changed || PresenterSelectionLimiter.ShouldEmit(now, instanceId, state))
        {
            Write("presenter-draw-selection", new
            {
                movie,
                movieInstanceId = instanceId,
                hostFrameAvailable,
                hostPlaybackActive,
                selectedHostMovie,
                frameSerial,
                lumaUploadedFrameSerial,
                chromaUploadedFrameSerial,
                lumaTextureIndex,
                chromaTextureIndex,
            });
        }

        _hasPresenterSelection = true;
        _lastPresenterFrameAvailable = hostFrameAvailable;
        _lastPresenterPlaybackActive = hostPlaybackActive;
        _lastPresenterInstanceId = instanceId;
        _lastPresenterMovie = movie;
    }

    internal static void PresenterPresentation(
        string? path,
        long instanceId,
        bool selectedHostMovie,
        bool hostPlaybackActive,
        long frameSerial,
        long presentationSequence,
        string presentationKind)
    {
        if (!Enabled)
        {
            return;
        }

        var movie = MovieIdentity(path);
        var now = Stopwatch.GetTimestamp();
        var changed = !_hasPresenterPresentation ||
            _lastPresenterPresentedHost != selectedHostMovie ||
            _lastPresenterPresentedInstanceId != instanceId ||
            !string.Equals(_lastPresenterPresentedMovie, movie, StringComparison.Ordinal);
        var state = selectedHostMovie ? 1 : 0;
        if (changed && _hasPresenterPresentation && _lastPresenterPresentedHost &&
            (!selectedHostMovie || _lastPresenterPresentedInstanceId != instanceId))
        {
            Write("presenter-present-end", new
            {
                movie = _lastPresenterPresentedMovie,
                movieInstanceId = _lastPresenterPresentedInstanceId,
                reason = "presentation-changed",
            });
        }

        if (selectedHostMovie && changed)
        {
            Write("presenter-present-start", new
            {
                movie,
                movieInstanceId = instanceId,
                frameSerial,
            });
        }

        if (changed || PresenterPresentationLimiter.ShouldEmit(now, instanceId, state))
        {
            Write("presenter-present", new
            {
                movie,
                movieInstanceId = instanceId,
                selectedHostMovie,
                hostPlaybackActive,
                frameSerial,
                presentationSequence,
                presentationKind,
            });
        }

        _hasPresenterPresentation = true;
        _lastPresenterPresentedHost = selectedHostMovie;
        _lastPresenterPresentedInstanceId = instanceId;
        _lastPresenterPresentedMovie = movie;
    }

    internal static void PresenterUpload(
        string? path,
        long instanceId,
        long frameSerial,
        int plane)
    {
        if (!Enabled)
        {
            return;
        }

        Write("presenter-upload", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            frameSerial,
            plane,
        });
    }

    internal static void PresenterShutdown(
        string? path,
        long instanceId,
        long frameSerial,
        bool hostPlaybackActive)
    {
        if (!Enabled)
        {
            return;
        }

        if (_hasPresenterPresentation && _lastPresenterPresentedHost)
        {
            Write("presenter-present-end", new
            {
                movie = _lastPresenterPresentedMovie,
                movieInstanceId = _lastPresenterPresentedInstanceId,
                reason = "shutdown",
            });
        }

        Write("presenter-shutdown", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            frameSerial,
            hostPlaybackActive,
        });
    }

    private static string MovieIdentity(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        return Path.GetFileName(path);
    }

    private static void Write(string eventName, object data)
    {
        var count = Interlocked.Increment(ref _eventCount);
        if (count > MaximumEvents)
        {
            return;
        }

        MemoryDiagnostics.RecordEvent("movie." + eventName, data);
    }
}

internal sealed class MovieDiagnosticRateLimiter
{
    private long _lastTicks;
    private long _lastInstanceId;
    private int _lastState;
    private bool _initialized;

    internal bool ShouldEmit(long nowTicks, long instanceId, int state)
    {
        var changed = !_initialized ||
            _lastInstanceId != instanceId ||
            _lastState != state;
        var elapsed = nowTicks - _lastTicks;
        if (!changed && elapsed < Stopwatch.Frequency)
        {
            return false;
        }

        _initialized = true;
        _lastTicks = nowTicks;
        _lastInstanceId = instanceId;
        _lastState = state;
        return true;
    }
}
