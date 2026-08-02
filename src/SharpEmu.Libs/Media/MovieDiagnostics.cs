// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using SharpEmu.Logging;

namespace SharpEmu.Libs.Media;

/// <summary>
/// Bounded, opt-in movie lifecycle diagnostics written to the existing JSONL
/// memory-diagnostics stream. The default path is a short-circuiting set of
/// volatile reads and does not allocate, format text, take a lock, or retain
/// diagnostic state.
/// </summary>
internal static class MovieDiagnostics
{
    internal const int MaximumEvents = 4096;
    private static readonly bool Requested = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_MOVIE_DIAGNOSTICS"),
        "1",
        StringComparison.Ordinal);
    private static long _nextMovieInstanceId;
    private static readonly MovieDiagnosticEventBudget EventBudget =
        new(MaximumEvents);
    private static readonly MovieDiagnosticRateLimiter PresenterPumpLimiter =
        new();
    private static readonly MovieDiagnosticRateLimiter PresenterSelectionLimiter =
        new();
    private static bool _hasPresenterSelection;
    private static bool _lastPresenterFrameAvailable;
    private static bool _lastPresenterPlaybackActive;
    private static long _lastPresenterInstanceId;
    private static long _lastPresenterFrameGeneration;
    private static long _lastPresenterActiveGeneration;
    private static string? _lastPresenterPath;
    private static readonly MovieDiagnosticRateLimiter PresenterPresentationLimiter =
        new();
    private static bool _hasPresenterPresentation;
    private static bool _lastPresenterPresentedHost;
    private static long _lastPresenterPresentedInstanceId;
    private static long _lastPresenterPresentedGeneration;
    private static string? _lastPresenterPresentedPath;
    private static string _lastPresenterPresentedMovie = string.Empty;

    internal static bool Enabled =>
        Requested &&
        MemoryDiagnostics.IsEnabled &&
        EventBudget.HasCapacity;

    private static bool CanDoDiagnosticWork =>
        Enabled;

    internal static long NewMovieInstanceId()
    {
        return CanDoDiagnosticWork ?
            Interlocked.Increment(ref _nextMovieInstanceId) :
            0;
    }

    private static bool TryReserveEvent() =>
        Enabled && EventBudget.TryReserve();

    internal static void Observe(
        string path,
        string state,
        long instanceId,
        long activeInstanceId,
        bool pending)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("observe", new
        {
            movie = MovieIdentity(path),
            state,
            movieInstanceId = instanceId,
            activeMovieInstanceId = activeInstanceId,
            pending,
        });
    }

    internal static void Observe(
        string path,
        HostMovieBridge.MovieMode mode,
        long instanceId,
        long activeInstanceId,
        bool pending)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("observe", new
        {
            movie = MovieIdentity(path),
            state = mode switch
            {
                HostMovieBridge.MovieMode.Guest => "guest",
                HostMovieBridge.MovieMode.Skip => "skip",
                HostMovieBridge.MovieMode.Dummy => "dummy",
                HostMovieBridge.MovieMode.Native => "native",
                _ => "unknown",
            },
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
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("queue", new
        {
            movie = MovieIdentity(path),
            activeMovieInstanceId = activeInstanceId,
            duplicate,
        });
    }

    internal static void Attach(
        string path,
        long instanceId,
        long hostGeneration,
        uint width,
        uint height,
        uint framesPerSecondNumerator,
        uint framesPerSecondDenominator,
        string mode)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("attach", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = hostGeneration,
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
        long previousGeneration,
        string nextPath,
        long nextInstanceId,
        long nextGeneration)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("reattach", new
        {
            previousMovie = MovieIdentity(previousPath),
            previousMovieInstanceId = previousInstanceId,
            previousHostMovieGeneration = previousGeneration,
            movie = MovieIdentity(nextPath),
            movieInstanceId = nextInstanceId,
            hostMovieGeneration = nextGeneration,
        });
    }

    internal static void Start(
        long instanceId,
        double audioStartSeconds,
        double audioSeconds,
        bool audioRunning,
        bool followGuestAudioClock)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("start", new
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
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("clock", new
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
        long hostGeneration,
        double wallSeconds,
        long frameIndex)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("complete", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = hostGeneration,
            wallSeconds,
            frameIndex,
        });
    }

    internal static void GenerationEnd(
        string path,
        long hostGeneration,
        long instanceId,
        string reason)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("generation-end", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = hostGeneration,
            reason,
        });
    }

    internal static void Stop(
        string path,
        long instanceId,
        long hostGeneration,
        string reason)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("stop", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = hostGeneration,
            reason,
        });
    }

    internal static void Dispose(
        string path,
        long instanceId,
        long hostGeneration,
        string reason)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("dispose", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = hostGeneration,
            reason,
        });
    }

    internal static void GuestOpen(
        int fileDescriptor,
        string path,
        long instanceId,
        bool completionShim)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("guest-open", new
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
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("guest-close", new
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
        long frameGeneration,
        long activeGeneration,
        bool hostFrameAvailable,
        bool hostPlaybackActive,
        bool advanced,
        long frameSerial,
        uint width,
        uint height)
    {
        if (!CanDoDiagnosticWork)
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

        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("presenter-pump", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = frameGeneration,
            activeHostMovieGeneration = activeGeneration,
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
        long frameGeneration,
        long activeGeneration,
        bool hostFrameAvailable,
        bool hostPlaybackActive,
        bool selectedHostMovie,
        long frameSerial,
        long lumaUploadedFrameSerial,
        long chromaUploadedFrameSerial,
        int lumaTextureIndex,
        int chromaTextureIndex)
    {
        if (!CanDoDiagnosticWork)
        {
            return;
        }

        var state = (hostFrameAvailable ? 1 : 0) |
            (hostPlaybackActive ? 2 : 0);
        var now = Stopwatch.GetTimestamp();
        var changed = !_hasPresenterSelection ||
            _lastPresenterFrameAvailable != hostFrameAvailable ||
            _lastPresenterPlaybackActive != hostPlaybackActive ||
            _lastPresenterInstanceId != instanceId ||
            _lastPresenterFrameGeneration != frameGeneration ||
            _lastPresenterActiveGeneration != activeGeneration ||
            !string.Equals(_lastPresenterPath, path, StringComparison.Ordinal);

        var shouldEmit = changed ||
            PresenterSelectionLimiter.ShouldEmit(now, instanceId, state);
        if (shouldEmit)
        {
            if (!TryReserveEvent())
            {
                return;
            }

            var movie = MovieIdentity(path);
            WriteReserved("presenter-draw-selection", new
            {
                movie,
                movieInstanceId = instanceId,
                hostMovieGeneration = frameGeneration,
                activeHostMovieGeneration = activeGeneration,
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

        if (!CanDoDiagnosticWork)
        {
            return;
        }

        _hasPresenterSelection = true;
        _lastPresenterFrameAvailable = hostFrameAvailable;
        _lastPresenterPlaybackActive = hostPlaybackActive;
        _lastPresenterInstanceId = instanceId;
        _lastPresenterFrameGeneration = frameGeneration;
        _lastPresenterActiveGeneration = activeGeneration;
        _lastPresenterPath = path;
    }

    internal static void PresenterPresentation(
        string? path,
        long instanceId,
        long frameGeneration,
        long activeGeneration,
        bool selectedHostMovie,
        bool hostPlaybackActive,
        long frameSerial,
        long presentationSequence,
        string presentationKind)
    {
        if (!CanDoDiagnosticWork)
        {
            return;
        }

        var now = Stopwatch.GetTimestamp();
        var changed = !_hasPresenterPresentation ||
            _lastPresenterPresentedHost != selectedHostMovie ||
            _lastPresenterPresentedInstanceId != instanceId ||
            _lastPresenterPresentedGeneration != frameGeneration ||
            !string.Equals(_lastPresenterPresentedPath, path, StringComparison.Ordinal);
        var state = selectedHostMovie ? 1 : 0;
        var shouldEmit = changed ||
            PresenterPresentationLimiter.ShouldEmit(now, instanceId, state);
        string? movie = null;
        if (changed && _hasPresenterPresentation && _lastPresenterPresentedHost &&
            (!selectedHostMovie || _lastPresenterPresentedInstanceId != instanceId))
        {
            if (!TryReserveEvent())
            {
                return;
            }

            WriteReserved("presenter-present-end", new
            {
                movie = _lastPresenterPresentedMovie,
                movieInstanceId = _lastPresenterPresentedInstanceId,
                hostMovieGeneration = _lastPresenterPresentedGeneration,
                reason = "presentation-changed",
            });
        }

        if (selectedHostMovie && changed)
        {
            if (!TryReserveEvent())
            {
                return;
            }

            movie = MovieIdentity(path);
            WriteReserved("presenter-present-start", new
            {
                movie,
                movieInstanceId = instanceId,
                hostMovieGeneration = frameGeneration,
                activeHostMovieGeneration = activeGeneration,
                frameSerial,
            });
        }

        if (shouldEmit)
        {
            if (!TryReserveEvent())
            {
                return;
            }

            movie ??= MovieIdentity(path);
            WriteReserved("presenter-present", new
            {
                movie,
                movieInstanceId = instanceId,
                hostMovieGeneration = frameGeneration,
                activeHostMovieGeneration = activeGeneration,
                selectedHostMovie,
                hostPlaybackActive,
                frameSerial,
                presentationSequence,
                presentationKind,
            });
        }

        if (!CanDoDiagnosticWork)
        {
            return;
        }

        _hasPresenterPresentation = true;
        _lastPresenterPresentedHost = selectedHostMovie;
        _lastPresenterPresentedInstanceId = instanceId;
        _lastPresenterPresentedGeneration = frameGeneration;
        _lastPresenterPresentedPath = path;
        _lastPresenterPresentedMovie = movie ?? _lastPresenterPresentedMovie;
    }

    internal static void PresenterInvalidation(
        string? path,
        long instanceId,
        long frameGeneration,
        long activeGeneration,
        long frameSerial,
        string reason)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("presenter-invalidation", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = frameGeneration,
            activeHostMovieGeneration = activeGeneration,
            frameSerial,
            reason,
        });
    }

    internal static void PresenterUpload(
        string? path,
        long instanceId,
        long frameGeneration,
        long activeGeneration,
        long frameSerial,
        int plane)
    {
        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("presenter-upload", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = frameGeneration,
            activeHostMovieGeneration = activeGeneration,
            frameSerial,
            plane,
        });
    }

    internal static void PresenterShutdown(
        string? path,
        long instanceId,
        long frameGeneration,
        long activeGeneration,
        long frameSerial,
        bool hostPlaybackActive)
    {
        if (!CanDoDiagnosticWork)
        {
            return;
        }

        if (_hasPresenterPresentation && _lastPresenterPresentedHost)
        {
            if (!TryReserveEvent())
            {
                return;
            }

            WriteReserved("presenter-present-end", new
            {
                movie = _lastPresenterPresentedMovie,
                movieInstanceId = _lastPresenterPresentedInstanceId,
                reason = "shutdown",
            });
        }

        if (!TryReserveEvent())
        {
            return;
        }

        WriteReserved("presenter-shutdown", new
        {
            movie = MovieIdentity(path),
            movieInstanceId = instanceId,
            hostMovieGeneration = frameGeneration,
            activeHostMovieGeneration = activeGeneration,
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

    private static void WriteReserved(string eventName, object data)
    {
        MemoryDiagnostics.RecordEvent("movie." + eventName, data);
    }
}

internal sealed class MovieDiagnosticEventBudget
{
    private readonly int _maximum;
    private int _accepted;

    internal MovieDiagnosticEventBudget(int maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        _maximum = maximum;
    }

    internal bool HasCapacity =>
        Volatile.Read(ref _accepted) < _maximum;

    internal int AcceptedCount =>
        Volatile.Read(ref _accepted);

    internal bool TryReserve()
    {
        while (true)
        {
            var accepted = Volatile.Read(ref _accepted);
            if (accepted >= _maximum)
            {
                return false;
            }

            if (Interlocked.CompareExchange(
                    ref _accepted,
                    accepted + 1,
                    accepted) == accepted)
            {
                return true;
            }
        }
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
