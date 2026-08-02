// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Media;

/// <summary>
/// Gives each successfully attached host movie a distinct lifetime token.
/// The bridge owns the active token; an old token cannot become active again.
/// </summary>
internal sealed class HostMovieGenerationTracker
{
    private readonly object _gate = new();
    private long _nextGeneration;
    private long _activeGeneration;

    internal long Activate()
    {
        lock (_gate)
        {
            var generation = ++_nextGeneration;
            if (generation <= 0)
            {
                throw new InvalidOperationException(
                    "Host movie generation counter overflowed.");
            }

            Volatile.Write(ref _activeGeneration, generation);
            return generation;
        }
    }

    internal long ActiveGeneration => Volatile.Read(ref _activeGeneration);

    internal bool IsActive(long generation) =>
        generation > 0 && Volatile.Read(ref _activeGeneration) == generation;

    internal bool Invalidate(long generation) =>
        generation > 0 &&
        Interlocked.CompareExchange(ref _activeGeneration, 0, generation) == generation;
}

/// <summary>
/// Tracks the presenter copy of a host frame separately from its CPU and
/// Vulkan storage. Invalidation changes selection eligibility only; resources
/// already owned by a submitted command remain under the presenter's normal
/// fence-based retirement rules.
/// </summary>
internal struct HostMovieFrameLifetime
{
    private long _generation;
    private bool _hasFrame;

    internal long Generation => _generation;

    internal bool HasFrame => _hasFrame;

    /// <summary>
    /// Publishes a frame and reports whether it belongs to a new generation.
    /// A new generation never inherits the previous frame's eligibility.
    /// </summary>
    internal bool Publish(long generation)
    {
        if (generation <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generation));
        }

        var changed = _generation != generation;
        if (changed)
        {
            _generation = generation;
            _hasFrame = false;
        }

        _hasFrame = true;
        return changed;
    }

    internal bool IsEligible(long activeGeneration) =>
        _hasFrame &&
        _generation > 0 &&
        activeGeneration == _generation;

    internal bool Invalidate(long generation)
    {
        if (!_hasFrame || _generation != generation)
        {
            return false;
        }

        _hasFrame = false;
        return true;
    }

    internal void Reset()
    {
        _generation = 0;
        _hasFrame = false;
    }
}
