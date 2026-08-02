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
    // Logical generation invalidation and the final Vulkan submission boundary
    // are serialized separately from the bridge lock. The presenter holds
    // this gate only from its final host-resource reservation through
    // QueueSubmit; an invalidation that gets the gate first makes the
    // presenter fall back to guest texture resolution.
    private readonly SemaphoreSlim _submissionGate = new(1, 1);
    private long _nextGeneration;
    private long _activeGeneration;

    internal long Activate()
    {
        _submissionGate.Wait();
        try
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
        finally
        {
            _submissionGate.Release();
        }
    }

    internal long ActiveGeneration => Volatile.Read(ref _activeGeneration);

    internal bool IsActive(long generation) =>
        generation > 0 && Volatile.Read(ref _activeGeneration) == generation;

    /// <summary>
    /// Reserves the final host-movie submission boundary for <paramref
    /// name="generation"/>. The caller owns the returned lease until the
    /// Vulkan command has either been submitted or discarded.
    /// </summary>
    internal bool TryBeginSubmission(
        long generation,
        out HostMovieGenerationSubmission? submission,
        out long activeGeneration)
    {
        submission = null;
        activeGeneration = 0;
        if (generation <= 0)
        {
            return false;
        }

        _submissionGate.Wait();
        var keepGate = false;
        try
        {
            activeGeneration = Volatile.Read(ref _activeGeneration);
            if (activeGeneration != generation)
            {
                return false;
            }

            submission = new HostMovieGenerationSubmission(this, generation);
            keepGate = true;
            return true;
        }
        finally
        {
            if (!keepGate)
            {
                _submissionGate.Release();
            }
        }
    }

    internal bool Invalidate(long generation)
    {
        if (generation <= 0)
        {
            return false;
        }

        _submissionGate.Wait();
        try
        {
            lock (_gate)
            {
                if (_activeGeneration != generation)
                {
                    return false;
                }

                Volatile.Write(ref _activeGeneration, 0);
                return true;
            }
        }
        finally
        {
            _submissionGate.Release();
        }
    }

    private void ReleaseSubmission() => _submissionGate.Release();

    internal sealed class HostMovieGenerationSubmission : IDisposable
    {
        private HostMovieGenerationTracker? _owner;
        private int _references = 1;

        internal HostMovieGenerationSubmission(
            HostMovieGenerationTracker owner,
            long generation)
        {
            _owner = owner;
            Generation = generation;
        }

        internal long Generation { get; }

        internal HostMovieGenerationSubmission AddReference()
        {
            while (true)
            {
                var references = Volatile.Read(ref _references);
                if (references <= 0)
                {
                    throw new ObjectDisposedException(
                        nameof(HostMovieGenerationSubmission));
                }

                if (Interlocked.CompareExchange(
                        ref _references,
                        references + 1,
                        references) == references)
                {
                    return this;
                }
            }
        }

        public void Dispose()
        {
            if (Interlocked.Decrement(ref _references) != 0)
            {
                return;
            }

            var owner = Interlocked.Exchange(ref _owner, null);
            owner?.ReleaseSubmission();
        }
    }
}

/// <summary>
/// Tracks the presenter copy of a host frame separately from its CPU and
/// Vulkan storage. Logical invalidation changes selection eligibility at the
/// generation tracker boundary. A submission reservation prevents that
/// boundary from passing while the presenter is committing a command; once
/// the command is submitted, its resources remain under the presenter's
/// normal fence-based retirement rules.
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
