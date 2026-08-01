// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;
using SharpEmu.Logging;
using Silk.NET.Vulkan;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Provides a bounded, opt-in Vulkan host-allocation callback probe. The
/// callbacks are installed only for the Vulkan instance and device objects;
/// normal execution continues to use Vulkan's default allocator.
/// </summary>
internal sealed unsafe class VulkanHostAllocationDiagnostics : IDisposable
{
    internal const int DefaultMaximumEntries = 16384;
    internal const int DefaultMaximumEvents = 65536;
    internal const int MaximumActiveSnapshotEntries = 64;
    internal const int MaximumRecentSnapshotEvents = 64;

    private static VulkanHostAllocationDiagnostics? _current;

    private static readonly AllocationFunction AllocationCallback = AllocateCallback;
    private static readonly ReallocationFunction ReallocationCallback = ReallocateCallback;
    private static readonly FreeFunction FreeCallback = FreeCallbackImpl;
    private static readonly InternalAllocationNotification InternalAllocationCallback =
        InternalAllocationCallbackImpl;
    private static readonly InternalFreeNotification InternalFreeCallback =
        InternalFreeCallbackImpl;

    private readonly VulkanHostAllocationLedger _ledger;
    private readonly AllocationCallbacks* _callbacks;
    private int _disposed;

    private VulkanHostAllocationDiagnostics(
        int maximumEntries,
        int maximumEvents)
    {
        _ledger = new VulkanHostAllocationLedger(maximumEntries, maximumEvents);
        _callbacks = (AllocationCallbacks*)NativeMemory.AllocZeroed((nuint)sizeof(AllocationCallbacks));
        if (_callbacks is null)
        {
            throw new OutOfMemoryException("Unable to allocate Vulkan callback storage.");
        }

        *_callbacks = new AllocationCallbacks(
            null,
            new PfnAllocationFunction(AllocationCallback),
            new PfnReallocationFunction(ReallocationCallback),
            new PfnFreeFunction(FreeCallback),
            new PfnInternalAllocationNotification(InternalAllocationCallback),
            new PfnInternalFreeNotification(InternalFreeCallback));
    }

    internal static VulkanHostAllocationDiagnostics? Start()
    {
        if (!MemoryDiagnostics.IsEnabled)
        {
            return null;
        }

        var diagnostics = new VulkanHostAllocationDiagnostics(
            DefaultMaximumEntries,
            DefaultMaximumEvents);
        if (Interlocked.CompareExchange(ref _current, diagnostics, null) is not null)
        {
            diagnostics.Dispose();
            throw new InvalidOperationException(
                "A Vulkan host-allocation diagnostics probe is already active.");
        }

        return diagnostics;
    }

    internal static AllocationCallbacks* CurrentCallbacks
    {
        get
        {
            var current = Volatile.Read(ref _current);
            return current is null ? null : current._callbacks;
        }
    }

    internal VulkanHostAllocationSnapshot GetSnapshot() => _ledger.GetSnapshot();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _ = Interlocked.CompareExchange(ref _current, null, this);
        _ledger.ReleaseOutstandingForShutdown();

        _callbacks->PfnAllocation.Dispose();
        _callbacks->PfnReallocation.Dispose();
        _callbacks->PfnFree.Dispose();
        _callbacks->PfnInternalAllocation.Dispose();
        _callbacks->PfnInternalFree.Dispose();
        NativeMemory.Free(_callbacks);
    }

    private static void* AllocateCallback(
        void* userData,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        _ = userData;
        var normalizedSize = size == 0 ? 1u : size;
        var normalizedAlignment = NormalizeAlignment(alignment);
        try
        {
            var pointer = NativeMemory.AlignedAlloc(normalizedSize, normalizedAlignment);
            if (pointer is null)
            {
                return null;
            }

            Volatile.Read(ref _current)?._ledger.TrackAllocation(
                (nint)pointer,
                size,
                normalizedAlignment,
                scope,
                MemoryDiagnostics.GetElapsedMilliseconds());
            return pointer;
        }
        catch
        {
            return null;
        }
    }

    private static void* ReallocateCallback(
        void* userData,
        void* original,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        _ = userData;
        var normalizedSize = size == 0 ? 1u : size;
        var normalizedAlignment = NormalizeAlignment(alignment);
        try
        {
            if (size == 0)
            {
                FreeCallbackImpl(null, original);
                return null;
            }

            var pointer = NativeMemory.AlignedRealloc(
                original,
                normalizedSize,
                normalizedAlignment);
            if (pointer is null)
            {
                return null;
            }

            Volatile.Read(ref _current)?._ledger.TrackReallocation(
                (nint)original,
                (nint)pointer,
                size,
                normalizedAlignment,
                scope,
                MemoryDiagnostics.GetElapsedMilliseconds());
            return pointer;
        }
        catch
        {
            return null;
        }
    }

    private static void FreeCallbackImpl(void* userData, void* memory)
    {
        _ = userData;
        if (memory is null)
        {
            return;
        }

        var current = Volatile.Read(ref _current);
        if (current is not null &&
            current._ledger.TryRelease(
                (nint)memory,
                MemoryDiagnostics.GetElapsedMilliseconds()))
        {
            NativeMemory.AlignedFree(memory);
            return;
        }

        // An entry dropped at the ledger bound is still memory returned by
        // this callback. A duplicate release is deliberately not freed a
        // second time; the ledger records it for the regression and report.
        if (current is null || !current._ledger.IsKnownDuplicate((nint)memory))
        {
            NativeMemory.AlignedFree(memory);
        }
    }

    private static void InternalAllocationCallbackImpl(
        void* userData,
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        _ = userData;
        _ = size;
        _ = allocationType;
        _ = scope;
    }

    private static void InternalFreeCallbackImpl(
        void* userData,
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        _ = userData;
        _ = size;
        _ = allocationType;
        _ = scope;
    }

    private static nuint NormalizeAlignment(nuint alignment)
    {
        var minimum = (nuint)sizeof(nint);
        if (alignment < minimum)
        {
            return minimum;
        }

        if ((alignment & (alignment - 1)) == 0)
        {
            return alignment;
        }

        var rounded = minimum;
        while (rounded < alignment && rounded <= nuint.MaxValue / 2)
        {
            rounded <<= 1;
        }

        return rounded >= alignment ? rounded : minimum;
    }
}

internal sealed unsafe class VulkanHostAllocationLedger
{
    private readonly object _gate = new();
    private readonly Dictionary<nint, Entry> _entries;
    private readonly AllocationEvent[] _events;
    private readonly HashSet<nint> _recentlyReleased = new();
    private readonly int _maximumEntries;
    private readonly int _maximumEvents;
    private long _nextAllocationId;
    private long _outstandingBytes;
    private int _eventCount;
    private int _droppedEntries;
    private int _droppedEvents;
    private int _duplicateReleases;
    private int _untrackedReleases;
    private long _largestRequestedBytes;
    private long _largestAllocationId;
    private nint _largestAddress;
    private SystemAllocationScope _largestScope;
    private long _largestCreatedMilliseconds;

    internal VulkanHostAllocationLedger(
        int maximumEntries = VulkanHostAllocationDiagnostics.DefaultMaximumEntries,
        int maximumEvents = VulkanHostAllocationDiagnostics.DefaultMaximumEvents)
    {
        if (maximumEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        if (maximumEvents <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        }

        _maximumEntries = maximumEntries;
        _maximumEvents = maximumEvents;
        _entries = new Dictionary<nint, Entry>(maximumEntries);
        _events = new AllocationEvent[maximumEvents];
    }

    internal long OutstandingBytes
    {
        get
        {
            lock (_gate)
            {
                return _outstandingBytes;
            }
        }
    }

    internal void TrackAllocation(
        nint address,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope,
        long elapsedMilliseconds)
    {
        if (address == 0)
        {
            return;
        }

        var requestedBytes = checked((long)size);
        lock (_gate)
        {
            _recentlyReleased.Remove(address);
            if (_entries.Count >= _maximumEntries)
            {
                _droppedEntries++;
                return;
            }

            var entry = new Entry
            {
                AllocationId = ++_nextAllocationId,
                Address = address,
                RequestedBytes = requestedBytes,
                Alignment = alignment,
                Scope = scope,
                CreatedMilliseconds = elapsedMilliseconds,
            };
            _entries.Add(address, entry);
            _outstandingBytes = checked(_outstandingBytes + requestedBytes);
            UpdateLargestLocked(entry);
            MemoryDiagnostics.Adjust(
                "vulkan.host-allocation",
                requestedBytes,
                countDelta: 1);
            RecordEventLocked(entry, action: "allocate", elapsedMilliseconds);
        }
    }

    internal void TrackReallocation(
        nint originalAddress,
        nint newAddress,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope,
        long elapsedMilliseconds)
    {
        var requestedBytes = checked((long)size);
        lock (_gate)
        {
            _recentlyReleased.Remove(newAddress);
            if (originalAddress == newAddress &&
                _entries.TryGetValue(originalAddress, out var existing))
            {
                _outstandingBytes = checked(
                    _outstandingBytes - existing.RequestedBytes + requestedBytes);
                MemoryDiagnostics.Adjust(
                    "vulkan.host-allocation",
                    requestedBytes - existing.RequestedBytes);
                existing.RequestedBytes = requestedBytes;
                existing.Alignment = alignment;
                existing.Scope = scope;
                _entries[originalAddress] = existing;
                UpdateLargestLocked(existing);
                RecordEventLocked(existing, action: "reallocate", elapsedMilliseconds);
                return;
            }

            if (_entries.Remove(originalAddress, out var oldEntry))
            {
                _outstandingBytes = checked(_outstandingBytes - oldEntry.RequestedBytes);
                MemoryDiagnostics.Adjust(
                    "vulkan.host-allocation",
                    -oldEntry.RequestedBytes,
                    countDelta: -1);
                RememberReleaseLocked(originalAddress);
                RecordEventLocked(oldEntry, action: "reallocate-release", elapsedMilliseconds);
            }

            if (_entries.Count >= _maximumEntries)
            {
                _droppedEntries++;
                return;
            }

            var entry = new Entry
            {
                AllocationId = ++_nextAllocationId,
                Address = newAddress,
                RequestedBytes = requestedBytes,
                Alignment = alignment,
                Scope = scope,
                CreatedMilliseconds = elapsedMilliseconds,
            };
            _entries[newAddress] = entry;
            _outstandingBytes = checked(_outstandingBytes + requestedBytes);
            UpdateLargestLocked(entry);
            MemoryDiagnostics.Adjust(
                "vulkan.host-allocation",
                requestedBytes,
                countDelta: 1);
            RecordEventLocked(entry, action: "reallocate", elapsedMilliseconds);
        }
    }

    internal bool TryRelease(nint address, long elapsedMilliseconds)
    {
        lock (_gate)
        {
            if (!_entries.Remove(address, out var entry))
            {
                if (_recentlyReleased.Contains(address))
                {
                    _duplicateReleases++;
                }
                else
                {
                    _untrackedReleases++;
                }

                return false;
            }

            _outstandingBytes = checked(_outstandingBytes - entry.RequestedBytes);
            MemoryDiagnostics.Adjust(
                "vulkan.host-allocation",
                -entry.RequestedBytes,
                countDelta: -1);
            RememberReleaseLocked(address);
            RecordEventLocked(entry, action: "free", elapsedMilliseconds);
            return true;
        }
    }

    internal bool IsKnownDuplicate(nint address)
    {
        lock (_gate)
        {
            return _recentlyReleased.Contains(address);
        }
    }

    internal VulkanHostAllocationSnapshot GetSnapshot()
    {
        lock (_gate)
        {
            var active = _entries.Values
                .OrderByDescending(static entry => entry.RequestedBytes)
                .ThenBy(static entry => entry.Address)
                .Take(VulkanHostAllocationDiagnostics.MaximumActiveSnapshotEntries)
                .Select(static entry => entry.ToSnapshot())
                .ToArray();
            var recentStart = Math.Max(
                0,
                _eventCount - VulkanHostAllocationDiagnostics.MaximumRecentSnapshotEvents);
            var recentEvents = new VulkanHostAllocationEventSnapshot[_eventCount - recentStart];
            for (var index = recentStart; index < _eventCount; index++)
            {
                recentEvents[index - recentStart] = _events[index].ToSnapshot();
            }

            return new VulkanHostAllocationSnapshot
            {
                MaximumEntries = _maximumEntries,
                MaximumEvents = _maximumEvents,
                ActiveEntryCount = _entries.Count,
                ActiveBytes = _outstandingBytes,
                AllocationIdHighWatermark = _nextAllocationId,
                EventCount = _eventCount,
                DroppedEntries = _droppedEntries,
                DroppedEvents = _droppedEvents,
                DuplicateReleases = _duplicateReleases,
                UntrackedReleases = _untrackedReleases,
                LargestRequestedBytes = _largestRequestedBytes,
                LargestAllocationId = _largestAllocationId,
                LargestAddress = unchecked((ulong)_largestAddress.ToInt64()),
                LargestScope = _largestScope.ToString(),
                LargestCreatedMilliseconds = _largestCreatedMilliseconds,
                ActiveAllocations = active,
                RecentEvents = recentEvents,
            };
        }
    }

    internal void ReleaseOutstandingForShutdown()
    {
        lock (_gate)
        {
            foreach (var entry in _entries.Values)
            {
                MemoryDiagnostics.Adjust(
                    "vulkan.host-allocation",
                    -entry.RequestedBytes,
                    countDelta: -1);
                NativeMemory.AlignedFree((void*)entry.Address);
            }

            _entries.Clear();
            _outstandingBytes = 0;
        }
    }

    private void RememberReleaseLocked(nint address)
    {
        if (_recentlyReleased.Count >= _maximumEvents)
        {
            _recentlyReleased.Clear();
        }

        _recentlyReleased.Add(address);
    }

    private void UpdateLargestLocked(Entry entry)
    {
        if (entry.RequestedBytes <= _largestRequestedBytes)
        {
            return;
        }

        _largestRequestedBytes = entry.RequestedBytes;
        _largestAllocationId = entry.AllocationId;
        _largestAddress = entry.Address;
        _largestScope = entry.Scope;
        _largestCreatedMilliseconds = entry.CreatedMilliseconds;
    }

    private void RecordEventLocked(
        Entry entry,
        string action,
        long elapsedMilliseconds)
    {
        if (_eventCount >= _maximumEvents)
        {
            _droppedEvents++;
            return;
        }

        _events[_eventCount++] = new AllocationEvent
        {
            Action = action,
            AllocationId = entry.AllocationId,
            Address = entry.Address,
            RequestedBytes = entry.RequestedBytes,
            Alignment = entry.Alignment,
            Scope = entry.Scope,
            ElapsedMilliseconds = elapsedMilliseconds,
        };
    }

    private struct Entry
    {
        public long AllocationId;
        public nint Address;
        public long RequestedBytes;
        public nuint Alignment;
        public SystemAllocationScope Scope;
        public long CreatedMilliseconds;

        public VulkanHostAllocationEntrySnapshot ToSnapshot() => new()
        {
            AllocationId = AllocationId,
            Address = unchecked((ulong)Address.ToInt64()),
            RequestedBytes = RequestedBytes,
            Alignment = checked((ulong)Alignment),
            Scope = Scope.ToString(),
            CreatedMilliseconds = CreatedMilliseconds,
        };
    }

    private struct AllocationEvent
    {
        public string Action;
        public long AllocationId;
        public nint Address;
        public long RequestedBytes;
        public nuint Alignment;
        public SystemAllocationScope Scope;
        public long ElapsedMilliseconds;

        public VulkanHostAllocationEventSnapshot ToSnapshot() => new()
        {
            Action = Action,
            AllocationId = AllocationId,
            Address = unchecked((ulong)Address.ToInt64()),
            RequestedBytes = RequestedBytes,
            Alignment = checked((ulong)Alignment),
            Scope = Scope.ToString(),
            ElapsedMilliseconds = ElapsedMilliseconds,
        };
    }
}

internal sealed class VulkanHostAllocationSnapshot
{
    public int MaximumEntries { get; init; }
    public int MaximumEvents { get; init; }
    public int ActiveEntryCount { get; init; }
    public long ActiveBytes { get; init; }
    public long AllocationIdHighWatermark { get; init; }
    public int EventCount { get; init; }
    public int DroppedEntries { get; init; }
    public int DroppedEvents { get; init; }
    public int DuplicateReleases { get; init; }
    public int UntrackedReleases { get; init; }
    public long LargestRequestedBytes { get; init; }
    public long LargestAllocationId { get; init; }
    public ulong LargestAddress { get; init; }
    public string LargestScope { get; init; } = string.Empty;
    public long LargestCreatedMilliseconds { get; init; }
    public VulkanHostAllocationEntrySnapshot[] ActiveAllocations { get; init; } = [];
    public VulkanHostAllocationEventSnapshot[] RecentEvents { get; init; } = [];
}

internal sealed class VulkanHostAllocationEntrySnapshot
{
    public long AllocationId { get; init; }
    public ulong Address { get; init; }
    public long RequestedBytes { get; init; }
    public ulong Alignment { get; init; }
    public string Scope { get; init; } = string.Empty;
    public long CreatedMilliseconds { get; init; }
}

internal sealed class VulkanHostAllocationEventSnapshot
{
    public string Action { get; init; } = string.Empty;
    public long AllocationId { get; init; }
    public ulong Address { get; init; }
    public long RequestedBytes { get; init; }
    public ulong Alignment { get; init; }
    public string Scope { get; init; } = string.Empty;
    public long ElapsedMilliseconds { get; init; }
}
