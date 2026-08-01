// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;
using SharpEmu.Logging;
using Silk.NET.Vulkan;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Provides a bounded, opt-in Vulkan host-allocation callback probe. The
/// pfnAllocation/pfnReallocation/pfnFree requests and informational internal
/// notifications are installed only at the Vulkan instance and device roots;
/// this is not complete coverage of Vulkan child-object or driver allocations.
/// Normal execution continues to use Vulkan's default allocator.
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

    internal VulkanHostAllocationLedger LedgerForTests => _ledger;

    internal static void* InvokeAllocationCallbackForTests(
        nuint size,
        nuint alignment,
        SystemAllocationScope scope) =>
        AllocateCallback(null, size, alignment, scope);

    internal static void* InvokeReallocationCallbackForTests(
        void* original,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope) =>
        ReallocateCallback(null, original, size, alignment, scope);

    internal static void InvokeFreeCallbackForTests(void* memory) =>
        FreeCallbackImpl(null, memory);

    internal void RecordReallocationForTests(
        nint originalAddress,
        nint newAddress,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        TrackReallocationBestEffort(
            originalAddress,
            newAddress,
            size,
            alignment,
            scope);
    }

    internal static void InvokeInternalAllocationCallbackForTests(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope) =>
        InternalAllocationCallbackImpl(null, size, allocationType, scope);

    internal static void InvokeInternalFreeCallbackForTests(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope) =>
        InternalFreeCallbackImpl(null, size, allocationType, scope);

    private void TrackAllocationBestEffort(
        nint address,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        try
        {
            _ledger.TrackAllocation(
                address,
                size,
                alignment,
                scope,
                MemoryDiagnostics.GetElapsedMilliseconds());
        }
        catch
        {
            _ledger.RecordBookkeepingFailure(
                size,
                VulkanHostAllocationBookkeepingFailure.Allocation);
        }
    }

    private void TrackReallocationBestEffort(
        nint originalAddress,
        nint newAddress,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        try
        {
            _ledger.TrackReallocation(
                originalAddress,
                newAddress,
                size,
                alignment,
                scope,
                MemoryDiagnostics.GetElapsedMilliseconds());
        }
        catch
        {
            // A successful realloc has consumed the source pointer even when
            // bookkeeping fails. Remove any stale source/replacement entries
            // without marking the live replacement as released. Vulkan will
            // release that replacement through pfnFree later.
            try
            {
                _ledger.ReconcileSuccessfulReallocationFailure(
                    originalAddress,
                    newAddress);
            }
            catch
            {
                // The scalar failure state below is still best effort. The
                // callback must return the native replacement pointer.
            }

            _ledger.RecordBookkeepingFailure(
                size,
                VulkanHostAllocationBookkeepingFailure.Reallocation);
        }
    }

    private VulkanHostAllocationReleaseResult ReleaseForCallback(nint address)
    {
        try
        {
            return _ledger.TryReleaseForCallback(
                address,
                MemoryDiagnostics.GetElapsedMilliseconds());
        }
        catch
        {
            _ledger.RecordBookkeepingFailure(
                0,
                VulkanHostAllocationBookkeepingFailure.Release);
            return VulkanHostAllocationReleaseResult.Untracked;
        }
    }

    private void RecordInternalAllocationBestEffort(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        try
        {
            _ledger.RecordInternalAllocation(size, allocationType, scope);
        }
        catch
        {
            _ledger.RecordInternalNotificationDrop();
        }
    }

    private void RecordInternalFreeBestEffort(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        try
        {
            _ledger.RecordInternalFree(size, allocationType, scope);
        }
        catch
        {
            _ledger.RecordInternalNotificationDrop();
        }
    }

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
        void* pointer;
        try
        {
            pointer = NativeMemory.AlignedAlloc(normalizedSize, normalizedAlignment);
        }
        catch
        {
            return null;
        }

        if (pointer is null)
        {
            return null;
        }

        var current = Volatile.Read(ref _current);
        current?.TrackAllocationBestEffort(
            (nint)pointer,
            size,
            normalizedAlignment,
            scope);
        return pointer;
    }

    private static void* ReallocateCallback(
        void* userData,
        void* original,
        nuint size,
        nuint alignment,
        SystemAllocationScope scope)
    {
        _ = userData;
        if (size == 0)
        {
            FreeCallbackImpl(null, original);
            return null;
        }

        if (original is null)
        {
            return AllocateCallback(null, size, alignment, scope);
        }

        var normalizedSize = size;
        var normalizedAlignment = NormalizeAlignment(alignment);
        void* pointer;
        try
        {
            pointer = NativeMemory.AlignedRealloc(
                original,
                normalizedSize,
                normalizedAlignment);
        }
        catch
        {
            return null;
        }

        if (pointer is null)
        {
            return null;
        }

        var current = Volatile.Read(ref _current);
        current?.TrackReallocationBestEffort(
            (nint)original,
            (nint)pointer,
            size,
            normalizedAlignment,
            scope);
        return pointer;
    }

    private static void FreeCallbackImpl(void* userData, void* memory)
    {
        _ = userData;
        if (memory is null)
        {
            return;
        }

        var current = Volatile.Read(ref _current);
        var releaseResult = current is null
            ? VulkanHostAllocationReleaseResult.Untracked
            : current.ReleaseForCallback((nint)memory);
        if (releaseResult != VulkanHostAllocationReleaseResult.Duplicate)
        {
            try
            {
                NativeMemory.AlignedFree(memory);
            }
            catch
            {
                // NativeMemory.AlignedFree is not expected to throw, but no
                // exception may cross the Vulkan callback boundary.
            }
        }
    }

    private static void InternalAllocationCallbackImpl(
        void* userData,
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        _ = userData;
        var current = Volatile.Read(ref _current);
        current?.RecordInternalAllocationBestEffort(size, allocationType, scope);
    }

    private static void InternalFreeCallbackImpl(
        void* userData,
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        _ = userData;
        var current = Volatile.Read(ref _current);
        current?.RecordInternalFreeBestEffort(size, allocationType, scope);
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

/// <summary>
/// Keeps the instance/device allocator callbacks alive until the Vulkan roots
/// that received them have been destroyed. It is deliberately small so the
/// partial-initialization path can be exercised without creating Vulkan
/// objects in a unit test.
/// </summary>
internal sealed class VulkanHostAllocationLifetime : IDisposable
{
    private readonly Action _disposeProbe;
    private Action? _destroyDevice;
    private Action? _destroyInstance;
    private int _disposed;

    internal VulkanHostAllocationLifetime(Action disposeProbe)
    {
        _disposeProbe = disposeProbe ?? throw new ArgumentNullException(nameof(disposeProbe));
    }

    internal void RegisterDevice(Action destroyDevice)
    {
        ArgumentNullException.ThrowIfNull(destroyDevice);
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(VulkanHostAllocationLifetime));
        }

        if (Interlocked.CompareExchange(ref _destroyDevice, destroyDevice, null) is not null)
        {
            throw new InvalidOperationException("The Vulkan device lifetime was already registered.");
        }
    }

    internal void RegisterInstance(Action destroyInstance)
    {
        ArgumentNullException.ThrowIfNull(destroyInstance);
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(VulkanHostAllocationLifetime));
        }

        if (Interlocked.CompareExchange(ref _destroyInstance, destroyInstance, null) is not null)
        {
            throw new InvalidOperationException("The Vulkan instance lifetime was already registered.");
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // The native Vulkan destroy calls used by the presenter do not throw.
        // Keep the ordering explicit: device, instance, then callback storage.
        Interlocked.Exchange(ref _destroyDevice, null)?.Invoke();
        Interlocked.Exchange(ref _destroyInstance, null)?.Invoke();
        _disposeProbe();
    }
}

internal enum VulkanHostAllocationBookkeepingFailure
{
    Allocation,
    Reallocation,
    Release,
}

internal enum VulkanHostAllocationReleaseResult
{
    Tracked,
    Duplicate,
    Untracked,
}

internal sealed unsafe class VulkanHostAllocationLedger
{
    private readonly object _gate = new();
    private readonly Dictionary<nint, Entry> _entries;
    private readonly AllocationEvent[] _events;
    private readonly HashSet<nint> _recentlyReleased;
    private readonly VulkanInternalAllocationNotifications _internalNotifications = new();
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
    private int _bookkeepingFailures;
    private long _bookkeepingFailureBytes;
    private int _allocationBookkeepingFailures;
    private int _reallocationBookkeepingFailures;
    private int _releaseBookkeepingFailures;
    private int _failNextAllocationBookkeeping;
    private int _failNextReallocationBookkeeping;

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
        _recentlyReleased = new HashSet<nint>(maximumEvents);
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

        if (Interlocked.Exchange(ref _failNextAllocationBookkeeping, 0) != 0)
        {
            throw new InvalidOperationException("Injected Vulkan allocation bookkeeping failure.");
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
            _outstandingBytes += requestedBytes;
            UpdateLargestLocked(entry);
            AdjustMemoryDiagnostics(
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
        if (Interlocked.Exchange(ref _failNextReallocationBookkeeping, 0) != 0)
        {
            throw new InvalidOperationException("Injected Vulkan reallocation bookkeeping failure.");
        }

        var requestedBytes = checked((long)size);
        lock (_gate)
        {
            _recentlyReleased.Remove(newAddress);
            if (originalAddress == newAddress &&
                _entries.TryGetValue(originalAddress, out var existing))
            {
                _outstandingBytes =
                    _outstandingBytes - existing.RequestedBytes + requestedBytes;
                AdjustMemoryDiagnostics(
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
                _outstandingBytes -= oldEntry.RequestedBytes;
                AdjustMemoryDiagnostics(
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
            _outstandingBytes += requestedBytes;
            UpdateLargestLocked(entry);
            AdjustMemoryDiagnostics(
                "vulkan.host-allocation",
                requestedBytes,
                countDelta: 1);
            RecordEventLocked(entry, action: "reallocate", elapsedMilliseconds);
        }
    }

    internal bool TryRelease(nint address, long elapsedMilliseconds) =>
        TryReleaseForCallback(address, elapsedMilliseconds) ==
        VulkanHostAllocationReleaseResult.Tracked;

    internal VulkanHostAllocationReleaseResult TryReleaseForCallback(
        nint address,
        long elapsedMilliseconds)
    {
        lock (_gate)
        {
            if (!_entries.Remove(address, out var entry))
            {
                if (_recentlyReleased.Contains(address))
                {
                    _duplicateReleases++;
                    return VulkanHostAllocationReleaseResult.Duplicate;
                }

                _untrackedReleases++;
                RememberReleaseLocked(address);
                return VulkanHostAllocationReleaseResult.Untracked;
            }

            _outstandingBytes -= entry.RequestedBytes;
            AdjustMemoryDiagnostics(
                "vulkan.host-allocation",
                -entry.RequestedBytes,
                countDelta: -1);
            RememberReleaseLocked(address);
            RecordEventLocked(entry, action: "free", elapsedMilliseconds);
            return VulkanHostAllocationReleaseResult.Tracked;
        }
    }

    internal void ReconcileSuccessfulReallocationFailure(
        nint originalAddress,
        nint newAddress)
    {
        lock (_gate)
        {
            if (originalAddress != 0 && originalAddress != newAddress &&
                _entries.Remove(originalAddress, out var oldEntry))
            {
                _outstandingBytes -= oldEntry.RequestedBytes;
                AdjustMemoryDiagnostics(
                    "vulkan.host-allocation",
                    -oldEntry.RequestedBytes,
                    countDelta: -1);
                RememberReleaseLocked(originalAddress);
                RecordEventLocked(oldEntry, action: "reallocate-release", elapsedMilliseconds: 0);
            }

            // If a bookkeeping operation added the replacement before
            // failing, remove that accounting. The replacement remains live
            // and must not enter the released-address set: the next pfnFree
            // must free it as an untracked successful allocation.
            if (newAddress != 0 && _entries.Remove(newAddress, out var newEntry))
            {
                _outstandingBytes -= newEntry.RequestedBytes;
                AdjustMemoryDiagnostics(
                    "vulkan.host-allocation",
                    -newEntry.RequestedBytes,
                    countDelta: -1);
            }

            if (originalAddress == newAddress && newAddress != 0)
            {
                // An in-place realloc consumes no distinct source pointer.
                // Removing the stale entry above is sufficient; do not mark
                // the live replacement as released.
                _recentlyReleased.Remove(newAddress);
            }
        }
    }

    internal void RecordBookkeepingFailure(
        nuint requestedBytes,
        VulkanHostAllocationBookkeepingFailure failure)
    {
        Interlocked.Increment(ref _bookkeepingFailures);
        AddSaturated(ref _bookkeepingFailureBytes, ToFailureBytes(requestedBytes));
        switch (failure)
        {
            case VulkanHostAllocationBookkeepingFailure.Allocation:
                Interlocked.Increment(ref _allocationBookkeepingFailures);
                break;
            case VulkanHostAllocationBookkeepingFailure.Reallocation:
                Interlocked.Increment(ref _reallocationBookkeepingFailures);
                break;
            case VulkanHostAllocationBookkeepingFailure.Release:
                Interlocked.Increment(ref _releaseBookkeepingFailures);
                break;
        }
    }

    internal void RecordInternalAllocation(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope) =>
        _internalNotifications.RecordAllocation(size, allocationType, scope);

    internal void RecordInternalFree(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope) =>
        _internalNotifications.RecordFree(size, allocationType, scope);

    internal void RecordInternalNotificationDrop() =>
        _internalNotifications.RecordDrop();

    internal void FailNextAllocationBookkeepingForTests() =>
        Interlocked.Exchange(ref _failNextAllocationBookkeeping, 1);

    internal void FailNextReallocationBookkeepingForTests() =>
        Interlocked.Exchange(ref _failNextReallocationBookkeeping, 1);

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
                BookkeepingFailures = Volatile.Read(ref _bookkeepingFailures),
                BookkeepingFailureBytes = Volatile.Read(ref _bookkeepingFailureBytes),
                AllocationBookkeepingFailures = Volatile.Read(ref _allocationBookkeepingFailures),
                ReallocationBookkeepingFailures = Volatile.Read(ref _reallocationBookkeepingFailures),
                ReleaseBookkeepingFailures = Volatile.Read(ref _releaseBookkeepingFailures),
                LargestRequestedBytes = _largestRequestedBytes,
                LargestAllocationId = _largestAllocationId,
                LargestAddress = unchecked((ulong)_largestAddress.ToInt64()),
                LargestScope = _largestScope.ToString(),
                LargestCreatedMilliseconds = _largestCreatedMilliseconds,
                InternalAllocationCount = _internalNotifications.AllocationCount,
                InternalFreeCount = _internalNotifications.FreeCount,
                InternalOutstandingBytes = _internalNotifications.OutstandingBytes,
                InternalPeakOutstandingBytes = _internalNotifications.PeakOutstandingBytes,
                InternalLargestAllocationBytes = _internalNotifications.LargestAllocationBytes,
                InternalLargestAllocationType = _internalNotifications.LargestAllocationType.ToString(),
                InternalLargestAllocationScope = _internalNotifications.LargestAllocationScope.ToString(),
                InternalDroppedNotifications = _internalNotifications.DroppedNotifications,
                InternalUnmatchedFreeNotifications = _internalNotifications.UnmatchedFreeNotifications,
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
                AdjustMemoryDiagnostics(
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

    private static long ToFailureBytes(nuint requestedBytes) =>
        requestedBytes > unchecked((nuint)long.MaxValue)
            ? long.MaxValue
            : (long)requestedBytes;

    private static void AddSaturated(ref long target, long value)
    {
        if (value <= 0)
        {
            return;
        }

        while (true)
        {
            var current = Volatile.Read(ref target);
            var next = current > long.MaxValue - value
                ? long.MaxValue
                : current + value;
            if (Interlocked.CompareExchange(ref target, next, current) == current)
            {
                return;
            }
        }
    }

    private static void AdjustMemoryDiagnostics(
        string category,
        long byteDelta,
        long countDelta = 0)
    {
        try
        {
            MemoryDiagnostics.Adjust(category, byteDelta, countDelta);
        }
        catch
        {
            // The callback ledger remains authoritative for pointer ownership;
            // the optional JSONL category counter is best effort.
        }
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

/// <summary>
/// Scalar-only accounting for Vulkan's informational internal-allocation
/// notifications. These callbacks do not own the reported memory and never
/// retain a pointer or allocate an event object.
/// </summary>
internal sealed class VulkanInternalAllocationNotifications
{
    private readonly object _largestGate = new();
    private long _allocationCount;
    private long _freeCount;
    private long _outstandingBytes;
    private long _peakOutstandingBytes;
    private long _largestAllocationBytes;
    private InternalAllocationType _largestAllocationType;
    private SystemAllocationScope _largestAllocationScope;
    private long _droppedNotifications;
    private long _unmatchedFreeNotifications;

    internal long AllocationCount => Interlocked.Read(ref _allocationCount);
    internal long FreeCount => Interlocked.Read(ref _freeCount);
    internal long OutstandingBytes => Interlocked.Read(ref _outstandingBytes);
    internal long PeakOutstandingBytes => Interlocked.Read(ref _peakOutstandingBytes);
    internal long LargestAllocationBytes => Interlocked.Read(ref _largestAllocationBytes);
    internal InternalAllocationType LargestAllocationType
    {
        get
        {
            lock (_largestGate)
            {
                return _largestAllocationType;
            }
        }
    }

    internal SystemAllocationScope LargestAllocationScope
    {
        get
        {
            lock (_largestGate)
            {
                return _largestAllocationScope;
            }
        }
    }

    internal long DroppedNotifications => Interlocked.Read(ref _droppedNotifications);
    internal long UnmatchedFreeNotifications => Interlocked.Read(ref _unmatchedFreeNotifications);

    internal void RecordAllocation(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        Interlocked.Increment(ref _allocationCount);
        if (!TryConvertSize(size, out var bytes))
        {
            RecordDrop();
            return;
        }

        if (!TryAdd(ref _outstandingBytes, bytes))
        {
            RecordDrop();
            return;
        }

        UpdatePeak();
        var largest = Interlocked.Read(ref _largestAllocationBytes);
        if (bytes <= largest)
        {
            return;
        }

        lock (_largestGate)
        {
            if (bytes > _largestAllocationBytes)
            {
                _largestAllocationBytes = bytes;
                _largestAllocationType = allocationType;
                _largestAllocationScope = scope;
            }
        }
    }

    internal void RecordFree(
        nuint size,
        InternalAllocationType allocationType,
        SystemAllocationScope scope)
    {
        _ = allocationType;
        _ = scope;
        Interlocked.Increment(ref _freeCount);
        if (!TryConvertSize(size, out var bytes))
        {
            RecordDrop();
            Interlocked.Increment(ref _unmatchedFreeNotifications);
            return;
        }

        while (true)
        {
            var current = Interlocked.Read(ref _outstandingBytes);
            if (bytes > current)
            {
                if (Interlocked.CompareExchange(ref _outstandingBytes, 0, current) == current)
                {
                    Interlocked.Increment(ref _unmatchedFreeNotifications);
                    return;
                }

                continue;
            }

            if (Interlocked.CompareExchange(
                    ref _outstandingBytes,
                    current - bytes,
                    current) == current)
            {
                return;
            }
        }
    }

    internal void RecordDrop() => Interlocked.Increment(ref _droppedNotifications);

    private static bool TryConvertSize(nuint size, out long bytes)
    {
        if (size > unchecked((nuint)long.MaxValue))
        {
            bytes = 0;
            return false;
        }

        bytes = (long)size;
        return true;
    }

    private static bool TryAdd(ref long target, long bytes)
    {
        while (true)
        {
            var current = Interlocked.Read(ref target);
            if (bytes > long.MaxValue - current)
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref target, current + bytes, current) == current)
            {
                return true;
            }
        }
    }

    private void UpdatePeak()
    {
        while (true)
        {
            var current = Interlocked.Read(ref _outstandingBytes);
            var peak = Interlocked.Read(ref _peakOutstandingBytes);
            if (current <= peak)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _peakOutstandingBytes, current, peak) == peak)
            {
                return;
            }
        }
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
    public int BookkeepingFailures { get; init; }
    public long BookkeepingFailureBytes { get; init; }
    public int AllocationBookkeepingFailures { get; init; }
    public int ReallocationBookkeepingFailures { get; init; }
    public int ReleaseBookkeepingFailures { get; init; }
    public long LargestRequestedBytes { get; init; }
    public long LargestAllocationId { get; init; }
    public ulong LargestAddress { get; init; }
    public string LargestScope { get; init; } = string.Empty;
    public long LargestCreatedMilliseconds { get; init; }
    public long InternalAllocationCount { get; init; }
    public long InternalFreeCount { get; init; }
    public long InternalOutstandingBytes { get; init; }
    public long InternalPeakOutstandingBytes { get; init; }
    public long InternalLargestAllocationBytes { get; init; }
    public string InternalLargestAllocationType { get; init; } = string.Empty;
    public string InternalLargestAllocationScope { get; init; } = string.Empty;
    public long InternalDroppedNotifications { get; init; }
    public long InternalUnmatchedFreeNotifications { get; init; }
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
