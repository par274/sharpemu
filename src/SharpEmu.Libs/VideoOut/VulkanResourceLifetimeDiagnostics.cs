// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Logging;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Scalar identity used by the opt-in Vulkan texture lifetime ledger. It is
/// deliberately independent of TextureResource so the ledger never retains a
/// guest payload or a Vulkan resource object.
/// </summary>
internal readonly record struct VulkanTextureDiagnosticDescriptor(
    ulong GuestAddress,
    uint Width,
    uint Height,
    uint Depth,
    uint Format,
    uint NumberType,
    uint DstSelect,
    uint TileMode,
    uint Pitch,
    uint MipLevel,
    uint BaseMipLevel,
    uint ResourceMipLevels,
    uint Layers,
    uint Type,
    bool Arrayed,
    bool IsStorage);

internal sealed class VulkanResourceLifetimeDiagnostics
{
    internal const int DefaultMaximumEntries = 256;
    internal const int DefaultMaximumLifecycleEvents = 2048;

    private readonly object _gate = new();
    private readonly Dictionary<long, Entry> _entries = new();
    private readonly int _maximumEntries;
    private readonly int _maximumLifecycleEvents;
    private long _nextResourceId;
    private long _retainedImageBytes;
    private long _retainedStagingBytes;
    private long _deferredBytes;
    private int _lifecycleEventCount;
    private int _droppedLifecycleEvents;
    private int _droppedEntries;

    internal VulkanResourceLifetimeDiagnostics(
        int maximumEntries = DefaultMaximumEntries,
        int maximumLifecycleEvents = DefaultMaximumLifecycleEvents)
    {
        if (maximumEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        if (maximumLifecycleEvents <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLifecycleEvents));
        }

        _maximumEntries = maximumEntries;
        _maximumLifecycleEvents = maximumLifecycleEvents;
    }

    internal long TrackCacheInsertion(
        VulkanTextureDiagnosticDescriptor descriptor,
        long guestWorkSequence,
        string queue,
        long insertionMilliseconds,
        long imageMemoryBytes,
        long stagingMemoryBytes,
        bool stagingMapped,
        bool uploadRecorded)
    {
        imageMemoryBytes = NonNegative(imageMemoryBytes);
        stagingMemoryBytes = NonNegative(stagingMemoryBytes);
        queue = Bounded(queue);

        lock (_gate)
        {
            if (_entries.Count >= _maximumEntries)
            {
                _droppedEntries++;
                return 0;
            }

            var resourceId = ++_nextResourceId;
            var entry = new Entry
            {
                ResourceId = resourceId,
                GuestAddress = descriptor.GuestAddress,
                Width = descriptor.Width,
                Height = descriptor.Height,
                Depth = descriptor.Depth,
                Format = descriptor.Format,
                NumberType = descriptor.NumberType,
                DstSelect = descriptor.DstSelect,
                TileMode = descriptor.TileMode,
                Pitch = descriptor.Pitch,
                MipLevel = descriptor.MipLevel,
                BaseMipLevel = descriptor.BaseMipLevel,
                ResourceMipLevels = descriptor.ResourceMipLevels,
                Layers = descriptor.Layers,
                Type = descriptor.Type,
                Arrayed = descriptor.Arrayed,
                IsStorage = descriptor.IsStorage,
                CreatingGuestWorkSequence = guestWorkSequence,
                CreatingQueue = queue,
                InsertionMilliseconds = insertionMilliseconds,
                ImageMemoryBytes = imageMemoryBytes,
                StagingMemoryBytes = stagingMemoryBytes,
                StagingMapped = stagingMapped,
                UploadRecorded = uploadRecorded,
                State = "cached",
                Retained = true,
            };
            _entries.Add(resourceId, entry);
            _retainedImageBytes = checked(_retainedImageBytes + imageMemoryBytes);
            _retainedStagingBytes = checked(_retainedStagingBytes + stagingMemoryBytes);
            RecordLifecycleEventLocked(
                "insert",
                entry,
                "cache-inserted",
                retireTimeline: 0,
                actualTimeline: 0);
            return resourceId;
        }
    }

    internal void RecordUse(
        long resourceId,
        bool cacheHit,
        ulong timeline,
        long guestWorkSequence,
        string queue,
        long timestampMilliseconds)
    {
        if (resourceId == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry))
            {
                return;
            }

            if (cacheHit && entry.CacheHitCount < int.MaxValue)
            {
                entry.CacheHitCount++;
            }

            if (!entry.FirstUseRecorded)
            {
                entry.FirstUseMilliseconds = timestampMilliseconds;
                entry.FirstUseRecorded = true;
            }

            entry.LastUseMilliseconds = timestampMilliseconds;
            entry.LatestGuestWorkSequence = Math.Max(
                entry.LatestGuestWorkSequence,
                guestWorkSequence);
            entry.LastUseQueue = Bounded(queue);
            if (timeline != 0)
            {
                entry.FirstUseTimeline = entry.FirstUseTimeline == 0
                    ? timeline
                    : Math.Min(entry.FirstUseTimeline, timeline);
                entry.LastUseTimeline = Math.Max(entry.LastUseTimeline, timeline);
            }
        }
    }

    internal void RecordSubmission(
        long resourceId,
        ulong timeline)
    {
        if (resourceId == 0 || timeline == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry))
            {
                return;
            }

            entry.FirstUseTimeline = entry.FirstUseTimeline == 0
                ? timeline
                : Math.Min(entry.FirstUseTimeline, timeline);
            entry.LastUseTimeline = Math.Max(entry.LastUseTimeline, timeline);
            if (entry.UploadRecorded && entry.UploadSubmissionTimeline == 0)
            {
                entry.UploadSubmissionTimeline = timeline;
            }
        }
    }

    internal void RecordUploadRecorded(long resourceId)
    {
        if (resourceId == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (_entries.TryGetValue(resourceId, out var entry))
            {
                entry.UploadRecorded = true;
            }
        }
    }

    internal void RecordUploadCompletion(long resourceId, ulong timeline)
    {
        if (resourceId == 0 || timeline == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry) ||
                !entry.UploadRecorded ||
                entry.UploadSubmissionTimeline == 0 ||
                entry.UploadCompletionTimeline != 0)
            {
                return;
            }

            entry.UploadCompletionTimeline = timeline;
        }
    }

    internal void RecordCacheRemoval(
        long resourceId,
        string reason,
        long timestampMilliseconds,
        ulong retireTimeline)
    {
        if (resourceId == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry))
            {
                return;
            }

            var firstRemoval = !entry.CacheRemovalRecorded;
            if (firstRemoval)
            {
                entry.CacheRemovalMilliseconds = timestampMilliseconds;
                entry.CacheRemovalReason = Bounded(reason);
                entry.CacheRemovalRecorded = true;
            }

            if (entry.Retained)
            {
                entry.Retained = false;
                _retainedImageBytes = checked(_retainedImageBytes - entry.ImageMemoryBytes);
                _retainedStagingBytes = checked(_retainedStagingBytes - entry.StagingMemoryBytes);
            }

            if (entry.State == "cached")
            {
                entry.State = "removed";
            }

            if (firstRemoval)
            {
                RecordLifecycleEventLocked(
                    "remove",
                    entry,
                    reason,
                    retireTimeline,
                    actualTimeline: 0);
            }
        }
    }

    internal void RecordDeferredDestroy(
        long resourceId,
        ulong retireTimeline,
        long timestampMilliseconds)
    {
        if (resourceId == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry) ||
                entry.Deferred)
            {
                return;
            }

            entry.Deferred = true;
            entry.DeferredRetireTimeline = retireTimeline;
            entry.DeferredMilliseconds = timestampMilliseconds;
            entry.State = "deferred-destruction";
            if (entry.Retained)
            {
                entry.Retained = false;
                _retainedImageBytes = checked(_retainedImageBytes - entry.ImageMemoryBytes);
                _retainedStagingBytes = checked(_retainedStagingBytes - entry.StagingMemoryBytes);
            }
            var bytes = checked(entry.ImageMemoryBytes + entry.StagingMemoryBytes);
            _deferredBytes = checked(_deferredBytes + bytes);
            RecordLifecycleEventLocked(
                "deferred",
                entry,
                "deferred-destruction",
                retireTimeline,
                actualTimeline: 0);
        }
    }

    internal void RecordActualDestroy(
        long resourceId,
        ulong timeline,
        long timestampMilliseconds,
        string reason)
    {
        if (resourceId == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(resourceId, out var entry) ||
                entry.ActualDestructionRecorded)
            {
                return;
            }

            if (entry.Deferred)
            {
                var bytes = checked(entry.ImageMemoryBytes + entry.StagingMemoryBytes);
                _deferredBytes = checked(_deferredBytes - bytes);
                entry.Deferred = false;
            }

            entry.ActualDestructionMilliseconds = timestampMilliseconds;
            entry.ActualDestructionRecorded = true;
            entry.ActualDestructionReason = Bounded(reason);
            entry.ActualDestructionTimeline = timeline;
            entry.State = "destroyed";
            RecordLifecycleEventLocked(
                "destroy",
                entry,
                reason,
                retireTimeline: entry.DeferredRetireTimeline,
                actualTimeline: timeline);
        }
    }

    internal VulkanResourceLifetimeSnapshot GetSnapshot()
    {
        lock (_gate)
        {
            return new VulkanResourceLifetimeSnapshot
            {
                MaximumEntries = _maximumEntries,
                MaximumLifecycleEvents = _maximumLifecycleEvents,
                EntryCount = _entries.Count,
                DroppedEntries = _droppedEntries,
                LifecycleEventCount = _lifecycleEventCount,
                DroppedLifecycleEvents = _droppedLifecycleEvents,
                RetainedImageBytes = _retainedImageBytes,
                RetainedStagingBytes = _retainedStagingBytes,
                DeferredDestructionBytes = _deferredBytes,
                Entries = _entries.Values
                    .OrderBy(static entry => entry.ResourceId)
                    .Select(static entry => entry.ToSnapshot())
                    .ToArray(),
            };
        }
    }

    private void RecordLifecycleEventLocked(
        string action,
        Entry entry,
        string reason,
        ulong retireTimeline,
        ulong actualTimeline)
    {
        if (_lifecycleEventCount >= _maximumLifecycleEvents)
        {
            _droppedLifecycleEvents++;
            return;
        }

        _lifecycleEventCount++;
        MemoryDiagnostics.RecordEvent(
            "vulkan-texture-lifetime",
            new
            {
                action,
                resourceId = entry.ResourceId,
                guestAddress = entry.GuestAddress,
                imageMemoryBytes = entry.ImageMemoryBytes,
                stagingMemoryBytes = entry.StagingMemoryBytes,
                retireTimeline,
                actualTimeline,
                reason = Bounded(reason),
            });
    }

    private static long NonNegative(long value) => Math.Max(0, value);

    private static string Bounded(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Length <= 96 ? value : value[..96];
    }

    private sealed class Entry
    {
        public long ResourceId;
        public ulong GuestAddress;
        public uint Width;
        public uint Height;
        public uint Depth;
        public uint Format;
        public uint NumberType;
        public uint DstSelect;
        public uint TileMode;
        public uint Pitch;
        public uint MipLevel;
        public uint BaseMipLevel;
        public uint ResourceMipLevels;
        public uint Layers;
        public uint Type;
        public bool Arrayed;
        public bool IsStorage;
        public long CreatingGuestWorkSequence;
        public string CreatingQueue = string.Empty;
        public long InsertionMilliseconds;
        public long ImageMemoryBytes;
        public long StagingMemoryBytes;
        public bool StagingMapped;
        public bool UploadRecorded;
        public int CacheHitCount;
        public ulong FirstUseTimeline;
        public ulong LastUseTimeline;
        public long FirstUseMilliseconds;
        public bool FirstUseRecorded;
        public long LastUseMilliseconds;
        public long LatestGuestWorkSequence;
        public string LastUseQueue = string.Empty;
        public ulong UploadSubmissionTimeline;
        public ulong UploadCompletionTimeline;
        public long CacheRemovalMilliseconds;
        public bool CacheRemovalRecorded;
        public string CacheRemovalReason = string.Empty;
        public ulong DeferredRetireTimeline;
        public long DeferredMilliseconds;
        public long ActualDestructionMilliseconds;
        public bool ActualDestructionRecorded;
        public ulong ActualDestructionTimeline;
        public string ActualDestructionReason = string.Empty;
        public string State = string.Empty;
        public bool Retained;
        public bool Deferred;

        public VulkanTextureResourceLifetimeSnapshot ToSnapshot() => new()
        {
            ResourceId = ResourceId,
            GuestAddress = GuestAddress,
            Width = Width,
            Height = Height,
            Depth = Depth,
            Format = Format,
            NumberType = NumberType,
            DstSelect = DstSelect,
            TileMode = TileMode,
            Pitch = Pitch,
            MipLevel = MipLevel,
            BaseMipLevel = BaseMipLevel,
            ResourceMipLevels = ResourceMipLevels,
            Layers = Layers,
            Type = Type,
            Arrayed = Arrayed,
            IsStorage = IsStorage,
            CreatingGuestWorkSequence = CreatingGuestWorkSequence,
            CreatingQueue = CreatingQueue,
            InsertionMilliseconds = InsertionMilliseconds,
            ImageMemoryBytes = ImageMemoryBytes,
            StagingMemoryBytes = StagingMemoryBytes,
            StagingMapped = StagingMapped,
            UploadRecorded = UploadRecorded,
            CacheHitCount = CacheHitCount,
            FirstUseTimeline = FirstUseTimeline,
            LastUseTimeline = LastUseTimeline,
            FirstUseMilliseconds = FirstUseMilliseconds,
            LastUseMilliseconds = LastUseMilliseconds,
            LatestGuestWorkSequence = LatestGuestWorkSequence,
            LastUseQueue = LastUseQueue,
            UploadSubmissionTimeline = UploadSubmissionTimeline,
            UploadCompletionTimeline = UploadCompletionTimeline,
            CacheRemovalMilliseconds = CacheRemovalMilliseconds,
            CacheRemovalReason = CacheRemovalReason,
            DeferredRetireTimeline = DeferredRetireTimeline,
            DeferredMilliseconds = DeferredMilliseconds,
            ActualDestructionMilliseconds = ActualDestructionMilliseconds,
            ActualDestructionTimeline = ActualDestructionTimeline,
            ActualDestructionReason = ActualDestructionReason,
            State = State,
            Retained = Retained,
            Deferred = Deferred,
        };
    }
}

internal sealed class VulkanResourceLifetimeSnapshot
{
    public int MaximumEntries { get; init; }
    public int MaximumLifecycleEvents { get; init; }
    public int EntryCount { get; init; }
    public int DroppedEntries { get; init; }
    public int LifecycleEventCount { get; init; }
    public int DroppedLifecycleEvents { get; init; }
    public long RetainedImageBytes { get; init; }
    public long RetainedStagingBytes { get; init; }
    public long DeferredDestructionBytes { get; init; }
    public VulkanTextureResourceLifetimeSnapshot[] Entries { get; init; } = [];
}

internal sealed class VulkanTextureResourceLifetimeSnapshot
{
    public long ResourceId { get; init; }
    public ulong GuestAddress { get; init; }
    public uint Width { get; init; }
    public uint Height { get; init; }
    public uint Depth { get; init; }
    public uint Format { get; init; }
    public uint NumberType { get; init; }
    public uint DstSelect { get; init; }
    public uint TileMode { get; init; }
    public uint Pitch { get; init; }
    public uint MipLevel { get; init; }
    public uint BaseMipLevel { get; init; }
    public uint ResourceMipLevels { get; init; }
    public uint Layers { get; init; }
    public uint Type { get; init; }
    public bool Arrayed { get; init; }
    public bool IsStorage { get; init; }
    public long CreatingGuestWorkSequence { get; init; }
    public string CreatingQueue { get; init; } = string.Empty;
    public long InsertionMilliseconds { get; init; }
    public long ImageMemoryBytes { get; init; }
    public long StagingMemoryBytes { get; init; }
    public bool StagingMapped { get; init; }
    public bool UploadRecorded { get; init; }
    public int CacheHitCount { get; init; }
    public ulong FirstUseTimeline { get; init; }
    public ulong LastUseTimeline { get; init; }
    public long FirstUseMilliseconds { get; init; }
    public long LastUseMilliseconds { get; init; }
    public long LatestGuestWorkSequence { get; init; }
    public string LastUseQueue { get; init; } = string.Empty;
    public ulong UploadSubmissionTimeline { get; init; }
    public ulong UploadCompletionTimeline { get; init; }
    public long CacheRemovalMilliseconds { get; init; }
    public string CacheRemovalReason { get; init; } = string.Empty;
    public ulong DeferredRetireTimeline { get; init; }
    public long DeferredMilliseconds { get; init; }
    public long ActualDestructionMilliseconds { get; init; }
    public ulong ActualDestructionTimeline { get; init; }
    public string ActualDestructionReason { get; init; } = string.Empty;
    public string State { get; init; } = string.Empty;
    public bool Retained { get; init; }
    public bool Deferred { get; init; }
}
