// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Tests.Diagnostics;
using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

[Collection(MemoryDiagnosticsStateCollection.Name)]
public sealed class VulkanResourceLifetimeDiagnosticsTests
{
    private static readonly VulkanTextureDiagnosticDescriptor Descriptor = new(
        GuestAddress: 0x4000,
        Width: 64,
        Height: 32,
        Depth: 1,
        Format: 10,
        NumberType: 0,
        DstSelect: 0xFAC,
        TileMode: 3,
        Pitch: 64,
        MipLevel: 0,
        BaseMipLevel: 0,
        ResourceMipLevels: 1,
        Layers: 1,
        Type: 9,
        Arrayed: false,
        IsStorage: false);

    [Fact]
    public void ImageAndStagingOwnershipRemainSeparateAndBalanced()
    {
        var diagnostics = new VulkanResourceLifetimeDiagnostics();
        var resourceId = diagnostics.TrackCacheInsertion(
            Descriptor,
            guestWorkSequence: 7,
            queue: "graphics",
            insertionMilliseconds: 10,
            imageMemoryBytes: 100,
            stagingMemoryBytes: 40,
            stagingMapped: false,
            uploadRecorded: false);

        var retained = diagnostics.GetSnapshot();
        Assert.Equal(100, retained.RetainedImageBytes);
        Assert.Equal(40, retained.RetainedStagingBytes);
        Assert.Single(retained.Entries);

        diagnostics.RecordCacheRemoval(resourceId, "test", 20, 12);
        diagnostics.RecordCacheRemoval(resourceId, "duplicate", 21, 13);
        diagnostics.RecordDeferredDestroy(resourceId, 12, 20);
        diagnostics.RecordDeferredDestroy(resourceId, 12, 21);
        var deferred = diagnostics.GetSnapshot();
        Assert.Equal(0, deferred.RetainedImageBytes);
        Assert.Equal(0, deferred.RetainedStagingBytes);
        Assert.Equal(140, deferred.DeferredDestructionBytes);

        diagnostics.RecordActualDestroy(resourceId, 12, 30, "retired");
        diagnostics.RecordActualDestroy(resourceId, 12, 31, "duplicate");
        var destroyed = diagnostics.GetSnapshot();
        Assert.Equal(0, destroyed.RetainedImageBytes);
        Assert.Equal(0, destroyed.RetainedStagingBytes);
        Assert.Equal(0, destroyed.DeferredDestructionBytes);
        Assert.Equal("destroyed", destroyed.Entries[0].State);
        Assert.Equal("test", destroyed.Entries[0].CacheRemovalReason);
        Assert.Equal("retired", destroyed.Entries[0].ActualDestructionReason);
    }

    [Fact]
    public void CacheHitsAndUploadLifetimeUseScalarMetadata()
    {
        var diagnostics = new VulkanResourceLifetimeDiagnostics();
        var resourceId = diagnostics.TrackCacheInsertion(
            Descriptor,
            guestWorkSequence: 4,
            queue: "compute",
            insertionMilliseconds: 5,
            imageMemoryBytes: 512,
            stagingMemoryBytes: 128,
            stagingMapped: false,
            uploadRecorded: false);

        diagnostics.RecordUse(resourceId, cacheHit: false, 0, 4, "compute", 6);
        diagnostics.RecordUse(resourceId, cacheHit: true, 0, 9, "compute", 15);
        diagnostics.RecordUploadRecorded(resourceId);
        diagnostics.RecordSubmission(resourceId, 22);
        diagnostics.RecordUploadCompletion(resourceId, 22);

        var entry = Assert.Single(diagnostics.GetSnapshot().Entries);
        Assert.Equal(1, entry.CacheHitCount);
        Assert.Equal(6, entry.FirstUseMilliseconds);
        Assert.Equal(15, entry.LastUseMilliseconds);
        Assert.Equal(9, entry.LatestGuestWorkSequence);
        Assert.Equal(22UL, entry.FirstUseTimeline);
        Assert.Equal(22UL, entry.LastUseTimeline);
        Assert.Equal(22UL, entry.UploadSubmissionTimeline);
        Assert.Equal(22UL, entry.UploadCompletionTimeline);
        Assert.False(entry.StagingMapped);
        Assert.Equal("cached", entry.State);
    }

    [Fact]
    public void DeviceTeardownIsAnExplicitDiagnosticLifecycleState()
    {
        var diagnostics = new VulkanResourceLifetimeDiagnostics();
        var resourceId = diagnostics.TrackCacheInsertion(
            Descriptor,
            guestWorkSequence: 1,
            queue: "graphics",
            insertionMilliseconds: 2,
            imageMemoryBytes: 8,
            stagingMemoryBytes: 4,
            stagingMapped: false,
            uploadRecorded: true);

        diagnostics.RecordCacheRemoval(resourceId, "device-teardown", 3, 19);
        diagnostics.RecordActualDestroy(resourceId, 19, 3, "vulkan-device-teardown");

        var entry = Assert.Single(diagnostics.GetSnapshot().Entries);
        Assert.Equal("vulkan-device-teardown", entry.ActualDestructionReason);
        Assert.False(entry.Retained);
        Assert.Equal(0, diagnostics.GetSnapshot().DeferredDestructionBytes);
    }

    [Fact]
    public void TraceIsBoundedAndDropsAdditionalEntries()
    {
        var diagnostics = new VulkanResourceLifetimeDiagnostics(maximumEntries: 4);
        for (var index = 0; index < 7; index++)
        {
            _ = diagnostics.TrackCacheInsertion(
                Descriptor with { GuestAddress = (ulong)(0x4000 + index * 0x1000) },
                guestWorkSequence: index,
                queue: "graphics",
                insertionMilliseconds: index,
                imageMemoryBytes: 1,
                stagingMemoryBytes: 2,
                stagingMapped: false,
                uploadRecorded: false);
        }

        var snapshot = diagnostics.GetSnapshot();
        Assert.Equal(4, snapshot.EntryCount);
        Assert.Equal(3, snapshot.DroppedEntries);
        Assert.Equal(4, snapshot.Entries.Length);
    }

    [Fact]
    public void LifecycleTraceDropsEventsAfterItsBound()
    {
        var diagnostics = new VulkanResourceLifetimeDiagnostics(
            maximumEntries: 2,
            maximumLifecycleEvents: 1);
        var resourceId = diagnostics.TrackCacheInsertion(
            Descriptor,
            guestWorkSequence: 1,
            queue: "graphics",
            insertionMilliseconds: 1,
            imageMemoryBytes: 1,
            stagingMemoryBytes: 1,
            stagingMapped: false,
            uploadRecorded: false);

        diagnostics.RecordCacheRemoval(resourceId, "bounded", 2, 1);

        var snapshot = diagnostics.GetSnapshot();
        Assert.Equal(1, snapshot.MaximumLifecycleEvents);
        Assert.Equal(1, snapshot.LifecycleEventCount);
        Assert.True(snapshot.DroppedLifecycleEvents > 0);
    }
}
