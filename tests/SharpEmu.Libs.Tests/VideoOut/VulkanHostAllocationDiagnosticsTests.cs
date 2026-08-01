// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;
using SharpEmu.Libs.Tests.Diagnostics;
using SharpEmu.Libs.VideoOut;
using SharpEmu.Logging;
using Silk.NET.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

[Collection(MemoryDiagnosticsStateCollection.Name)]
public sealed unsafe class VulkanHostAllocationDiagnosticsTests
{
    [Fact]
    public void LedgerBalancesAllocationAndDuplicateRelease()
    {
        var ledger = new VulkanHostAllocationLedger(maximumEntries: 4, maximumEvents: 8);
        var pointer = NativeMemory.AlignedAlloc(4096, 16);

        try
        {
            ledger.TrackAllocation(
                (nint)pointer,
                4096,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 10);

            Assert.Equal(4096, ledger.OutstandingBytes);
            Assert.True(ledger.TryRelease((nint)pointer, elapsedMilliseconds: 20));
            Assert.Equal(0, ledger.OutstandingBytes);
            Assert.False(ledger.TryRelease((nint)pointer, elapsedMilliseconds: 30));
            Assert.True(ledger.IsKnownDuplicate((nint)pointer));

            var snapshot = ledger.GetSnapshot();
            Assert.Equal(1, snapshot.DuplicateReleases);
            Assert.Equal(0, snapshot.ActiveEntryCount);
        }
        finally
        {
            NativeMemory.AlignedFree(pointer);
        }
    }

    [Fact]
    public void LedgerReallocationKeepsOutstandingBytesExact()
    {
        var ledger = new VulkanHostAllocationLedger(maximumEntries: 4, maximumEvents: 8);
        var first = NativeMemory.AlignedAlloc(4096, 16);
        var second = NativeMemory.AlignedAlloc(8192, 16);

        try
        {
            ledger.TrackAllocation(
                (nint)first,
                4096,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 1);
            ledger.TrackReallocation(
                (nint)first,
                (nint)second,
                8192,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 2);

            Assert.Equal(8192, ledger.OutstandingBytes);
            Assert.False(ledger.TryRelease((nint)first, elapsedMilliseconds: 3));
            Assert.True(ledger.TryRelease((nint)second, elapsedMilliseconds: 4));
            Assert.Equal(0, ledger.OutstandingBytes);
        }
        finally
        {
            NativeMemory.AlignedFree(first);
            NativeMemory.AlignedFree(second);
        }
    }

    [Fact]
    public void LedgerDropsEntriesAtConfiguredBound()
    {
        var ledger = new VulkanHostAllocationLedger(maximumEntries: 1, maximumEvents: 2);
        var first = NativeMemory.AlignedAlloc(4096, 16);
        var second = NativeMemory.AlignedAlloc(4096, 16);

        try
        {
            ledger.TrackAllocation(
                (nint)first,
                4096,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 1);
            ledger.TrackAllocation(
                (nint)second,
                4096,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 2);

            var snapshot = ledger.GetSnapshot();
            Assert.Equal(1, snapshot.ActiveEntryCount);
            Assert.Equal(1, snapshot.DroppedEntries);
            Assert.Equal(4096, snapshot.ActiveBytes);
        }
        finally
        {
            Assert.True(ledger.TryRelease((nint)first, elapsedMilliseconds: 3));
            NativeMemory.AlignedFree(first);
            NativeMemory.AlignedFree(second);
        }
    }

    [Fact]
    public void AllocationBookkeepingFailureReturnsPointerAndLaterReleaseIsSafe()
    {
        var path = CreateDiagnosticsPath();
        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            using (var probe = VulkanHostAllocationDiagnostics.Start())
            {
                Assert.NotNull(probe);
                probe!.LedgerForTests.FailNextAllocationBookkeepingForTests();

                var pointer = VulkanHostAllocationDiagnostics.InvokeAllocationCallbackForTests(
                    4096,
                    16,
                    SystemAllocationScope.Object);
                Assert.NotEqual((nint)0, (nint)pointer);

                var afterAllocation = probe.GetSnapshot();
                Assert.Equal(1, afterAllocation.AllocationBookkeepingFailures);
                Assert.Equal(0, afterAllocation.ActiveEntryCount);

                // The successful native allocation was intentionally
                // untracked. pfnFree still owns the one and only release.
                VulkanHostAllocationDiagnostics.InvokeFreeCallbackForTests(pointer);
                var afterRelease = probe.GetSnapshot();
                Assert.Equal(1, afterRelease.UntrackedReleases);
                Assert.Equal(0, afterRelease.ActiveEntryCount);
            }
        }
        finally
        {
            DeleteDiagnosticsPath(path);
        }
    }

    [Fact]
    public void MovedReallocationBookkeepingFailureLeavesReplacementUntracked()
    {
        var path = CreateDiagnosticsPath();
        var original = NativeMemory.AlignedAlloc(4096, 16);
        var replacement = NativeMemory.AlignedAlloc(8192, 16);
        var replacementReleased = false;
        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            using (var probe = VulkanHostAllocationDiagnostics.Start())
            {
                Assert.NotNull(probe);
                probe!.LedgerForTests.TrackAllocation(
                    (nint)original,
                    4096,
                    16,
                    SystemAllocationScope.Object,
                    elapsedMilliseconds: 1);
                probe.LedgerForTests.FailNextReallocationBookkeepingForTests();

                // The native move has already consumed original and returned
                // replacement; only the bookkeeping boundary is injected.
                probe.RecordReallocationForTests(
                    (nint)original,
                    (nint)replacement,
                    8192,
                    16,
                    SystemAllocationScope.Object);

                var afterReallocation = probe.GetSnapshot();
                Assert.Equal(1, afterReallocation.ReallocationBookkeepingFailures);
                Assert.Equal(0, afterReallocation.ActiveEntryCount);
                Assert.Equal(0, afterReallocation.ActiveBytes);

                VulkanHostAllocationDiagnostics.InvokeFreeCallbackForTests(replacement);
                replacementReleased = true;
                var afterRelease = probe.GetSnapshot();
                Assert.Equal(1, afterRelease.UntrackedReleases);
            }
        }
        finally
        {
            NativeMemory.AlignedFree(original);
            if (!replacementReleased)
            {
                NativeMemory.AlignedFree(replacement);
            }
            DeleteDiagnosticsPath(path);
        }
    }

    [Fact]
    public void InPlaceReallocationBookkeepingFailureKeepsLivePointerReleasable()
    {
        var ledger = new VulkanHostAllocationLedger(maximumEntries: 4, maximumEvents: 8);
        var pointer = NativeMemory.AlignedAlloc(4096, 16);
        try
        {
            ledger.TrackAllocation(
                (nint)pointer,
                4096,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 1);
            ledger.FailNextReallocationBookkeepingForTests();
            Assert.Throws<InvalidOperationException>(() => ledger.TrackReallocation(
                (nint)pointer,
                (nint)pointer,
                8192,
                16,
                SystemAllocationScope.Object,
                elapsedMilliseconds: 2));
            ledger.ReconcileSuccessfulReallocationFailure((nint)pointer, (nint)pointer);

            Assert.Equal(
                VulkanHostAllocationReleaseResult.Untracked,
                ledger.TryReleaseForCallback((nint)pointer, elapsedMilliseconds: 3));
            Assert.Equal(0, ledger.OutstandingBytes);
        }
        finally
        {
            NativeMemory.AlignedFree(pointer);
        }
    }

    [Fact]
    public void ZeroSizeReallocationReleasesOriginalAndReturnsNull()
    {
        var path = CreateDiagnosticsPath();
        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            using (var probe = VulkanHostAllocationDiagnostics.Start())
            {
                Assert.NotNull(probe);
                var pointer = VulkanHostAllocationDiagnostics.InvokeAllocationCallbackForTests(
                    4096,
                    16,
                    SystemAllocationScope.Object);
                Assert.NotEqual((nint)0, (nint)pointer);

                var result = VulkanHostAllocationDiagnostics.InvokeReallocationCallbackForTests(
                    pointer,
                    0,
                    16,
                    SystemAllocationScope.Object);
                Assert.Equal((nint)0, (nint)result);
                Assert.Equal(0, probe!.GetSnapshot().ActiveEntryCount);
            }
        }
        finally
        {
            DeleteDiagnosticsPath(path);
        }
    }

    [Fact]
    public void InternalAllocationNotificationsRemainScalarAndBounded()
    {
        var path = CreateDiagnosticsPath();
        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            using (var probe = VulkanHostAllocationDiagnostics.Start())
            {
                Assert.NotNull(probe);
                VulkanHostAllocationDiagnostics.InvokeInternalAllocationCallbackForTests(
                    512,
                    (InternalAllocationType)0,
                    SystemAllocationScope.Instance);
                VulkanHostAllocationDiagnostics.InvokeInternalAllocationCallbackForTests(
                    1024,
                    (InternalAllocationType)0,
                    SystemAllocationScope.Object);
                VulkanHostAllocationDiagnostics.InvokeInternalFreeCallbackForTests(
                    512,
                    (InternalAllocationType)0,
                    SystemAllocationScope.Instance);
                VulkanHostAllocationDiagnostics.InvokeInternalFreeCallbackForTests(
                    4096,
                    (InternalAllocationType)0,
                    SystemAllocationScope.Object);

                var snapshot = probe!.GetSnapshot();
                Assert.Equal(2, snapshot.InternalAllocationCount);
                Assert.Equal(2, snapshot.InternalFreeCount);
                Assert.Equal(1536, snapshot.InternalPeakOutstandingBytes);
                Assert.Equal(0, snapshot.InternalOutstandingBytes);
                Assert.Equal(1024, snapshot.InternalLargestAllocationBytes);
                Assert.Equal(1, snapshot.InternalUnmatchedFreeNotifications);
                Assert.Equal(0, snapshot.InternalDroppedNotifications);
            }
        }
        finally
        {
            DeleteDiagnosticsPath(path);
        }
    }

    [Fact]
    public void LifetimeFailureBeforeInstanceDisposesProbe()
    {
        var order = new List<string>();
        using var lifetime = new VulkanHostAllocationLifetime(() => order.Add("probe"));
        lifetime.Dispose();
        Assert.Equal(["probe"], order);
    }

    [Fact]
    public void LifetimeFailureAfterInstanceDestroysInstanceBeforeProbe()
    {
        var order = new List<string>();
        using var lifetime = new VulkanHostAllocationLifetime(() => order.Add("probe"));
        lifetime.RegisterInstance(() => order.Add("instance"));
        lifetime.Dispose();
        Assert.Equal(["instance", "probe"], order);
    }

    [Fact]
    public void LifetimeFailureAfterDeviceDestroysDeviceInstanceAndProbe()
    {
        var order = new List<string>();
        using var lifetime = new VulkanHostAllocationLifetime(() => order.Add("probe"));
        lifetime.RegisterInstance(() => order.Add("instance"));
        lifetime.RegisterDevice(() => order.Add("device"));
        lifetime.Dispose();
        Assert.Equal(["device", "instance", "probe"], order);
    }

    [Fact]
    public void LifetimeNormalShutdownUsesTheSameRootOrder()
    {
        var order = new List<string>();
        using var lifetime = new VulkanHostAllocationLifetime(() => order.Add("probe"));
        lifetime.RegisterInstance(() => order.Add("instance"));
        lifetime.RegisterDevice(() => order.Add("device"));
        lifetime.Dispose();
        Assert.Equal(["device", "instance", "probe"], order);
    }

    [Fact]
    public void LifetimeRepeatedDisposalIsIdempotent()
    {
        var order = new List<string>();
        using var lifetime = new VulkanHostAllocationLifetime(() => order.Add("probe"));
        lifetime.RegisterInstance(() => order.Add("instance"));
        lifetime.RegisterDevice(() => order.Add("device"));
        lifetime.Dispose();
        lifetime.Dispose();
        Assert.Equal(["device", "instance", "probe"], order);
    }

    [Fact]
    public void ProbeIsAbsentWhenDiagnosticsAreDisabled()
    {
        Assert.False(MemoryDiagnostics.IsEnabled);
        Assert.Null(VulkanHostAllocationDiagnostics.Start());
        Assert.True(VulkanHostAllocationDiagnostics.CurrentCallbacks == null);
    }

    [Fact]
    public void ProbeOwnsCallbacksOnlyForEnabledSession()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-vulkan-allocation-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");

        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            {
                using var probe = VulkanHostAllocationDiagnostics.Start();
                Assert.NotNull(probe);
                Assert.True(VulkanHostAllocationDiagnostics.CurrentCallbacks != null);
            }

            Assert.True(VulkanHostAllocationDiagnostics.CurrentCallbacks == null);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static string CreateDiagnosticsPath()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-vulkan-allocation-diagnostics");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"{Guid.NewGuid():N}.jsonl");
    }

    private static void DeleteDiagnosticsPath(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
