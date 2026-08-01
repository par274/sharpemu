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
}
