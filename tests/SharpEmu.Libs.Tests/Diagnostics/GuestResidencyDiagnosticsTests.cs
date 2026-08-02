// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Memory;
using Xunit;

namespace SharpEmu.Libs.Tests.Diagnostics;

[Collection(MemoryDiagnosticsStateCollection.Name)]
public sealed class GuestResidencyDiagnosticsTests
{
    [Fact]
    public void PlanAlignsPagesAndRemovesOverlapFromQueryUnion()
    {
        var plan = GuestResidencyScanPlanBuilder.Create(
            new[]
            {
                new GuestHostMappingDiagnosticRange(
                    BaseAddress: 0x1003,
                    ReservedBytes: 0x2FFD,
                    CommittedBytes: 0x2FFD,
                    Executable: false,
                    ReservedOnly: false),
                new GuestHostMappingDiagnosticRange(
                    BaseAddress: 0x2000,
                    ReservedBytes: 0x3000,
                    CommittedBytes: 0x3000,
                    Executable: false,
                    ReservedOnly: false),
                new GuestHostMappingDiagnosticRange(
                    BaseAddress: 0x8000,
                    ReservedBytes: 0x1000,
                    CommittedBytes: 0x1000,
                    Executable: true,
                    ReservedOnly: false),
            },
            pageSize: 0x1000);

        Assert.Equal(3, plan.Mappings.Length);
        Assert.Equal(5UL, plan.UnionPageCount);
        Assert.Equal(5UL * 0x1000, plan.UnionReservedBytes);
        Assert.Equal(4, plan.QueryRanges.Length);
        Assert.Equal(
            new[] { 0x1000UL, 0x2000UL, 0x4000UL, 0x8000UL },
            plan.QueryRanges.Select(static range => range.Start).ToArray());
        Assert.Equal(
            new[] { 0x2000UL, 0x4000UL, 0x5000UL, 0x9000UL },
            plan.QueryRanges.Select(static range => range.End).ToArray());
        Assert.Equal(
            new[] { 1, 2, 1, 1 },
            plan.QueryRanges.Select(static range => range.MappingIndices.Length).ToArray());
        Assert.Equal(3UL, plan.Mappings[0].QueryPageCount);
        Assert.Equal(3UL, plan.Mappings[1].QueryPageCount);
    }

    [Fact]
    public void AggregationCountsUnionAndPerMappingPages()
    {
        var plan = GuestResidencyScanPlanBuilder.Create(
            new[]
            {
                Mapping(0x1000, 0x2000),
                Mapping(0x5000, 0x1000),
            },
            pageSize: 0x1000);
        var aggregation = new GuestResidencyAggregation(plan.Mappings.Length);

        aggregation.AddPage(plan.QueryRanges[0], querySucceeded: true, resident: true);
        aggregation.AddPage(plan.QueryRanges[0], querySucceeded: true, resident: false);
        aggregation.AddPage(plan.QueryRanges[1], querySucceeded: true, resident: true);

        Assert.Equal(3UL, aggregation.QueriedPages);
        Assert.Equal(2UL, aggregation.ResidentPages);
        Assert.Equal(1UL, aggregation.InvalidOrUnqueryablePages);
        Assert.Equal(0UL, aggregation.QueryFailurePages);
        Assert.Equal(
            new GuestResidencyMappingAggregation(2, 1, 1, 0),
            aggregation.GetMapping(0));
        Assert.Equal(
            new GuestResidencyMappingAggregation(1, 1, 0, 0),
            aggregation.GetMapping(1));
    }

    [Fact]
    public void PartialQueryFailureIsCountedAsUnqueryable()
    {
        var plan = GuestResidencyScanPlanBuilder.Create(
            new[] { Mapping(0x1000, 0x3000) },
            pageSize: 0x1000);
        var aggregation = new GuestResidencyAggregation(plan.Mappings.Length);

        aggregation.AddQueryFailure(plan.QueryRanges[0], pageCount: 2);
        aggregation.AddPage(plan.QueryRanges[0], querySucceeded: true, resident: true);

        Assert.Equal(3UL, aggregation.QueriedPages);
        Assert.Equal(1UL, aggregation.ResidentPages);
        Assert.Equal(2UL, aggregation.InvalidOrUnqueryablePages);
        Assert.Equal(2UL, aggregation.QueryFailurePages);
        Assert.Equal(
            new GuestResidencyMappingAggregation(3, 1, 2, 2),
            aggregation.GetMapping(0));
    }

    [Fact]
    public void DisabledPathDoesNotAttachOrCreateDiagnosticOutput()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-guest-residency",
            $"{Guid.NewGuid():N}.json");

        try
        {
            Assert.False(GuestResidencyDiagnosticsSession.IsEnabled);
            Assert.True(GuestResidencyDiagnosticsSession.IsCaptureDisabledForTests());
            using var memory = new PhysicalVirtualMemory();
            Assert.False(GuestResidencyDiagnosticsSession.TryAttach(memory));
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static GuestHostMappingDiagnosticRange Mapping(
        ulong baseAddress,
        ulong size) =>
        new(
            BaseAddress: baseAddress,
            ReservedBytes: size,
            CommittedBytes: size,
            Executable: false,
            ReservedOnly: false);
}
