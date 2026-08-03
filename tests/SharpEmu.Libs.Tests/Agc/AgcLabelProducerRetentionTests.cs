// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Collections.Generic;
using System.Linq;
using SharpEmu.Libs.Agc;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

public sealed class AgcLabelProducerRetentionTests
{
    [Fact]
    public void ProducerHistoryCompactionNeverEvictsActiveRecords()
    {
        var entries = new List<(string Name, bool Completed)>
        {
            ("active-a", false),
            ("complete-a", true),
            ("complete-b", true),
            ("active-b", false),
            ("complete-c", true),
        };

        var removed = AgcExports.CompactCompletedEntries(
            entries,
            static entry => entry.Completed,
            targetCount: 2);

        Assert.Equal(3, removed);
        Assert.Equal(
            ["active-a", "active-b"],
            entries.Select(static entry => entry.Name));
    }

    [Fact]
    public void ProducerHistoryMayExceedSoftBoundWhileAllRecordsAreActive()
    {
        var entries = new List<bool> { false, false, false };

        var removed = AgcExports.CompactCompletedEntries(
            entries,
            static completed => completed,
            targetCount: 1);

        Assert.Equal(0, removed);
        Assert.Equal(3, entries.Count);
    }
}
