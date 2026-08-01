// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;
using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.Diagnostics;

public sealed class MemoryDiagnosticsTests
{
    [Fact]
    public void SessionWritesRuntimeCountersAndCategoryDeltas()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-memory-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");

        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            {
                MemoryDiagnostics.Adjust("synthetic", 4096, countDelta: 1);
            }

            var records = File.ReadAllLines(path);
            Assert.Equal(2, records.Length);

            using var header = JsonDocument.Parse(records[0]);
            Assert.Equal("header", header.RootElement.GetProperty("kind").GetString());
            Assert.True(header.RootElement.GetProperty("processId").GetInt32() > 0);

            using var sample = JsonDocument.Parse(records[1]);
            var root = sample.RootElement;
            Assert.Equal("sample", root.GetProperty("kind").GetString());
            Assert.True(root.GetProperty("workingSetBytes").GetInt64() > 0);
            Assert.True(root.GetProperty("gcCommittedBytes").GetInt64() >= 0);

            var category = root.GetProperty("categories").GetProperty("synthetic");
            Assert.Equal(4096, category.GetProperty("bytes").GetInt64());
            Assert.Equal(4096, category.GetProperty("deltaBytes").GetInt64());
            Assert.Equal(1, category.GetProperty("count").GetInt64());
            Assert.Equal(1, category.GetProperty("deltaCount").GetInt64());
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
