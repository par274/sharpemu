// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;
using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.Diagnostics;

[Collection(MemoryDiagnosticsStateCollection.Name)]
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

    [Fact]
    public void SessionWritesStructuredEvents()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-memory-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");

        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            {
                MemoryDiagnostics.RecordEvent(
                    "synthetic-event",
                    new { Sequence = 7, PayloadBytes = 4096UL });
            }

            var records = File.ReadAllLines(path);
            Assert.Equal(3, records.Length);

            using var eventDocument = JsonDocument.Parse(records[1]);
            var eventRoot = eventDocument.RootElement;
            Assert.Equal("event", eventRoot.GetProperty("kind").GetString());
            Assert.Equal(
                "synthetic-event",
                eventRoot.GetProperty("event").GetString());
            Assert.Equal(
                7,
                eventRoot.GetProperty("data").GetProperty("sequence").GetInt32());
            Assert.Equal(
                4096UL,
                eventRoot.GetProperty("data").GetProperty("payloadBytes").GetUInt64());
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task DisposeDrainsAnInFlightTimerSampleBeforeClosingJsonl()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-memory-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");
        using var sampleEntered = new ManualResetEventSlim(false);
        using var releaseSample = new ManualResetEventSlim(false);
        using var timerDrainStarted = new ManualResetEventSlim(false);
        MemoryDiagnosticsSession? session = null;

        try
        {
            session = MemoryDiagnosticsSession.StartForTests(
                path,
                TimeSpan.FromMilliseconds(1),
                beforeSampleWrite: () =>
                {
                    sampleEntered.Set();
                    releaseSample.Wait();
                },
                timerDrainStarted: () => timerDrainStarted.Set());

            Assert.True(sampleEntered.Wait(TimeSpan.FromSeconds(5)));

            var disposeTask = Task.Run(session!.Dispose);
            Assert.True(timerDrainStarted.Wait(TimeSpan.FromSeconds(5)));
            var earlyCompletion = await Task.WhenAny(
                disposeTask,
                Task.Delay(TimeSpan.FromMilliseconds(100)));
            Assert.NotSame(disposeTask, earlyCompletion);

            releaseSample.Set();
            await disposeTask;
            session.Dispose();
            Assert.False(MemoryDiagnostics.IsEnabled);

            var records = File.ReadAllLines(path);
            Assert.True(records.Length >= 3);
            foreach (var record in records)
            {
                using var document = JsonDocument.Parse(record);
                Assert.Contains(
                    document.RootElement.GetProperty("kind").GetString(),
                    new[] { "header", "sample" });
            }

            Assert.Equal("sample", JsonDocument.Parse(records[^1]).RootElement.GetProperty("kind").GetString());
        }
        finally
        {
            releaseSample.Set();
            session?.Dispose();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task RecordEventThatRacesDisposeDoesNotWriteAfterShutdown()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-memory-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");
        var recordEventEntered = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRecordEvent = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        MemoryDiagnosticsSession? session = null;

        try
        {
            session = MemoryDiagnosticsSession.StartForTests(
                path,
                TimeSpan.FromHours(1),
                beforeSampleWrite: static () => { },
                timerDrainStarted: static () => { },
                recordEventBeforeWriteGate: () =>
                {
                    recordEventEntered.SetResult(true);
                    releaseRecordEvent.Task.GetAwaiter().GetResult();
                });

            var recordTask = Task.Run(
                () => MemoryDiagnostics.RecordEvent(
                    "late-event",
                    new { Sequence = 1 }));

            await recordEventEntered.Task;
            session.Dispose();
            releaseRecordEvent.SetResult(true);
            await recordTask;

            Assert.False(MemoryDiagnostics.IsEnabled);
            var records = File.ReadAllLines(path);
            Assert.Equal(2, records.Length);
            foreach (var record in records)
            {
                using var document = JsonDocument.Parse(record);
                Assert.Contains(
                    document.RootElement.GetProperty("kind").GetString(),
                    new[] { "header", "sample" });
            }
        }
        finally
        {
            releaseRecordEvent.TrySetResult(true);
            session?.Dispose();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
