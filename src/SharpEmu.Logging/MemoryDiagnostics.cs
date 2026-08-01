// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharpEmu.Logging;

/// <summary>
/// Owns a low-overhead, opt-in memory counter stream for the current process.
/// The session records host/runtime counters periodically; subsystems can add
/// current ownership totals through <see cref="MemoryDiagnostics.Adjust"/>.
/// </summary>
public sealed class MemoryDiagnosticsSession : IDisposable
{
    private const int SchemaVersion = 1;
    private readonly object _writeGate = new();
    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private readonly TimeSpan _sampleInterval;
    private readonly Action? _beforeSampleWriteForTests;
    private readonly Action? _timerDrainStartedForTests;
    private readonly Action? _recordEventBeforeWriteGateForTests;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly System.Threading.Timer _timer;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CategorySample> _previousCategories = new(StringComparer.Ordinal);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };
    private long _lastAllocatedBytes;
    private long _lastSampleMilliseconds;
    private int _sampleInProgress;
    private int _disposed;

    private MemoryDiagnosticsSession(
        string path,
        TimeSpan sampleInterval,
        Action? beforeSampleWriteForTests,
        Action? timerDrainStartedForTests,
        Action? recordEventBeforeWriteGateForTests)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A diagnostics path is required.", nameof(path));
        }

        if (sampleInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(sampleInterval));
        }

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _stream = new FileStream(
            fullPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 16 * 1024,
            options: FileOptions.SequentialScan);
        _writer = new StreamWriter(_stream, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = false,
        };
        _sampleInterval = sampleInterval;
        _beforeSampleWriteForTests = beforeSampleWriteForTests;
        _timerDrainStartedForTests = timerDrainStartedForTests;
        _recordEventBeforeWriteGateForTests = recordEventBeforeWriteGateForTests;
        _timer = new System.Threading.Timer(
            static state => ((MemoryDiagnosticsSession)state!).WriteSampleIfIdle(),
            this,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);

        WriteRecord(new MemoryDiagnosticsHeader
        {
            ProcessId = Environment.ProcessId,
            ProcessName = Process.GetCurrentProcess().ProcessName,
            Is64BitProcess = Environment.Is64BitProcess,
            RuntimeVersion = Environment.Version.ToString(),
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            SampleIntervalMilliseconds = (int)Math.Ceiling(sampleInterval.TotalMilliseconds),
        });
    }

    public static MemoryDiagnosticsSession Start(
        string path,
        TimeSpan? sampleInterval = null)
    {
        return StartCore(path, sampleInterval, null, null, null);
    }

    internal static MemoryDiagnosticsSession StartForTests(
        string path,
        TimeSpan sampleInterval,
        Action beforeSampleWrite,
        Action timerDrainStarted,
        Action? recordEventBeforeWriteGate = null)
    {
        ArgumentNullException.ThrowIfNull(beforeSampleWrite);
        ArgumentNullException.ThrowIfNull(timerDrainStarted);
        return StartCore(
            path,
            sampleInterval,
            beforeSampleWrite,
            timerDrainStarted,
            recordEventBeforeWriteGate);
    }

    private static MemoryDiagnosticsSession StartCore(
        string path,
        TimeSpan? sampleInterval,
        Action? beforeSampleWriteForTests,
        Action? timerDrainStartedForTests,
        Action? recordEventBeforeWriteGateForTests)
    {
        var session = new MemoryDiagnosticsSession(
            path,
            sampleInterval ?? TimeSpan.FromMilliseconds(500),
            beforeSampleWriteForTests,
            timerDrainStartedForTests,
            recordEventBeforeWriteGateForTests);
        if (Interlocked.CompareExchange(ref MemoryDiagnostics.ActiveSession, session, null) is not null)
        {
            session.Dispose();
            throw new InvalidOperationException("A memory diagnostics session is already active.");
        }

        session._timer.Change(session._sampleInterval, session._sampleInterval);
        return session;
    }

    internal void Adjust(string category, long byteDelta, long countDelta)
    {
        if (string.IsNullOrWhiteSpace(category) || (byteDelta == 0 && countDelta == 0))
        {
            return;
        }

        var counter = _counters.GetOrAdd(category, static _ => new Counter());
        if (byteDelta != 0)
        {
            Interlocked.Add(ref counter.Bytes, byteDelta);
        }

        if (countDelta != 0)
        {
            Interlocked.Add(ref counter.Count, countDelta);
        }
    }

    internal void RecordEvent(string eventName, object data)
    {
        if (string.IsNullOrWhiteSpace(eventName) || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _recordEventBeforeWriteGateForTests?.Invoke();

        lock (_writeGate)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            _writer.WriteLine(
                JsonSerializer.Serialize(
                    new MemoryDiagnosticsEvent
                    {
                        ElapsedMilliseconds = (long)_clock.Elapsed.TotalMilliseconds,
                        Event = eventName,
                        Data = data,
                    },
                    _jsonOptions));
            _writer.Flush();
        }
    }

    private void WriteSampleIfIdle()
    {
        if (Volatile.Read(ref _disposed) != 0 || Interlocked.Exchange(ref _sampleInProgress, 1) != 0)
        {
            return;
        }

        try
        {
            _beforeSampleWriteForTests?.Invoke();
            WriteSample();
        }
        finally
        {
            Volatile.Write(ref _sampleInProgress, 0);
        }
    }

    private void WriteSample()
    {
        var nowMilliseconds = (long)_clock.Elapsed.TotalMilliseconds;
        var previousMilliseconds = Interlocked.Exchange(ref _lastSampleMilliseconds, nowMilliseconds);
        var elapsedMilliseconds = nowMilliseconds - previousMilliseconds;
        if (elapsedMilliseconds <= 0)
        {
            elapsedMilliseconds = (long)_sampleInterval.TotalMilliseconds;
        }

        var process = Process.GetCurrentProcess();
        process.Refresh();
        var totalAllocatedBytes = GC.GetTotalAllocatedBytes(precise: false);
        var previousAllocatedBytes = Interlocked.Exchange(ref _lastAllocatedBytes, totalAllocatedBytes);
        var allocationRate = previousMilliseconds == 0
            ? 0
            : Math.Max(0, totalAllocatedBytes - previousAllocatedBytes) * 1000d / elapsedMilliseconds;
        var gcInfo = GC.GetGCMemoryInfo();
        var categorySamples = new SortedDictionary<string, CategorySample>(StringComparer.Ordinal);

        foreach (var entry in _counters)
        {
            var bytes = Volatile.Read(ref entry.Value.Bytes);
            var count = Volatile.Read(ref entry.Value.Count);
            _previousCategories.TryGetValue(entry.Key, out var previous);
            var previousBytes = previous?.Bytes ?? 0;
            var previousCount = previous?.Count ?? 0;
            categorySamples[entry.Key] = new CategorySample
            {
                Bytes = bytes,
                Count = count,
                DeltaBytes = bytes - previousBytes,
                DeltaCount = count - previousCount,
            };
        }

        // Providers are deliberately sampled outside the write gate. A provider
        // may need to take a subsystem lock, while a producer may hold that lock
        // while recording an event. Keeping the provider out of _writeGate avoids
        // turning a bounded diagnostic snapshot into a lock-ordering hazard.
        var diagnostics = MemoryDiagnostics.GetSampleProviderSnapshot();

        lock (_writeGate)
        {
            WriteRecord(new MemoryDiagnosticsSample
            {
                ElapsedMilliseconds = nowMilliseconds,
                WorkingSetBytes = process.WorkingSet64,
                PrivateBytes = process.PrivateMemorySize64,
                VirtualBytes = process.VirtualMemorySize64,
                PagedBytes = process.PagedMemorySize64,
                PeakWorkingSetBytes = process.PeakWorkingSet64,
                ThreadCount = process.Threads.Count,
                GcHeapSizeBytes = gcInfo.HeapSizeBytes,
                GcCommittedBytes = gcInfo.TotalCommittedBytes,
                GcTotalMemoryBytes = GC.GetTotalMemory(forceFullCollection: false),
                GcTotalAllocatedBytes = totalAllocatedBytes,
                GcAllocationRateBytesPerSecond = allocationRate,
                GcCollectionCount0 = GC.CollectionCount(0),
                GcCollectionCount1 = GC.CollectionCount(1),
                GcCollectionCount2 = GC.CollectionCount(2),
                GcFragmentedBytes = gcInfo.FragmentedBytes,
                Categories = categorySamples,
                Diagnostics = diagnostics,
            });
        }

        _previousCategories.Clear();
        foreach (var entry in categorySamples)
        {
            _previousCategories[entry.Key] = entry.Value;
        }
    }

    private void WriteRecord<T>(T record)
    {
        lock (_writeGate)
        {
            _writer.WriteLine(JsonSerializer.Serialize(record, _jsonOptions));
            _writer.Flush();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _timerDrainStartedForTests?.Invoke();
            _timer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            WriteSample();
        }
        finally
        {
            _ = Interlocked.CompareExchange(ref MemoryDiagnostics.ActiveSession, null, this);

            lock (_writeGate)
            {
                _writer.Flush();
                _writer.Dispose();
                _stream.Dispose();
            }
        }
    }

    private sealed class Counter
    {
        public long Bytes;
        public long Count;
    }
}

public static class MemoryDiagnostics
{
    internal static MemoryDiagnosticsSession? ActiveSession;
    private static Func<object?>? _sampleProvider;

    public static bool IsEnabled => Volatile.Read(ref ActiveSession) is not null;

    public static void Adjust(string category, long byteDelta, long countDelta = 0)
    {
        Volatile.Read(ref ActiveSession)?.Adjust(category, byteDelta, countDelta);
    }

    public static void RecordEvent(string eventName, object data)
    {
        ArgumentNullException.ThrowIfNull(data);
        Volatile.Read(ref ActiveSession)?.RecordEvent(eventName, data);
    }

    /// <summary>
    /// Registers one bounded, current-state provider for the opt-in sample
    /// stream. The provider must return scalar/structural state only; it must
    /// not retain guest payloads or perform blocking work.
    /// </summary>
    public static IDisposable RegisterSampleProvider(Func<object?> provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (Interlocked.CompareExchange(ref _sampleProvider, provider, null) is not null)
        {
            throw new InvalidOperationException(
                "A memory diagnostics sample provider is already active.");
        }

        return new SampleProviderRegistration(provider);
    }

    internal static object? GetSampleProviderSnapshot()
    {
        var provider = Volatile.Read(ref _sampleProvider);
        if (provider is null)
        {
            return null;
        }

        try
        {
            return provider();
        }
        catch (Exception exception)
        {
            // A diagnostics provider must never take down the timer or the
            // emulator. Keep the error bounded and content-free.
            return new
            {
                providerError = exception.GetType().Name,
            };
        }
    }

    private sealed class SampleProviderRegistration : IDisposable
    {
        private readonly Func<object?> _provider;
        private int _disposed;

        public SampleProviderRegistration(Func<object?> provider)
        {
            _provider = provider;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _ = Interlocked.CompareExchange(ref _sampleProvider, null, _provider);
        }
    }
}

internal sealed class MemoryDiagnosticsHeader
{
    public string Kind => "header";
    public int SchemaVersion => 1;
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public bool Is64BitProcess { get; init; }
    public string RuntimeVersion { get; init; } = string.Empty;
    public string Architecture { get; init; } = string.Empty;
    public int SampleIntervalMilliseconds { get; init; }
}

internal sealed class MemoryDiagnosticsSample
{
    public string Kind => "sample";
    public long ElapsedMilliseconds { get; init; }
    public long WorkingSetBytes { get; init; }
    public long PrivateBytes { get; init; }
    public long VirtualBytes { get; init; }
    public long PagedBytes { get; init; }
    public long PeakWorkingSetBytes { get; init; }
    public int ThreadCount { get; init; }
    public long GcHeapSizeBytes { get; init; }
    public long GcCommittedBytes { get; init; }
    public long GcTotalMemoryBytes { get; init; }
    public long GcTotalAllocatedBytes { get; init; }
    public double GcAllocationRateBytesPerSecond { get; init; }
    public int GcCollectionCount0 { get; init; }
    public int GcCollectionCount1 { get; init; }
    public int GcCollectionCount2 { get; init; }
    public long GcFragmentedBytes { get; init; }
    public SortedDictionary<string, CategorySample> Categories { get; init; } = new(StringComparer.Ordinal);
    public object? Diagnostics { get; init; }
}

internal sealed class MemoryDiagnosticsEvent
{
    public string Kind => "event";
    public long ElapsedMilliseconds { get; init; }
    public string Event { get; init; } = string.Empty;
    public object Data { get; init; } = default!;
}

internal sealed class CategorySample
{
    public long Bytes { get; init; }
    public long Count { get; init; }
    public long DeltaBytes { get; init; }
    public long DeltaCount { get; init; }
}
