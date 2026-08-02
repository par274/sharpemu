// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using SharpEmu.Logging;

namespace SharpEmu.Core.Memory;

internal readonly record struct GuestHostMappingDiagnosticRange(
    ulong BaseAddress,
    ulong ReservedBytes,
    ulong CommittedBytes,
    bool Executable,
    bool ReservedOnly);

internal sealed class GuestResidencyMappingPlanEntry
{
    public GuestResidencyMappingPlanEntry(
        GuestHostMappingDiagnosticRange source,
        ulong queryStart,
        ulong queryEnd,
        ulong queryPageCount)
    {
        Source = source;
        QueryStart = queryStart;
        QueryEnd = queryEnd;
        QueryPageCount = queryPageCount;
    }

    public GuestHostMappingDiagnosticRange Source { get; }

    public ulong QueryStart { get; }

    public ulong QueryEnd { get; }

    public ulong QueryPageCount { get; }
}

internal sealed class GuestResidencyQueryRange
{
    public GuestResidencyQueryRange(ulong start, ulong end, int[] mappingIndices)
    {
        Start = start;
        End = end;
        MappingIndices = mappingIndices;
    }

    public ulong Start { get; }

    public ulong End { get; }

    public int[] MappingIndices { get; }

    public ulong PageCount { get; internal set; }
}

internal sealed class GuestResidencyScanPlan
{
    public GuestResidencyScanPlan(
        ulong pageSize,
        GuestResidencyMappingPlanEntry[] mappings,
        GuestResidencyQueryRange[] queryRanges)
    {
        PageSize = pageSize;
        Mappings = mappings;
        QueryRanges = queryRanges;
        UnionReservedBytes = queryRanges.Aggregate(
            0UL,
            static (total, range) => checked(total + range.End - range.Start));
        UnionPageCount = queryRanges.Aggregate(
            0UL,
            static (total, range) => checked(total + range.PageCount));
    }

    public ulong PageSize { get; }

    public GuestResidencyMappingPlanEntry[] Mappings { get; }

    public GuestResidencyQueryRange[] QueryRanges { get; }

    public ulong UnionReservedBytes { get; }

    public ulong UnionPageCount { get; }
}

internal static class GuestResidencyScanPlanBuilder
{
    internal const int MaximumOwnerReferences = 262_144;

    public static GuestResidencyScanPlan Create(
        IReadOnlyList<GuestHostMappingDiagnosticRange> source,
        ulong pageSize)
    {
        ArgumentNullException.ThrowIfNull(source);
        ValidatePageSize(pageSize);

        var mappings = new GuestResidencyMappingPlanEntry[source.Count];
        var events = new List<MappingBoundaryEvent>(checked(source.Count * 2));
        for (var index = 0; index < source.Count; index++)
        {
            var mapping = source[index];
            if (mapping.ReservedBytes == 0)
            {
                throw new ArgumentException(
                    "A guest mapping must have a non-zero reserved size.",
                    nameof(source));
            }

            var mappingEnd = checked(mapping.BaseAddress + mapping.ReservedBytes);
            var queryStart = AlignDown(mapping.BaseAddress, pageSize);
            var queryEnd = AlignUp(mappingEnd, pageSize);
            mappings[index] = new GuestResidencyMappingPlanEntry(
                mapping,
                queryStart,
                queryEnd,
                checked((queryEnd - queryStart) / pageSize));
            events.Add(new MappingBoundaryEvent(queryStart, index, IsStart: true));
            events.Add(new MappingBoundaryEvent(queryEnd, index, IsStart: false));
        }

        // Retain only the sorted boundary array while the disjoint query plan
        // is being built; no per-page state is kept.
        var sortedEvents = events.ToArray();
        Array.Sort(
            sortedEvents,
            static (left, right) => left.Address != right.Address
                ? left.Address.CompareTo(right.Address)
                : left.IsStart.CompareTo(right.IsStart));

        var activeMappings = new SortedSet<int>();
        var queryRanges = new List<GuestResidencyQueryRange>(source.Count);
        var ownerReferenceCount = 0;
        var eventIndex = 0;
        while (eventIndex < sortedEvents.Length)
        {
            var boundary = sortedEvents[eventIndex].Address;
            var nextEventIndex = eventIndex;
            while (nextEventIndex < sortedEvents.Length &&
                   sortedEvents[nextEventIndex].Address == boundary)
            {
                nextEventIndex++;
            }

            // End points are removed before starts are added. The active set
            // therefore represents the half-open interval [boundary, next).
            for (var index = eventIndex; index < nextEventIndex; index++)
            {
                if (!sortedEvents[index].IsStart)
                {
                    activeMappings.Remove(sortedEvents[index].MappingIndex);
                }
            }

            for (var index = eventIndex; index < nextEventIndex; index++)
            {
                if (sortedEvents[index].IsStart)
                {
                    activeMappings.Add(sortedEvents[index].MappingIndex);
                }
            }

            if (nextEventIndex < sortedEvents.Length && activeMappings.Count != 0)
            {
                var nextBoundary = sortedEvents[nextEventIndex].Address;
                if (nextBoundary > boundary)
                {
                    ownerReferenceCount = checked(ownerReferenceCount + activeMappings.Count);
                    if (ownerReferenceCount > MaximumOwnerReferences)
                    {
                        throw new InvalidOperationException(
                            $"Guest mapping overlap owner count exceeded {MaximumOwnerReferences}.");
                    }

                    var queryRange = new GuestResidencyQueryRange(
                        boundary,
                        nextBoundary,
                        activeMappings.ToArray())
                    {
                        PageCount = checked((nextBoundary - boundary) / pageSize),
                    };
                    queryRanges.Add(queryRange);
                }
            }

            eventIndex = nextEventIndex;
        }

        return new GuestResidencyScanPlan(pageSize, mappings, queryRanges.ToArray());
    }

    private static void ValidatePageSize(ulong pageSize)
    {
        if (pageSize == 0 || (pageSize & (pageSize - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pageSize));
        }
    }

    private static ulong AlignDown(ulong value, ulong alignment) =>
        value & ~(alignment - 1);

    private static ulong AlignUp(ulong value, ulong alignment) =>
        checked((value + alignment - 1) & ~(alignment - 1));

    private readonly record struct MappingBoundaryEvent(
        ulong Address,
        int MappingIndex,
        bool IsStart);
}

internal sealed class GuestResidencyAggregation
{
    private readonly ulong[] _queriedPages;
    private readonly ulong[] _residentPages;
    private readonly ulong[] _invalidOrUnqueryablePages;
    private readonly ulong[] _queryFailurePages;

    public GuestResidencyAggregation(int mappingCount)
    {
        if (mappingCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(mappingCount));
        }

        _queriedPages = new ulong[mappingCount];
        _residentPages = new ulong[mappingCount];
        _invalidOrUnqueryablePages = new ulong[mappingCount];
        _queryFailurePages = new ulong[mappingCount];
    }

    public ulong QueriedPages { get; private set; }

    public ulong ResidentPages { get; private set; }

    public ulong InvalidOrUnqueryablePages { get; private set; }

    public ulong QueryFailurePages { get; private set; }

    public void AddPage(GuestResidencyQueryRange range, bool querySucceeded, bool resident)
    {
        QueriedPages = checked(QueriedPages + 1);
        if (querySucceeded && resident)
        {
            ResidentPages = checked(ResidentPages + 1);
        }
        else
        {
            InvalidOrUnqueryablePages = checked(InvalidOrUnqueryablePages + 1);
        }

        foreach (var mappingIndex in range.MappingIndices)
        {
            _queriedPages[mappingIndex] = checked(_queriedPages[mappingIndex] + 1);
            if (querySucceeded && resident)
            {
                _residentPages[mappingIndex] = checked(_residentPages[mappingIndex] + 1);
            }
            else
            {
                _invalidOrUnqueryablePages[mappingIndex] =
                    checked(_invalidOrUnqueryablePages[mappingIndex] + 1);
                if (!querySucceeded)
                {
                    _queryFailurePages[mappingIndex] =
                        checked(_queryFailurePages[mappingIndex] + 1);
                }
            }
        }

        if (!querySucceeded)
        {
            QueryFailurePages = checked(QueryFailurePages + 1);
        }
    }

    public void AddQueryFailure(GuestResidencyQueryRange range, ulong pageCount)
    {
        QueriedPages = checked(QueriedPages + pageCount);
        InvalidOrUnqueryablePages = checked(InvalidOrUnqueryablePages + pageCount);
        QueryFailurePages = checked(QueryFailurePages + pageCount);
        foreach (var mappingIndex in range.MappingIndices)
        {
            _queriedPages[mappingIndex] = checked(_queriedPages[mappingIndex] + pageCount);
            _invalidOrUnqueryablePages[mappingIndex] =
                checked(_invalidOrUnqueryablePages[mappingIndex] + pageCount);
            _queryFailurePages[mappingIndex] =
                checked(_queryFailurePages[mappingIndex] + pageCount);
        }
    }

    public GuestResidencyMappingAggregation GetMapping(int mappingIndex)
    {
        return new GuestResidencyMappingAggregation(
            _queriedPages[mappingIndex],
            _residentPages[mappingIndex],
            _invalidOrUnqueryablePages[mappingIndex],
            _queryFailurePages[mappingIndex]);
    }
}

internal readonly record struct GuestResidencyMappingAggregation(
    ulong QueriedPages,
    ulong ResidentPages,
    ulong InvalidOrUnqueryablePages,
    ulong QueryFailurePages);

/// <summary>
/// Runs one bounded, opt-in Windows working-set query over the exact current
/// guest host-mapping range union. It is deliberately separate from normal
/// memory management and never changes page state.
/// </summary>
public sealed class GuestResidencyDiagnosticsSession : IDisposable
{
    private const int SchemaVersion = 1;
    private const ulong TriggerWorkingSetBytes = 8UL << 30;
    private const int SampleIntervalMilliseconds = 250;
    private const int MaximumMappings = 16_384;
    private const int MaximumPagesPerQuery = 8_192;

    private static GuestResidencyDiagnosticsSession? _active;

    private readonly string _path;
    private readonly Process _process;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Timer _timer;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };
    private PhysicalVirtualMemory? _memory;
    private int _mappingSourceConflict;
    private int _triggerState;
    private int _disposed;
    private int _outputWritten;

    private GuestResidencyDiagnosticsSession(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A diagnostics path is required.", nameof(path));
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Guest residency diagnostics are supported only on Windows.");
        }

        _path = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _process = Process.GetCurrentProcess();
        _timer = new Timer(
            static state => ((GuestResidencyDiagnosticsSession)state!).Poll(),
            this,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);
    }

    public static bool IsEnabled => Volatile.Read(ref _active) is not null;

    public static GuestResidencyDiagnosticsSession Start(string path)
    {
        var session = new GuestResidencyDiagnosticsSession(path);
        if (Interlocked.CompareExchange(ref _active, session, null) is not null)
        {
            session.Dispose();
            throw new InvalidOperationException(
                "A guest residency diagnostics session is already active.");
        }

        session._timer.Change(
            TimeSpan.FromMilliseconds(SampleIntervalMilliseconds),
            TimeSpan.FromMilliseconds(SampleIntervalMilliseconds));
        return session;
    }

    internal static bool TryAttach(PhysicalVirtualMemory memory)
    {
        var session = Volatile.Read(ref _active);
        return session is not null && session.Attach(memory);
    }

    internal static void DetachMemory(PhysicalVirtualMemory memory)
    {
        var session = Volatile.Read(ref _active);
        session?.DetachAttachedMemory(memory);
    }

    internal static bool IsCaptureDisabledForTests() =>
        Volatile.Read(ref _active) is null;

    private bool Attach(PhysicalVirtualMemory memory)
    {
        if (ReferenceEquals(Volatile.Read(ref _memory), memory))
        {
            return true;
        }

        if (Interlocked.CompareExchange(ref _memory, memory, null) is null)
        {
            return true;
        }

        Interlocked.Exchange(ref _mappingSourceConflict, 1);
        return false;
    }

    private void DetachAttachedMemory(PhysicalVirtualMemory memory)
    {
        _ = Interlocked.CompareExchange(ref _memory, null, memory);
    }

    private void Poll()
    {
        if (Volatile.Read(ref _disposed) != 0 ||
            Volatile.Read(ref _triggerState) != 0)
        {
            return;
        }

        try
        {
            _process.Refresh();
            var workingSetBytes = checked((ulong)Math.Max(0, _process.WorkingSet64));
            if (workingSetBytes < TriggerWorkingSetBytes ||
                Interlocked.CompareExchange(ref _triggerState, 1, 0) != 0)
            {
                return;
            }

            Capture(workingSetBytes);
            Volatile.Write(ref _triggerState, 2);
        }
        catch (Exception exception)
        {
            if (Interlocked.Exchange(ref _triggerState, 2) == 1)
            {
                WriteFailure("capture-exception", exception.GetType().Name);
            }
        }
    }

    private void Capture(ulong triggerWorkingSetBytes)
    {
        var memory = Volatile.Read(ref _memory);
        if (memory is null)
        {
            WriteFailure("mapping-source-unavailable", null);
            return;
        }

        if (Volatile.Read(ref _mappingSourceConflict) != 0)
        {
            WriteFailure("multiple-mapping-sources", null);
            return;
        }

        var snapshotStarted = _clock.ElapsedMilliseconds;
        var mappings = memory.SnapshotGuestHostMappingsForDiagnostics();
        if (mappings.Length > MaximumMappings)
        {
            WriteFailure("mapping-limit", mappings.Length.ToString());
            return;
        }

        var pageSize = checked((ulong)Environment.SystemPageSize);
        var plan = GuestResidencyScanPlanBuilder.Create(mappings, pageSize);
        var snapshotCompleted = _clock.ElapsedMilliseconds;

        _process.Refresh();
        var processWorkingSetBytes = checked((ulong)Math.Max(0, _process.WorkingSet64));
        var processPrivateBytes = checked((ulong)Math.Max(0, _process.PrivateMemorySize64));
        var queryStarted = _clock.ElapsedMilliseconds;
        var aggregation = new GuestResidencyAggregation(plan.Mappings.Length);
        var queryBuffer = new WorkingSetExInformation[MaximumPagesPerQuery];
        var informationSize = Marshal.SizeOf<WorkingSetExInformation>();
        var queryCallCount = 0;
        var queryFailureCount = 0;
        var firstQueryError = (int?)null;

        foreach (var queryRange in plan.QueryRanges)
        {
            var pageAddress = queryRange.Start;
            var remainingPages = queryRange.PageCount;
            while (remainingPages != 0)
            {
                var pagesThisQuery = (int)Math.Min(
                    (ulong)MaximumPagesPerQuery,
                    remainingPages);
                for (var pageIndex = 0; pageIndex < pagesThisQuery; pageIndex++)
                {
                    queryBuffer[pageIndex].VirtualAddress =
                        unchecked((nint)pageAddress);
                    pageAddress = checked(pageAddress + pageSize);
                }

                queryCallCount++;
                var queryBytes = checked(pagesThisQuery * informationSize);
                if (!QueryWorkingSetEx(
                        _process.Handle,
                        queryBuffer,
                        queryBytes))
                {
                    queryFailureCount++;
                    var error = Marshal.GetLastWin32Error();
                    firstQueryError ??= error;
                    aggregation.AddQueryFailure(queryRange, (ulong)pagesThisQuery);
                }
                else
                {
                    for (var pageIndex = 0; pageIndex < pagesThisQuery; pageIndex++)
                    {
                        aggregation.AddPage(
                            queryRange,
                            querySucceeded: true,
                            resident: (queryBuffer[pageIndex].VirtualAttributes & 1) != 0);
                    }
                }

                remainingPages -= (ulong)pagesThisQuery;
            }
        }

        var queryCompleted = _clock.ElapsedMilliseconds;
        var residentBytes = checked(aggregation.ResidentPages * pageSize);
        var remainderBytes = processWorkingSetBytes > long.MaxValue
            ? throw new InvalidOperationException("Process working set exceeded signed range.")
            : checked((long)processWorkingSetBytes - checked((long)residentBytes));
        var resultMappings = new GuestResidencyMappingResult[plan.Mappings.Length];
        for (var index = 0; index < resultMappings.Length; index++)
        {
            var mapping = plan.Mappings[index];
            var aggregate = aggregation.GetMapping(index);
            resultMappings[index] = new GuestResidencyMappingResult
            {
                BaseAddress = mapping.Source.BaseAddress,
                ReservedBytes = mapping.Source.ReservedBytes,
                CommittedBytes = mapping.Source.CommittedBytes,
                Executable = mapping.Source.Executable,
                ReservedOnly = mapping.Source.ReservedOnly,
                QueryPageCount = mapping.QueryPageCount,
                QueriedPageCount = aggregate.QueriedPages,
                ResidentPageCount = aggregate.ResidentPages,
                InvalidOrUnqueryablePageCount = aggregate.InvalidOrUnqueryablePages,
                QueryFailurePageCount = aggregate.QueryFailurePages,
                ResidentBytes = checked(aggregate.ResidentPages * pageSize),
            };
        }

        Array.Sort(
            resultMappings,
            static (left, right) => left.ResidentBytes != right.ResidentBytes
                ? right.ResidentBytes.CompareTo(left.ResidentBytes)
                : left.BaseAddress.CompareTo(right.BaseAddress));

        WriteDocument(
            new GuestResidencyDiagnosticDocument
            {
                Status = queryFailureCount == 0 ? "complete" : "partial",
                Trigger = new GuestResidencyTrigger
                {
                    ThresholdWorkingSetBytes = TriggerWorkingSetBytes,
                    TriggerWorkingSetBytes = triggerWorkingSetBytes,
                    ElapsedMilliseconds = GetDiagnosticElapsedMilliseconds(),
                },
                Process = new GuestResidencyProcess
                {
                    ProcessId = _process.Id,
                    ProcessName = _process.ProcessName,
                    WorkingSetBytes = processWorkingSetBytes,
                    PrivateBytes = processPrivateBytes,
                    ElapsedMilliseconds = queryStarted,
                },
                Scan = new GuestResidencyScan
                {
                    PageSizeBytes = pageSize,
                    MappingCount = plan.Mappings.Length,
                    NormalizedRangeCount = plan.QueryRanges.Length,
                    QueryPageCount = aggregation.QueriedPages,
                    ResidentPageCount = aggregation.ResidentPages,
                    InvalidOrUnqueryablePageCount = aggregation.InvalidOrUnqueryablePages,
                    QueryFailurePageCount = aggregation.QueryFailurePages,
                    QueryCallCount = queryCallCount,
                    SnapshotElapsedMilliseconds = snapshotCompleted - snapshotStarted,
                    ScanDurationMilliseconds = queryCompleted - snapshotStarted,
                    QueryDurationMilliseconds = queryCompleted - queryStarted,
                    MaximumQueryChunkPages = MaximumPagesPerQuery,
                    MaximumQueryBufferBytes = checked(MaximumPagesPerQuery * informationSize),
                    FirstQueryError = firstQueryError,
                },
                GuestMappingUnion = new GuestResidencyUnion
                {
                    ReservedBytes = plan.UnionReservedBytes,
                    SumCommittedBytes = mappings.Aggregate(
                        0UL,
                        static (total, mapping) => checked(total + mapping.CommittedBytes)),
                    ResidentBytes = residentBytes,
                    ResidentPageCount = aggregation.ResidentPages,
                },
                WorkingSetMinusGuestResidentBytes = remainderBytes,
                Mappings = resultMappings,
            });

        MemoryDiagnostics.RecordEvent(
            "guest-residency-complete",
            new
            {
                status = queryFailureCount == 0 ? "complete" : "partial",
                processWorkingSetBytes,
                processPrivateBytes,
                residentBytes,
                remainderBytes,
                queryPageCount = aggregation.QueriedPages,
                residentPageCount = aggregation.ResidentPages,
                invalidOrUnqueryablePageCount = aggregation.InvalidOrUnqueryablePages,
                queryFailurePageCount = aggregation.QueryFailurePages,
                queryDurationMilliseconds = queryCompleted - queryStarted,
            });
    }

    private long GetDiagnosticElapsedMilliseconds() =>
        MemoryDiagnostics.IsEnabled
            ? MemoryDiagnostics.GetElapsedMilliseconds()
            : _clock.ElapsedMilliseconds;

    private void WriteFailure(string status, string? detail)
    {
        WriteDocument(
            new GuestResidencyDiagnosticDocument
            {
                Status = status,
                Error = detail,
                Trigger = new GuestResidencyTrigger
                {
                    ThresholdWorkingSetBytes = TriggerWorkingSetBytes,
                    ElapsedMilliseconds = GetDiagnosticElapsedMilliseconds(),
                },
                Process = new GuestResidencyProcess
                {
                    ProcessId = _process.Id,
                    ProcessName = _process.ProcessName,
                },
            });
    }

    private void WriteDocument(GuestResidencyDiagnosticDocument document)
    {
        if (Interlocked.Exchange(ref _outputWritten, 1) != 0)
        {
            return;
        }

        var json = JsonSerializer.Serialize(document, _jsonOptions);
        File.WriteAllText(_path, json);
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
            _timer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            if (Volatile.Read(ref _triggerState) == 0)
            {
                Interlocked.CompareExchange(ref _triggerState, 2, 0);
                WriteFailure("not-triggered", null);
            }
        }
        finally
        {
            _process.Dispose();
            _ = Interlocked.CompareExchange(ref _active, null, this);
            GC.SuppressFinalize(this);
        }
    }

    [DllImport("psapi.dll", EntryPoint = "QueryWorkingSetEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryWorkingSetEx(
        nint processHandle,
        [In, Out] WorkingSetExInformation[] workingSetInformation,
        int byteCount);

    [StructLayout(LayoutKind.Sequential)]
    private struct WorkingSetExInformation
    {
        public nint VirtualAddress;
        public nuint VirtualAttributes;
    }
}

internal sealed class GuestResidencyDiagnosticDocument
{
    public string Kind => "guest-residency";

    public int SchemaVersion => 1;

    public string Status { get; init; } = string.Empty;

    public string? Error { get; init; }

    public GuestResidencyTrigger? Trigger { get; init; }

    public GuestResidencyProcess? Process { get; init; }

    public GuestResidencyScan? Scan { get; init; }

    public GuestResidencyUnion? GuestMappingUnion { get; init; }

    public long? WorkingSetMinusGuestResidentBytes { get; init; }

    public GuestResidencyMappingResult[]? Mappings { get; init; }
}

internal sealed class GuestResidencyTrigger
{
    public ulong ThresholdWorkingSetBytes { get; init; }

    public ulong? TriggerWorkingSetBytes { get; init; }

    public long ElapsedMilliseconds { get; init; }
}

internal sealed class GuestResidencyProcess
{
    public int ProcessId { get; init; }

    public string ProcessName { get; init; } = string.Empty;

    public ulong? WorkingSetBytes { get; init; }

    public ulong? PrivateBytes { get; init; }

    public long? ElapsedMilliseconds { get; init; }
}

internal sealed class GuestResidencyScan
{
    public ulong PageSizeBytes { get; init; }

    public int MappingCount { get; init; }

    public int NormalizedRangeCount { get; init; }

    public ulong QueryPageCount { get; init; }

    public ulong ResidentPageCount { get; init; }

    public ulong InvalidOrUnqueryablePageCount { get; init; }

    public ulong QueryFailurePageCount { get; init; }

    public int QueryCallCount { get; init; }

    public long SnapshotElapsedMilliseconds { get; init; }

    public long ScanDurationMilliseconds { get; init; }

    public long QueryDurationMilliseconds { get; init; }

    public int MaximumQueryChunkPages { get; init; }

    public int MaximumQueryBufferBytes { get; init; }

    public int? FirstQueryError { get; init; }
}

internal sealed class GuestResidencyUnion
{
    public ulong ReservedBytes { get; init; }

    public ulong SumCommittedBytes { get; init; }

    public ulong ResidentBytes { get; init; }

    public ulong ResidentPageCount { get; init; }
}

internal sealed class GuestResidencyMappingResult
{
    public ulong BaseAddress { get; init; }

    public ulong ReservedBytes { get; init; }

    public ulong CommittedBytes { get; init; }

    public bool Executable { get; init; }

    public bool ReservedOnly { get; init; }

    public ulong QueryPageCount { get; init; }

    public ulong QueriedPageCount { get; init; }

    public ulong ResidentPageCount { get; init; }

    public ulong InvalidOrUnqueryablePageCount { get; init; }

    public ulong QueryFailurePageCount { get; init; }

    public ulong ResidentBytes { get; init; }
}
