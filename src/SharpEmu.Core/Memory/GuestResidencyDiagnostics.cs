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
    private readonly ulong[] _nonResidentOrInvalidPages;
    private readonly ulong[] _queryFailurePages;

    public GuestResidencyAggregation(int mappingCount)
    {
        if (mappingCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(mappingCount));
        }

        _queriedPages = new ulong[mappingCount];
        _residentPages = new ulong[mappingCount];
        _nonResidentOrInvalidPages = new ulong[mappingCount];
        _queryFailurePages = new ulong[mappingCount];
    }

    public ulong QueriedPages { get; private set; }

    public ulong ResidentPages { get; private set; }

    public ulong NonResidentOrInvalidPages { get; private set; }

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
            NonResidentOrInvalidPages = checked(NonResidentOrInvalidPages + 1);
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
                _nonResidentOrInvalidPages[mappingIndex] =
                    checked(_nonResidentOrInvalidPages[mappingIndex] + 1);
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
        NonResidentOrInvalidPages = checked(NonResidentOrInvalidPages + pageCount);
        QueryFailurePages = checked(QueryFailurePages + pageCount);
        foreach (var mappingIndex in range.MappingIndices)
        {
            _queriedPages[mappingIndex] = checked(_queriedPages[mappingIndex] + pageCount);
            _nonResidentOrInvalidPages[mappingIndex] =
                checked(_nonResidentOrInvalidPages[mappingIndex] + pageCount);
            _queryFailurePages[mappingIndex] =
                checked(_queryFailurePages[mappingIndex] + pageCount);
        }
    }

    public GuestResidencyMappingAggregation GetMapping(int mappingIndex)
    {
        return new GuestResidencyMappingAggregation(
            _queriedPages[mappingIndex],
            _residentPages[mappingIndex],
            _nonResidentOrInvalidPages[mappingIndex],
            _queryFailurePages[mappingIndex]);
    }
}

internal readonly record struct GuestResidencyMappingAggregation(
    ulong QueriedPages,
    ulong ResidentPages,
    ulong NonResidentOrInvalidPages,
    ulong QueryFailurePages);

internal readonly record struct GuestResidencyMappingSnapshotComparison(
    bool IsStable,
    int BeforeCount,
    int AfterCount,
    int AddedCount,
    int RemovedCount,
    int ChangedCount);

internal static class GuestResidencyMappingSnapshotComparer
{
    public static GuestResidencyMappingSnapshotComparison Compare(
        IReadOnlyList<GuestHostMappingDiagnosticRange> before,
        IReadOnlyList<GuestHostMappingDiagnosticRange> after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var beforeSorted = before.ToArray();
        var afterSorted = after.ToArray();
        Array.Sort(beforeSorted, static (left, right) => left.BaseAddress.CompareTo(right.BaseAddress));
        Array.Sort(afterSorted, static (left, right) => left.BaseAddress.CompareTo(right.BaseAddress));

        var beforeIndex = 0;
        var afterIndex = 0;
        var addedCount = 0;
        var removedCount = 0;
        var changedCount = 0;
        while (beforeIndex < beforeSorted.Length || afterIndex < afterSorted.Length)
        {
            if (beforeIndex == beforeSorted.Length)
            {
                addedCount++;
                afterIndex++;
                continue;
            }

            if (afterIndex == afterSorted.Length)
            {
                removedCount++;
                beforeIndex++;
                continue;
            }

            var beforeMapping = beforeSorted[beforeIndex];
            var afterMapping = afterSorted[afterIndex];
            if (beforeMapping.BaseAddress < afterMapping.BaseAddress)
            {
                removedCount++;
                beforeIndex++;
            }
            else if (afterMapping.BaseAddress < beforeMapping.BaseAddress)
            {
                addedCount++;
                afterIndex++;
            }
            else
            {
                if (beforeMapping != afterMapping)
                {
                    changedCount++;
                }

                beforeIndex++;
                afterIndex++;
            }
        }

        return new GuestResidencyMappingSnapshotComparison(
            IsStable: addedCount == 0 && removedCount == 0 && changedCount == 0,
            BeforeCount: before.Count,
            AfterCount: after.Count,
            AddedCount: addedCount,
            RemovedCount: removedCount,
            ChangedCount: changedCount);
    }
}

internal readonly record struct GuestResidencyByteRange(
    long MinimumBytes,
    long MaximumBytes);

internal readonly record struct GuestResidencyPercentageRange(
    double MinimumPercent,
    double MaximumPercent);

internal static class GuestResidencyCounterRanges
{
    public static GuestResidencyByteRange Remainder(
        ulong workingSetBefore,
        ulong workingSetAfter,
        ulong residentBytes)
    {
        var before = checked(ToSigned(workingSetBefore) - ToSigned(residentBytes));
        var after = checked(ToSigned(workingSetAfter) - ToSigned(residentBytes));
        return new GuestResidencyByteRange(Math.Min(before, after), Math.Max(before, after));
    }

    public static GuestResidencyPercentageRange ResidentPercentage(
        ulong workingSetBefore,
        ulong workingSetAfter,
        ulong residentBytes)
    {
        if (workingSetBefore == 0 || workingSetAfter == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(workingSetBefore));
        }

        var before = 100d * residentBytes / workingSetBefore;
        var after = 100d * residentBytes / workingSetAfter;
        return new GuestResidencyPercentageRange(
            Math.Min(before, after),
            Math.Max(before, after));
    }

    private static long ToSigned(ulong value) =>
        value <= long.MaxValue
            ? (long)value
            : throw new InvalidOperationException("A diagnostic counter exceeded the signed range.");
}

internal sealed class GuestResidencyDiagnosticWriteGuard
{
    private readonly Func<GuestResidencyDiagnosticDocument, string> _serialize;
    private readonly Action<string> _write;
    private readonly Action<Exception> _reportFailure;
    private int _state;

    public GuestResidencyDiagnosticWriteGuard(
        Func<GuestResidencyDiagnosticDocument, string> serialize,
        Action<string> write,
        Action<Exception> reportFailure)
    {
        _serialize = serialize ?? throw new ArgumentNullException(nameof(serialize));
        _write = write ?? throw new ArgumentNullException(nameof(write));
        _reportFailure = reportFailure ?? throw new ArgumentNullException(nameof(reportFailure));
    }

    public bool IsWritten => Volatile.Read(ref _state) == 2;

    public bool TryWrite(GuestResidencyDiagnosticDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            return false;
        }

        try
        {
            var serialized = _serialize(document);
            _write(serialized);
            Volatile.Write(ref _state, 2);
            return true;
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _state, 0);
            try
            {
                _reportFailure(exception);
            }
            catch
            {
                // Diagnostics must not turn a persistence failure into an emulator failure.
            }

            return false;
        }
    }
}

/// <summary>
/// Runs one bounded, opt-in Windows working-set query over a snapshot of the
/// guest host-mapping range union. It is deliberately separate from normal
/// memory management and never changes page state; the result records whether
/// the mapping snapshot remained stable across the asynchronous query.
/// </summary>
public sealed class GuestResidencyDiagnosticsSession : IDisposable
{
    private const ulong TriggerWorkingSetBytes = 8UL << 30;
    private const int SampleIntervalMilliseconds = 250;
    private const int MaximumMappings = 16_384;
    private const int MaximumPagesPerQuery = 8_192;

    private static GuestResidencyDiagnosticsSession? _active;
    private static readonly SharpEmuLogger Log = SharpEmuLog.For("GuestResidency");

    private readonly string _path;
    private readonly Process _process;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Timer _timer;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };
    private readonly GuestResidencyDiagnosticWriteGuard _outputGuard;
    private PhysicalVirtualMemory? _memory;
    private int _mappingSourceConflict;
    private int _triggerState;
    private int _disposed;

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
        _outputGuard = new(
            document => JsonSerializer.Serialize(document, _jsonOptions),
            json => File.WriteAllText(_path, json),
            static exception => LogPersistenceFailure(exception));
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

        try
        {
            session._timer.Change(
                TimeSpan.FromMilliseconds(SampleIntervalMilliseconds),
                TimeSpan.FromMilliseconds(SampleIntervalMilliseconds));
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
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
        var mappingsBefore = memory.SnapshotGuestHostMappingsForDiagnostics();
        if (mappingsBefore.Length > MaximumMappings)
        {
            WriteFailure("mapping-limit", mappingsBefore.Length.ToString());
            return;
        }

        var pageSize = checked((ulong)Environment.SystemPageSize);
        var plan = GuestResidencyScanPlanBuilder.Create(mappingsBefore, pageSize);
        var snapshotCompleted = _clock.ElapsedMilliseconds;
        var aggregation = new GuestResidencyAggregation(plan.Mappings.Length);
        var queryBuffer = new WorkingSetExInformation[MaximumPagesPerQuery];
        var informationSize = Marshal.SizeOf<WorkingSetExInformation>();
        var queryCallCount = 0;
        var queryFailureCount = 0;
        var firstQueryError = (int?)null;

        // The query buffer is allocated before the first process sample so the
        // counters bracket the QueryWorkingSetEx calls themselves.
        _process.Refresh();
        var processWorkingSetBytesBefore = checked((ulong)Math.Max(0, _process.WorkingSet64));
        var processPrivateBytesBefore = checked((ulong)Math.Max(0, _process.PrivateMemorySize64));
        var queryStarted = _clock.ElapsedMilliseconds;

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
        _process.Refresh();
        var processWorkingSetBytesAfter = checked((ulong)Math.Max(0, _process.WorkingSet64));
        var processPrivateBytesAfter = checked((ulong)Math.Max(0, _process.PrivateMemorySize64));

        // This lock is acquired only for the second snapshot. It is not held
        // while QueryWorkingSetEx scans the process working set.
        var afterSnapshotStarted = _clock.ElapsedMilliseconds;
        var mappingsAfter = memory.SnapshotGuestHostMappingsForDiagnostics();
        var afterSnapshotCompleted = _clock.ElapsedMilliseconds;
        var mappingComparison = GuestResidencyMappingSnapshotComparer.Compare(
            mappingsBefore,
            mappingsAfter);

        var residentBytes = checked(aggregation.ResidentPages * pageSize);
        var remainderRange = GuestResidencyCounterRanges.Remainder(
            processWorkingSetBytesBefore,
            processWorkingSetBytesAfter,
            residentBytes);
        var residentPercentageRange = GuestResidencyCounterRanges.ResidentPercentage(
            processWorkingSetBytesBefore,
            processWorkingSetBytesAfter,
            residentBytes);
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
                NonResidentOrInvalidPageCount = aggregate.NonResidentOrInvalidPages,
                QueryFailurePageCount = aggregate.QueryFailurePages,
                ResidentBytes = checked(aggregate.ResidentPages * pageSize),
            };
        }

        Array.Sort(
            resultMappings,
                static (left, right) => left.ResidentBytes != right.ResidentBytes
                ? right.ResidentBytes.CompareTo(left.ResidentBytes)
                : left.BaseAddress.CompareTo(right.BaseAddress));

        var status = !mappingComparison.IsStable
            ? "unstable"
            : queryFailureCount == 0
                ? "complete"
                : "partial";
        var exactCurrentMappingUnion = mappingComparison.IsStable && queryFailureCount == 0;
        var document = new GuestResidencyDiagnosticDocument
            {
                Status = status,
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
                    WorkingSetBytesBeforeScan = processWorkingSetBytesBefore,
                    PrivateBytesBeforeScan = processPrivateBytesBefore,
                    WorkingSetBytesAfterScan = processWorkingSetBytesAfter,
                    PrivateBytesAfterScan = processPrivateBytesAfter,
                    BeforeScanElapsedMilliseconds = queryStarted,
                    AfterScanElapsedMilliseconds = queryCompleted,
                },
                Scan = new GuestResidencyScan
                {
                    PageSizeBytes = pageSize,
                    MappingCount = plan.Mappings.Length,
                    NormalizedRangeCount = plan.QueryRanges.Length,
                    QueryPageCount = aggregation.QueriedPages,
                    ResidentPageCount = aggregation.ResidentPages,
                    NonResidentOrInvalidPageCount = aggregation.NonResidentOrInvalidPages,
                    QueryFailurePageCount = aggregation.QueryFailurePages,
                    QueryCallCount = queryCallCount,
                    BeforeMappingSnapshotDurationMilliseconds = snapshotCompleted - snapshotStarted,
                    ScanDurationMilliseconds = afterSnapshotCompleted - snapshotStarted,
                    QueryDurationMilliseconds = queryCompleted - queryStarted,
                    AfterMappingSnapshotDurationMilliseconds = afterSnapshotCompleted - afterSnapshotStarted,
                    MaximumQueryChunkPages = MaximumPagesPerQuery,
                    MaximumQueryBufferBytes = checked(MaximumPagesPerQuery * informationSize),
                    FirstQueryError = firstQueryError,
                },
                MappingSnapshot = new GuestResidencyMappingSnapshot
                {
                    IsStable = mappingComparison.IsStable,
                    BeforeCount = mappingComparison.BeforeCount,
                    AfterCount = mappingComparison.AfterCount,
                    AddedCount = mappingComparison.AddedCount,
                    RemovedCount = mappingComparison.RemovedCount,
                    ChangedCount = mappingComparison.ChangedCount,
                },
                GuestMappingUnion = new GuestResidencyUnion
                {
                    ExactCurrentMappingUnion = exactCurrentMappingUnion,
                    ReservedBytes = plan.UnionReservedBytes,
                    SumCommittedBytes = mappingsBefore.Aggregate(
                        0UL,
                        static (total, mapping) => checked(total + mapping.CommittedBytes)),
                    ResidentBytes = residentBytes,
                    ResidentPageCount = aggregation.ResidentPages,
                },
                WorkingSetMinusGuestResidentBytesRange = remainderRange,
                GuestResidentPercentageOfWorkingSetRange = residentPercentageRange,
                Mappings = resultMappings,
            };
        if (!WriteDocument(document) && !_outputGuard.IsWritten)
        {
            // A result that could not be persisted still gets one bounded
            // chance to leave a machine-readable failure record.
            WriteFailure("result-not-persisted", status);
        }

        TryRecordEvent(
            "guest-residency-complete",
            new
            {
                status,
                mappingSetStable = mappingComparison.IsStable,
                processWorkingSetBytesBeforeScan = processWorkingSetBytesBefore,
                processPrivateBytesBeforeScan = processPrivateBytesBefore,
                processWorkingSetBytesAfterScan = processWorkingSetBytesAfter,
                processPrivateBytesAfterScan = processPrivateBytesAfter,
                residentBytes,
                remainderMinimumBytes = remainderRange.MinimumBytes,
                remainderMaximumBytes = remainderRange.MaximumBytes,
                queryPageCount = aggregation.QueriedPages,
                residentPageCount = aggregation.ResidentPages,
                nonResidentOrInvalidPageCount = aggregation.NonResidentOrInvalidPages,
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
        try
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
        catch (Exception exception)
        {
            LogPersistenceFailure(exception);
        }
    }

    private bool WriteDocument(GuestResidencyDiagnosticDocument document) =>
        _outputGuard.TryWrite(document);

    private static void TryRecordEvent(string kind, object payload)
    {
        try
        {
            MemoryDiagnostics.RecordEvent(kind, payload);
        }
        catch (Exception exception)
        {
            try
            {
                Log.Warning(
                    $"Guest residency diagnostic event was not recorded ({exception.GetType().Name}).");
            }
            catch
            {
                // Logging is best effort inside the timer callback.
            }
        }
    }

    private static void LogPersistenceFailure(Exception exception)
    {
        LogDiagnosticFailure("output persistence", exception);
    }

    private static void LogDiagnosticFailure(string operation, Exception exception)
    {
        try
        {
            Log.Error(
                $"Guest residency diagnostic {operation} failed ({exception.GetType().Name}).");
        }
        catch
        {
            // A logging failure must not escape the diagnostic callback either.
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
            try
            {
                _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                _timer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                LogDiagnosticFailure("timer disposal", exception);
            }

            if (Volatile.Read(ref _triggerState) == 0)
            {
                Interlocked.CompareExchange(ref _triggerState, 2, 0);
                WriteFailure("not-triggered", null);
            }
        }
        catch (Exception exception)
        {
            LogDiagnosticFailure("diagnostic disposal", exception);
        }
        try
        {
            _process.Dispose();
        }
        catch (Exception exception)
        {
            LogDiagnosticFailure("process disposal", exception);
        }
        finally
        {
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

    public int SchemaVersion => 2;

    public string Status { get; init; } = string.Empty;

    public string? Error { get; init; }

    public GuestResidencyTrigger? Trigger { get; init; }

    public GuestResidencyProcess? Process { get; init; }

    public GuestResidencyScan? Scan { get; init; }

    public GuestResidencyMappingSnapshot? MappingSnapshot { get; init; }

    public GuestResidencyUnion? GuestMappingUnion { get; init; }

    public GuestResidencyByteRange? WorkingSetMinusGuestResidentBytesRange { get; init; }

    public GuestResidencyPercentageRange? GuestResidentPercentageOfWorkingSetRange { get; init; }

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

    public ulong? WorkingSetBytesBeforeScan { get; init; }

    public ulong? PrivateBytesBeforeScan { get; init; }

    public ulong? WorkingSetBytesAfterScan { get; init; }

    public ulong? PrivateBytesAfterScan { get; init; }

    public long? BeforeScanElapsedMilliseconds { get; init; }

    public long? AfterScanElapsedMilliseconds { get; init; }
}

internal sealed class GuestResidencyScan
{
    public ulong PageSizeBytes { get; init; }

    public int MappingCount { get; init; }

    public int NormalizedRangeCount { get; init; }

    public ulong QueryPageCount { get; init; }

    public ulong ResidentPageCount { get; init; }

    public ulong NonResidentOrInvalidPageCount { get; init; }

    public ulong QueryFailurePageCount { get; init; }

    public int QueryCallCount { get; init; }

    public long BeforeMappingSnapshotDurationMilliseconds { get; init; }

    public long ScanDurationMilliseconds { get; init; }

    public long QueryDurationMilliseconds { get; init; }

    public long AfterMappingSnapshotDurationMilliseconds { get; init; }

    public int MaximumQueryChunkPages { get; init; }

    public int MaximumQueryBufferBytes { get; init; }

    public int? FirstQueryError { get; init; }
}

internal sealed class GuestResidencyUnion
{
    public bool ExactCurrentMappingUnion { get; init; }

    public ulong ReservedBytes { get; init; }

    public ulong SumCommittedBytes { get; init; }

    public ulong ResidentBytes { get; init; }

    public ulong ResidentPageCount { get; init; }
}

internal sealed class GuestResidencyMappingSnapshot
{
    public bool IsStable { get; init; }

    public int BeforeCount { get; init; }

    public int AfterCount { get; init; }

    public int AddedCount { get; init; }

    public int RemovedCount { get; init; }

    public int ChangedCount { get; init; }
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

    public ulong NonResidentOrInvalidPageCount { get; init; }

    public ulong QueryFailurePageCount { get; init; }

    public ulong ResidentBytes { get; init; }
}
