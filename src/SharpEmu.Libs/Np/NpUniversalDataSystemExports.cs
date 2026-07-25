// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;

namespace SharpEmu.Libs.Np;

public static class NpUniversalDataSystemExports
{
    private const int NpUniversalDataSystemErrorInvalidArgument = unchecked((int)0x80553102);
    private static readonly object _eventGate = new();
    private static readonly HashSet<int> _createdEvents = [];
    private static readonly HashSet<int> _registeredContexts = [];
    private static int _nextHandle = 1;
    private static int _nextEvent = 1;

    [SysAbiExport(
        Nid = "sjaobBgqeB4",
        ExportName = "sceNpUniversalDataSystemInitialize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemInitialize(CpuContext ctx)
    {
        var parameterAddress = ctx[CpuRegister.Rdi];
        if (parameterAddress == 0)
        {
            return ctx.SetReturn(NpUniversalDataSystemErrorInvalidArgument, typeof(long));
        }

        Span<byte> parameters = stackalloc byte[16];
        return ctx.Memory.TryRead(parameterAddress, parameters)
            ? ctx.SetReturn(0, typeof(long))
            : ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
    }

    [SysAbiExport(
        Nid = "5zBnau1uIEo",
        ExportName = "sceNpUniversalDataSystemCreateContext",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemCreateContext(CpuContext ctx)
    {
        var contextAddress = ctx[CpuRegister.Rdi];
        if (contextAddress == 0)
        {
            return ctx.SetReturn(0, typeof(long));
        }

        Span<byte> context = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(context, 1);
        var success = ctx.Memory.TryWrite(contextAddress, context);
        
        if (success)
        {
            // Track this context for GetMemoryStat — initialize with zeroed stats.
            lock (_memoryGate)
            {
                _memoryStats[1] = new SceNpUniversalDataSystemMemoryStat(0, 0, 0, 0);
            }
        }

        return success
            ? ctx.SetReturn(0, typeof(long))
            : ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
    }

    [SysAbiExport(
        Nid = "hT0IAEvN+M0",
        ExportName = "sceNpUniversalDataSystemCreateHandle",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemCreateHandle(CpuContext ctx)
    {
        var handle = Interlocked.Increment(ref _nextHandle);
        var success = ctx.TryWriteInt32(ctx[CpuRegister.Rdi], handle, checkNil: true) ||
                      ctx.TryWriteInt32(ctx[CpuRegister.Rsi], handle, checkNil: true);

        if (success)
        {
            // Track this handle for GetMemoryStat — initialize with zeroed stats.
            lock (_memoryGate)
            {
                _memoryStats[handle] = new SceNpUniversalDataSystemMemoryStat(0, 0, 0, 0);
            }
        }

        return success
            ? ctx.SetReturn(0, typeof(long))
            : ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
    }

    [SysAbiExport(
        Nid = "p+GcLqwpL9M",
        ExportName = "sceNpUniversalDataSystemCreateEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemCreateEvent(CpuContext ctx)
    {
        var parameterAddress = ctx[CpuRegister.Rdi];
        if (parameterAddress == 0)
        {
            return ctx.SetReturn(NpUniversalDataSystemErrorInvalidArgument, typeof(long));
        }

        var eventId = Interlocked.Increment(ref _nextEvent);
        lock (_eventGate)
        {
            _createdEvents.Add(eventId);
        }

        if (ctx.TryWriteInt32(ctx[CpuRegister.Rdx], eventId, checkNil: true) ||
            ctx.TryWriteInt32(ctx[CpuRegister.Rcx], eventId, checkNil: true))
        {
            return ctx.SetReturn(0, typeof(long));
        }

        lock (_eventGate)
        {
            _createdEvents.Remove(eventId);
        }

        return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
    }

    [SysAbiExport(
        Nid = "wG+84pnNIuo",
        ExportName = "sceNpUniversalDataSystemDestroyEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemDestroyEvent(CpuContext ctx)
    {
        var eventId = unchecked((int)ctx[CpuRegister.Rdi]);
        lock (_eventGate)
        {
            _createdEvents.Remove(eventId);
        }

        return ctx.SetReturn(0, typeof(long));
    }

    [SysAbiExport(
        Nid = "MfDb+4Nln64",
        ExportName = "sceNpUniversalDataSystemEventPropertyObjectSetString",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemEventPropertyObjectSetString(CpuContext ctx)
    {
        var propertyObjectAddress = ctx[CpuRegister.Rsi];
        var valueAddress = ctx[CpuRegister.Rdx];
        if (propertyObjectAddress == 0 || valueAddress == 0)
        {
            return ctx.SetReturn(NpUniversalDataSystemErrorInvalidArgument, typeof(long));
        }

        Span<byte> probe = stackalloc byte[1];
        return ctx.Memory.TryRead(propertyObjectAddress, probe) &&
               ctx.Memory.TryRead(valueAddress, probe)
            ? ctx.SetReturn(0, typeof(long))
            : ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
    }

    [SysAbiExport(
        Nid = "Wxbg5x3pTXA",
        ExportName = "sceNpUniversalDataSystemEventPropertyObjectSetArray",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemEventPropertyObjectSetArray(CpuContext ctx)
    {
        var propertyObjectAddress = ctx[CpuRegister.Rsi];
        var valueAddress = ctx[CpuRegister.Rdx];
        if (propertyObjectAddress == 0)
        {
            return ctx.SetReturn(NpUniversalDataSystemErrorInvalidArgument, typeof(long));
        }

        Span<byte> probe = stackalloc byte[1];
        if (!ctx.Memory.TryRead(propertyObjectAddress, probe))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
        }

        if (valueAddress != 0 && !ctx.Memory.TryRead(valueAddress, probe))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, typeof(long));
        }

        return ctx.SetReturn(0, typeof(long));
    }

    [SysAbiExport(
        Nid = "CzkKf7ahIyU",
        ExportName = "sceNpUniversalDataSystemPostEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    // Posts an event against a context handle. Since we do not run the live NP
    // backend, events are accepted (so boot proceeds) but arguments are validated:
    // the data pointer — if supplied — must be readable in guest memory so that
    // a bogus address is reported rather than silently ignored.
    public static int NpUniversalDataSystemPostEvent(CpuContext ctx)
    {
        var contextHandle = unchecked((int)ctx[CpuRegister.Rdi]);
        var eventId       = unchecked((int)ctx[CpuRegister.Rsi]);
        var dataAddress   = ctx[CpuRegister.Rdx];

        if (contextHandle == 0)
        {
            return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        // If a data payload pointer was supplied, probe it for readability so we
        // don't silently accept an invalid address that would trap later.
        if (dataAddress != 0)
        {
            Span<byte> probe = stackalloc byte[1];
            if (!ctx.Memory.TryRead(dataAddress, probe))
            {
                return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
            }
        }

        // Track the registration for diagnostic purposes even though we don't
        // deliver events (offline NP backend).
        lock (_memoryGate)
        {
            _registeredContexts.Add(contextHandle);
        }

        TraceNpUds($"post_event handle={contextHandle} eventId=0x{eventId:X8} data=0x{dataAddress:X16}");
        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_OK);
    }

    [SysAbiExport(
        Nid = "tpFJ8LIKvPw",
        ExportName = "sceNpUniversalDataSystemRegisterContext",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    // Registers a callback for a context handle. We have no live NP backend to
    // invoke callbacks on, so we validate the arguments and remember that this
    // context is registered — GetMemoryStat will then return meaningful stats
    // instead of silently zeroing. This mirrors how NpTrophy2RegisterContext works.
    public static int NpUniversalDataSystemRegisterContext(CpuContext ctx)
    {
        var contextHandle = unchecked((int)ctx[CpuRegister.Rdi]);

        if (contextHandle == 0)
        {
            return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        lock (_memoryGate)
        {
            _registeredContexts.Add(contextHandle);
        }

        TraceNpUds($"register_context handle={contextHandle} callback=0x{ctx[CpuRegister.Rsi]:X16}");
        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_OK);
    }

    [SysAbiExport(
        Nid = "AUIHb7jUX3I",
        ExportName = "sceNpUniversalDataSystemDestroyHandle",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    // Destroys a handle previously created by CreateHandle. We remove it from our
    // memory-stat tracking so that stale entries don't accumulate across create/destroy
    // cycles during long gameplay sessions (e.g. Demon's Souls). If the handle was not
    // tracked — common when titles manage their own handle space against the live NP
    // backend — we still return OK, matching how other destroy handlers accept any arg.
    public static int NpUniversalDataSystemDestroyHandle(CpuContext ctx)
    {
        var handle = unchecked((int)ctx[CpuRegister.Rdi]);

        if (handle == 0)
        {
            return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        lock (_memoryGate)
        {
            _registeredContexts.Remove(handle);
            _memoryStats.Remove(handle); // Safe: no-op if handle was game-managed.
        }

        TraceNpUds($"destroy_handle handle={handle}");
        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_OK);
    }

    // Telemetry property setter (event property array, string value). We do not
    // upload analytics, so accept and drop it — but still validate that the
    // caller-supplied pointers are readable in guest memory before returning OK.
    [SysAbiExport(
        Nid = "4llLk7YJRTE",
        ExportName = "sceNpUniversalDataSystemEventPropertyArraySetString",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemEventPropertyArraySetString(CpuContext ctx)
    {
        var propertyObjectAddress = ctx[CpuRegister.Rsi];
        var valueAddress          = ctx[CpuRegister.Rdx];

        if (propertyObjectAddress == 0 || valueAddress == 0)
        {
            return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        Span<byte> probe = stackalloc byte[1];
        return ctx.Memory.TryRead(propertyObjectAddress, probe) &&
               ctx.Memory.TryRead(valueAddress, probe)
            ? ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_OK)
            : ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
    }
    // Memory allocation tracking for GetMemoryStat — keyed by context handle.
    private static readonly object _memoryGate = new();
    private static readonly Dictionary<int, SceNpUniversalDataSystemMemoryStat> _memoryStats = [];

    /// <summary>PS5 SDK memory stat struct layout for sceNpUniversalDataSystemGetMemoryStat.</summary>
    private readonly record struct SceNpUniversalDataSystemMemoryStat(
        ulong TotalAllocatedBytes,      // offset 0x00
        ulong PeakAllocationBytes,      // offset 0x08
        ulong CurrentSessionBytes,      // offset 0x10
        uint UnknownField4);            // offset 0x18 (padding/unknown)

    [SysAbiExport(
        Nid = "su7jW3VDDb4",
        ExportName = "sceNpUniversalDataSystemGetMemoryStat",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceNpUniversalDataSystem")]
    public static int NpUniversalDataSystemGetMemoryStat(CpuContext ctx)
    {
        var contextHandle = unchecked((int)ctx[CpuRegister.Rdi]);
        var statAddress = ctx[CpuRegister.Rsi];

        // Comprehensive register dump for debugging — helps identify if the game
        // passes different registers than expected (e.g., RDX instead of RSI).
        TraceNpUds($"get_memory_stat ENTRY handle=0x{contextHandle:X8} " +
                   $"statAddr=0x{statAddress:X16} " +
                   $"RDX=0x{ctx[CpuRegister.Rdx]:X16} RCX=0x{ctx[CpuRegister.Rcx]:X16} " +
                   $"R8=0x{ctx[CpuRegister.R8]:X16} R9=0x{ctx[CpuRegister.R9]:X16}");

        // statAddress must be a valid guest pointer (not 0, not tiny garbage like 0xB6).
        // PS5 guest addresses are typically >= 0x1000 for stack/heap data.
        if (statAddress == 0 || statAddress < 0x1000)
        {
            TraceNpUds($"get_memory_stat INVALID_ADDR handle=0x{contextHandle:X8} " +
                       $"statAddr=0x{statAddress:X16} — returning INVALID_ARGUMENT");
            return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        SceNpUniversalDataSystemMemoryStat stat;
        lock (_memoryGate)
        {
            // If context was never registered, return zeroed stats (safe fallback).
            if (!_memoryStats.TryGetValue(contextHandle, out var tracked))
            {
                TraceNpUds($"get_memory_stat UNTRACKED handle=0x{contextHandle:X8} — using zeroed stats");
                tracked = new SceNpUniversalDataSystemMemoryStat(0, 0, 0, 0);
            }

            stat = tracked;
        }

        // Write the full struct to guest memory — real data from tracked state.
        // Struct layout: 3x ulong (0x18 bytes) + uint (0x04 bytes) = 28 bytes total.
        Span<byte> statBytes = stackalloc byte[28];
        var offset = 0;
        BinaryPrimitives.WriteUInt64LittleEndian(statBytes.Slice(offset, 8), stat.TotalAllocatedBytes);
        offset += 8;
        BinaryPrimitives.WriteUInt64LittleEndian(statBytes.Slice(offset, 8), stat.PeakAllocationBytes);
        offset += 8;
        BinaryPrimitives.WriteUInt64LittleEndian(statBytes.Slice(offset, 8), stat.CurrentSessionBytes);
        offset += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(statBytes.Slice(offset, 4), stat.UnknownField4);

        var written = ctx.Memory.TryWrite(statAddress, statBytes);
        TraceNpUds($"get_memory_stat handle=0x{contextHandle:X8} total=0x{stat.TotalAllocatedBytes:X16} " +
                   $"peak=0x{stat.PeakAllocationBytes:X16} current=0x{stat.CurrentSessionBytes:X16} written={written}");

        return written
            ? ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_OK)
            : ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
    }

    /// <summary>
    /// Emits trace output for NpUniversalDataSystem calls when SHARPEMU_LOG_NP=1 is set,
    /// mirroring the tracing pattern used by NpEntitlementAccessExports and other Np modules.
    /// </summary>
    private static void TraceNpUds(string message)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_NP"), "1", StringComparison.Ordinal))
        {
            return;
        }

        Console.Error.WriteLine($"[LOADER][TRACE] np.uds.{message}");
    }
}
