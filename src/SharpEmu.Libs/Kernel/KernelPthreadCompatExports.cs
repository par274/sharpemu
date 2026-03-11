// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Threading;

namespace SharpEmu.Libs.Kernel;

public static class KernelPthreadCompatExports
{
    private const int MutexTypeNormal = 0;
    private const int MutexTypeRecursive = 1;
    private const ulong SyntheticMutexHandleBase = 0x00006000_0000_0000;
    private const ulong SyntheticMutexAttrHandleBase = 0x00006001_0000_0000;

    private static readonly object _stateGate = new();
    private static readonly Dictionary<ulong, PthreadMutexState> _mutexStates = new();
    private static readonly Dictionary<ulong, PthreadMutexAttrState> _mutexAttrStates = new();
    private static readonly Dictionary<ulong, PthreadCondState> _condStates = new();
    private static readonly HashSet<ulong> _condAttrStates = new();
    private static long _nextSyntheticThreadId = 1;
    private static long _nextSyntheticMutexHandleId = 1;
    private static long _nextSyntheticMutexAttrHandleId = 1;
    [ThreadStatic]
    private static ulong _currentThreadId;

    private sealed class PthreadMutexState
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);
        public ulong OwnerThreadId { get; set; }
        public int RecursionCount { get; set; }
        public int Type { get; set; } = MutexTypeNormal;
        public int Protocol { get; set; }
    }

    private sealed class PthreadCondState
    {
        public int PendingSignals { get; set; }
        public int Waiters { get; set; }
    }

    private readonly record struct PthreadMutexAttrState(int Type, int Protocol);

    [SysAbiExport(
        Nid = "aI+OeCz8xrQ",
        ExportName = "scePthreadSelf",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSelf(CpuContext ctx)
    {
        var currentThreadId = GetCurrentThreadId();
        ctx[CpuRegister.Rax] = currentThreadId;
        TracePthreadSelf(ctx, currentThreadId);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "3PtV6p3QNX4",
        ExportName = "scePthreadEqual",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadEqual(CpuContext ctx)
    {
        var left = ctx[CpuRegister.Rdi];
        var right = ctx[CpuRegister.Rsi];
        ctx[CpuRegister.Rax] = left == right ? 1UL : 0UL;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "T72hz6ffq08",
        ExportName = "scePthreadYield",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadYield(CpuContext ctx)
    {
        _ = ctx;
        Thread.Yield();
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "EI-5-jlq2dE",
        ExportName = "scePthreadGetthreadid",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetthreadid(CpuContext ctx)
    {
        var currentThreadId = GetCurrentThreadId();
        var outAddress = ctx[CpuRegister.Rdi];
        if (outAddress != 0 && !ctx.TryWriteUInt64(outAddress, currentThreadId))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = currentThreadId;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "cmo1RIYva9o",
        ExportName = "scePthreadMutexInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexInit(CpuContext ctx) => PthreadMutexInitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi]);

    [SysAbiExport(
        Nid = "2Of0f+3mhhE",
        ExportName = "scePthreadMutexDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexDestroy(CpuContext ctx) => PthreadMutexDestroyCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "9UK1vLZQft4",
        ExportName = "scePthreadMutexLock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexLock(CpuContext ctx) => PthreadMutexLockCore(ctx, ctx[CpuRegister.Rdi], tryOnly: false);

    [SysAbiExport(
        Nid = "upoVrzMHFeE",
        ExportName = "scePthreadMutexTrylock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexTrylock(CpuContext ctx) => PthreadMutexLockCore(ctx, ctx[CpuRegister.Rdi], tryOnly: true);

    [SysAbiExport(
        Nid = "tn3VlD0hG60",
        ExportName = "scePthreadMutexUnlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexUnlock(CpuContext ctx) => PthreadMutexUnlockCore(ctx, ctx[CpuRegister.Rdi], requireOwner: true);

    [SysAbiExport(
        Nid = "ttHNfU+qDBU",
        ExportName = "pthread_mutex_init",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexInit(CpuContext ctx) => PthreadMutexInitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi]);

    [SysAbiExport(
        Nid = "ltCfaGr2JGE",
        ExportName = "pthread_mutex_destroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexDestroy(CpuContext ctx) => PthreadMutexDestroyCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "7H0iTOciTLo",
        ExportName = "pthread_mutex_lock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexLock(CpuContext ctx) => PthreadMutexLockCore(ctx, ctx[CpuRegister.Rdi], tryOnly: false);

    [SysAbiExport(
        Nid = "K-jXhbt2gn4",
        ExportName = "pthread_mutex_trylock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexTrylock(CpuContext ctx) => PthreadMutexLockCore(ctx, ctx[CpuRegister.Rdi], tryOnly: true);

    [SysAbiExport(
        Nid = "2Z+PpY6CaJg",
        ExportName = "pthread_mutex_unlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexUnlock(CpuContext ctx) => PthreadMutexUnlockCore(ctx, ctx[CpuRegister.Rdi], requireOwner: true);

    [SysAbiExport(
        Nid = "F8bUHwAG284",
        ExportName = "scePthreadMutexattrInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexattrInit(CpuContext ctx) => PthreadMutexattrInitCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "smWEktiyyG0",
        ExportName = "scePthreadMutexattrDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexattrDestroy(CpuContext ctx) => PthreadMutexattrDestroyCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "iMp8QpE+XO4",
        ExportName = "scePthreadMutexattrSettype",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexattrSettype(CpuContext ctx) => PthreadMutexattrSettypeCore(ctx, ctx[CpuRegister.Rdi], unchecked((int)ctx[CpuRegister.Rsi]));

    [SysAbiExport(
        Nid = "1FGvU0i9saQ",
        ExportName = "scePthreadMutexattrSetprotocol",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadMutexattrSetprotocol(CpuContext ctx) => PthreadMutexattrSetprotocolCore(ctx, ctx[CpuRegister.Rdi], unchecked((int)ctx[CpuRegister.Rsi]));

    [SysAbiExport(
        Nid = "dQHWEsJtoE4",
        ExportName = "pthread_mutexattr_init",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexattrInit(CpuContext ctx) => PthreadMutexattrInitCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "HF7lK46xzjY",
        ExportName = "pthread_mutexattr_destroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexattrDestroy(CpuContext ctx) => PthreadMutexattrDestroyCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "mDmgMOGVUqg",
        ExportName = "pthread_mutexattr_settype",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexattrSettype(CpuContext ctx) => PthreadMutexattrSettypeCore(ctx, ctx[CpuRegister.Rdi], unchecked((int)ctx[CpuRegister.Rsi]));

    [SysAbiExport(
        Nid = "2Tb92quprl0",
        ExportName = "scePthreadCondInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondInit(CpuContext ctx) => PthreadCondInitCore(ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "g+PZd2hiacg",
        ExportName = "scePthreadCondDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondDestroy(CpuContext ctx) => PthreadCondDestroyCore(ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "WKAXJ4XBPQ4",
        ExportName = "scePthreadCondWait",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondWait(CpuContext ctx) => PthreadCondWaitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi], timed: false);

    [SysAbiExport(
        Nid = "BmMjYxmew1w",
        ExportName = "scePthreadCondTimedwait",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondTimedwait(CpuContext ctx) => PthreadCondWaitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi], timed: true);

    [SysAbiExport(
        Nid = "kDh-NfxgMtE",
        ExportName = "scePthreadCondSignal",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondSignal(CpuContext ctx) => PthreadCondSignalCore(ctx[CpuRegister.Rdi], broadcast: false);

    [SysAbiExport(
        Nid = "JGgj7Uvrl+A",
        ExportName = "scePthreadCondBroadcast",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondBroadcast(CpuContext ctx) => PthreadCondSignalCore(ctx[CpuRegister.Rdi], broadcast: true);

    [SysAbiExport(
        Nid = "Op8TBGY5KHg",
        ExportName = "pthread_cond_wait",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadCondWait(CpuContext ctx) => PthreadCondWaitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi], timed: false);

    [SysAbiExport(
        Nid = "mkx2fVhNMsg",
        ExportName = "pthread_cond_broadcast",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadCondBroadcast(CpuContext ctx) => PthreadCondSignalCore(ctx[CpuRegister.Rdi], broadcast: true);

    [SysAbiExport(
        Nid = "m5-2bsNfv7s",
        ExportName = "scePthreadCondattrInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondattrInit(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _condAttrStates.Add(attrAddress);
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "waPcxYiR3WA",
        ExportName = "scePthreadCondattrDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondattrDestroy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _condAttrStates.Remove(attrAddress);
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexInitCore(CpuContext ctx, ulong mutexAddress, ulong attrAddress)
    {
        if (mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var attr = ResolveMutexAttrState(ctx, attrAddress);
        var state = new PthreadMutexState
        {
            Type = attr.Type,
            Protocol = attr.Protocol,
        };

        var syntheticHandle = AllocateSyntheticHandle(SyntheticMutexHandleBase, ref _nextSyntheticMutexHandleId);
        lock (_stateGate)
        {
            _mutexStates[mutexAddress] = state;
            _mutexStates[syntheticHandle] = state;
        }

        _ = ctx.TryWriteUInt64(mutexAddress, syntheticHandle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexDestroyCore(CpuContext ctx, ulong mutexAddress)
    {
        if (mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexHandle(ctx, mutexAddress);
        PthreadMutexState? state;
        lock (_stateGate)
        {
            _mutexStates.TryGetValue(resolvedAddress, out state);
            _mutexStates.Remove(resolvedAddress);
            if (resolvedAddress != mutexAddress)
            {
                _mutexStates.Remove(mutexAddress);
            }
        }

        if (state is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        state.Semaphore.Dispose();
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexLockCore(CpuContext ctx, ulong mutexAddress, bool tryOnly)
    {
        if (mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexHandle(ctx, mutexAddress);
        PthreadMutexState state;
        lock (_stateGate)
        {
            if (!_mutexStates.TryGetValue(resolvedAddress, out state!))
            {
                state = new PthreadMutexState();
                _mutexStates[resolvedAddress] = state;
            }

            if (resolvedAddress != mutexAddress)
            {
                _mutexStates[mutexAddress] = state;
            }
        }

        var currentThreadId = GetCurrentThreadId();
        lock (state)
        {
            if (state.OwnerThreadId == currentThreadId)
            {
                if (state.Type == MutexTypeRecursive)
                {
                    state.RecursionCount++;
                    TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_OK);
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_ALREADY_EXISTS);
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_ALREADY_EXISTS;
            }
        }

        var acquired = true;
        if (tryOnly)
        {
            acquired = state.Semaphore.Wait(0);
        }
        else
        {
            state.Semaphore.Wait();
        }
        if (!acquired)
        {
            TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_ALREADY_EXISTS);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_ALREADY_EXISTS;
        }

        lock (state)
        {
            state.OwnerThreadId = currentThreadId;
            state.RecursionCount = 1;
        }

        TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_OK);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexUnlockCore(CpuContext ctx, ulong mutexAddress, bool requireOwner)
    {
        if (mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexHandle(ctx, mutexAddress);
        PthreadMutexState? state;
        lock (_stateGate)
        {
            _mutexStates.TryGetValue(resolvedAddress, out state);
        }

        if (state is null)
        {
            TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, null, GetCurrentThreadId(), (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = GetCurrentThreadId();
        var shouldRelease = false;
        lock (state)
        {
            if (state.RecursionCount <= 0)
            {
                TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }

            if (requireOwner && state.OwnerThreadId != currentThreadId)
            {
                TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }

            state.RecursionCount--;
            if (state.RecursionCount == 0)
            {
                state.OwnerThreadId = 0;
                shouldRelease = true;
            }
        }

        if (shouldRelease)
        {
            try
            {
                state.Semaphore.Release();
            }
            catch (SemaphoreFullException)
            {
                TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }
        }

        TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_OK);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexattrInitCore(CpuContext ctx, ulong attrAddress)
    {
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var syntheticHandle = AllocateSyntheticHandle(SyntheticMutexAttrHandleBase, ref _nextSyntheticMutexAttrHandleId);
        lock (_stateGate)
        {
            _mutexAttrStates[attrAddress] = new PthreadMutexAttrState(MutexTypeNormal, 0);
            _mutexAttrStates[syntheticHandle] = new PthreadMutexAttrState(MutexTypeNormal, 0);
        }

        _ = ctx.TryWriteUInt64(attrAddress, syntheticHandle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexattrDestroyCore(CpuContext ctx, ulong attrAddress)
    {
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            _mutexAttrStates.Remove(resolvedAddress);
            if (resolvedAddress != attrAddress)
            {
                _mutexAttrStates.Remove(attrAddress);
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexattrSettypeCore(CpuContext ctx, ulong attrAddress, int type)
    {
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            if (!_mutexAttrStates.TryGetValue(resolvedAddress, out var state))
            {
                state = new PthreadMutexAttrState(MutexTypeNormal, 0);
            }

            _mutexAttrStates[resolvedAddress] = state with { Type = type };
            if (resolvedAddress != attrAddress)
            {
                _mutexAttrStates[attrAddress] = _mutexAttrStates[resolvedAddress];
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexattrSetprotocolCore(CpuContext ctx, ulong attrAddress, int protocol)
    {
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveMutexAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            if (!_mutexAttrStates.TryGetValue(resolvedAddress, out var state))
            {
                state = new PthreadMutexAttrState(MutexTypeNormal, 0);
            }

            _mutexAttrStates[resolvedAddress] = state with { Protocol = protocol };
            if (resolvedAddress != attrAddress)
            {
                _mutexAttrStates[attrAddress] = _mutexAttrStates[resolvedAddress];
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static ulong ResolveMutexHandle(CpuContext ctx, ulong mutexAddress)
    {
        if (mutexAddress == 0)
        {
            return 0;
        }

        lock (_stateGate)
        {
            if (_mutexStates.ContainsKey(mutexAddress))
            {
                return mutexAddress;
            }
        }

        if (ctx.TryReadUInt64(mutexAddress, out var pointedHandle) && pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_mutexStates.ContainsKey(pointedHandle))
                {
                    return pointedHandle;
                }
            }
        }

        return mutexAddress;
    }

    private static ulong ResolveMutexAttrHandle(CpuContext ctx, ulong attrAddress)
    {
        if (attrAddress == 0)
        {
            return 0;
        }

        lock (_stateGate)
        {
            if (_mutexAttrStates.ContainsKey(attrAddress))
            {
                return attrAddress;
            }
        }

        if (ctx.TryReadUInt64(attrAddress, out var pointedHandle) && pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_mutexAttrStates.ContainsKey(pointedHandle))
                {
                    return pointedHandle;
                }
            }
        }

        return attrAddress;
    }

    private static PthreadMutexAttrState ResolveMutexAttrState(CpuContext ctx, ulong attrAddress)
    {
        if (attrAddress == 0)
        {
            return default;
        }

        var resolvedAddress = ResolveMutexAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            return _mutexAttrStates.TryGetValue(resolvedAddress, out var state)
                ? state
                : default;
        }
    }

    private static ulong AllocateSyntheticHandle(ulong baseAddress, ref long nextId)
    {
        var id = unchecked((ulong)Interlocked.Increment(ref nextId));
        return baseAddress + (id << 4);
    }

    private static int PthreadCondInitCore(ulong condAddress)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _condStates[condAddress] = new PthreadCondState();
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadCondDestroyCore(ulong condAddress)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _condStates.Remove(condAddress);
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadCondWaitCore(CpuContext ctx, ulong condAddress, ulong mutexAddress, bool timed)
    {
        if (condAddress == 0 || mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            if (!_condStates.TryGetValue(condAddress, out var state))
            {
                state = new PthreadCondState();
                _condStates[condAddress] = state;
            }

            state.Waiters++;
            if (state.PendingSignals > 0)
            {
                state.PendingSignals--;
                state.Waiters--;
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }
        }

        var unlockResult = PthreadMutexUnlockCore(ctx, mutexAddress, requireOwner: true);
        if (unlockResult != (int)OrbisGen2Result.ORBIS_GEN2_OK)
        {
            return unlockResult;
        }

        if (timed)
        {
            Thread.Sleep(1);
        }
        else
        {
            Thread.Yield();
        }

        var lockResult = PthreadMutexLockCore(ctx, mutexAddress, tryOnly: false);
        lock (_stateGate)
        {
            if (_condStates.TryGetValue(condAddress, out var state))
            {
                state.Waiters = Math.Max(0, state.Waiters - 1);
            }
        }

        return lockResult;
    }

    private static int PthreadCondSignalCore(ulong condAddress, bool broadcast)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            if (!_condStates.TryGetValue(condAddress, out var state))
            {
                state = new PthreadCondState();
                _condStates[condAddress] = state;
            }

            if (broadcast)
            {
                state.PendingSignals += Math.Max(1, state.Waiters);
            }
            else
            {
                state.PendingSignals++;
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static ulong GetCurrentThreadId()
    {
        if (_currentThreadId != 0)
        {
            return _currentThreadId;
        }

        _currentThreadId = unchecked((ulong)Interlocked.Increment(ref _nextSyntheticThreadId));
        return _currentThreadId;
    }

    private static void TracePthreadSelf(CpuContext ctx, ulong currentThreadId)
    {
        if (!ShouldTracePthread())
        {
            return;
        }

        Console.Error.WriteLine(
            $"[LOADER][TRACE] pthread_self: stale_rdi=0x{ctx[CpuRegister.Rdi]:X16} thread=0x{currentThreadId:X16}");
    }

    private static void TracePthreadMutex(CpuContext ctx, string operation, ulong mutexAddress, ulong resolvedAddress, PthreadMutexState? state, ulong currentThreadId, int result)
    {
        if (!ShouldTracePthread())
        {
            return;
        }

        _ = ctx.TryReadUInt64(mutexAddress, out var guestWord0);
        _ = ctx.TryReadUInt64(mutexAddress + 8, out var guestWord1);
        Console.Error.WriteLine(
            $"[LOADER][TRACE] pthread_{operation}: mutex=0x{mutexAddress:X16} resolved=0x{resolvedAddress:X16} " +
            $"guest[0]=0x{guestWord0:X16} guest[8]=0x{guestWord1:X16} " +
            $"current=0x{currentThreadId:X16} owner=0x{(state?.OwnerThreadId ?? 0):X16} " +
            $"recursion={(state?.RecursionCount ?? 0)} type={(state?.Type ?? 0)} result=0x{unchecked((uint)result):X8}");
    }

    private static bool ShouldTracePthread()
    {
        return string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_PTHREADS"), "1", StringComparison.Ordinal);
    }
}
