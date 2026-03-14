// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Threading;

namespace SharpEmu.Libs.Kernel;

public static class KernelPthreadCompatExports
{
    private const int MutexTypeDefault = 1;
    private const int MutexTypeErrorCheck = 1;
    private const int MutexTypeRecursive = 2;
    private const int MutexTypeNormal = 4;
    private const ulong SyntheticMutexHandleBase = 0x00006000_0000_0000;
    private const ulong SyntheticMutexAttrHandleBase = 0x00006001_0000_0000;
    private const ulong SyntheticCondHandleBase = 0x00006002_0000_0000;

    private static readonly object _stateGate = new();
    private static readonly Dictionary<ulong, PthreadMutexState> _mutexStates = new();
    private static readonly Dictionary<ulong, PthreadMutexAttrState> _mutexAttrStates = new();
    private static readonly Dictionary<ulong, PthreadCondState> _condStates = new();
    private static readonly HashSet<ulong> _condAttrStates = new();
    private static long _nextSyntheticMutexHandleId = 1;
    private static long _nextSyntheticMutexAttrHandleId = 1;
    private static long _nextSyntheticCondHandleId = 1;

    private sealed class PthreadMutexState
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);
        public ulong OwnerThreadId { get; set; }
        public int RecursionCount { get; set; }
        public int Type { get; set; } = MutexTypeDefault;
        public int Protocol { get; set; }
    }

    private sealed class PthreadCondState
    {
        public object SyncRoot { get; } = new();
        public ulong SignalEpoch { get; set; }
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
        var currentThreadHandle = KernelPthreadState.GetCurrentThreadHandle();
        ctx[CpuRegister.Rax] = currentThreadHandle;
        TracePthreadSelf(ctx, currentThreadHandle);
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
        var currentThreadId = KernelPthreadState.GetCurrentThreadUniqueId();
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
        Nid = "5txKfcMUAok",
        ExportName = "pthread_mutexattr_setprotocol",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadMutexattrSetprotocol(CpuContext ctx) => PthreadMutexattrSetprotocolCore(ctx, ctx[CpuRegister.Rdi], unchecked((int)ctx[CpuRegister.Rsi]));

    [SysAbiExport(
        Nid = "2Tb92quprl0",
        ExportName = "scePthreadCondInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondInit(CpuContext ctx) => PthreadCondInitCore(ctx, ctx[CpuRegister.Rdi]);

    [SysAbiExport(
        Nid = "g+PZd2hiacg",
        ExportName = "scePthreadCondDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCondDestroy(CpuContext ctx) => PthreadCondDestroyCore(ctx, ctx[CpuRegister.Rdi]);

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
    public static int PthreadCondTimedwait(CpuContext ctx) => PthreadCondWaitCore(ctx, ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi], timed: true, timeoutUsec: unchecked((uint)ctx[CpuRegister.Rdx]));

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

        _ = ctx.TryWriteUInt64(mutexAddress, 0);
        state.Semaphore.Dispose();
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadMutexLockCore(CpuContext ctx, ulong mutexAddress, bool tryOnly)
    {
        if (mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveMutexState(ctx, mutexAddress, createIfZero: true, out var resolvedAddress, out var state))
        {
            TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, null, KernelPthreadState.GetCurrentThreadHandle(), (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadHandle();
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

                var ownedResult = tryOnly
                    ? (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY
                    : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_DEADLOCK;
                TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, ownedResult);
                return ownedResult;
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
            TracePthreadMutex(ctx, tryOnly ? "trylock" : "lock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY;
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

        if (!TryResolveMutexState(ctx, mutexAddress, createIfZero: true, out var resolvedAddress, out var state))
        {
            TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, null, KernelPthreadState.GetCurrentThreadHandle(), (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadHandle();
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
                TracePthreadMutex(ctx, "unlock", mutexAddress, resolvedAddress, state, currentThreadId, (int)OrbisGen2Result.ORBIS_GEN2_ERROR_PERMISSION_DENIED);
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_PERMISSION_DENIED;
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
            _mutexAttrStates[attrAddress] = new PthreadMutexAttrState(MutexTypeDefault, 0);
            _mutexAttrStates[syntheticHandle] = new PthreadMutexAttrState(MutexTypeDefault, 0);
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
                state = new PthreadMutexAttrState(MutexTypeDefault, 0);
            }

            _mutexAttrStates[resolvedAddress] = state with { Type = NormalizeMutexType(type) };
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
                state = new PthreadMutexAttrState(MutexTypeDefault, 0);
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

    private static bool TryResolveMutexState(CpuContext ctx, ulong mutexAddress, bool createIfZero, out ulong resolvedAddress, out PthreadMutexState? state)
    {
        resolvedAddress = 0;
        state = null;
        if (mutexAddress == 0)
        {
            return false;
        }

        lock (_stateGate)
        {
            if (_mutexStates.TryGetValue(mutexAddress, out state))
            {
                resolvedAddress = mutexAddress;
                return true;
            }
        }

        if (!ctx.TryReadUInt64(mutexAddress, out var pointedHandle))
        {
            return false;
        }

        if (pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_mutexStates.TryGetValue(pointedHandle, out state))
                {
                    _mutexStates[mutexAddress] = state;
                    resolvedAddress = pointedHandle;
                    return true;
                }
            }

            resolvedAddress = pointedHandle;
            return false;
        }

        if (!createIfZero)
        {
            resolvedAddress = mutexAddress;
            return false;
        }

        var createdState = new PthreadMutexState();
        var syntheticHandle = AllocateSyntheticHandle(SyntheticMutexHandleBase, ref _nextSyntheticMutexHandleId);
        lock (_stateGate)
        {
            _mutexStates[mutexAddress] = createdState;
            _mutexStates[syntheticHandle] = createdState;
        }

        _ = ctx.TryWriteUInt64(mutexAddress, syntheticHandle);
        resolvedAddress = syntheticHandle;
        state = createdState;
        return true;
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
                : new PthreadMutexAttrState(MutexTypeDefault, 0);
        }
    }

    private static ulong ResolveCondHandle(CpuContext ctx, ulong condAddress)
    {
        if (condAddress == 0)
        {
            return 0;
        }

        lock (_stateGate)
        {
            if (_condStates.ContainsKey(condAddress))
            {
                return condAddress;
            }
        }

        if (ctx.TryReadUInt64(condAddress, out var pointedHandle) && pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_condStates.ContainsKey(pointedHandle))
                {
                    return pointedHandle;
                }
            }
        }

        return condAddress;
    }

    private static bool TryResolveCondState(CpuContext? ctx, ulong condAddress, bool createIfZero, out ulong resolvedAddress, out PthreadCondState? state)
    {
        resolvedAddress = 0;
        state = null;
        if (condAddress == 0)
        {
            return false;
        }

        lock (_stateGate)
        {
            if (_condStates.TryGetValue(condAddress, out state))
            {
                resolvedAddress = condAddress;
                return true;
            }
        }

        if (ctx is null || !ctx.TryReadUInt64(condAddress, out var pointedHandle))
        {
            return false;
        }

        if (pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_condStates.TryGetValue(pointedHandle, out state))
                {
                    _condStates[condAddress] = state;
                    resolvedAddress = pointedHandle;
                    return true;
                }
            }

            resolvedAddress = pointedHandle;
            return false;
        }

        if (!createIfZero)
        {
            resolvedAddress = condAddress;
            return false;
        }

        var createdState = new PthreadCondState();
        var syntheticHandle = AllocateSyntheticHandle(SyntheticCondHandleBase, ref _nextSyntheticCondHandleId);
        lock (_stateGate)
        {
            _condStates[condAddress] = createdState;
            _condStates[syntheticHandle] = createdState;
        }

        _ = ctx.TryWriteUInt64(condAddress, syntheticHandle);
        resolvedAddress = syntheticHandle;
        state = createdState;
        return true;
    }

    private static ulong AllocateSyntheticHandle(ulong baseAddress, ref long nextId)
    {
        var id = unchecked((ulong)Interlocked.Increment(ref nextId));
        return baseAddress + (id << 4);
    }

    private static int PthreadCondInitCore(CpuContext ctx, ulong condAddress)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var syntheticHandle = AllocateSyntheticHandle(SyntheticCondHandleBase, ref _nextSyntheticCondHandleId);
        lock (_stateGate)
        {
            var state = new PthreadCondState();
            _condStates[condAddress] = state;
            _condStates[syntheticHandle] = state;
        }

        _ = ctx.TryWriteUInt64(condAddress, syntheticHandle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadCondDestroyCore(CpuContext ctx, ulong condAddress)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveCondHandle(ctx, condAddress);
        lock (_stateGate)
        {
            _condStates.Remove(resolvedAddress);
            if (resolvedAddress != condAddress)
            {
                _condStates.Remove(condAddress);
            }
        }

        _ = ctx.TryWriteUInt64(condAddress, 0);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadCondWaitCore(CpuContext ctx, ulong condAddress, ulong mutexAddress, bool timed, uint timeoutUsec = 0)
    {
        if (condAddress == 0 || mutexAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveCondState(ctx, condAddress, createIfZero: true, out _, out var state))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var waitResult = (int)OrbisGen2Result.ORBIS_GEN2_OK;
        lock (state.SyncRoot)
        {
            state.Waiters++;
            var observedEpoch = state.SignalEpoch;
            TracePthreadCond("wait-enter", condAddress, mutexAddress, state, timed, waitResult);

            var unlockResult = PthreadMutexUnlockCore(ctx, mutexAddress, requireOwner: true);
            if (unlockResult != (int)OrbisGen2Result.ORBIS_GEN2_OK)
            {
                state.Waiters--;
                TracePthreadCond("wait-unlock-fail", condAddress, mutexAddress, state, timed, unlockResult);
                return unlockResult;
            }

            while (state.SignalEpoch == observedEpoch)
            {
                if (!timed)
                {
                    Monitor.Wait(state.SyncRoot);
                    continue;
                }

                if (!Monitor.Wait(state.SyncRoot, GetCondWaitTimeout(timeoutUsec)))
                {
                    waitResult = (int)OrbisGen2Result.ORBIS_GEN2_ERROR_TIMED_OUT;
                    break;
                }
            }

            state.Waiters = Math.Max(0, state.Waiters - 1);
            TracePthreadCond(waitResult == (int)OrbisGen2Result.ORBIS_GEN2_OK ? "wait-wake" : "wait-timeout", condAddress, mutexAddress, state, timed, waitResult);
        }

        var lockResult = PthreadMutexLockCore(ctx, mutexAddress, tryOnly: false);
        if (lockResult != (int)OrbisGen2Result.ORBIS_GEN2_OK)
        {
            TracePthreadCond("wait-relock-fail", condAddress, mutexAddress, state, timed, lockResult);
            return lockResult;
        }

        TracePthreadCond(waitResult == (int)OrbisGen2Result.ORBIS_GEN2_OK ? "wait-exit" : "wait-exit-timeout", condAddress, mutexAddress, state, timed, waitResult);
        return waitResult;
    }

    private static int PthreadCondSignalCore(ulong condAddress, bool broadcast)
    {
        if (condAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveCondState(null, condAddress, createIfZero: false, out _, out var state))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        lock (state.SyncRoot)
        {
            if (state.Waiters > 0)
            {
                state.SignalEpoch++;
                if (broadcast)
                {
                    Monitor.PulseAll(state.SyncRoot);
                }
                else
                {
                    Monitor.Pulse(state.SyncRoot);
                }
            }

            TracePthreadCond(broadcast ? "broadcast" : "signal", condAddress, mutexAddress: 0, state, timed: false, (int)OrbisGen2Result.ORBIS_GEN2_OK);
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static TimeSpan GetCondWaitTimeout(uint timeoutUsec)
    {
        if (timeoutUsec == 0)
        {
            return TimeSpan.Zero;
        }

        return TimeSpan.FromTicks((long)timeoutUsec * 10L);
    }

    private static int NormalizeMutexType(int type)
    {
        return type switch
        {
            0 => MutexTypeDefault,
            1 => MutexTypeErrorCheck,
            2 => MutexTypeRecursive,
            3 => MutexTypeNormal,
            4 => MutexTypeNormal,
            _ => MutexTypeDefault,
        };
    }

    private static void TracePthreadSelf(CpuContext ctx, ulong currentThreadHandle)
    {
        if (!ShouldTracePthread())
        {
            return;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadUniqueId();
        Console.Error.WriteLine(
            $"[LOADER][TRACE] pthread_self: stale_rdi=0x{ctx[CpuRegister.Rdi]:X16} thread=0x{currentThreadHandle:X16} tid=0x{currentThreadId:X16}");
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

    private static void TracePthreadCond(string operation, ulong condAddress, ulong mutexAddress, PthreadCondState? state, bool timed, int result)
    {
        if (!ShouldTracePthread())
        {
            return;
        }

        Console.Error.WriteLine(
            $"[LOADER][TRACE] pthread_cond_{operation}: cond=0x{condAddress:X16} mutex=0x{mutexAddress:X16} " +
            $"waiters={(state?.Waiters ?? 0)} epoch=0x{(state?.SignalEpoch ?? 0):X} timed={timed} result=0x{unchecked((uint)result):X8}");
    }

    private static bool ShouldTracePthread()
    {
        return string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_PTHREADS"), "1", StringComparison.Ordinal);
    }
}
