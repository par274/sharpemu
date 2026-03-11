// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;
using System.Text;
using System.Threading;

namespace SharpEmu.Libs.Kernel;

public static class KernelPthreadExtendedCompatExports
{
    private const int DefaultThreadPriority = 700;
    private const ulong DefaultThreadAffinityMask = ulong.MaxValue;
    private const int DefaultDetachState = 0;
    private const ulong DefaultGuardSize = 0x1000UL;
    private const ulong DefaultStackSize = 0x1_00000UL;
    private const int DefaultInheritSched = 0;
    private const int DefaultSchedPolicy = 0;
    private const int DefaultSchedPriority = 0;

    private static readonly object _stateGate = new();
    private static readonly Dictionary<ulong, ThreadState> _threadStates = new();
    private static readonly Dictionary<ulong, PthreadAttrState> _attrStates = new();
    private static readonly Dictionary<ulong, ReaderWriterLockSlim> _rwlockStates = new();
    private static readonly Dictionary<int, TlsKeyState> _tlsKeys = new();
    private static int _nextTlsKey = 1;

    [ThreadStatic]
    private static Dictionary<int, ulong>? _threadLocalSpecific;

    private sealed class ThreadState
    {
        public string Name { get; set; } = string.Empty;
        public int Priority { get; set; } = DefaultThreadPriority;
        public ulong AffinityMask { get; set; } = DefaultThreadAffinityMask;
        public int DetachState { get; set; } = DefaultDetachState;
        public PthreadAttrState Attributes { get; set; } = PthreadAttrState.Default;
    }

    private readonly record struct TlsKeyState(ulong Destructor);

    private readonly record struct PthreadAttrState(
        ulong AffinityMask,
        int DetachState,
        ulong StackAddress,
        ulong StackSize,
        ulong GuardSize,
        int InheritSched,
        int SchedPolicy,
        int SchedPriority)
    {
        public static PthreadAttrState Default =>
            new(
                DefaultThreadAffinityMask,
                DefaultDetachState,
                0,
                DefaultStackSize,
                DefaultGuardSize,
                DefaultInheritSched,
                DefaultSchedPolicy,
                DefaultSchedPriority);
    }

    [SysAbiExport(
        Nid = "4qGrR6eoP9Y",
        ExportName = "scePthreadDetach",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadDetach(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.DetachState = 1;
            state.Attributes = state.Attributes with { DetachState = 1 };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "How7B8Oet6k",
        ExportName = "scePthreadGetname",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetname(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outNameAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outNameAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        string name;
        lock (_stateGate)
        {
            name = GetOrCreateThreadStateLocked(thread).Name;
        }

        if (!TryWriteFixedUtf8CString(ctx, outNameAddress, name, 32))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "bt3CTBKmGyI",
        ExportName = "scePthreadSetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetaffinity(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var mask = ctx[CpuRegister.Rsi];
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.AffinityMask = mask;
            state.Attributes = state.Attributes with { AffinityMask = mask };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "1tKyG7RlMJo",
        ExportName = "scePthreadGetprio",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetprio(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outPriorityAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outPriorityAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        int priority;
        lock (_stateGate)
        {
            priority = GetOrCreateThreadStateLocked(thread).Priority;
        }

        if (!TryWriteInt32(ctx, outPriorityAddress, priority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((uint)priority);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "W0Hpm2X0uPE",
        ExportName = "scePthreadSetprio",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetprio(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var priority = unchecked((int)ctx[CpuRegister.Rsi]);
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            GetOrCreateThreadStateLocked(thread).Priority = priority;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "nsYoNRywwNg",
        ExportName = "scePthreadAttrInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrInit(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _attrStates[attrAddress] = PthreadAttrState.Default;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "62KCwEMmzcM",
        ExportName = "scePthreadAttrDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrDestroy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            _attrStates.Remove(attrAddress);
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "x1X76arYMxU",
        ExportName = "scePthreadAttrGet",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGet(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outAttrAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outAttrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var threadState = GetOrCreateThreadStateLocked(thread);
            _attrStates[outAttrAddress] = threadState.Attributes;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "8+s5BzZjxSg",
        ExportName = "scePthreadAttrGetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetaffinity(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outMaskAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outMaskAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outMaskAddress, state.AffinityMask))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.AffinityMask;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "JaRMy+QcpeU",
        ExportName = "scePthreadAttrGetdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetdetachstate(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStateAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStateAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!TryWriteInt32(ctx, outStateAddress, state.DetachState))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((uint)state.DetachState);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "txHtngJ+eyc",
        ExportName = "scePthreadAttrGetguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetguardsize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outGuardSizeAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outGuardSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outGuardSizeAddress, state.GuardSize))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.GuardSize;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ru36fiTtJzA",
        ExportName = "scePthreadAttrGetstackaddr",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstackaddr(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStackAddressPointer = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStackAddressPointer == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outStackAddressPointer, state.StackAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.StackAddress;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "-fA+7ZlGDQs",
        ExportName = "scePthreadAttrGetstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstacksize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStackSizeAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStackSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outStackSizeAddress, state.StackSize))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.StackSize;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "3qxgM4ezETA",
        ExportName = "scePthreadAttrSetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetaffinity(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var mask = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { AffinityMask = mask };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "-Wreprtu0Qs",
        ExportName = "scePthreadAttrSetdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetdetachstate(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var detachState = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { DetachState = detachState };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "El+cQ20DynU",
        ExportName = "scePthreadAttrSetguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetguardsize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var guardSize = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { GuardSize = guardSize };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "eXbUSpEaTsA",
        ExportName = "scePthreadAttrSetinheritsched",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetinheritsched(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var inheritSched = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { InheritSched = inheritSched };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "DzES9hQF4f4",
        ExportName = "scePthreadAttrSetschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedparam(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var schedParamAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || schedParamAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryReadInt32(ctx, schedParamAddress, out var schedPriority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { SchedPriority = schedPriority };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "4+h9EzwKF4I",
        ExportName = "scePthreadAttrSetschedpolicy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedpolicy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var policy = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { SchedPolicy = policy };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "UTXzJbWhhTE",
        ExportName = "scePthreadAttrSetstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetstacksize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var stackSize = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { StackSize = stackSize };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6ULAa0fq4jA",
        ExportName = "scePthreadRwlockInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockInit(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            if (_rwlockStates.Remove(rwlockAddress, out var existing))
            {
                existing.Dispose();
            }

            _rwlockStates[rwlockAddress] = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "BB+kb08Tl9A",
        ExportName = "scePthreadRwlockDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockDestroy(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        ReaderWriterLockSlim? state;
        lock (_stateGate)
        {
            _rwlockStates.Remove(rwlockAddress, out state);
        }

        if (state is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        state.Dispose();
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ox9i0c7L5w0",
        ExportName = "scePthreadRwlockRdlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockRdlock(CpuContext ctx) => PthreadRwlockLockCore(ctx[CpuRegister.Rdi], write: false);

    [SysAbiExport(
        Nid = "mqdNorrB+gI",
        ExportName = "scePthreadRwlockWrlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockWrlock(CpuContext ctx) => PthreadRwlockLockCore(ctx[CpuRegister.Rdi], write: true);

    [SysAbiExport(
        Nid = "+L98PIbGttk",
        ExportName = "scePthreadRwlockUnlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockUnlock(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        ReaderWriterLockSlim? rwlock;
        lock (_stateGate)
        {
            _rwlockStates.TryGetValue(rwlockAddress, out rwlock);
        }

        if (rwlock is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        try
        {
            if (rwlock.IsWriteLockHeld)
            {
                rwlock.ExitWriteLock();
            }
            else if (rwlock.IsReadLockHeld)
            {
                rwlock.ExitReadLock();
            }
            else
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }
        }
        catch (SynchronizationLockException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "mqULNdimTn0",
        ExportName = "pthread_key_create",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadKeyCreate(CpuContext ctx)
    {
        var outKeyAddress = ctx[CpuRegister.Rdi];
        var destructor = ctx[CpuRegister.Rsi];
        if (outKeyAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        int key;
        lock (_stateGate)
        {
            while (_tlsKeys.ContainsKey(_nextTlsKey))
            {
                _nextTlsKey++;
            }

            key = _nextTlsKey++;
            _tlsKeys[key] = new TlsKeyState(destructor);
        }

        if (!TryWriteInt32(ctx, outKeyAddress, key))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((uint)key);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6BpEZuDT7YI",
        ExportName = "pthread_key_delete",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadKeyDelete(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        lock (_stateGate)
        {
            if (!_tlsKeys.Remove(key))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }
        }

        _threadLocalSpecific?.Remove(key);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "WrOLvHU0yQM",
        ExportName = "pthread_setspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadSetspecific(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        var value = ctx[CpuRegister.Rsi];
        lock (_stateGate)
        {
            if (!_tlsKeys.TryGetValue(key, out _))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }
        }

        _threadLocalSpecific ??= new Dictionary<int, ulong>();
        _threadLocalSpecific[key] = value;
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "0-KXaS70xy4",
        ExportName = "pthread_getspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadGetspecific(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        lock (_stateGate)
        {
            if (!_tlsKeys.TryGetValue(key, out _))
            {
                ctx[CpuRegister.Rax] = 0;
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }
        }

        ctx[CpuRegister.Rax] =
            _threadLocalSpecific is not null && _threadLocalSpecific.TryGetValue(key, out var value)
                ? value
                : 0UL;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int PthreadRwlockLockCore(ulong rwlockAddress, bool write)
    {
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        ReaderWriterLockSlim rwlock;
        lock (_stateGate)
        {
            if (!_rwlockStates.TryGetValue(rwlockAddress, out rwlock!))
            {
                rwlock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);
                _rwlockStates[rwlockAddress] = rwlock;
            }
        }

        try
        {
            if (write)
            {
                rwlock.EnterWriteLock();
            }
            else
            {
                rwlock.EnterReadLock();
            }
        }
        catch (LockRecursionException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_ALREADY_EXISTS;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static ThreadState GetOrCreateThreadStateLocked(ulong thread)
    {
        if (_threadStates.TryGetValue(thread, out var state))
        {
            return state;
        }

        state = new ThreadState
        {
            Name = $"Thread-{thread:X}",
            Priority = DefaultThreadPriority,
            AffinityMask = DefaultThreadAffinityMask,
            DetachState = DefaultDetachState,
            Attributes = PthreadAttrState.Default,
        };
        _threadStates[thread] = state;
        return state;
    }

    private static PthreadAttrState GetOrCreateAttrStateLocked(ulong attrAddress)
    {
        if (_attrStates.TryGetValue(attrAddress, out var state))
        {
            return state;
        }

        state = PthreadAttrState.Default;
        _attrStates[attrAddress] = state;
        return state;
    }

    private static bool TryWriteFixedUtf8CString(CpuContext ctx, ulong address, string value, int maxBytes)
    {
        if (maxBytes <= 0)
        {
            return false;
        }

        var utf8 = Encoding.UTF8.GetBytes(value);
        var payloadLength = Math.Min(utf8.Length, maxBytes - 1);
        var payload = new byte[payloadLength + 1];
        utf8.AsSpan(0, payloadLength).CopyTo(payload);
        payload[^1] = 0;
        return ctx.Memory.TryWrite(address, payload);
    }

    private static bool TryReadInt32(CpuContext ctx, ulong address, out int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        if (!ctx.Memory.TryRead(address, bytes))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        return true;
    }

    private static bool TryWriteInt32(CpuContext ctx, ulong address, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return ctx.Memory.TryWrite(address, bytes);
    }
}
