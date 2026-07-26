// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SharpEmu.Core.Cpu.Emulation;
using SharpEmu.Core.Cpu.Native;
using SharpEmu.HLE;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

/// <summary>
/// Coverage for illegal-instruction recovery through the POSIX signal bridge. Tests
/// fabricate the platform signal frames consumed by TryHandlePosixFault and verify
/// that recovered register state is written back exactly as sigreturn would restore it.
/// </summary>
public sealed unsafe class PosixSignalRecoveryTests
{
    private const int PosixSigIll = 4;
    private const uint CarryFlag = 1u << 0;
    private const uint ReservedFlag = 1u << 1;
    private const uint ZeroFlag = 1u << 6;
    private const uint DirectionFlag = 1u << 10;

    private const int DarwinUcontextMcontextOffset = 48;
    private const int DarwinRaxOffset = 16;
    private const int DarwinRipOffset = 144;
    private const int DarwinRflagsOffset = 152;
    private const int LinuxUcontextGregsOffset = 40;
    private const int LinuxGregsRaxOffset = 13 * 8;
    private const int LinuxGregsRipOffset = 16 * 8;
    private const int LinuxGregsRflagsOffset = 17 * 8;
    private const int LinuxGregsFpstateOffset = 184;
    private const int FxsaveXmm0Offset = 160;
    private const int FxsaveXmm1Offset = 176;

    private static readonly MethodInfo TryHandlePosixFault = typeof(DirectExecutionBackend).GetMethod(
        "TryHandlePosixFault",
        BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo PosixSignalBackend = typeof(DirectExecutionBackend).GetField(
        "_posixSignalBackend",
        BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo EmulatedCounter = typeof(DirectExecutionBackend).GetField(
        "_sse4aInstructionsEmulated",
        BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo XmmBridgedFlag = typeof(DirectExecutionBackend).GetField(
        "_posixXmmContextBridged",
        BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo TryRecoverAmdCompat = typeof(DirectExecutionBackend).GetMethod(
        "TryRecoverAmdCompatInstruction",
        BindingFlags.Instance | BindingFlags.NonPublic)!;

    [Fact]
    public void ExtrqSigillRoundTripsXmmThroughTheBridge()
    {
        if (!OperatingSystem.IsLinux() ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return;
        }

        // extrq xmm0, 0x10, 0x08
        var code = AllocateProbeVisibleCode([0x66, 0x0F, 0x78, 0xC0, 0x10, 0x08]);
        try
        {
            const ulong value = 0x1234_5678_9ABC_DEF0UL;
            var frame = new FakeSignalFrame((ulong)code);
            frame.SetXmmLow(FxsaveXmm0Offset, value);
            var emulatedBefore = (long)EmulatedCounter.GetValue(null)!;

            Assert.True(frame.Dispatch());

            Assert.Equal(
                Sse4aBitFieldEmulator.ExtractBitField(value, length: 0x10, index: 0x08),
                frame.XmmLow(FxsaveXmm0Offset));
            Assert.Equal(0UL, frame.XmmHigh(FxsaveXmm0Offset));
            Assert.Equal((ulong)code + 6, frame.Rip);
            Assert.True((long)EmulatedCounter.GetValue(null)! > emulatedBefore);
        }
        finally
        {
            FreeProbeVisibleCode(code);
        }
    }

    [Fact]
    public void InsertqSigillReadsSourceXmmThroughTheBridge()
    {
        if (!OperatingSystem.IsLinux() ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return;
        }

        // insertq xmm0, xmm1, 0x10, 0x08
        var code = AllocateProbeVisibleCode([0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x08]);
        try
        {
            const ulong destination = 0x1111_2222_3333_4444UL;
            const ulong source = 0xAAAA_BBBB_CCCC_DDDDUL;
            var frame = new FakeSignalFrame((ulong)code);
            frame.SetXmmLow(FxsaveXmm0Offset, destination);
            frame.SetXmmLow(FxsaveXmm1Offset, source);

            Assert.True(frame.Dispatch());

            Assert.Equal(
                Sse4aBitFieldEmulator.InsertBitField(destination, source, length: 0x10, index: 0x08),
                frame.XmmLow(FxsaveXmm0Offset));
            Assert.Equal((ulong)code + 6, frame.Rip);
        }
        finally
        {
            FreeProbeVisibleCode(code);
        }
    }

    [Fact]
    public void TzcntSigillRoundTripsEflagsThroughTheBridge()
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return;
        }

        // tzcnt eax, eax
        var code = AllocateProbeVisibleCode([0xF3, 0x0F, 0xBC, 0xC0]);
        try
        {
            var frame = new FakeSignalFrame((ulong)code)
            {
                Rax = 1,
                EFlags = ReservedFlag | CarryFlag | DirectionFlag,
            };

            Assert.True(frame.Dispatch());

            Assert.Equal(0UL, frame.Rax);
            Assert.Equal((ulong)code + 4, frame.Rip);
            Assert.Equal(0u, frame.EFlags & CarryFlag);
            Assert.Equal(ZeroFlag, frame.EFlags & ZeroFlag);
            Assert.Equal(DirectionFlag, frame.EFlags & DirectionFlag);
        }
        finally
        {
            FreeProbeVisibleCode(code);
        }
    }

    [Fact]
    public void RecoveryDeclinesWhenNoXmmStateWasBridged()
    {
        if (!OperatingSystem.IsLinux() ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return;
        }

        // extrq xmm0, 0x10, 0x08 - valid and recoverable, but without bridged XMM state
        // (fpstate missing from the frame) the recovery must decline rather than emulate
        // over the zeroed scratch bytes. Drive the recovery entry directly: earlier tests
        // on this thread leave the thread-static bridge flag set, so clear it the way a
        // fpstate-less capture would.
        var code = AllocateProbeVisibleCode([0x66, 0x0F, 0x78, 0xC0, 0x10, 0x08]);
        try
        {
            XmmBridgedFlag.SetValue(null, false);
            var backend = RuntimeHelpers.GetUninitializedObject(typeof(DirectExecutionBackend));
            var contextRecord = stackalloc byte[0x4D0];

            var recovered = (bool)TryRecoverAmdCompat.Invoke(
                backend,
                [Pointer.Box(contextRecord, typeof(void*)), (ulong)code])!;

            Assert.False(recovered);
        }
        finally
        {
            FreeProbeVisibleCode(code);
        }
    }

    private sealed class FakeSignalFrame
    {
        private readonly byte[] _ucontext = new byte[512];
        private readonly byte[] _mcontext = new byte[512];
        private readonly byte[] _fpstate = new byte[512];
        private readonly bool _wireFpstate;

        public FakeSignalFrame(ulong rip, bool wireFpstate = true)
        {
            _wireFpstate = wireFpstate;
            WriteRegisterU64(PlatformRipOffset, rip);
        }

        public ulong Rax
        {
            get => ReadRegisterU64(PlatformRaxOffset);
            set => WriteRegisterU64(PlatformRaxOffset, value);
        }

        public uint EFlags
        {
            get => ReadRegisterU32(PlatformRflagsOffset);
            set => WriteRegisterU32(PlatformRflagsOffset, value);
        }

        public ulong Rip => ReadRegisterU64(PlatformRipOffset);

        public void SetXmmLow(int fxsaveOffset, ulong value)
        {
            fixed (byte* fpstate = _fpstate)
            {
                *(ulong*)(fpstate + fxsaveOffset) = value;
            }
        }

        public ulong XmmLow(int fxsaveOffset)
        {
            fixed (byte* fpstate = _fpstate)
            {
                return *(ulong*)(fpstate + fxsaveOffset);
            }
        }

        public ulong XmmHigh(int fxsaveOffset)
        {
            fixed (byte* fpstate = _fpstate)
            {
                return *(ulong*)(fpstate + fxsaveOffset + 8);
            }
        }

        public bool Dispatch()
        {
            EnsureBridgeBackend();
            fixed (byte* ucontext = _ucontext)
            fixed (byte* mcontext = _mcontext)
            fixed (byte* fpstate = _fpstate)
            {
                if (OperatingSystem.IsMacOS())
                {
                    *(byte**)(ucontext + DarwinUcontextMcontextOffset) = mcontext;
                }
                else if (_wireFpstate)
                {
                    *(byte**)(ucontext + LinuxUcontextGregsOffset + LinuxGregsFpstateOffset) = fpstate;
                }

                return (bool)TryHandlePosixFault.Invoke(
                    null,
                    [PosixSigIll, (nint)0, (nint)ucontext])!;
            }
        }

        private static int PlatformRaxOffset =>
            OperatingSystem.IsMacOS() ? DarwinRaxOffset : LinuxGregsRaxOffset;

        private static int PlatformRipOffset =>
            OperatingSystem.IsMacOS() ? DarwinRipOffset : LinuxGregsRipOffset;

        private static int PlatformRflagsOffset =>
            OperatingSystem.IsMacOS() ? DarwinRflagsOffset : LinuxGregsRflagsOffset;

        private byte[] RegisterStorage => OperatingSystem.IsMacOS() ? _mcontext : _ucontext;

        private int RegisterBaseOffset => OperatingSystem.IsMacOS() ? 0 : LinuxUcontextGregsOffset;

        private ulong ReadRegisterU64(int offset)
        {
            var storage = RegisterStorage;
            fixed (byte* registers = storage)
            {
                return *(ulong*)(registers + RegisterBaseOffset + offset);
            }
        }

        private uint ReadRegisterU32(int offset)
        {
            var storage = RegisterStorage;
            fixed (byte* registers = storage)
            {
                return *(uint*)(registers + RegisterBaseOffset + offset);
            }
        }

        private void WriteRegisterU64(int offset, ulong value)
        {
            var storage = RegisterStorage;
            fixed (byte* registers = storage)
            {
                *(ulong*)(registers + RegisterBaseOffset + offset) = value;
            }
        }

        private void WriteRegisterU32(int offset, uint value)
        {
            var storage = RegisterStorage;
            fixed (byte* registers = storage)
            {
                *(uint*)(registers + RegisterBaseOffset + offset) = value;
            }
        }
    }

    /// <summary>
    /// TryHandlePosixFault only runs the recovery chain when a backend instance is
    /// registered. The tests do not need any of the constructor's state (and must not run
    /// it: it installs process-wide signal handlers), so register an uninitialized
    /// instance - the SIGILL recovery path only touches static state.
    /// </summary>
    private static void EnsureBridgeBackend()
    {
        if (PosixSignalBackend.GetValue(null) == null)
        {
            PosixSignalBackend.SetValue(
                null,
                RuntimeHelpers.GetUninitializedObject(typeof(DirectExecutionBackend)));
        }
    }

    /// <summary>
    /// The instruction bytes must live in memory the fault-time page probe
    /// (TryReadHostBytes -> VirtualQuery) can see; on POSIX that is HostMemory's shadow
    /// region table, the same allocator guest code pages come from. A raw libc mmap or a
    /// pinned managed array would be invisible and the recovery would decline before
    /// decoding.
    /// </summary>
    private static nint AllocateProbeVisibleCode(ReadOnlySpan<byte> instructions)
    {
        var size = checked((nuint)Environment.SystemPageSize);
        var mapping = (nint)HostMemory.Alloc(
            null,
            size,
            HostMemory.MEM_COMMIT | HostMemory.MEM_RESERVE,
            HostMemory.PAGE_READWRITE);
        Assert.NotEqual((nint)0, mapping);

        instructions.CopyTo(new Span<byte>((void*)mapping, checked((int)size)));
        return mapping;
    }

    private static void FreeProbeVisibleCode(nint mapping)
    {
        Assert.True(HostMemory.Free((void*)mapping, 0, HostMemory.MEM_RELEASE));
    }
}
