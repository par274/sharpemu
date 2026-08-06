// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Iced.Intel;
using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

/// <summary>
/// The VEH trampoline is hand-emitted machine code, so a wrong bit in a REX prefix is a silent
/// hang rather than a compile error. The recursive managed-entry spinlock addressed its lock word
/// through <c>[rcx]</c> instead of <c>[r9]</c> because REX.B was clear, and in a vectored handler
/// <c>rcx</c> is the <c>EXCEPTION_POINTERS*</c> argument - so the compare-exchange tested the
/// exception-record pointer against the free-lock value, never matched, and spun forever with the
/// managed handler never entered.
///
/// These decode the bytes the emitter actually produces rather than asserting on the source, so
/// the guarantee survives any future re-ordering of the emission code.
/// </summary>
public sealed unsafe class VehTrampolineSpinlockEncodingTests
{
    [Fact]
    public void EmittedSpinlockCompareExchangesAgainstTheLockRegisterNotTheHandlerArgument()
    {
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return;
        }

        var exchanges = DecodeTrampoline()
            .Where(instruction => instruction.Mnemonic == Mnemonic.Cmpxchg)
            .ToArray();

        Assert.NotEmpty(exchanges);
        foreach (var exchange in exchanges)
        {
            // The lock pointer is held in r9 for the whole acquire sequence.
            Assert.Equal(OpKind.Memory, exchange.Op0Kind);
            Assert.Equal(Register.R9, exchange.MemoryBase);
            Assert.Equal(Register.R10, exchange.Op1Register);
            Assert.True(exchange.HasLockPrefix, "the acquire must be atomic");
        }
    }

    /// <summary>
    /// Pins the specific encoding, so the failure message names the defect if it ever returns.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0xF0, 0x4D, 0x0F, 0xB1, 0x11 }, "R9")]
    [InlineData(new byte[] { 0xF0, 0x4C, 0x0F, 0xB1, 0x11 }, "RCX")]
    public void RexBSelectsWhichRegisterTheCompareExchangeAddresses(byte[] encoding, string expectedBase)
    {
        var decoder = Decoder.Create(64, encoding);
        var instruction = decoder.Decode();

        Assert.Equal(Mnemonic.Cmpxchg, instruction.Mnemonic);
        Assert.Equal(expectedBase, instruction.MemoryBase.ToString());
    }

    /// <summary>
    /// Builds a trampoline the way SetupExceptionHandler does. The constructor is skipped - it
    /// installs process-wide handlers - and only the fields the emitter reads are supplied.
    /// </summary>
    private static Instruction[] DecodeTrampoline()
    {
        var backend = RuntimeHelpers.GetUninitializedObject(typeof(DirectExecutionBackend));
        SetField(backend, "_vehManagedEntryLock", (nint)0x1000);
        SetField(backend, "_hostRspSlotTlsIndex", uint.MaxValue);

        var create = typeof(DirectExecutionBackend).GetMethod(
            "CreateExceptionHandlerTrampoline",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var trampoline = (nint)create.Invoke(backend, [(nint)0x2000])!;
        Assert.NotEqual((nint)0, trampoline);

        // The emitter seals the page execute-read; re-open it so the decoder can read the bytes.
        var code = new byte[2048];
        Marshal.Copy(trampoline, code, 0, code.Length);

        var decoder = Decoder.Create(64, code);
        decoder.IP = (ulong)trampoline;
        var decoded = new List<Instruction>();
        while (decoder.IP - (ulong)trampoline < (ulong)code.Length)
        {
            decoded.Add(decoder.Decode());
        }

        return [.. decoded];
    }

    private static void SetField(object target, string name, object value) =>
        typeof(DirectExecutionBackend)
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(target, value);
}
