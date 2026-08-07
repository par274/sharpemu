// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using SharpEmu.Core.Cpu.Emulation;
using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

/// <summary>
/// Covers the decoder shared by the load-time TLS patcher and the access-violation fallback that
/// finishes a <c>mov reg, fs:[0]</c> the patcher did not reach.
/// </summary>
public sealed class TlsThreadPointerLoadTests
{
    /// <summary>
    /// The instruction God of War Ragnarök, EA UFC 5 and Minecraft all die on, byte for byte.
    /// LLVM's TLS general-dynamic relaxation leaves three operand-size prefixes in front.
    /// </summary>
    [Fact]
    public void DecodesTheInstructionShippingTitlesActuallyFaultOn()
    {
        byte[] code =
        [
            0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25,
            0x00, 0x00, 0x00, 0x00,
        ];

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out var register, out var length));
        Assert.Equal(0, register); // rax
        Assert.Equal(12, length);
    }

    /// <summary>Unpadded <c>mov rax, fs:[0]</c> — no prefixes, still the same instruction.</summary>
    [Fact]
    public void DecodesTheUnpaddedForm()
    {
        byte[] code = [0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00];

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out var register, out var length));
        Assert.Equal(0, register);
        Assert.Equal(9, length);
    }

    /// <summary>No REX at all: <c>mov eax, fs:[0]</c> is eight bytes.</summary>
    [Fact]
    public void DecodesTheFormWithNoRexByte()
    {
        byte[] code = [0x64, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00];

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out var register, out var length));
        Assert.Equal(0, register);
        Assert.Equal(8, length);
    }

    /// <summary>
    /// The destination comes from ModRM.reg extended by REX.R. Getting this wrong writes the
    /// thread pointer into the wrong register, which corrupts the guest silently rather than
    /// crashing it.
    /// </summary>
    [Theory]
    [InlineData(0x48, 0x04, 0)]  //             rax
    [InlineData(0x48, 0x0C, 1)]  //             rcx
    [InlineData(0x48, 0x14, 2)]  //             rdx
    [InlineData(0x48, 0x1C, 3)]  //             rbx
    [InlineData(0x48, 0x24, 4)]  //             rsp
    [InlineData(0x48, 0x2C, 5)]  //             rbp
    [InlineData(0x48, 0x34, 6)]  //             rsi
    [InlineData(0x48, 0x3C, 7)]  //             rdi
    [InlineData(0x4C, 0x04, 8)]  // REX.R set → r8
    [InlineData(0x4C, 0x2C, 13)] // REX.R set → r13
    [InlineData(0x4C, 0x3C, 15)] // REX.R set → r15
    public void ExtractsTheDestinationRegisterFromModRmAndRex(byte rex, byte modRm, int expected)
    {
        byte[] code = [0x64, rex, 0x8B, modRm, 0x25, 0x00, 0x00, 0x00, 0x00];

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out var register, out var length));
        Assert.Equal(expected, register);
        Assert.Equal(9, length);
    }

    /// <summary>
    /// Only offset 0 is the thread pointer. A non-zero displacement is a different TLS access
    /// whose value is not the base, so accepting it would resume the guest with a wrong value —
    /// worse than the fault it replaces.
    /// </summary>
    [Fact]
    public void RejectsANonZeroDisplacement()
    {
        byte[] code = [0x64, 0x48, 0x8B, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00];

        Assert.False(TlsThreadPointerLoad.TryDecode(code, out _, out _));
    }

    [Theory]
    [InlineData(new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 })]       // GS, not FS
    [InlineData(new byte[] { 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0, 0 })]          // no segment override
    [InlineData(new byte[] { 0x64, 0x48, 0x89, 0x04, 0x25, 0, 0, 0, 0 })]       // store, not load
    [InlineData(new byte[] { 0x64, 0x48, 0x8B, 0x44, 0x25, 0, 0, 0, 0 })]       // mod=01, not mod=00
    [InlineData(new byte[] { 0x64, 0x48, 0x8B, 0x00, 0x25, 0, 0, 0, 0 })]       // rm=000, no SIB
    [InlineData(new byte[] { 0x64, 0x48, 0x8B, 0x04, 0x24, 0, 0, 0, 0 })]       // SIB names a base
    [InlineData(new byte[] { 0x64, 0xC7, 0x04, 0x25, 0, 0, 0, 0, 0 })]          // immediate TLS store
    public void RejectsInstructionsThatAreNotAThreadPointerLoad(byte[] code)
    {
        Assert.False(TlsThreadPointerLoad.TryDecode(code, out _, out _));
    }

    /// <summary>
    /// The handler reads a fixed-size window that can end mid-instruction at a page boundary.
    /// Every truncation must be rejected rather than read past the end.
    /// </summary>
    [Fact]
    public void RejectsEveryTruncationOfAValidInstruction()
    {
        byte[] code =
        [
            0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25,
            0x00, 0x00, 0x00, 0x00,
        ];

        for (var take = 0; take < code.Length; take++)
        {
            Assert.False(
                TlsThreadPointerLoad.TryDecode(code.AsSpan(0, take), out _, out _),
                $"accepted a {take}-byte prefix of a {code.Length}-byte instruction");
        }

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out _, out _));
    }

    /// <summary>An empty window must not fault.</summary>
    [Fact]
    public void RejectsAnEmptyWindow()
    {
        Assert.False(TlsThreadPointerLoad.TryDecode(ReadOnlySpan<byte>.Empty, out _, out _));
    }

    /// <summary>Trailing bytes after the instruction are the next instruction, not a mismatch.</summary>
    [Fact]
    public void ReportsOnlyTheLengthOfTheLoadItself()
    {
        byte[] code =
        [
            0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25,
            0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0D, 0x00,
        ];

        Assert.True(TlsThreadPointerLoad.TryDecode(code, out _, out var length));
        Assert.Equal(12, length);
    }

    /// <summary>
    /// The fault handler writes the recovered thread pointer with
    /// <c>CTX_RAX + 8 * destinationRegister</c>. That shortcut is only valid because the Win64
    /// CONTEXT stores its integer registers in x86 encoding order; if a future edit reorders the
    /// offsets, the recovery would write the value into the wrong register — including RSP.
    /// </summary>
    [Fact]
    public void ContextOffsetsAreLaidOutInEncodingOrderFromRax()
    {
        string[] encodingOrder =
        [
            "CTX_RAX", "CTX_RCX", "CTX_RDX", "CTX_RBX",
            "CTX_RSP", "CTX_RBP", "CTX_RSI", "CTX_RDI",
            "CTX_R8", "CTX_R9", "CTX_R10", "CTX_R11",
            "CTX_R12", "CTX_R13", "CTX_R14", "CTX_R15",
        ];

        var baseOffset = ContextOffset("CTX_RAX");
        for (var register = 0; register < encodingOrder.Length; register++)
        {
            Assert.Equal(baseOffset + (8 * register), ContextOffset(encodingOrder[register]));
        }
    }

    private static int ContextOffset(string name) => (int)typeof(DirectExecutionBackend)
        .GetField(name, BindingFlags.Static | BindingFlags.NonPublic)!
        .GetRawConstantValue()!;
}
