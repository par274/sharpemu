// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

/// <summary>
/// Drives the access-violation recovery for a guest <c>mov reg, fs:[0]</c> that reached the CPU
/// unrewritten, over the exception parameters the OS would supply.
/// </summary>
public sealed class UnpatchedTlsLoadRecoveryTests
{
    private const int CtxRax = 120;
    private const ulong Rip = 0x0000_0008_0028_4106UL;
    private const ulong TlsBase = 0x0000_0008_1234_5000UL;

    /// <summary>Access violation, read, target 0 — what the OS reports for this fault.</summary>
    private const ulong Read = 0;

    /// <summary>
    /// The instruction and the exception parameters from the God of War Ragnarök log, which are
    /// the same in the Minecraft and EA UFC 5 logs.
    /// </summary>
    private static readonly byte[] RealFault =
    [
        0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25,
        0x00, 0x00, 0x00, 0x00,
    ];

    [Fact]
    public void RecoversTheFaultThreeShippingTitlesTerminateOn()
    {
        Assert.True(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            RealFault, Rip, Read, faultAddress: 0, TlsBase,
            out var contextOffset, out var resumeRip, out var register));

        Assert.Equal(0, register);              // rax
        Assert.Equal(CtxRax, contextOffset);
        Assert.Equal(Rip + 12, resumeRip);      // past the whole padded instruction
    }

    /// <summary>
    /// Resuming has to land exactly one instruction on. Short of that the guest re-executes the
    /// load and faults forever; past it, it skips real work.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x64, 0x8B, 0x04, 0x25, 0, 0, 0, 0 }, 8)]
    [InlineData(new byte[] { 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 }, 9)]
    [InlineData(new byte[] { 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 }, 10)]
    [InlineData(new byte[] { 0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 }, 12)]
    public void ResumesExactlyPastTheInstruction(byte[] code, int length)
    {
        Assert.True(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            code, Rip, Read, faultAddress: 0, TlsBase, out _, out var resumeRip, out _));

        Assert.Equal(Rip + (ulong)length, resumeRip);
    }

    /// <summary>
    /// The thread pointer must reach the register the instruction names. Writing the right value
    /// to the wrong register corrupts the guest without crashing it.
    /// </summary>
    [Theory]
    [InlineData(0x48, 0x04, 0, 120)]   // rax
    [InlineData(0x48, 0x0C, 1, 128)]   // rcx
    [InlineData(0x48, 0x14, 2, 136)]   // rdx
    [InlineData(0x48, 0x1C, 3, 144)]   // rbx
    [InlineData(0x48, 0x24, 4, 152)]   // rsp
    [InlineData(0x48, 0x2C, 5, 160)]   // rbp
    [InlineData(0x48, 0x34, 6, 168)]   // rsi
    [InlineData(0x48, 0x3C, 7, 176)]   // rdi
    [InlineData(0x4C, 0x04, 8, 184)]   // r8
    [InlineData(0x4C, 0x2C, 13, 224)]  // r13
    [InlineData(0x4C, 0x3C, 15, 240)]  // r15
    public void TargetsTheContextSlotForTheEncodedRegister(
        byte rex, byte modRm, int expectedRegister, int expectedOffset)
    {
        byte[] code = [0x64, rex, 0x8B, modRm, 0x25, 0x00, 0x00, 0x00, 0x00];

        Assert.True(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            code, Rip, Read, faultAddress: 0, TlsBase,
            out var contextOffset, out _, out var register));

        Assert.Equal(expectedRegister, register);
        Assert.Equal(expectedOffset, contextOffset);
    }

    /// <summary>
    /// A thread with no guest TLS block gets no recovery. Resuming it with a null thread pointer
    /// trades a crash that names the cause for one that happens later somewhere unrelated.
    /// </summary>
    [Fact]
    public void DeclinesWhenTheThreadHasNoGuestTlsBase()
    {
        Assert.False(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            RealFault, Rip, Read, faultAddress: 0, guestTlsBase: 0, out _, out _, out _));
    }

    /// <summary>
    /// A genuine null dereference reaches this handler with identical exception parameters. Only
    /// the instruction bytes separate the two, so anything that is not the load must fall
    /// through and be reported.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x48, 0x8B, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0 })]        // mov rax,[rax]
    [InlineData(new byte[] { 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0, 0, 0, 0, 0 })]     // mov rax,[0] — no FS
    [InlineData(new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0, 0, 0, 0 })]  // GS, not FS
    [InlineData(new byte[] { 0x64, 0x48, 0x89, 0x04, 0x25, 0, 0, 0, 0, 0, 0, 0 })]  // a store
    public void DeclinesFaultsThatOnlyLookLikeTheTlsLoad(byte[] code)
    {
        Assert.False(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            code, Rip, Read, faultAddress: 0, TlsBase, out _, out _, out _));
    }

    /// <summary>
    /// Writes and execute faults are not this instruction, whatever the bytes at RIP decode to.
    /// </summary>
    [Theory]
    [InlineData(1UL)] // write
    [InlineData(8UL)] // execute
    public void DeclinesAccessTypesOtherThanRead(ulong accessType)
    {
        Assert.False(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            RealFault, Rip, accessType, faultAddress: 0, TlsBase, out _, out _, out _));
    }

    /// <summary>
    /// <c>fs:[0]</c> faults at linear address 0 and nowhere else. A fault at any other address is
    /// a different problem that must not be silently resumed.
    /// </summary>
    [Theory]
    [InlineData(0x8UL)]
    [InlineData(0x1000UL)]
    [InlineData(0xFFFF_FFFF_FFFF_FFF0UL)]
    public void DeclinesFaultsAtAnyAddressOtherThanZero(ulong faultAddress)
    {
        Assert.False(DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
            RealFault, Rip, Read, faultAddress, TlsBase, out _, out _, out _));
    }

    /// <summary>
    /// The handler reads a fixed window that can stop at a page boundary mid-instruction. A
    /// truncated decode must decline rather than resume at a wrong offset.
    /// </summary>
    [Fact]
    public void DeclinesATruncatedInstructionWindow()
    {
        for (var take = 0; take < RealFault.Length; take++)
        {
            Assert.False(
                DirectExecutionBackend.TryPlanUnpatchedTlsLoadRecovery(
                    RealFault.AsSpan(0, take), Rip, Read, faultAddress: 0, TlsBase,
                    out _, out _, out _),
                $"recovered from a {take}-byte window");
        }
    }
}
