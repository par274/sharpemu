// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

public sealed class TlsLoadPatchBoundaryTests
{
    [Fact]
    public void RejectsGtaShortJumpDisplacementAsTlsPrefix()
    {
        byte[] code =
        [
            0x90,
            0xEB, 0x66,
            0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];

        Assert.True(DirectExecutionBackend.IsTlsLoadCandidateInsideShortJump(code, candidateOffset: 2));
        Assert.False(DirectExecutionBackend.IsTlsLoadCandidateInsideShortJump(code, candidateOffset: 3));
    }

    [Fact]
    public void KeepsDreamingSarahTlsInstructionAfterBackwardJnz()
    {
        byte[] code =
        [
            0x48, 0x8B, 0x1C, 0xD0,
            0x4C, 0x39, 0x2B,
            0x0F, 0x84, 0x10, 0x01, 0x00, 0x00,
            0x48, 0xFF, 0xC2,
            0x48, 0x39, 0xD1,
            0x75, 0xEB,
            0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];

        Assert.False(DirectExecutionBackend.IsTlsLoadCandidateInsideShortJump(code, candidateOffset: 21));
    }

    [Theory]
    [InlineData(0x70)]
    [InlineData(0x7F)]
    [InlineData(0xE0)]
    [InlineData(0xE3)]
    [InlineData(0xEB)]
    public void KeepsTlsInstructionAfterRel8ControlFlow(byte opcode)
    {
        byte[] code =
        [
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            opcode, 0xEB,
            0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];

        Assert.False(DirectExecutionBackend.IsTlsLoadCandidateInsideShortJump(code, candidateOffset: 21));
    }

    [Fact]
    public void Rel8OpcodeByteInsidePreviousInstructionDoesNotBypassGuard()
    {
        byte[] code =
        [
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x6A, 0x75,
            0xEB, 0x66,
            0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];

        Assert.True(DirectExecutionBackend.IsTlsLoadCandidateInsideShortJump(code, candidateOffset: 21));
    }
}
