// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.ShaderCompiler;
using SharpEmu.ShaderCompiler.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// VOP3 opcodes below 0x100 are VOPC compares promoted to the VOP3 encoding,
// which a compiler emits when the compare needs an SGPR-pair destination other
// than VCC. The VOP3 decoder had no entries at all in that range, so any such
// instruction failed to decode and took its whole shader down with it.
// Word layouts: VOP3 is word0[31:26]=0x35, opcode in word0[25:16], vdst in
// word0[7:0], src0/src1 in word1[8:0]/[17:9]; native VOPC is word0[30:25]=0x3E,
// opcode in word0[24:17].
public sealed class Gen5Vop3CompareTests
{
    private const ulong ShaderAddress = 0x1_0000_0000;

    private static uint Vop3(uint opcode, uint vdst) =>
        (0x35u << 26) | ((opcode & 0x3FFu) << 16) | (vdst & 0xFFu);

    private static uint Vop3Sources(uint source0, uint source1) =>
        (source0 & 0x1FFu) | ((source1 & 0x1FFu) << 9);

    [Fact]
    public void Vop3EncodedCompare_DecodesThroughTheSharedVopcTable()
    {
        // V_CMP_LT_U32 s[12:13], v0, v1
        var instruction = DecodeSingle(Vop3(0xC1, 12), Vop3Sources(0x100, 0x101));

        Assert.Equal("VCmpLtU32", instruction.Opcode);
        Assert.Equal(Gen5ShaderEncoding.Vop3, instruction.Encoding);
        Assert.Equal(new[] { Gen5Operand.Scalar(12) }, instruction.Destinations);
        Assert.Equal(Gen5Operand.Vector(0), instruction.Sources[0]);
        Assert.Equal(Gen5Operand.Vector(1), instruction.Sources[1]);
    }

    [Fact]
    public void Vop3EncodedCompareU64_DecodesAsA64BitCompare()
    {
        // V_CMP_GT_U64 s[10:11], v[0:1], v[2:3]. Opcode 0xE4 is the one that
        // killed Ghost of Yotei's cs=0x80003CB200 at pc=0xD8.
        var instruction = DecodeSingle(Vop3(0xE4, 10), Vop3Sources(0x100, 0x102));

        Assert.Equal("VCmpGtU64", instruction.Opcode);
        Assert.Equal(new[] { Gen5Operand.Scalar(10) }, instruction.Destinations);
        Assert.Equal(Gen5Operand.Vector(0), instruction.Sources[0]);
        Assert.Equal(Gen5Operand.Vector(2), instruction.Sources[1]);
    }

    [Fact]
    public void NativeVopcCompare_KeepsItsImplicitVccDestination()
    {
        // V_CMP_GT_U32 vcc, v0, v1 in the native VOPC encoding. This one has no
        // explicit destination operand and must keep writing VCC, so the VOP3
        // destination handling above must not leak into it.
        var instruction = DecodeSingle(
            (0x3Eu << 25) | (0xC4u << 17) | (1u << 9) | 0x100u);

        Assert.Equal("VCmpGtU32", instruction.Opcode);
        Assert.Equal(Gen5ShaderEncoding.Vopc, instruction.Encoding);
        Assert.Empty(instruction.Destinations);
    }

    [Fact]
    public void Vop3EncodedCompareU64_EmitsAnUnsignedGreaterThan()
    {
        // The 64-bit operands come from VGPR pairs, so the emitted compare must
        // be a single 64-bit UGreaterThan, not a pair of 32-bit ones.
        var opcodes = CompileCompute([Vop3(0xE4, 10), Vop3Sources(0x100, 0x102)]);

        Assert.Contains((ushort)SpirvOp.UGreaterThan, opcodes);
    }

    [Fact]
    public void Vop3EncodedCompare_EmitsA32BitCompare()
    {
        var opcodes = CompileCompute([Vop3(0xC1, 12), Vop3Sources(0x100, 0x101)]);

        Assert.Contains((ushort)SpirvOp.ULessThan, opcodes);
    }

    private static Gen5ShaderInstruction DecodeSingle(params uint[] words)
    {
        var memory = new FakeCpuMemory(ShaderAddress, 0x1000);
        var ctx = new CpuContext(memory, Generation.Gen5);
        Gen5ShaderAtomicDecodeTests.WriteProgram(memory, ShaderAddress, words);
        Assert.True(
            Gen5ShaderTranslator.TryCreateState(
                ctx,
                ShaderAddress,
                0,
                new Dictionary<uint, uint>
                {
                    [Gen5ShaderAtomicDecodeTests.ComputePgmRsrc2Register] = 0,
                },
                Gen5ShaderAtomicDecodeTests.ComputeUserDataRegister,
                out var state,
                out var error),
            error);
        return state.Program.Instructions[0];
    }

    private static HashSet<ushort> CompileCompute(uint[] programWords)
    {
        var memory = new FakeCpuMemory(ShaderAddress, 0x2000);
        var ctx = new CpuContext(memory, Generation.Gen5);
        Gen5ShaderAtomicDecodeTests.WriteProgram(memory, ShaderAddress, programWords);
        Assert.True(
            Gen5ShaderTranslator.TryCreateState(
                ctx,
                ShaderAddress,
                0,
                new Dictionary<uint, uint>
                {
                    [Gen5ShaderAtomicDecodeTests.ComputePgmRsrc2Register] = 16u << 1,
                },
                Gen5ShaderAtomicDecodeTests.ComputeUserDataRegister,
                out var state,
                out var error),
            error);
        Assert.True(
            Gen5ShaderScalarEvaluator.TryEvaluate(ctx, state, out var evaluation, out error),
            error);
        Assert.True(
            Gen5SpirvTranslator.TryCompileComputeShader(
                state,
                evaluation,
                1,
                1,
                1,
                out var shader,
                out error),
            error);

        var opcodes = new HashSet<ushort>();
        for (var offset = 20; offset + 4 <= shader.Spirv.Length;)
        {
            var word = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                shader.Spirv.AsSpan(offset, sizeof(uint)));
            var wordCount = (int)(word >> 16);
            if (wordCount == 0)
            {
                break;
            }

            opcodes.Add((ushort)(word & 0xFFFF));
            offset += wordCount * sizeof(uint);
        }

        return opcodes;
    }
}
