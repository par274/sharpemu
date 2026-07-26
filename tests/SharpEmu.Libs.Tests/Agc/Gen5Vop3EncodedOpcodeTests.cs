// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.ShaderCompiler;
using SharpEmu.ShaderCompiler.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// GFX10 re-encodes VOP1, VOP2 and VOPC instructions in VOP3 form whenever they need
// source modifiers, clamp/omod, an SGPR src1, or a compare destination other than VCC.
// These lock the opcode-space mapping (VOPC at 0x000, VOP2 at 0x100, VOP1 at 0x180) and
// the VOPC-specific detail that the vdst byte is an SGPR pair, not a VGPR.
//
// Word layout (VOP3A): word0 [31:26]=0x35, [25:16]=op, [15]=clamp, [14:11]=op_sel,
// [10:8]=abs, [7:0]=vdst/sdst; word1 [8:0]=src0, [17:9]=src1, [26:18]=src2,
// [28:27]=omod, [31:29]=neg. Register operands encode VGPR n as 256+n.
public sealed class Gen5Vop3EncodedOpcodeTests
{
    private const ulong ShaderAddress = 0x1_0000_0000;
    private const uint Vop3 = 0xD400_0000;
    private const uint V0 = 0x100;
    private const uint V1 = 0x101;

    [Fact]
    public void Vop3EncodedCompare_KeepsVopcNameAndWritesScalarDestination()
    {
        // v_cmp_lt_f32_e64 s[10:11], v0, v1 - VOPC op 0x01 sits at VOP3 op 0x001.
        var instruction = DecodeSingle(Vop3 | (0x001u << 16) | 10u, V0 | (V1 << 9));

        Assert.Equal("VCmpLtF32", instruction.Opcode);
        Assert.Equal(Gen5ShaderEncoding.Vop3, instruction.Encoding);

        // The whole reason a compare takes the VOP3 form is usually that the result
        // goes somewhere other than VCC, so the destination must survive as an SGPR.
        var destination = Assert.Single(instruction.Destinations);
        Assert.Equal(Gen5OperandKind.ScalarRegister, destination.Kind);
        Assert.Equal(10u, destination.Value);
    }

    [Fact]
    public void Vop3EncodedVop1_KeepsVop1NameAndVectorDestination()
    {
        // v_rcp_f32_e64 v1, -v0 - VOP1 op 0x2A sits at VOP3 op 0x1AA, neg bit set.
        var instruction = DecodeSingle(Vop3 | (0x1AAu << 16) | 1u, V0 | (1u << 29));

        Assert.Equal("VRcpF32", instruction.Opcode);
        Assert.Equal(new[] { Gen5Operand.Vector(1) }, instruction.Destinations);

        var control = Assert.IsType<Gen5Vop3Control>(instruction.Control);
        Assert.Equal(1u, control.NegateMask);
    }

    [Fact]
    public void Vop3EncodedVop2_KeepsVop2NameAndAcceptsScalarSource1()
    {
        // v_sub_f32_e64 v2, v0, s3 - VOP2 op 0x04 sits at VOP3 op 0x104. An SGPR in
        // src1 is exactly the case the compact VOP2 encoding cannot express.
        var instruction = DecodeSingle(Vop3 | (0x104u << 16) | 2u, V0 | (3u << 9));

        Assert.Equal("VSubF32", instruction.Opcode);
        Assert.Equal(new[] { Gen5Operand.Vector(2) }, instruction.Destinations);
        Assert.Equal(Gen5Operand.Source(3), instruction.Sources[1]);
    }

    [Fact]
    public void Vop3OnlyOpcodes_AreNotShadowedByTheReEncodingRanges()
    {
        // VOP2 is a 6-bit opcode, so the re-encoding window stops at 0x13F and 0x141
        // stays V_MAD_F32 rather than being read as a VOP2.
        Assert.Equal("VMadF32", DecodeSingle(Vop3 | (0x141u << 16), V0).Opcode);
        Assert.Equal("VMulHiI32", DecodeSingle(Vop3 | (0x16Cu << 16), V0).Opcode);
    }

    [Fact]
    public void Vop3EncodedCompares_CompileToSpirvComparisons()
    {
        // v_cmp_lt_f32_e64 s[10:11], v0, v1 ; v_cmp_ge_u32_e64 s[12:13], v0, v1
        // Before the VOP3 opcode ranges were decoded these bailed out of translation
        // with "unsupported vector opcode Vop3Raw001", failing the whole draw.
        var opcodes = CompileCompute(
        [
            Vop3 | (0x001u << 16) | 10u, V0 | (V1 << 9),
            Vop3 | (0x0C6u << 16) | 12u, V0 | (V1 << 9),
        ]);

        Assert.Contains((ushort)SpirvOp.FOrdLessThan, opcodes);
        Assert.Contains((ushort)SpirvOp.UGreaterThanEqual, opcodes);
    }

    [Fact]
    public void Vop3EncodedVop1AndVop2_CompileToSpirvArithmetic()
    {
        // v_rcp_f32_e64 v1, v0 ; v_sub_f32_e64 v2, v0, v1
        var opcodes = CompileCompute(
        [
            Vop3 | (0x1AAu << 16) | 1u, V0,
            Vop3 | (0x104u << 16) | 2u, V0 | (V1 << 9),
        ]);

        // V_RCP_F32 lowers to a reciprocal divide rather than a GLSL extended
        // instruction, so the divide is what proves it reached the emitter.
        Assert.Contains((ushort)SpirvOp.FSub, opcodes);
        Assert.Contains((ushort)SpirvOp.FDiv, opcodes);
    }

    [Fact]
    public void AlwaysFalseAndAlwaysTrueIntegerCompares_CompileInBothCmpAndCmpxForms()
    {
        // v_cmpx_f_i32_e64 / v_cmpx_t_u32_e64 - the VCMPX halves of the constant
        // compares. Only the VCMP halves were handled, so these failed translation.
        var opcodes = CompileCompute(
        [
            Vop3 | (0x090u << 16), V0 | (V1 << 9),
            Vop3 | (0x0D7u << 16), V0 | (V1 << 9),
        ]);

        Assert.NotEmpty(opcodes);
    }

    private static Gen5ShaderInstruction DecodeSingle(params uint[] words)
    {
        var state = CreateState(words);
        return state.Program.Instructions[0];
    }

    private static Gen5ShaderState CreateState(uint[] words)
    {
        var memory = new FakeCpuMemory(ShaderAddress, 0x2000);
        var ctx = new CpuContext(memory, Generation.Gen5);
        Gen5ShaderAtomicDecodeTests.WriteProgram(memory, ShaderAddress, words);
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
        return state;
    }

    private static HashSet<ushort> CompileCompute(uint[] words)
    {
        var memory = new FakeCpuMemory(ShaderAddress, 0x2000);
        var ctx = new CpuContext(memory, Generation.Gen5);
        Gen5ShaderAtomicDecodeTests.WriteProgram(memory, ShaderAddress, words);
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
        for (var offset = 5 * sizeof(uint); offset + sizeof(uint) <= shader.Spirv.Length;)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(
                shader.Spirv.AsSpan(offset, sizeof(uint)));
            opcodes.Add((ushort)word);
            offset += Math.Max((int)(word >> 16), 1) * sizeof(uint);
        }

        return opcodes;
    }
}
