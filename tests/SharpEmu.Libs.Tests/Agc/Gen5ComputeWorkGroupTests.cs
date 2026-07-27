// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.ShaderCompiler;
using SharpEmu.ShaderCompiler.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// GCN allows up to 1024 threads on a single workgroup axis; Vulkan devices
// routinely cap Y/Z much lower, so a legal guest workgroup such as 1x1x256 has
// no host equivalent and its dispatch was dropped outright. The translator can
// declare such a workgroup flat and unpack the guest's x/y/z from the linear
// invocation index instead. These tests pin both the declared shape and the
// fact that an ordinary workgroup is left completely alone.
public sealed class Gen5ComputeWorkGroupTests
{
    private const ulong ShaderAddress = 0x1_0000_0000;
    private const ushort OpExecutionMode = 16;
    private const uint LocalSizeExecutionMode = 17;

    [Fact]
    public void OrdinaryWorkGroup_DeclaresTheGuestShapeUnchanged()
    {
        var spirv = CompileCompute(8, 8, 1, linearizeWorkGroup: false);

        Assert.Equal((8u, 8u, 1u), ReadDeclaredLocalSize(spirv));
    }

    [Fact]
    public void LinearizedWorkGroup_DeclaresAFlatWorkGroupOfTheSameSize()
    {
        // 1x1x256 is the shape that no host workgroup can express here; the
        // declared shape must carry the same 256 invocations on one axis.
        var spirv = CompileCompute(1, 1, 256, linearizeWorkGroup: true);

        Assert.Equal((256u, 1u, 1u), ReadDeclaredLocalSize(spirv));
    }

    [Fact]
    public void LinearizedWorkGroup_UnpacksTheGuestAxesFromTheLinearIndex()
    {
        // A shape with more than one non-trivial axis has to divide and wrap to
        // recover the guest coordinates; 1x1x256 alone would not exercise that
        // because both of its leading axes fold away to a constant zero.
        var spirv = CompileCompute(4, 2, 32, linearizeWorkGroup: true);
        var opcodes = CollectOpcodes(spirv);

        Assert.Equal((256u, 1u, 1u), ReadDeclaredLocalSize(spirv));
        Assert.Contains((ushort)SpirvOp.UDiv, opcodes);
        Assert.Contains((ushort)SpirvOp.UMod, opcodes);
    }

    [Fact]
    public void LinearizedWorkGroup_WithSingleWideAxesEmitsNoDivision()
    {
        // Every leading axis is 1, so each guest coordinate is either a
        // constant zero or the linear index itself. Emitting a division here
        // would be pure waste on the hottest path in the shader.
        var opcodes = CollectOpcodes(CompileCompute(1, 1, 256, linearizeWorkGroup: true));

        Assert.DoesNotContain((ushort)SpirvOp.UDiv, opcodes);
        Assert.DoesNotContain((ushort)SpirvOp.UMod, opcodes);
    }

    private static (uint X, uint Y, uint Z) ReadDeclaredLocalSize(byte[] spirv)
    {
        for (var offset = 20; offset + 4 <= spirv.Length;)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(
                spirv.AsSpan(offset, sizeof(uint)));
            var wordCount = (int)(word >> 16);
            if (wordCount == 0)
            {
                break;
            }

            if ((ushort)(word & 0xFFFF) == OpExecutionMode &&
                wordCount == 6 &&
                ReadWord(spirv, offset + 8) == LocalSizeExecutionMode)
            {
                return (
                    ReadWord(spirv, offset + 12),
                    ReadWord(spirv, offset + 16),
                    ReadWord(spirv, offset + 20));
            }

            offset += wordCount * sizeof(uint);
        }

        Assert.Fail("no LocalSize execution mode in the emitted module");
        return default;
    }

    private static uint ReadWord(byte[] spirv, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(spirv.AsSpan(offset, sizeof(uint)));

    private static HashSet<ushort> CollectOpcodes(byte[] spirv)
    {
        var opcodes = new HashSet<ushort>();
        for (var offset = 20; offset + 4 <= spirv.Length;)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(
                spirv.AsSpan(offset, sizeof(uint)));
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

    private static byte[] CompileCompute(
        uint localSizeX,
        uint localSizeY,
        uint localSizeZ,
        bool linearizeWorkGroup)
    {
        var memory = new FakeCpuMemory(ShaderAddress, 0x2000);
        var ctx = new CpuContext(memory, Generation.Gen5);
        // V_MOV_B32 v0, v1 so the module has a body that reads a VGPR the
        // local-invocation setup wrote.
        Gen5ShaderAtomicDecodeTests.WriteProgram(memory, ShaderAddress, [0x7E000301]);
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
                localSizeX,
                localSizeY,
                localSizeZ,
                out var shader,
                out error,
                linearizeWorkGroup: linearizeWorkGroup),
            error);
        return shader.Spirv;
    }
}
