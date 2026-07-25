// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.Libs.Agc;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

public sealed class AgcIndirectDrawTests
{
    private const ulong BaseAddress = 0x1_0000_0000;
    private const ulong CommandBufferAddress = BaseAddress + 0x100;
    private const ulong PacketAddress = BaseAddress + 0x400;

    [Fact]
    public void DcbDrawIndirect_EmitsGen5PacketLayout()
    {
        var memory = CreateMemory(out var ctx);
        const ulong modifier =
            (3ul << 29) |
            (5ul << 9) |
            (7ul << 19) |
            0x105ul;

        ctx[CpuRegister.Rdi] = CommandBufferAddress;
        ctx[CpuRegister.Rsi] = 0x120;
        ctx[CpuRegister.Rdx] = modifier;

        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_OK,
            AgcExports.DcbDrawIndirect(ctx));
        Assert.Equal(PacketAddress, ctx[CpuRegister.Rax]);
        Assert.Equal(0xC003_2400u, ReadUInt32(memory, PacketAddress));
        Assert.Equal(0x120u, ReadUInt32(memory, PacketAddress + 4));
        Assert.Equal(0x111u, ReadUInt32(memory, PacketAddress + 8));
        Assert.Equal(0x113u, ReadUInt32(memory, PacketAddress + 12));
        Assert.Equal(0x22u, ReadUInt32(memory, PacketAddress + 16));
        Assert.Equal(PacketAddress + 20, ReadUInt64(memory, CommandBufferAddress + 0x10));
    }

    [Fact]
    public void DcbDrawIndexIndirect_DecodesIndexedPatchLocations()
    {
        var memory = CreateMemory(out var ctx);
        const ulong modifier =
            (1ul << 32) |
            (3ul << 29) |
            (7ul << 19) |
            (9ul << 14) |
            (5ul << 9) |
            0x7ul;

        ctx[CpuRegister.Rdi] = CommandBufferAddress;
        ctx[CpuRegister.Rsi] = 0x80;
        ctx[CpuRegister.Rdx] = modifier;

        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_OK,
            AgcExports.DcbDrawIndexIndirect(ctx));
        Assert.Equal(0xC003_2500u, ReadUInt32(memory, PacketAddress));
        Assert.Equal(0x80u, ReadUInt32(memory, PacketAddress + 4));
        Assert.Equal(0x0115_0111u, ReadUInt32(memory, PacketAddress + 8));
        Assert.Equal(0x0800_0113u, ReadUInt32(memory, PacketAddress + 12));
        Assert.Equal(2u, ReadUInt32(memory, PacketAddress + 16));
    }

    [Fact]
    public void IndirectDrawSizes_AreFiveDwords()
    {
        var memory = new FakeCpuMemory(BaseAddress, 0x1000);
        var ctx = new CpuContext(memory, Generation.Gen5);

        Assert.Equal(20, AgcExports.DcbDrawIndirectGetSize(ctx));
        Assert.Equal(20ul, ctx[CpuRegister.Rax]);
        Assert.Equal(20, AgcExports.DcbDrawIndexIndirectGetSize(ctx));
        Assert.Equal(20ul, ctx[CpuRegister.Rax]);
    }

    private static FakeCpuMemory CreateMemory(out CpuContext ctx)
    {
        var memory = new FakeCpuMemory(BaseAddress, 0x1000);
        ctx = new CpuContext(memory, Generation.Gen5);
        WriteUInt64(memory, CommandBufferAddress + 0x10, PacketAddress);
        WriteUInt64(memory, CommandBufferAddress + 0x18, PacketAddress + 0x100);
        return memory;
    }

    private static uint ReadUInt32(FakeCpuMemory memory, ulong address)
    {
        Span<byte> buffer = stackalloc byte[4];
        Assert.True(memory.TryRead(address, buffer));
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }

    private static ulong ReadUInt64(FakeCpuMemory memory, ulong address)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(memory.TryRead(address, buffer));
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer);
    }

    private static void WriteUInt64(FakeCpuMemory memory, ulong address, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        Assert.True(memory.TryWrite(address, buffer));
    }
}
