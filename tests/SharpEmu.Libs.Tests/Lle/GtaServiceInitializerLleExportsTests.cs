// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.Libs.Lle;
using Xunit;

namespace SharpEmu.Libs.Tests.Lle;

public sealed class GtaServiceInitializerLleExportsTests : IDisposable
{
    private const ulong MemoryBase = 0x100_000;
    private const ulong ParameterAddress = MemoryBase + 0x100;
    private const uint MemoryFault = unchecked((uint)(int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);

    public GtaServiceInitializerLleExportsTests() => ResetState();

    public void Dispose() => ResetState();

    [Fact]
    public void RegistryDispatchesTheGtaVoiceContractsToSemanticFallbacks()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5);

        Assert.Equal(
            (SysAbiFunction)VoiceLleExports.InitializeWithoutGuestProvider,
            Assert.Single(exports, export => export.Nid == "9TrhuGzberQ").Function);
        Assert.Equal(
            (SysAbiFunction)VoiceLleExports.SetThreadsParamsWithoutGuestProvider,
            Assert.Single(exports, export => export.Nid == "clyKUyi3RYU").Function);
        Assert.Equal(
            (SysAbiFunction)ContentSearchLleExports.InitializeWithoutGuestProvider,
            Assert.Single(exports, export => export.Nid == "dPj4ZtRcIWk").Function);
        Assert.Equal(
            (SysAbiFunction)ContentDeleteLleExports.InitializeWithoutGuestProvider,
            Assert.Single(exports, export => export.Nid == "zoxb0wEChEM").Function);
    }

    [Fact]
    public void VoiceInitializeMatchesProviderValidationAndLifecycleOrder()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x1000);
        var context = new CpuContext(memory, Generation.Gen5);

        AssertResult(0x804E0805, VoiceLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = MemoryBase + 0x2000;
        AssertResult(MemoryFault, VoiceLleExports.InitializeWithoutGuestProvider, context);

        Span<byte> parameters = stackalloc byte[0x28];
        BinaryPrimitives.WriteUInt64LittleEndian(parameters, 0x10000000);
        Assert.True(memory.TryWrite(ParameterAddress, parameters));
        context[CpuRegister.Rdi] = ParameterAddress;
        context[CpuRegister.Rsi] = 0x1_0000_0064;
        AssertResult(0, VoiceLleExports.InitializeWithoutGuestProvider, context);
        Assert.Equal(100U, VoiceLleExports.VersionForTests);

        context[CpuRegister.Rdi] = 0;
        AssertResult(0x804E0802, VoiceLleExports.InitializeWithoutGuestProvider, context);
    }

    [Fact]
    public void VoiceSetThreadsParamsMatchesProviderSelectorAndStateContract()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x1000);
        var context = new CpuContext(memory, Generation.Gen5);

        context[CpuRegister.Rdi] = ParameterAddress;
        AssertResult(0x804E0801, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);

        Span<byte> initParameters = stackalloc byte[0x28];
        Assert.True(memory.TryWrite(ParameterAddress, initParameters));
        context[CpuRegister.Rdi] = ParameterAddress;
        AssertResult(0, VoiceLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = 0;
        AssertResult(0x804E0805, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = MemoryBase + 0x2000;
        AssertResult(MemoryFault, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);

        WriteUInt32(memory, ParameterAddress, 2);
        context[CpuRegister.Rdi] = ParameterAddress;
        AssertResult(0x804E0805, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);

        WriteUInt32(memory, MemoryBase + 0xffc, 0);
        context[CpuRegister.Rdi] = MemoryBase + 0xffc;
        AssertResult(0, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);
        Assert.False(VoiceLleExports.ThreadParametersConfiguredForTests);

        Span<byte> threadParameters = stackalloc byte[0x30];
        BinaryPrimitives.WriteUInt32LittleEndian(threadParameters, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(threadParameters[4..], 700);
        BinaryPrimitives.WriteUInt64LittleEndian(threadParameters[8..], 0x7f);
        BinaryPrimitives.WriteUInt32LittleEndian(threadParameters[16..], 700);
        BinaryPrimitives.WriteUInt64LittleEndian(threadParameters[24..], 0x7f);
        BinaryPrimitives.WriteUInt32LittleEndian(threadParameters[32..], 700);
        BinaryPrimitives.WriteUInt64LittleEndian(threadParameters[40..], 0x7f);
        Assert.True(memory.TryWrite(ParameterAddress, threadParameters));
        context[CpuRegister.Rdi] = ParameterAddress;
        AssertResult(0, VoiceLleExports.SetThreadsParamsWithoutGuestProvider, context);
        Assert.True(VoiceLleExports.ThreadParametersConfiguredForTests);
        Assert.Equal(threadParameters.ToArray(), VoiceLleExports.ThreadParametersForTests);
    }

    [Fact]
    public void ContentSearchInitializeMatchesProviderPoolAndLifecycleContract()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x1000);
        var context = new CpuContext(memory, Generation.Gen5);

        AssertResult(0x809D1003, ContentSearchLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = MemoryBase + 0x2000;
        AssertResult(MemoryFault, ContentSearchLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = ParameterAddress;
        WriteUInt64(memory, ParameterAddress, 0);
        AssertResult(0x809D1003, ContentSearchLleExports.InitializeWithoutGuestProvider, context);

        WriteUInt64(memory, ParameterAddress, 0x4001);
        AssertResult(0x809D1003, ContentSearchLleExports.InitializeWithoutGuestProvider, context);

        WriteUInt64(memory, ParameterAddress, 0x400000);
        AssertResult(0, ContentSearchLleExports.InitializeWithoutGuestProvider, context);
        Assert.Equal(0x400000UL, ContentSearchLleExports.MemorySizeForTests);

        context[CpuRegister.Rdi] = 0;
        AssertResult(0x809D1002, ContentSearchLleExports.InitializeWithoutGuestProvider, context);
    }

    [Fact]
    public void ContentDeleteInitializeValidatesPoolBeforeLifecycleState()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x1000);
        var context = new CpuContext(memory, Generation.Gen5);

        AssertResult(0x809D5001, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = MemoryBase + 0x2000;
        AssertResult(MemoryFault, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);

        context[CpuRegister.Rdi] = ParameterAddress;
        WriteUInt64(memory, ParameterAddress + 8, 0x3FFF);
        AssertResult(0x809D5001, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);

        WriteUInt64(memory, ParameterAddress + 8, 0x4000);
        AssertResult(0, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);
        AssertResult(0x809D5003, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);

        WriteUInt64(memory, ParameterAddress + 8, 0x3FFF);
        AssertResult(0x809D5001, ContentDeleteLleExports.InitializeWithoutGuestProvider, context);
    }

    private static void AssertResult(
        uint expected,
        SysAbiFunction function,
        CpuContext context)
    {
        Assert.Equal(unchecked((int)expected), function(context));
        Assert.Equal(unchecked((ulong)unchecked((int)expected)), context[CpuRegister.Rax]);
    }

    private static void WriteUInt64(FakeCpuMemory memory, ulong address, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        Assert.True(memory.TryWrite(address, bytes));
    }

    private static void WriteUInt32(FakeCpuMemory memory, ulong address, uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        Assert.True(memory.TryWrite(address, bytes));
    }

    private static void ResetState()
    {
        VoiceLleExports.ResetForTests();
        ContentSearchLleExports.ResetForTests();
        ContentDeleteLleExports.ResetForTests();
    }
}
