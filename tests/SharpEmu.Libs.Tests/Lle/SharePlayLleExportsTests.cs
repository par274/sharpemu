// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Lle;
using Xunit;

namespace SharpEmu.Libs.Tests.Lle;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SharePlayStateCollection
{
    public const string Name = "SharePlayState";
}

[Collection(SharePlayStateCollection.Name)]
public sealed class SharePlayLleExportsTests : IDisposable
{
    private const int SharePlayErrorInvalidWorkspace = unchecked((int)0x810E0001);
    private const int SharePlayErrorAlreadyInitialized = unchecked((int)0x810E0003);
    private const int SharePlayErrorNotInitialized = unchecked((int)0x810E0004);
    private readonly CpuContext _ctx = new(new NullMemory(), Generation.Gen5);

    public SharePlayLleExportsTests() => SharePlayLleExports.ResetForTests();

    public void Dispose() => SharePlayLleExports.ResetForTests();

    [Fact]
    public void ExportsRegisterExactGen5ProviderPreferredIdentities()
    {
        var exports = SharpEmu.Generated.SysAbiExportRegistry.CreateExports(Generation.Gen5);

        var initialize = Assert.Single(exports, export => export.Nid == "isruqthpYcw");
        Assert.Equal("sceSharePlayInitialize", initialize.Name);
        Assert.Equal("libSceSharePlay", initialize.LibraryName);
        Assert.True(initialize.PreferLle);
        Assert.Equal(typeof(SharePlayLleExports), initialize.Function.Method.DeclaringType);

        var terminate = Assert.Single(exports, export => export.Nid == "UaLjloJinow");
        Assert.Equal("sceSharePlayTerminate", terminate.Name);
        Assert.Equal("libSceSharePlay", terminate.LibraryName);
        Assert.True(terminate.PreferLle);
        Assert.Equal(typeof(SharePlayLleExports), terminate.Function.Method.DeclaringType);
    }

    [Fact]
    public void InitializeAcceptsGtaWorkspaceAndTerminateTracksLifecycle()
    {
        _ctx[CpuRegister.Rdi] = 0x1_05B7_7270;
        _ctx[CpuRegister.Rsi] = 0x1800;

        AssertResult(0, SharePlayLleExports.SharePlayInitialize);
        Assert.True(SharePlayLleExports.IsInitializedForTests);
        AssertResult(SharePlayErrorAlreadyInitialized, SharePlayLleExports.SharePlayInitialize);

        AssertResult(0, SharePlayLleExports.SharePlayTerminate);
        Assert.False(SharePlayLleExports.IsInitializedForTests);
        AssertResult(SharePlayErrorNotInitialized, SharePlayLleExports.SharePlayTerminate);
    }

    [Fact]
    public void InitializeRejectsUndersizedCallerWorkspaceWithoutChangingState()
    {
        _ctx[CpuRegister.Rdi] = 0x1_05B7_7270;
        _ctx[CpuRegister.Rsi] = 0x17FF;

        AssertResult(SharePlayErrorInvalidWorkspace, SharePlayLleExports.SharePlayInitialize);
        Assert.False(SharePlayLleExports.IsInitializedForTests);
    }

    [Fact]
    public void InitializeAllowsProviderStyleInternalWorkspace()
    {
        _ctx[CpuRegister.Rdi] = 0;
        _ctx[CpuRegister.Rsi] = 0;

        AssertResult(0, SharePlayLleExports.SharePlayInitialize);
        Assert.True(SharePlayLleExports.IsInitializedForTests);
    }

    private void AssertResult(int expected, Func<CpuContext, int> export)
    {
        Assert.Equal(expected, export(_ctx));
        Assert.Equal(unchecked((ulong)expected), _ctx[CpuRegister.Rax]);
    }

    private sealed class NullMemory : ICpuMemory
    {
        public bool TryRead(ulong virtualAddress, Span<byte> destination) => false;

        public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source) => false;
    }
}
