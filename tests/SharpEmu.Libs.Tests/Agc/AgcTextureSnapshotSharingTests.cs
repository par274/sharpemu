// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Agc;
using SharpEmu.Libs.Gpu;
using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

public sealed class AgcTextureSnapshotSharingTests
{
    private const ulong MemoryBase = 0x1000_0000;
    private const int MemorySize = 0x800_000;

    private static readonly IReadOnlyList<uint> SamplerA =
        [0x0800_4092, 0x00FF_F000, 0x0650_0000, 0x4000_0000];

    private static readonly IReadOnlyList<uint> SamplerB =
        [0x0800_4092, 0x00FF_F000, 0x0650_0001, 0x4000_0000];

    [Fact]
    public void CompatibleGpuDetileBindingsShareOneTiledSourceAndRetainSamplerState()
    {
        var address = MemoryBase + 0x10_000;
        var memory = CreateMemory(address);
        var textures = CreateTextures(
            memory,
            Binding(Descriptor(address), SamplerA),
            Binding(Descriptor(address), SamplerB));

        var first = textures[0];
        var second = textures[1];

        Assert.False(first.IsFallback);
        Assert.False(second.IsFallback);
        Assert.NotNull(first.TiledSource);
        Assert.Same(first.TiledSource, second.TiledSource);
        Assert.Empty(first.RgbaPixels);
        Assert.Empty(second.RgbaPixels);
        Assert.NotEqual(first.Sampler, second.Sampler);
        Assert.Equal(ToSampler(SamplerA), first.Sampler);
        Assert.Equal(ToSampler(SamplerB), second.Sampler);

        var work = new VulkanComputeGuestDispatch(
            ShaderAddress: 1,
            ComputeSpirv: [],
            Textures: textures,
            GlobalMemoryBuffers: [],
            GroupCountX: 1,
            GroupCountY: 1,
            GroupCountZ: 1,
            BaseGroupX: 0,
            BaseGroupY: 0,
            BaseGroupZ: 0,
            LocalSizeX: 1,
            LocalSizeY: 1,
            LocalSizeZ: 1,
            IsIndirect: false,
            WritesGlobalMemory: false);

        Assert.Equal(
            (ulong)first.TiledSource!.Length,
            VulkanVideoPresenter.GetGuestWorkPayloadBytes(work));
    }

    [Fact]
    public void CompatibleCpuMaterializedBindingsShareOneRgbaPixelsArray()
    {
        var address = MemoryBase + 0x90_000;
        var memory = CreateMemory(address);
        var descriptor = Descriptor(address, format: 1);
        var textures = CreateTextures(
            memory,
            Binding(descriptor, SamplerA),
            Binding(descriptor, SamplerB));

        var first = textures[0];
        var second = textures[1];

        Assert.False(first.IsFallback);
        Assert.False(second.IsFallback);
        Assert.NotEmpty(first.RgbaPixels);
        Assert.Same(first.RgbaPixels, second.RgbaPixels);
        Assert.Null(first.TiledSource);
        Assert.Null(second.TiledSource);
        Assert.NotEqual(first.Sampler, second.Sampler);
    }

    [Fact]
    public void DifferentSourceRangesDoNotShare()
    {
        var firstAddress = MemoryBase + 0x110_000;
        var secondAddress = MemoryBase + 0x210_000;
        var memory = CreateMemory(firstAddress, secondAddress);
        var textures = CreateTextures(
            memory,
            Binding(Descriptor(firstAddress), SamplerA),
            Binding(Descriptor(secondAddress), SamplerA));

        AssertNotShared(textures[0], textures[1]);
    }

    [Fact]
    public void IncompatibleMipViewFormatLayoutStorageLayerAndDetileStateDoNotShare()
    {
        var memory = new FakeCpuMemory(MemoryBase, MemorySize);
        var nextAddress = MemoryBase + 0x300_000;

        var mipAddress = nextAddress;
        WriteSource(memory, mipAddress);
        var mipDescriptor = Descriptor(
            mipAddress,
            maxMip: 2,
            lastLevel: 2,
            extended: true);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(mipDescriptor, SamplerA, mipLevel: 0),
                Binding(mipDescriptor, SamplerA, mipLevel: 1)));

        var viewAddress = nextAddress + 0x40_000;
        WriteSource(memory, viewAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(
                    Descriptor(
                        viewAddress,
                        maxMip: 2,
                        lastLevel: 2,
                        extended: true,
                        baseLevel: 0),
                    SamplerA),
                Binding(
                    Descriptor(
                        viewAddress,
                        maxMip: 2,
                        lastLevel: 2,
                        extended: true,
                        baseLevel: 1),
                    SamplerA)));

        var formatAddress = nextAddress + 0x80_000;
        WriteSource(memory, formatAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(Descriptor(formatAddress, format: 10), SamplerA),
                Binding(Descriptor(formatAddress, format: 1), SamplerA)));

        var layoutAddress = nextAddress + 0xC0_000;
        WriteSource(memory, layoutAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(Descriptor(layoutAddress, format: 1, tileMode: 0, pitch: 64), SamplerA),
                Binding(Descriptor(layoutAddress, format: 1, tileMode: 0, pitch: 128), SamplerA)));

        var storageAddress = nextAddress + 0x100_000;
        WriteSource(memory, storageAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(Descriptor(storageAddress), SamplerA),
                Binding(Descriptor(storageAddress), SamplerA, isStorage: true)));

        var layerAddress = nextAddress + 0x140_000;
        WriteSource(memory, layerAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(
                    Descriptor(layerAddress, type: 13, depth: 2),
                    SamplerA,
                    isArrayed: true),
                Binding(
                    Descriptor(layerAddress, type: 13, depth: 3),
                    SamplerA,
                    isArrayed: true)));

        var detileAddress = nextAddress + 0x180_000;
        WriteSource(memory, detileAddress);
        AssertNotShared(
            CreateTextures(
                memory,
                Binding(Descriptor(detileAddress, tileMode: 9), SamplerA),
                Binding(Descriptor(detileAddress, tileMode: 24), SamplerA)));
    }

    [Fact]
    public void KnownWriteGenerationIsPartOfSnapshotIdentity()
    {
        var descriptor = Descriptor(MemoryBase + 0x500_000);
        var firstKey = SnapshotKey(descriptor, writeGeneration: 4);
        var secondKey = firstKey with { WriteGeneration = 5 };
        var pixels = new byte[] { 0xA5 };
        var table = new AgcExports.GuestTextureSnapshotTable();
        var snapshot = new AgcExports.GuestTextureSnapshot(
            pixels,
            TiledSource: null,
            Detile: null,
            SnapshotInfo: default,
            WriteGeneration: 4);

        table.Add(firstKey, snapshot);

        Assert.True(table.TryGet(firstKey, out var sameGeneration));
        Assert.Same(pixels, sameGeneration.RgbaPixels);
        Assert.False(table.TryGet(secondKey, out _));
    }

    [Fact]
    public void UntrackedGenerationUsesOneDispatchLocalExactAliasInvariant()
    {
        var address = MemoryBase + 0x580_000;
        var memory = CreateMemory(address);
        var textures = CreateTextures(
            memory,
            Binding(Descriptor(address, format: 1), SamplerA),
            Binding(Descriptor(address, format: 1), SamplerA));

        // Windows leaves the tracker unavailable by default. The production
        // table therefore matches the exact capture key with a null generation;
        // its lifetime ends with this CreateGuestDrawTextures call.
        Assert.Same(textures[0].RgbaPixels, textures[1].RgbaPixels);
    }

    [Fact]
    public void FailedReadsDoNotPoisonOrReuseSnapshotEntries()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x1000);
        var descriptor = Descriptor(MemoryBase + 0x20_000);
        var textures = AgcExports.CreateGuestDrawTextures(
            new CpuContext(memory, Generation.Gen5),
            [
                Binding(descriptor, SamplerA),
                Binding(descriptor, SamplerA),
            ],
            out var fallbackCount);

        Assert.Equal(2, fallbackCount);
        Assert.Equal(2, textures.Count);
        Assert.All(textures, texture => Assert.True(texture.IsFallback));
        Assert.All(textures, texture => Assert.Equal([0, 0, 0, 255], texture.RgbaPixels));
        Assert.NotSame(textures[0].RgbaPixels, textures[1].RgbaPixels);
        Assert.All(textures, texture => Assert.Null(texture.TiledSource));
    }

    [Fact]
    public void SnapshotTableIsScopedToOneConstructionInvocation()
    {
        var address = MemoryBase + 0x600_000;
        var memory = CreateMemory(address);
        var first = CreateTextures(
            memory,
            Binding(Descriptor(address, format: 1), SamplerA));
        var second = CreateTextures(
            memory,
            Binding(Descriptor(address, format: 1), SamplerA));

        Assert.NotSame(first[0].RgbaPixels, second[0].RgbaPixels);
    }

    private static IReadOnlyList<GuestDrawTexture> CreateTextures(
        FakeCpuMemory memory,
        params AgcExports.TranslatedImageBinding[] bindings)
    {
        var textures = AgcExports.CreateGuestDrawTextures(
            new CpuContext(memory, Generation.Gen5),
            bindings,
            out var fallbackCount);
        Assert.Equal(0, fallbackCount);
        return textures;
    }

    private static AgcExports.TranslatedImageBinding Binding(
        AgcExports.TextureDescriptor descriptor,
        IReadOnlyList<uint> sampler,
        uint mipLevel = 0,
        bool isStorage = false,
        bool isArrayed = false) =>
        new(descriptor, isStorage, mipLevel, sampler, isArrayed);

    private static AgcExports.TextureDescriptor Descriptor(
        ulong address,
        uint format = 10,
        uint tileMode = 9,
        uint type = 9,
        uint depth = 1,
        uint pitch = 64,
        uint baseLevel = 0,
        uint lastLevel = 0,
        uint maxMip = 0,
        bool extended = false) =>
        new(
            address,
            Width: 64,
            Height: 64,
            format,
            NumberType: 0,
            tileMode,
            type,
            baseLevel,
            lastLevel,
            pitch,
            DstSelect: 0xFAC,
            Depth: depth,
            MaxMip: maxMip,
            HasExtendedDescriptor: extended);

    private static FakeCpuMemory CreateMemory(params ulong[] addresses)
    {
        var memory = new FakeCpuMemory(MemoryBase, MemorySize);
        foreach (var address in addresses)
        {
            WriteSource(memory, address);
        }

        return memory;
    }

    private static void WriteSource(FakeCpuMemory memory, ulong address)
    {
        Assert.True(memory.TryWrite(address, new byte[0x40_000]));
    }

    private static GuestSampler ToSampler(IReadOnlyList<uint> words) =>
        new(words[0], words[1], words[2], words[3]);

    private static AgcExports.GuestTextureSnapshotKey SnapshotKey(
        AgcExports.TextureDescriptor descriptor,
        long? writeGeneration) =>
        new(
            descriptor,
            MipLevel: 0,
            IsStorage: false,
            IsArrayed: false,
            TextureDepth: 1,
            SourceWidth: 64,
            OutputArrayLayers: 1,
            BaseMipByteOffset: 0,
            SourceAddress: descriptor.Address,
            SourceCoveredByteCount: 16,
            LogicalSourceByteCount: 16,
            PhysicalSourceByteCount: 16,
            SourceSliceByteCount: 16,
            SourceSliceStride: 16,
            SourceLayerCount: 1,
            BaseMipInTail: false,
            MipTailElementX: 0,
            MipTailElementY: 0,
            Representation: AgcExports.GuestTextureSnapshotRepresentation.RgbaPixels,
            Detile: null,
            WriteGeneration: writeGeneration);

    private static void AssertNotShared(IReadOnlyList<GuestDrawTexture> textures)
    {
        Assert.Equal(2, textures.Count);
        AssertNotShared(textures[0], textures[1]);
    }

    private static void AssertNotShared(GuestDrawTexture first, GuestDrawTexture second)
    {
        Assert.False(
            first.RgbaPixels.Length != 0 &&
            second.RgbaPixels.Length != 0 &&
            ReferenceEquals(first.RgbaPixels, second.RgbaPixels));
        Assert.False(
            first.TiledSource is not null &&
            ReferenceEquals(first.TiledSource, second.TiledSource));
    }
}
