// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Gpu;

namespace SharpEmu.Libs.VideoOut;

internal sealed record GuestWorkPayloadCategorySummary(
    string Category,
    int UniqueArrayCount,
    ulong UniqueBytes,
    int ReferenceCount,
    ulong ReferencedBytes);

internal sealed record GuestWorkPayloadArraySummary(
    int ArrayId,
    string PrimaryCategory,
    ulong Length,
    int ReferenceCount,
    IReadOnlyList<string> Roles);

internal sealed record GuestTextureContentKey(
    ulong Address,
    uint Width,
    uint Height,
    uint Format,
    uint NumberType,
    uint DstSelect,
    uint TileMode,
    uint Pitch,
    uint SamplerWord0,
    uint SamplerWord1,
    uint SamplerWord2,
    uint SamplerWord3,
    bool Arrayed,
    uint ArrayLayers,
    uint Type,
    uint Depth);

internal sealed record GuestWorkTextureSummary(
    int TextureIndex,
    ulong Address,
    ulong GuestSourceAddress,
    ulong GuestSourceCoveredEnd,
    ulong GuestSourceCoveredRangeBytes,
    ulong CalculatedLogicalSourceBytes,
    ulong CalculatedPhysicalSourceBytes,
    ulong CalculatedSourceSliceBytes,
    ulong CalculatedSourceSliceStride,
    uint CalculatedSourceLayerCount,
    double SnapshotAgeMilliseconds,
    uint Width,
    uint Height,
    uint Depth,
    uint Pitch,
    uint ArrayLayers,
    uint Format,
    uint NumberType,
    uint TileMode,
    uint Type,
    uint MipLevel,
    uint BaseMipLevel,
    uint ResourceMipLevels,
    bool IsStorage,
    bool ArrayedView,
    int? RgbaArrayId,
    ulong RgbaAllocatedBytes,
    int? TiledArrayId,
    ulong TiledAllocatedBytes,
    GuestTextureContentKey ContentIdentity);

internal sealed record GuestWorkPayloadSummary(
    ulong TotalBytes,
    int UniqueArrayCount,
    IReadOnlyList<GuestWorkPayloadCategorySummary> Categories,
    IReadOnlyList<GuestWorkPayloadArraySummary> LargestArrays,
    IReadOnlyList<GuestWorkTextureSummary> Textures);

/// <summary>
/// Builds a bounded, content-free ownership description for one guest work
/// item. The temporary byte-array map is reference keyed and never escapes this
/// method; the returned records contain lengths and descriptor metadata only.
/// </summary>
internal static class VulkanGuestWorkDiagnostics
{
    // The observed oversized dispatch has 43 unique arrays. Keep the cap
    // above that target shape so one event is complete for this investigation
    // while remaining bounded for future work items.
    internal const int MaximumDetailedArrays = 64;
    internal const int MaximumDetailedTextures = 64;

    public static GuestWorkPayloadSummary Build(
        object work,
        int maximumDetailedArrays = MaximumDetailedArrays,
        int maximumDetailedTextures = MaximumDetailedTextures)
    {
        var arrays = new Dictionary<byte[], ArrayOwner>(
            System.Collections.Generic.ReferenceEqualityComparer.Instance);
        var categories = new Dictionary<string, CategoryTotals>(StringComparer.Ordinal);
        var allArrays = new List<ArrayOwner>();
        var textures = new List<GuestWorkTextureSummary>();

        void Add(
            string category,
            string role,
            byte[]? data,
            out int? arrayId,
            out ulong length)
        {
            arrayId = null;
            length = 0;
            if (data is null)
            {
                return;
            }

            length = checked((ulong)data.LongLength);
            if (!categories.TryGetValue(category, out var categoryTotals))
            {
                categoryTotals = new CategoryTotals(category);
                categories.Add(category, categoryTotals);
            }

            categoryTotals.ReferenceCount = checked(categoryTotals.ReferenceCount + 1);
            categoryTotals.ReferencedBytes = checked(
                categoryTotals.ReferencedBytes + length);

            if (!arrays.TryGetValue(data, out var owner))
            {
                owner = new ArrayOwner(
                    checked(allArrays.Count + 1),
                    category,
                    length);
                arrays.Add(data, owner);
                allArrays.Add(owner);
                categoryTotals.UniqueArrayCount = checked(
                    categoryTotals.UniqueArrayCount + 1);
                categoryTotals.UniqueBytes = checked(
                    categoryTotals.UniqueBytes + length);
            }

            owner.ReferenceCount = checked(owner.ReferenceCount + 1);
            if (!owner.Roles.Contains(role, StringComparer.Ordinal))
            {
                owner.Roles.Add(role);
            }

            arrayId = owner.ArrayId;
        }

        void AddTexture(GuestDrawTexture texture, int index)
        {
            Add(
                "rgbaPixels",
                $"texture[{index}].rgbaPixels",
                texture.RgbaPixels,
                out var rgbaArrayId,
                out var rgbaLength);
            Add(
                "tiledSource",
                $"texture[{index}].tiledSource",
                texture.TiledSource,
                out var tiledArrayId,
                out var tiledLength);

            var snapshot = texture.SnapshotInfo;
            var sourceAddress = snapshot.GuestSourceAddress;
            var sourceLayers = snapshot.SourceLayerCount;
            var sourceSliceBytes = snapshot.SourceSliceByteCount;
            var sourceStride = snapshot.SourceSliceStride;
            var sourceEnd = sourceAddress;
            if (sourceAddress != 0 && sourceLayers != 0)
            {
                sourceEnd = checked(
                    sourceAddress +
                    checked((ulong)(sourceLayers - 1) * sourceStride) +
                    sourceSliceBytes);
            }

            textures.Add(new GuestWorkTextureSummary(
                index,
                texture.Address,
                sourceAddress,
                sourceEnd,
                sourceAddress == 0 ? 0 : checked(sourceEnd - sourceAddress),
                snapshot.LogicalSourceByteCount,
                snapshot.PhysicalSourceByteCount,
                sourceSliceBytes,
                sourceStride,
                sourceLayers,
                snapshot.CreatedTicks <= 0
                    ? -1
                    : Math.Max(
                        0,
                        (System.Diagnostics.Stopwatch.GetTimestamp() -
                            snapshot.CreatedTicks) *
                        1000.0 / System.Diagnostics.Stopwatch.Frequency),
                texture.Width,
                texture.Height,
                texture.Depth,
                texture.Pitch,
                texture.ArrayLayers,
                texture.Format,
                texture.NumberType,
                texture.TileMode,
                texture.Type,
                texture.MipLevel,
                texture.BaseMipLevel,
                texture.ResourceMipLevels,
                texture.IsStorage,
                texture.ArrayedView,
                rgbaArrayId,
                rgbaLength,
                tiledArrayId,
                tiledLength,
                new GuestTextureContentKey(
                    texture.Address,
                    texture.Width,
                    texture.Height,
                    texture.Format,
                    texture.NumberType,
                    texture.DstSelect,
                    texture.TileMode,
                    texture.Pitch,
                    texture.Sampler.Word0,
                    texture.Sampler.Word1,
                    texture.Sampler.Word2,
                    texture.Sampler.Word3,
                    texture.ArrayedView,
                    Math.Max(texture.ArrayLayers, 1),
                    texture.Type,
                    VulkanVideoPresenter.GetGuestTextureDepth(
                        texture.Type,
                        texture.Depth))));
        }

        void AddTextures(IReadOnlyList<GuestDrawTexture> input)
        {
            for (var index = 0; index < input.Count; index++)
            {
                AddTexture(input[index], index);
            }
        }

        void AddGlobalBuffers(IReadOnlyList<GuestMemoryBuffer> buffers)
        {
            for (var index = 0; index < buffers.Count; index++)
            {
                Add(
                    "globalBuffers",
                    $"globalBuffer[{index}]",
                    buffers[index].Data,
                    out _,
                    out _);
            }
        }

        switch (work)
        {
            case VulkanComputeGuestDispatch compute:
                Add(
                    "computeShader",
                    "computeShader",
                    compute.ComputeSpirv,
                    out _,
                    out _);
                AddTextures(compute.Textures);
                AddGlobalBuffers(compute.GlobalMemoryBuffers);
                break;
            case VulkanOffscreenGuestDraw offscreen:
                Add(
                    "vertexShader",
                    "vertexShader",
                    offscreen.Draw.VertexSpirv,
                    out _,
                    out _);
                Add(
                    "pixelShader",
                    "pixelShader",
                    offscreen.Draw.PixelSpirv,
                    out _,
                    out _);
                AddTextures(offscreen.Draw.Textures);
                AddGlobalBuffers(offscreen.Draw.GlobalMemoryBuffers);
                for (var index = 0; index < offscreen.Draw.VertexBuffers.Count; index++)
                {
                    Add(
                        "vertexBuffers",
                        $"vertexBuffer[{index}]",
                        offscreen.Draw.VertexBuffers[index].Data,
                        out _,
                        out _);
                }

                if (offscreen.Draw.IndexBuffer is { } indexBuffer)
                {
                    Add(
                        "indexBuffers",
                        "indexBuffer",
                        indexBuffer.Data,
                        out _,
                        out _);
                }

                break;
            case VulkanVideoPresenter.VulkanGuestImageWrite imageWrite:
                Add(
                    "imageWritePixels",
                    "imageWritePixels",
                    imageWrite.Pixels,
                    out _,
                    out _);
                break;
        }

        var categorySummaries = categories.Values
            .OrderBy(static category => category.Name, StringComparer.Ordinal)
            .Select(static category => new GuestWorkPayloadCategorySummary(
                category.Name,
                category.UniqueArrayCount,
                category.UniqueBytes,
                category.ReferenceCount,
                category.ReferencedBytes))
            .ToArray();
        var largestArrays = allArrays
            .OrderByDescending(static array => array.Length)
            .ThenBy(static array => array.ArrayId)
            .Take(Math.Max(maximumDetailedArrays, 0))
            .Select(static array => new GuestWorkPayloadArraySummary(
                array.ArrayId,
                array.PrimaryCategory,
                array.Length,
                array.ReferenceCount,
                array.Roles.ToArray()))
            .ToArray();
        var totalBytes = allArrays.Aggregate(
            0UL,
            static (total, array) => checked(total + array.Length));

        return new GuestWorkPayloadSummary(
            totalBytes,
            allArrays.Count,
            categorySummaries,
            largestArrays,
            textures
                .Take(Math.Max(maximumDetailedTextures, 0))
                .ToArray());
    }

    private sealed class CategoryTotals(string name)
    {
        public string Name { get; } = name;
        public int UniqueArrayCount;
        public ulong UniqueBytes;
        public int ReferenceCount;
        public ulong ReferencedBytes;
    }

    private sealed class ArrayOwner(
        int arrayId,
        string primaryCategory,
        ulong length)
    {
        public int ArrayId { get; } = arrayId;
        public string PrimaryCategory { get; } = primaryCategory;
        public ulong Length { get; } = length;
        public int ReferenceCount;
        public List<string> Roles { get; } = [];
    }
}
