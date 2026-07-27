// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Silk.NET.Vulkan;

namespace SharpEmu.Libs.VideoOut;

internal readonly record struct LegacyImageBarrierContract(
    ImageLayout OldLayout,
    ImageLayout NewLayout,
    PipelineStageFlags SourceStage,
    PipelineStageFlags DestinationStage,
    AccessFlags SourceAccess,
    AccessFlags DestinationAccess);

internal static class VulkanHarnessCapturePolicy
{
    public static LegacyImageBarrierContract PresentToTransfer { get; } = new(
        ImageLayout.PresentSrcKhr,
        ImageLayout.TransferSrcOptimal,
        PipelineStageFlags.AllCommandsBit,
        PipelineStageFlags.TransferBit,
        AccessFlags.MemoryWriteBit,
        AccessFlags.TransferReadBit);

    public static LegacyImageBarrierContract TransferToPresent { get; } = new(
        ImageLayout.TransferSrcOptimal,
        ImageLayout.PresentSrcKhr,
        PipelineStageFlags.TransferBit,
        PipelineStageFlags.BottomOfPipeBit,
        AccessFlags.TransferReadBit,
        0);

    public static bool IsCanonicalFourByteFormat(Format format) => format is
        Format.B8G8R8A8Unorm or Format.B8G8R8A8Srgb or
        Format.R8G8B8A8Unorm or Format.R8G8B8A8Srgb;

    public static void EnsureCaptureFormat(Format format)
    {
        if (!IsCanonicalFourByteFormat(format))
        {
            throw new NotSupportedException($"Harness capture does not support swapchain format '{format}'.");
        }
    }

    public static bool ShouldRecord(bool instrumentationEnabled, bool frameRequested) =>
        instrumentationEnabled && frameRequested;
}
