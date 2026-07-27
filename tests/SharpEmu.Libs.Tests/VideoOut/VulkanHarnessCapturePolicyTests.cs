// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.VideoOut;
using Silk.NET.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanHarnessCapturePolicyTests
{
    [Theory]
    [InlineData(Format.B8G8R8A8Unorm)]
    [InlineData(Format.B8G8R8A8Srgb)]
    [InlineData(Format.R8G8B8A8Unorm)]
    [InlineData(Format.R8G8B8A8Srgb)]
    public void CanonicalFourByteFormatsAreSupported(Format format)
    {
        Assert.True(VulkanHarnessCapturePolicy.IsCanonicalFourByteFormat(format));
        VulkanHarnessCapturePolicy.EnsureCaptureFormat(format);
    }

    [Fact]
    public void UnsupportedSurfaceFormatIsRejected()
    {
        Assert.Throws<NotSupportedException>(() => VulkanHarnessCapturePolicy.EnsureCaptureFormat(Format.R16G16B16A16Sfloat));
    }

    [Fact]
    public void CaptureBarrierRestoresPresentLayoutWithoutBottomOfPipeMemoryReadPairing()
    {
        var acquire = VulkanHarnessCapturePolicy.PresentToTransfer;
        var restore = VulkanHarnessCapturePolicy.TransferToPresent;
        Assert.Equal(ImageLayout.PresentSrcKhr, acquire.OldLayout);
        Assert.Equal(ImageLayout.TransferSrcOptimal, acquire.NewLayout);
        Assert.Equal(PipelineStageFlags.AllCommandsBit, acquire.SourceStage);
        Assert.Equal(AccessFlags.MemoryWriteBit, acquire.SourceAccess);
        Assert.Equal(ImageLayout.TransferSrcOptimal, restore.OldLayout);
        Assert.Equal(ImageLayout.PresentSrcKhr, restore.NewLayout);
        Assert.Equal(PipelineStageFlags.BottomOfPipeBit, restore.DestinationStage);
        Assert.Equal((AccessFlags)0, restore.DestinationAccess);
    }

    [Fact]
    public void DisabledInstrumentationRecordsNoCaptureWork()
    {
        Assert.False(VulkanHarnessCapturePolicy.ShouldRecord(instrumentationEnabled: false, frameRequested: true));
        Assert.True(VulkanHarnessCapturePolicy.ShouldRecord(instrumentationEnabled: true, frameRequested: true));
    }
}
