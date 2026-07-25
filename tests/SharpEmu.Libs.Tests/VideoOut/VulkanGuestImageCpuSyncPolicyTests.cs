// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

/// <summary>
/// Guards the two policy decisions that let a guest CPU rewrite reach a host
/// image that the GPU also renders into. Both used to be answered by proxies
/// that silently excluded real surfaces: a 1920x1080 arming cap (which left
/// every 4K target un-invalidated) and an IsCpuBacked latch (which flips false
/// the first time an address is used as a render target and never flips back).
/// The Vulkan device code around them cannot be unit-tested without a device,
/// so the decisions themselves are exercised here.
/// </summary>
public sealed class VulkanGuestImageCpuSyncPolicyTests
{
    private const uint Rgba8Format = 10;
    private const uint Rgba16FFormat = 11;
    private const uint Rgba32FFormat = 14;

    [Theory]
    // 4K UI sheets are the whole point of the change: under the old
    // resolution cap none of these were ever armed.
    [InlineData(Rgba8Format, 3840u, 2160u)]
    [InlineData(Rgba16FFormat, 3840u, 2160u)]
    [InlineData(Rgba32FFormat, 3840u, 2160u)]
    // Supersampled and unusual-aspect targets above 1080p in one axis only.
    [InlineData(Rgba8Format, 2560u, 1440u)]
    [InlineData(Rgba8Format, 1920u, 2160u)]
    [InlineData(Rgba8Format, 3840u, 1080u)]
    public void OversizedTargetsRemainEligibleForWriteTracking(
        uint format,
        uint width,
        uint height)
    {
        var byteCount = VulkanVideoPresenter.GetGuestImageByteCount(
            format,
            width,
            height,
            depth: 1);

        Assert.True(VulkanVideoPresenter.ShouldTrackGuestImageWrites(byteCount));
    }

    [Fact]
    public void SubHdTargetsRemainEligibleForWriteTracking()
    {
        var byteCount = VulkanVideoPresenter.GetGuestImageByteCount(
            Rgba8Format,
            1280u,
            720u,
            depth: 1);

        Assert.True(VulkanVideoPresenter.ShouldTrackGuestImageWrites(byteCount));
    }

    [Fact]
    public void EmptyExtentIsNotTracked()
    {
        Assert.False(VulkanVideoPresenter.ShouldTrackGuestImageWrites(0));
    }

    [Fact]
    public void ExtentBeyondTheReUploadBudgetIsNotTracked()
    {
        // Arming beyond the budget the flip/acquire sync path is willing to
        // read back can only cost faults; it can never produce a re-upload.
        Assert.True(
            VulkanVideoPresenter.ShouldTrackGuestImageWrites(
                VulkanVideoPresenter.MaxTrackedGuestImageBytes));
        Assert.False(
            VulkanVideoPresenter.ShouldTrackGuestImageWrites(
                VulkanVideoPresenter.MaxTrackedGuestImageBytes + 1));
    }

    [Fact]
    public void VolumeDepthCountsAgainstTheTrackingBudget()
    {
        // A resolution cap could not see volume depth at all. 512^3 RGBA8 is
        // 512 MiB of backing memory behind a "512x512" surface.
        var byteCount = VulkanVideoPresenter.GetGuestImageByteCount(
            Rgba8Format,
            512u,
            512u,
            depth: 512u);

        Assert.False(VulkanVideoPresenter.ShouldTrackGuestImageWrites(byteCount));
    }

    [Fact]
    public void CpuBackedImageAlwaysRefreshes()
    {
        Assert.True(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: true,
                textureWriteGeneration: -1,
                hasUploadedGeneration: false,
                uploadedGeneration: 0));
    }

    [Fact]
    public void RenderTargetLatchNoLongerBlocksAnObservedCpuWrite()
    {
        // The surface was rendered into (IsCpuBacked latched false) and the
        // guest CPU then rewrote its backing memory, so the parse thread
        // shipped fresh texels carrying a newer generation than the upload.
        Assert.True(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: false,
                textureWriteGeneration: 3,
                hasUploadedGeneration: true,
                uploadedGeneration: 2));
    }

    [Fact]
    public void ObservedCpuWriteRefreshesEvenWithNoRecordedUpload()
    {
        // The render-target recreate/retain paths drop the recorded upload
        // generation; a tracked CPU write must still win.
        Assert.True(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: false,
                textureWriteGeneration: 1,
                hasUploadedGeneration: false,
                uploadedGeneration: 0));
    }

    [Fact]
    public void GpuFeedbackSurfaceKeepsItsLiveImage()
    {
        // Tracked but never CPU-written: generation zero. Render-into-then-
        // sample must not be overwritten with guest memory.
        Assert.False(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: false,
                textureWriteGeneration: 0,
                hasUploadedGeneration: false,
                uploadedGeneration: 0));
    }

    [Fact]
    public void UntrackedSurfaceKeepsItsLiveImage()
    {
        // -1 is the "no tracker generation" sentinel the parse thread ships
        // when the range is not tracked (or tracking is disabled entirely,
        // as on Windows).
        Assert.False(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: false,
                textureWriteGeneration: -1,
                hasUploadedGeneration: false,
                uploadedGeneration: 0));
    }

    [Fact]
    public void AlreadyUploadedGenerationDoesNotRefreshAgain()
    {
        // The upload recorded this exact generation, so the host image is
        // current: re-uploading every draw would restage the whole surface.
        Assert.False(
            VulkanVideoPresenter.ShouldRefreshGuestImageFromCpu(
                isCpuBacked: false,
                textureWriteGeneration: 4,
                hasUploadedGeneration: true,
                uploadedGeneration: 4));
    }
}
