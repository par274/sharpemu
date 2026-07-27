// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanPresentationAspectTests
{
    [Theory]
    [InlineData(1920u, 1080u, 1920u, 1080u, 0u, 0u, 1920u, 1080u)]
    [InlineData(1280u, 720u, 2048u, 1126u, 23u, 0u, 2001u, 1126u)]
    [InlineData(1280u, 720u, 1280u, 1024u, 0u, 152u, 1280u, 720u)]
    [InlineData(640u, 480u, 1920u, 1080u, 240u, 0u, 1440u, 1080u)]
    public void AspectFitCentersTheWholeGuestFrame(
        uint sourceWidth,
        uint sourceHeight,
        uint destinationWidth,
        uint destinationHeight,
        uint expectedX,
        uint expectedY,
        uint expectedWidth,
        uint expectedHeight)
    {
        var result = VulkanVideoPresenter.CalculateAspectFitRect(
            sourceWidth,
            sourceHeight,
            destinationWidth,
            destinationHeight);

        Assert.Equal(
            new VulkanPresentRect(
                expectedX,
                expectedY,
                expectedWidth,
                expectedHeight),
            result);
    }

    [Theory]
    [InlineData(0u, 720u, 1920u, 1080u)]
    [InlineData(1280u, 0u, 1920u, 1080u)]
    [InlineData(1280u, 720u, 0u, 1080u)]
    [InlineData(1280u, 720u, 1920u, 0u)]
    public void EmptyDimensionsProduceAnEmptyRectangle(
        uint sourceWidth,
        uint sourceHeight,
        uint destinationWidth,
        uint destinationHeight)
    {
        Assert.Equal(
            default,
            VulkanVideoPresenter.CalculateAspectFitRect(
                sourceWidth,
                sourceHeight,
                destinationWidth,
                destinationHeight));
    }
}
