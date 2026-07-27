// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanOverlayFrameChannelTests
{
    [Fact]
    public unsafe void PublishesCoherentBgraFrameAndVisibility()
    {
        using var writer = new VulkanOverlayFrameWriter();
        Assert.True(
            VulkanOverlayFrameReader.TryOpen(
                writer.Descriptor,
                out var reader,
                out var error),
            error);
        using (reader)
        {
            byte[] source =
            [
                1, 2, 3, 4,
                5, 6, 7, 8,
                9, 10, 11, 12,
                13, 14, 15, 16,
            ];
            fixed (byte* pixels = source)
            {
                writer.PublishFrame((nint)pixels, 2, 2, 8);
            }

            var destination = new byte[source.Length];
            Assert.True(reader!.TryCopyLatest(
                destination,
                2,
                2,
                previousSequence: -1,
                out var visible,
                out var sequence,
                out var copied));
            Assert.True(visible);
            Assert.True(copied);
            Assert.True(sequence > 0);
            Assert.Equal(source, destination);

            Assert.True(reader.TryCopyLatest(
                destination,
                2,
                2,
                sequence,
                out visible,
                out var unchangedSequence,
                out copied));
            Assert.True(visible);
            Assert.False(copied);
            Assert.Equal(sequence, unchangedSequence);

            writer.SetVisible(false);
            Assert.True(reader.TryCopyLatest(
                destination,
                2,
                2,
                unchangedSequence,
                out visible,
                out _,
                out copied));
            Assert.False(visible);
            Assert.False(copied);
        }
    }

    [Theory]
    [InlineData(1280, 720, 1280, 720)]
    [InlineData(3840, 2160, 3840, 2160)]
    [InlineData(5120, 1440, 4096, 1152)]
    [InlineData(4096, 2304, 3840, 2160)]
    public void FrameSizePreservesAspectWithinProtocolLimit(
        int surfaceWidth,
        int surfaceHeight,
        int expectedWidth,
        int expectedHeight)
    {
        Assert.Equal(
            (expectedWidth, expectedHeight),
            VulkanOverlayFrameWriter.GetFrameSize(surfaceWidth, surfaceHeight));
    }
}
