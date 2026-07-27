// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Tools.AgentHarness.Tests;

public sealed class VisualTests
{
    [Fact]
    public void RawConversionHonorsBgraRowPitchAndVerticalOrientation()
    {
        byte[] raw =
        [
            30, 20, 10, 255, 60, 50, 40, 255, 0, 0, 0, 0,
            90, 80, 70, 255, 120, 110, 100, 255, 0, 0, 0, 0,
        ];

        var image = RgbaImage.FromRaw(2, 2, raw, "B8G8R8A8_UNORM", rowPitch: 12, flipVertical: true);

        Assert.Equal(new byte[] { 70, 80, 90, 255, 100, 110, 120, 255, 10, 20, 30, 255, 40, 50, 60, 255 }, image.Pixels);
    }

    [Fact]
    public void PngRoundTripPreservesExactRgbaPixels()
    {
        var image = SyntheticCommand.Checkerboard(17, 11, 0);
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        var path = System.IO.Path.Combine(directory, "roundtrip.png");
        try
        {
            PngCodec.Write(path, image);
            var decoded = PngCodec.Read(path);
            Assert.Equal(image.Width, decoded.Width);
            Assert.Equal(image.Height, decoded.Height);
            Assert.Equal(image.Pixels, decoded.Pixels);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void MetricsDetectBlankFrozenAndChangedFrames()
    {
        var black = new RgbaImage(8, 8, Enumerable.Range(0, 64).SelectMany(_ => new byte[] { 0, 0, 0, 255 }).ToArray());
        var checker = SyntheticCommand.Checkerboard(8, 8, 0);
        var shifted = SyntheticCommand.Checkerboard(8, 8, 1);

        Assert.True(VisualAnalyzer.Analyze(black, "hash").LikelyBlank);
        Assert.False(VisualAnalyzer.Analyze(checker, "hash").LikelyBlank);
        Assert.True(VisualAnalyzer.IsFrozen([checker, new RgbaImage(checker.Width, checker.Height, [.. checker.Pixels])]));
        Assert.False(VisualAnalyzer.IsFrozen([checker, shifted]));
        Assert.True(VisualAnalyzer.Compare(checker, shifted).ChangedPixelRatio > 0.9);
        Assert.Equal(checker.Pixels.Length, VisualAnalyzer.AbsoluteDifference(checker, shifted).Pixels.Length);
    }

    [Fact]
    public void ContactSheetHasDeterministicGeometry()
    {
        var image = SyntheticCommand.Checkerboard(32, 18, 0);
        var sheet = ContactSheet.Create("RUN", [(image, "FRAME ONE"), (image, "FRAME TWO"), (image, "FRAME THREE"), (image, "FRAME FOUR")]);
        Assert.Equal(960, sheet.Width);
        Assert.Equal(474, sheet.Height);
        Assert.All(sheet.Pixels.Where((_, index) => index % 4 == 3), alpha => Assert.Equal(255, alpha));
    }

    [Fact]
    public async Task VisualAnalysisAssociatesRawDescriptorWithEncodedPng()
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        var frames = System.IO.Path.Combine(directory, "frames");
        Directory.CreateDirectory(frames);
        try
        {
            var raw = new byte[] { 1, 2, 3, 255 };
            await File.WriteAllBytesAsync(System.IO.Path.Combine(frames, "native-00000001.raw"), raw);
            var descriptor = new RawFrameDescriptor(
                "native-00000001.raw", 1, 1, 4, "R8G8B8A8_UNORM", "emulator-native-final-frame", 1, 0.5,
                DateTimeOffset.UtcNow, "sRGB", false, "first-frame-available");
            await File.WriteAllTextAsync(
                System.IO.Path.Combine(frames, "native-00000001.raw.json"),
                System.Text.Json.JsonSerializer.Serialize(descriptor, Program.JsonOptions));

            var report = await VisualCommand.AnalyzeRunAsync(directory);

            var frame = Assert.Single(report.Frames);
            Assert.Equal("emulator-native-final-frame", frame.CaptureSource);
            Assert.Equal(1, frame.FrameNumber);
            Assert.Equal("R8G8B8A8_UNORM", frame.SourcePixelFormat);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
