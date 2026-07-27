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

    [Fact]
    public async Task VisualEncodingFailureDoesNotPersistPrivateExceptionDetails()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        var frames = Path.Combine(directory, "frames");
        Directory.CreateDirectory(frames);
        try
        {
            var privatePath = Path.Combine(directory, "private-input", "missing.raw");
            var descriptor = new RawFrameDescriptor(
                privatePath, 1, 1, 4, "R8G8B8A8_UNORM", "synthetic", 1, 0.5,
                DateTimeOffset.UtcNow, "sRGB", false, null);
            await File.WriteAllTextAsync(
                Path.Combine(frames, "invalid.raw.json"),
                System.Text.Json.JsonSerializer.Serialize(descriptor, Program.JsonOptions));

            var report = await VisualCommand.AnalyzeRunAsync(directory);

            Assert.Equal("capture-failed", report.CaptureStatus);
            var warning = Assert.Single(report.Warnings);
            Assert.DoesNotContain(privatePath, warning, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith("Exception.", warning, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task MatchingRunsAreStrictlyComparable()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync();
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, requestedFrame: null, exploratory: false);
        Assert.Equal(0, exitCode);
        Assert.Equal("strictly-comparable", report.Classification);
        Assert.True(report.StrictComparabilityProven);
        Assert.NotNull(report.PixelDifference);
    }

    [Theory]
    [InlineData("repositorySha", "different-commit")]
    [InlineData("executableSha256", "different-executable")]
    [InlineData("buildConfiguration", "Release")]
    public async Task BuildIdentityDifferencesAreNotStrictlyComparable(string property, string value)
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterRunOverrides: new Dictionary<string, string> { [property] = value });
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: false);
        Assert.Equal(2, exitCode);
        Assert.Equal("pixel-comparable-environment-unverified", report.Classification);
        Assert.Null(report.PixelDifference);
    }

    [Fact]
    public async Task DifferentHardwareIsNotStrictlyComparable()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterHardwareFingerprint: "hardware-b");
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: false);
        Assert.Equal(2, exitCode);
        Assert.Equal("pixel-comparable-environment-unverified", report.Classification);
    }

    [Fact]
    public async Task DifferentProfileIsNotPixelComparable()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterRunOverrides: new Dictionary<string, string> { ["profile"] = "profile-b" });
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: false);
        Assert.Equal(2, exitCode);
        Assert.Equal("not-comparable", report.Classification);
    }

    [Fact]
    public async Task DifferentCapturePolicyIsNotPixelComparable()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterCaptureInterval: 30);
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: false);
        Assert.Equal(2, exitCode);
        Assert.Equal("not-comparable", report.Classification);
    }

    [Fact]
    public async Task MissingEnvironmentMetadataCannotBeStrict()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(omitAfterEnvironment: true);
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: false);
        Assert.Equal(2, exitCode);
        Assert.Equal("pixel-comparable-environment-unverified", report.Classification);
        Assert.Contains(report.Fields, field => field.Name == "hardware fingerprint" && field.Status == "missing");
    }

    [Fact]
    public async Task MismatchedFrameNumbersAreNotSilentlyCompared()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterFrame: 2);
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, null, exploratory: true);
        Assert.Equal(2, exitCode);
        Assert.Equal("not-comparable", report.Classification);
        Assert.Null(report.PixelDifference);
    }

    [Fact]
    public async Task ExploratoryOverridePermitsPixelsWithoutCorrectnessConclusion()
    {
        using var fixture = await VisualComparisonFixture.CreateAsync(afterRunOverrides: new Dictionary<string, string> { ["repositorySha"] = "different-commit" });
        var (report, exitCode) = await VisualCommand.CompareRunsAsync(fixture.Before, fixture.After, requestedFrame: 1, exploratory: true);
        Assert.Equal(0, exitCode);
        Assert.Equal("pixel-comparable-environment-unverified", report.Classification);
        Assert.NotNull(report.PixelDifference);
        Assert.Contains("do not establish", report.PixelConclusion, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class VisualComparisonFixture : IDisposable
    {
        private VisualComparisonFixture(string root)
        {
            Root = root;
            Before = Path.Combine(root, "before");
            After = Path.Combine(root, "after");
        }

        public string Root { get; }
        public string Before { get; }
        public string After { get; }

        public static async Task<VisualComparisonFixture> CreateAsync(
            IReadOnlyDictionary<string, string>? afterRunOverrides = null,
            string afterHardwareFingerprint = "hardware-a",
            int afterCaptureInterval = 0,
            bool omitAfterEnvironment = false,
            long afterFrame = 1)
        {
            var fixture = new VisualComparisonFixture(Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N")));
            Directory.CreateDirectory(fixture.Before);
            Directory.CreateDirectory(fixture.After);
            await WriteFrameAsync(fixture.Before, 1, 0);
            await WriteFrameAsync(fixture.After, afterFrame, 1);
            await WriteRunMetadataAsync(fixture.Before, null, "hardware-a", 0, omitEnvironment: false);
            await WriteRunMetadataAsync(fixture.After, afterRunOverrides, afterHardwareFingerprint, afterCaptureInterval, omitAfterEnvironment);
            return fixture;
        }

        private static async Task WriteFrameAsync(string run, long frameNumber, int shift)
        {
            var frames = Path.Combine(run, "frames");
            Directory.CreateDirectory(frames);
            var image = SyntheticCommand.Checkerboard(8, 8, shift);
            var rawName = $"native-{frameNumber:D8}.raw";
            await File.WriteAllBytesAsync(Path.Combine(frames, rawName), image.Pixels);
            var descriptor = new RawFrameDescriptor(rawName, image.Width, image.Height, image.Stride, "R8G8B8A8_UNORM", "emulator-native-final-frame", frameNumber, 1.0, DateTimeOffset.UtcNow, "sRGB", false, "first-host-frame");
            await File.WriteAllTextAsync(Path.Combine(frames, rawName + ".json"), System.Text.Json.JsonSerializer.Serialize(descriptor, Program.JsonOptions));
        }

        private static async Task WriteRunMetadataAsync(
            string run,
            IReadOnlyDictionary<string, string>? overrides,
            string hardwareFingerprint,
            int captureInterval,
            bool omitEnvironment)
        {
            var values = new Dictionary<string, string>
            {
                ["profile"] = "profile-a",
                ["targetId"] = "TARGET00001",
                ["expectedVersion"] = "01.000.000",
                ["verifiedVersion"] = "01.000.000",
                ["buildConfiguration"] = "Debug",
                ["repositorySha"] = "commit-a",
                ["executableSha256"] = "executable-a",
            };
            if (overrides is not null) foreach (var pair in overrides) values[pair.Key] = pair.Value;
            await File.WriteAllTextAsync(Path.Combine(run, "run.json"), System.Text.Json.JsonSerializer.Serialize(values, Program.JsonOptions));
            await File.WriteAllTextAsync(Path.Combine(run, "harness-config.json"), System.Text.Json.JsonSerializer.Serialize(new { capture = new { enabled = true, firstFrame = true, frameNumbers = Array.Empty<long>(), interval = captureInterval, maxFrames = 8 } }, Program.JsonOptions));
            if (!omitEnvironment)
            {
                await File.WriteAllTextAsync(Path.Combine(run, "environment.json"), System.Text.Json.JsonSerializer.Serialize(new
                {
                    hardwareFingerprint,
                    phaseZeroHardware = new { gpus = new[] { new { model = "Synthetic GPU", driver = "1.0" } } },
                }, Program.JsonOptions));
            }
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
