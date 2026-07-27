// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record RawFrameDescriptor(
    string RawFile,
    int Width,
    int Height,
    int RowPitch,
    string Format,
    string CaptureSource,
    long? FrameNumber,
    double? ElapsedSeconds,
    DateTimeOffset UtcTimestamp,
    string? ColorSpace,
    bool FlipVertical,
    string? NearestMilestone);

internal sealed record VisualReport(
    string SchemaVersion,
    string RunId,
    DateTimeOffset GeneratedUtc,
    string FirstFrameStatus,
    string CaptureStatus,
    bool LikelyFrozenSequence,
    IReadOnlyList<VisualFrame> Frames,
    string? ContactSheet,
    IReadOnlyList<string> Warnings);

internal static class VisualCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (arguments.Count == 0) return Program.Fail("visual requires analyze or compare.");
        return arguments[0].ToLowerInvariant() switch
        {
            "analyze" => await AnalyzeCommandAsync(repository, arguments.Slice(1)),
            "compare" => await CompareCommandAsync(repository, arguments.Slice(1)),
            _ => Program.Fail($"Unknown visual command '{arguments[0]}'."),
        };
    }

    internal static async Task<VisualReport> AnalyzeRunAsync(string runDirectory)
    {
        Directory.CreateDirectory(runDirectory);
        var frameDirectory = Path.Combine(runDirectory, "frames");
        Directory.CreateDirectory(frameDirectory);
        var warnings = new List<string>();
        foreach (var descriptorPath in Directory.EnumerateFiles(frameDirectory, "*.raw.json").Order(StringComparer.Ordinal))
        {
            try
            {
                var descriptor = JsonSerializer.Deserialize<RawFrameDescriptor>(await File.ReadAllTextAsync(descriptorPath), Program.JsonOptions)
                    ?? throw new InvalidDataException("Raw descriptor is empty.");
                var rawPath = Path.Combine(frameDirectory, descriptor.RawFile);
                var image = RgbaImage.FromRaw(
                    descriptor.Width,
                    descriptor.Height,
                    await File.ReadAllBytesAsync(rawPath),
                    descriptor.Format,
                    descriptor.RowPitch,
                    descriptor.FlipVertical);
                PngCodec.Write(Path.ChangeExtension(descriptorPath, ".png"), image);
            }
            catch (Exception exception)
            {
                warnings.Add($"Failed to encode {Path.GetFileName(descriptorPath)}: {exception.Message}");
            }
        }

        var pngPaths = Directory.EnumerateFiles(frameDirectory, "*.png").Order(StringComparer.Ordinal).ToArray();
        var images = new List<RgbaImage>(pngPaths.Length);
        var frames = new List<VisualFrame>(pngPaths.Length);
        for (var index = 0; index < pngPaths.Length; index++)
        {
            var pngPath = pngPaths[index];
            var image = PngCodec.Read(pngPath);
            images.Add(image);
            var descriptorPath = Path.ChangeExtension(pngPath, ".json");
            RawFrameDescriptor? descriptor = null;
            if (File.Exists(descriptorPath))
            {
                descriptor = JsonSerializer.Deserialize<RawFrameDescriptor>(await File.ReadAllTextAsync(descriptorPath), Program.JsonOptions);
            }
            var metrics = VisualAnalyzer.Analyze(image, GitRepository.Sha256File(pngPath));
            var difference = index == 0 ? null : VisualAnalyzer.Compare(images[index - 1], image);
            var inferredSource = Path.GetFileName(pngPath).StartsWith("window-", StringComparison.OrdinalIgnoreCase)
                ? "window-fallback"
                : Path.GetFileName(pngPath).StartsWith("synthetic-", StringComparison.OrdinalIgnoreCase) ? "synthetic" : "unknown";
            frames.Add(new VisualFrame(
                Path.GetRelativePath(runDirectory, pngPath).Replace('\\', '/'),
                descriptor?.CaptureSource ?? inferredSource,
                descriptor?.FrameNumber,
                descriptor?.ElapsedSeconds,
                descriptor?.Format ?? (inferredSource == "synthetic" ? "generated RGBA8" : "unknown"),
                "RGBA8 PNG",
                descriptor?.ColorSpace,
                descriptor?.FlipVertical ?? false,
                "success",
                metrics,
                difference));
        }

        var runId = Path.GetFileName(Path.TrimEndingDirectorySeparator(runDirectory));
        string? contactSheetRelative = null;
        if (frames.Count > 0)
        {
            var sheetFrames = frames.Select((frame, index) =>
            {
                var label = $"{Path.GetFileName(frame.File)} {frame.CaptureSource} F={frame.FrameNumber?.ToString() ?? "?"} " +
                    $"L={frame.Metrics.MeanLuminance:F1} SD={frame.Metrics.LuminanceStandardDeviation:F1} BLACK={frame.Metrics.NearBlackPercent:F1}%";
                return (images[index], label);
            }).ToArray();
            var contactSheetPath = Path.Combine(runDirectory, "contact-sheet.png");
            PngCodec.Write(contactSheetPath, ContactSheet.Create(runId, sheetFrames));
            contactSheetRelative = "contact-sheet.png";
        }
        var sources = frames.Select(frame => frame.CaptureSource).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var report = new VisualReport(
            "1.0.0",
            runId,
            DateTimeOffset.UtcNow,
            frames.Count == 0 ? "not-observed" : "observed",
            frames.Count == 0 ? "no-frame-produced" : string.Join('+', sources),
            VisualAnalyzer.IsFrozen(images),
            frames,
            contactSheetRelative,
            warnings);
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "visual.json"), JsonSerializer.Serialize(report, Program.JsonOptions));
        return report;
    }

    private static async Task<int> AnalyzeCommandAsync(GitRepository repository, CommandArguments arguments)
    {
        var run = arguments.Value("--run");
        if (string.IsNullOrWhiteSpace(run)) return Program.Fail("visual analyze requires --run.");
        var directory = ResolveRun(repository, run);
        if (!Directory.Exists(directory)) return Program.Fail($"Run '{run}' was not found.");
        var report = await AnalyzeRunAsync(directory);
        if (arguments.Has("--json")) Program.WriteJson(report);
        else
        {
            Console.WriteLine($"Visual analysis: {report.Frames.Count} frame(s), status {report.CaptureStatus}.");
            if (report.ContactSheet is not null) Console.WriteLine(Path.Combine(directory, report.ContactSheet));
            foreach (var warning in report.Warnings) Console.WriteLine($"warning: {warning}");
        }
        return 0;
    }

    private static async Task<int> CompareCommandAsync(GitRepository repository, CommandArguments arguments)
    {
        var beforeValue = arguments.Value("--before");
        var afterValue = arguments.Value("--after");
        if (string.IsNullOrWhiteSpace(beforeValue) || string.IsNullOrWhiteSpace(afterValue)) return Program.Fail("visual compare requires --before and --after.");
        var beforeDirectory = ResolveRun(repository, beforeValue);
        var afterDirectory = ResolveRun(repository, afterValue);
        var before = await AnalyzeRunAsync(beforeDirectory);
        var after = await AnalyzeRunAsync(afterDirectory);
        if (before.Frames.Count == 0 || after.Frames.Count == 0) return Program.Fail("Both runs must contain at least one frame.");
        var beforeFrame = before.Frames[0];
        var afterFrame = after.Frames[0];
        var beforeImage = PngCodec.Read(Path.Combine(beforeDirectory, beforeFrame.File));
        var afterImage = PngCodec.Read(Path.Combine(afterDirectory, afterFrame.File));
        var sourceMatches = string.Equals(beforeFrame.CaptureSource, afterFrame.CaptureSource, StringComparison.OrdinalIgnoreCase);
        var resolutionMatches = beforeImage.Width == afterImage.Width && beforeImage.Height == afterImage.Height;
        var compatible = sourceMatches && resolutionMatches;
        ImageDifference? difference = null;
        string? differencePath = null;
        string? sheetPath = null;
        var outputDirectory = Path.Combine(afterDirectory, "diffs", $"vs-{before.RunId}");
        Directory.CreateDirectory(outputDirectory);
        if (resolutionMatches)
        {
            difference = VisualAnalyzer.Compare(beforeImage, afterImage);
            differencePath = Path.Combine(outputDirectory, "absolute-difference.png");
            PngCodec.Write(differencePath, VisualAnalyzer.AbsoluteDifference(beforeImage, afterImage));
            sheetPath = Path.Combine(outputDirectory, "comparison.png");
            PngCodec.Write(sheetPath, ContactSheet.Create(
                $"{before.RunId} VS {after.RunId}",
                [(beforeImage, $"BEFORE {beforeFrame.CaptureSource}"), (afterImage, $"AFTER {afterFrame.CaptureSource}"), (VisualAnalyzer.AbsoluteDifference(beforeImage, afterImage), $"DIFF CHANGED={difference.ChangedPixelRatio:P2} MAD={difference.NormalizedMeanAbsoluteDifference:F4}")]));
        }
        var result = new
        {
            schemaVersion = "1.0.0",
            beforeRun = before.RunId,
            afterRun = after.RunId,
            sourceMatches,
            resolutionMatches,
            hardwareAndBuildProfileCheck = "not-proven-by-image-data",
            compatible,
            warning = compatible ? null : "Runs are not directly comparable; capture source or resolution differs.",
            difference,
            absoluteDifference = differencePath,
            contactSheet = sheetPath,
            metricDeltas = new
            {
                meanLuminance = afterFrame.Metrics.MeanLuminance - beforeFrame.Metrics.MeanLuminance,
                luminanceStandardDeviation = afterFrame.Metrics.LuminanceStandardDeviation - beforeFrame.Metrics.LuminanceStandardDeviation,
                nearBlackPercent = afterFrame.Metrics.NearBlackPercent - beforeFrame.Metrics.NearBlackPercent,
            },
        };
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "comparison.json"), JsonSerializer.Serialize(result, Program.JsonOptions));
        if (arguments.Has("--json")) Program.WriteJson(result); else Console.WriteLine(sheetPath ?? result.warning);
        return compatible ? 0 : 2;
    }

    private static string ResolveRun(GitRepository repository, string value)
    {
        if (Path.IsPathFullyQualified(value)) return Path.GetFullPath(value);
        var direct = repository.ResolvePath(value);
        if (Directory.Exists(direct)) return direct;
        return Path.Combine(repository.LocalRoot, "runs", value);
    }
}

internal static class SyntheticCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (!arguments.Is("visual")) return Program.Fail("synthetic requires visual.");
        var output = arguments.Value("--output") ?? Path.Combine(repository.LocalRoot, "runs", $"synthetic-{DateTime.UtcNow:yyyyMMddTHHmmssZ}");
        output = Path.IsPathFullyQualified(output) ? Path.GetFullPath(output) : repository.ResolvePath(output);
        var frames = Path.Combine(output, "frames");
        Directory.CreateDirectory(frames);
        var first = Checkerboard(128, 72, shift: 0);
        var second = Checkerboard(128, 72, shift: 1);
        PngCodec.Write(Path.Combine(frames, "synthetic-0001.png"), first);
        PngCodec.Write(Path.Combine(frames, "synthetic-0002.png"), second);
        var report = await VisualCommand.AnalyzeRunAsync(output);
        if (arguments.Has("--json")) Program.WriteJson(report);
        else
        {
            Console.WriteLine($"Synthetic visual validation passed: {report.Frames.Count} frames, frozen={report.LikelyFrozenSequence}.");
            Console.WriteLine(Path.Combine(output, report.ContactSheet!));
        }
        return report.Frames.Count == 2 && !report.LikelyFrozenSequence ? 0 : 2;
    }

    internal static RgbaImage Checkerboard(int width, int height, int shift)
    {
        var pixels = new byte[width * height * 4];
        for (var y = 0; y < height; y++)
        {
            for (var x = 0; x < width; x++)
            {
                var offset = (y * width + x) * 4;
                var checker = ((x / 8 + y / 8 + shift) & 1) == 0;
                pixels[offset] = checker ? (byte)240 : (byte)(x * 255 / Math.Max(1, width - 1));
                pixels[offset + 1] = checker ? (byte)(y * 255 / Math.Max(1, height - 1)) : (byte)32;
                pixels[offset + 2] = checker ? (byte)40 : (byte)220;
                pixels[offset + 3] = 255;
            }
        }
        return new RgbaImage(width, height, pixels);
    }
}
