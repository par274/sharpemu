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

internal sealed record ComparisonField(string Name, string? Before, string? After, string Status);

internal sealed record VisualComparisonReport(
    string SchemaVersion,
    string BeforeRun,
    string AfterRun,
    string Classification,
    bool StrictComparabilityProven,
    bool ExploratoryOverride,
    long? SelectedFrame,
    IReadOnlyList<ComparisonField> Fields,
    ImageDifference? PixelDifference,
    string PixelConclusion,
    string? AbsoluteDifference,
    string? ContactSheet,
    object? MetricDeltas,
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
                warnings.Add($"Failed to encode {Path.GetFileName(descriptorPath)}: {exception.GetType().Name}.");
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
                descriptor?.NearestMilestone,
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
        var captureFailed = frames.Count == 0 && warnings.Count > 0;
        var report = new VisualReport(
            "1.0.0",
            runId,
            DateTimeOffset.UtcNow,
            frames.Count == 0 ? captureFailed ? "capture-failed" : "not-observed" : "observed",
            frames.Count == 0 ? captureFailed ? "capture-failed" : "no-frame-produced" : string.Join('+', sources),
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
        var selectedFrame = arguments.Value("--frame");
        if (selectedFrame is not null && !long.TryParse(selectedFrame, out _)) return Program.Fail("visual compare --frame requires an integer frame number.");
        var frameNumber = long.TryParse(selectedFrame, out var parsedFrame) ? parsedFrame : (long?)null;
        var (result, exitCode) = await CompareRunsAsync(beforeDirectory, afterDirectory, frameNumber, arguments.Has("--exploratory"));
        if (arguments.Has("--json")) Program.WriteJson(result);
        else Console.WriteLine($"Visual comparison: {result.Classification}; pixels {(result.PixelDifference is null ? "not compared" : "compared for exploration/evidence only")}.");
        return exitCode;
    }

    internal static async Task<(VisualComparisonReport Report, int ExitCode)> CompareRunsAsync(
        string beforeDirectory,
        string afterDirectory,
        long? requestedFrame,
        bool exploratory)
    {
        var before = await AnalyzeRunAsync(beforeDirectory);
        var after = await AnalyzeRunAsync(afterDirectory);
        var fields = new List<ComparisonField>();
        var warnings = new List<string>();
        var pair = SelectFramePair(before.Frames, after.Frames, requestedFrame);
        if (pair is null)
        {
            warnings.Add(requestedFrame.HasValue
                ? $"Frame {requestedFrame.Value} with a matching capture source is not present in both runs."
                : "No common capture-source/frame-number pair exists; unlike first frames were not compared.");
            return (new VisualComparisonReport(
                "1.1.0", before.RunId, after.RunId, "not-comparable", false, exploratory, requestedFrame,
                fields, null, "No pixel comparison was performed and no correctness conclusion is available.", null, null, null, warnings), 2);
        }

        var (beforeFrame, afterFrame) = pair.Value;
        var beforeImage = PngCodec.Read(Path.Combine(beforeDirectory, beforeFrame.File));
        var afterImage = PngCodec.Read(Path.Combine(afterDirectory, afterFrame.File));
        var beforeMetadata = await ReadRunMetadataAsync(beforeDirectory);
        var afterMetadata = await ReadRunMetadataAsync(afterDirectory);
        AddField(fields, "target/profile identity", beforeMetadata.ProfileIdentity, afterMetadata.ProfileIdentity);
        AddField(fields, "capture source", beforeFrame.CaptureSource, afterFrame.CaptureSource);
        AddField(fields, "frame number", beforeFrame.FrameNumber?.ToString(), afterFrame.FrameNumber?.ToString());
        AddField(fields, "width", beforeImage.Width.ToString(), afterImage.Width.ToString());
        AddField(fields, "height", beforeImage.Height.ToString(), afterImage.Height.ToString());
        AddField(fields, "canonical pixel format", beforeFrame.CanonicalFormat, afterFrame.CanonicalFormat);
        AddField(fields, "capture policy", beforeMetadata.CapturePolicy, afterMetadata.CapturePolicy);
        var pixelFields = fields.Count;
        AddField(fields, "build configuration", beforeMetadata.BuildConfiguration, afterMetadata.BuildConfiguration);
        AddField(fields, "repository commit", beforeMetadata.RepositoryCommit, afterMetadata.RepositoryCommit);
        AddField(fields, "executable SHA-256", beforeMetadata.ExecutableSha256, afterMetadata.ExecutableSha256);
        AddField(fields, "hardware fingerprint", beforeMetadata.HardwareFingerprint, afterMetadata.HardwareFingerprint);
        AddField(fields, "GPU and driver", beforeMetadata.GpuAndDriver, afterMetadata.GpuAndDriver);

        var pixelComparable = fields.Take(pixelFields).All(field => field.Status == "matched");
        var strict = pixelComparable && fields.Skip(pixelFields).All(field => field.Status == "matched");
        var classification = strict
            ? "strictly-comparable"
            : pixelComparable ? "pixel-comparable-environment-unverified" : "not-comparable";
        ImageDifference? difference = null;
        string? differencePath = null;
        string? sheetPath = null;
        object? metricDeltas = null;
        var outputDirectory = Path.Combine(afterDirectory, "diffs", $"vs-{before.RunId}");
        Directory.CreateDirectory(outputDirectory);
        if (strict || exploratory && pixelComparable)
        {
            difference = VisualAnalyzer.Compare(beforeImage, afterImage);
            var absolute = VisualAnalyzer.AbsoluteDifference(beforeImage, afterImage);
            var differenceFullPath = Path.Combine(outputDirectory, $"frame-{beforeFrame.FrameNumber:D8}-absolute-difference.png");
            PngCodec.Write(differenceFullPath, absolute);
            differencePath = Path.GetRelativePath(afterDirectory, differenceFullPath).Replace('\\', '/');
            var sheetFullPath = Path.Combine(outputDirectory, $"frame-{beforeFrame.FrameNumber:D8}-comparison.png");
            PngCodec.Write(sheetFullPath, ContactSheet.Create(
                $"{before.RunId} VS {after.RunId}",
                [(beforeImage, $"BEFORE {beforeFrame.CaptureSource} F={beforeFrame.FrameNumber}"), (afterImage, $"AFTER {afterFrame.CaptureSource} F={afterFrame.FrameNumber}"), (absolute, $"PIXEL DIFF CHANGED={difference.ChangedPixelRatio:P2} MAD={difference.NormalizedMeanAbsoluteDifference:F4}")]));
            sheetPath = Path.GetRelativePath(afterDirectory, sheetFullPath).Replace('\\', '/');
            metricDeltas = new
            {
                meanLuminance = afterFrame.Metrics.MeanLuminance - beforeFrame.Metrics.MeanLuminance,
                luminanceStandardDeviation = afterFrame.Metrics.LuminanceStandardDeviation - beforeFrame.Metrics.LuminanceStandardDeviation,
                nearBlackPercent = afterFrame.Metrics.NearBlackPercent - beforeFrame.Metrics.NearBlackPercent,
            };
        }
        else if (pixelComparable)
        {
            warnings.Add("Pixel inputs align, but strict environment/build identity is not proven; use --exploratory to generate a non-correctness pixel comparison.");
        }

        var report = new VisualComparisonReport(
            "1.1.0", before.RunId, after.RunId, classification, strict, exploratory, beforeFrame.FrameNumber,
            fields, difference, "Pixel differences are evidence only and do not establish rendering correctness or compatibility.",
            differencePath, sheetPath, metricDeltas, warnings);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "comparison.json"), JsonSerializer.Serialize(report, Program.JsonOptions));
        return (report, strict || exploratory && pixelComparable ? 0 : 2);
    }

    private static (VisualFrame Before, VisualFrame After)? SelectFramePair(
        IReadOnlyList<VisualFrame> before,
        IReadOnlyList<VisualFrame> after,
        long? requestedFrame)
    {
        var pairs = from left in before
                    where left.FrameNumber.HasValue && (!requestedFrame.HasValue || left.FrameNumber == requestedFrame)
                    join right in after on new { Source = left.CaptureSource.ToUpperInvariant(), Frame = left.FrameNumber }
                        equals new { Source = right.CaptureSource.ToUpperInvariant(), Frame = right.FrameNumber }
                    orderby left.FrameNumber
                    select (left, right);
        foreach (var pair in pairs) return pair;
        return null;
    }

    private static void AddField(List<ComparisonField> fields, string name, string? before, string? after)
    {
        var status = string.IsNullOrWhiteSpace(before) || string.IsNullOrWhiteSpace(after)
            ? "missing"
            : string.Equals(before, after, StringComparison.OrdinalIgnoreCase) ? "matched" : "different";
        fields.Add(new ComparisonField(name, before, after, status));
    }

    private static async Task<RunComparisonMetadata> ReadRunMetadataAsync(string runDirectory)
    {
        using var run = await ReadJsonIfPresentAsync(Path.Combine(runDirectory, "run.json"));
        using var environment = await ReadJsonIfPresentAsync(Path.Combine(runDirectory, "environment.json"));
        using var config = await ReadJsonIfPresentAsync(Path.Combine(runDirectory, "harness-config.json"));
        var runRoot = run?.RootElement;
        var environmentRoot = environment?.RootElement;
        var profileIdentity = JoinIdentity(runRoot, "profile", "targetId", "expectedVersion", "verifiedVersion");
        var capturePolicy = config is not null && config.RootElement.TryGetProperty("capture", out var capture)
            ? CanonicalJson(capture)
            : null;
        var gpu = environmentRoot.HasValue && environmentRoot.Value.TryGetProperty("phaseZeroHardware", out var hardware) && hardware.TryGetProperty("gpus", out var gpus)
            ? CanonicalJson(gpus)
            : null;
        return new RunComparisonMetadata(
            profileIdentity,
            Property(runRoot, "buildConfiguration"),
            Property(runRoot, "repositorySha"),
            Property(runRoot, "executableSha256"),
            capturePolicy,
            Property(environmentRoot, "hardwareFingerprint"),
            gpu);
    }

    private static async Task<JsonDocument?> ReadJsonIfPresentAsync(string path) =>
        File.Exists(path) ? JsonDocument.Parse(await File.ReadAllTextAsync(path)) : null;

    private static string? JoinIdentity(JsonElement? root, params string[] names)
    {
        if (!root.HasValue) return null;
        var values = names.Select(name => Property(root, name)).ToArray();
        return values.Any(string.IsNullOrWhiteSpace) ? null : string.Join('|', values);
    }

    private static string? Property(JsonElement? root, string name) =>
        root.HasValue && root.Value.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string CanonicalJson(JsonElement element) => JsonSerializer.Serialize(element, Program.JsonOptions);

    private sealed record RunComparisonMetadata(
        string? ProfileIdentity,
        string? BuildConfiguration,
        string? RepositoryCommit,
        string? ExecutableSha256,
        string? CapturePolicy,
        string? HardwareFingerprint,
        string? GpuAndDriver);

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
