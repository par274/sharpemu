// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal static class RunCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        var profileValue = arguments.Value("--profile");
        if (string.IsNullOrWhiteSpace(profileValue)) return Program.Fail("run requires --profile.");
        var (profile, validation) = await ProfileLoader.LoadAndValidateAsync(repository, profileValue);
        if (profile is null || !validation.Valid)
        {
            foreach (var error in validation.Errors) Console.Error.WriteLine($"profile: {error}");
            return 2;
        }

        var executable = !string.IsNullOrWhiteSpace(profile.EmulatorExecutable)
            ? (Path.IsPathFullyQualified(profile.EmulatorExecutable) ? Path.GetFullPath(profile.EmulatorExecutable) : repository.ResolvePath(profile.EmulatorExecutable))
            : DoctorCommand.FindEmulator(repository, profile.BuildConfiguration);
        if (executable is null || !File.Exists(executable)) return Program.Fail($"SharpEmu {profile.BuildConfiguration} executable is missing; build the solution first.");

        var shortCommit = repository.Commit[..12];
        var runId = $"{DateTime.UtcNow:yyyyMMddTHHmmss.fffZ}-{shortCommit}-{Sanitize(profile.ExpectedTitleId)}";
        var runDirectory = Path.Combine(repository.LocalRoot, "runs", runId);
        var frameDirectory = Path.Combine(runDirectory, "frames");
        Directory.CreateDirectory(frameDirectory);
        Directory.CreateDirectory(Path.Combine(runDirectory, "diffs"));
        var eventsPath = Path.Combine(runDirectory, "events.jsonl");
        var stdoutPath = Path.Combine(runDirectory, "stdout.log");
        var stderrPath = Path.Combine(runDirectory, "stderr.log");
        var emulatorLogPath = Path.Combine(runDirectory, "emulator.log");
        var harnessConfigPath = Path.Combine(runDirectory, "harness-config.json");
        await File.WriteAllTextAsync(eventsPath, string.Empty);

        var ebootPath = Path.GetFullPath(profile.EbootPath);
        var redactionRoots = profile.RedactionRoots
            .Append(Path.GetDirectoryName(ebootPath)!)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var harnessConfig = new
        {
            schemaVersion = "1.0.0",
            eventsPath,
            rawFrameDirectory = frameDirectory,
            redactionRoots,
            capture = new
            {
                enabled = profile.Capture.NativeEnabled,
                profile.Capture.FirstFrame,
                profile.Capture.FrameNumbers,
                profile.Capture.Interval,
                profile.Capture.MaxFrames,
            },
        };
        await File.WriteAllTextAsync(harnessConfigPath, JsonSerializer.Serialize(harnessConfig, Program.JsonOptions));

        var emulatorArguments = new List<string>(profile.EmulatorArguments);
        if (profile.ImportTraceLimit > 0 && !ContainsOption(emulatorArguments, "--trace-imports")) emulatorArguments.Add($"--trace-imports={profile.ImportTraceLimit}");
        if (!ContainsOption(emulatorArguments, "--log-level")) emulatorArguments.Add($"--log-level={profile.LogLevel}");
        if (!ContainsOption(emulatorArguments, "--log-file")) emulatorArguments.Add($"--log-file={emulatorLogPath}");
        emulatorArguments.Add($"--harness-config={harnessConfigPath}");
        emulatorArguments.Add(ebootPath);

        var environment = new Dictionary<string, string?>(profile.Environment, StringComparer.OrdinalIgnoreCase);
        var environmentReport = await WriteEnvironmentAsync(repository, runDirectory, profile.BuildConfiguration);
        var preliminary = new
        {
            schemaVersion = "1.0.0",
            runId,
            status = "running",
            profile = $"<local-profile>/{Path.GetFileName(profileValue)}",
            repositorySha = repository.Commit,
            dirty = repository.IsDirty,
            buildConfiguration = profile.BuildConfiguration,
            executableSha256 = GitRepository.Sha256File(executable),
            targetId = profile.ExpectedTitleId,
            expectedVersion = profile.ExpectedVersion,
            verifiedVersion = profile.Metadata.VerifiedVersion,
            versionStatus = profile.Metadata.VersionStatus,
            commandArguments = RedactArguments(emulatorArguments, redactionRoots),
            startUtc = DateTimeOffset.UtcNow,
        };
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "run.json"), JsonSerializer.Serialize(preliminary, Program.JsonOptions));

        var sampledWindowSeconds = new HashSet<int>();
        var windowStatuses = new List<string>();
        async Task Sample(Process process, TimeSpan elapsed)
        {
            if (!profile.Capture.WindowFallbackEnabled || profile.Capture.WindowSampleSeconds.Count == 0) return;
            foreach (var second in profile.Capture.WindowSampleSeconds.Where(second => second >= 0 && elapsed.TotalSeconds >= second))
            {
                if (!sampledWindowSeconds.Add(second)) continue;
                if (Directory.EnumerateFiles(frameDirectory, "native-*.raw.json").Any()) continue;
                var existing = Directory.EnumerateFiles(frameDirectory, "*.raw.json").Count();
                if (existing >= profile.Capture.MaxFrames) continue;
                var captured = WindowCapture.TryCaptureClientArea(process, frameDirectory, existing + 1, elapsed.TotalSeconds, out var status);
                windowStatuses.Add($"t={second}s:{status}");
                if (!captured) await Task.CompletedTask;
            }
        }

        BoundedProcessResult processResult;
        try
        {
            processResult = await BoundedProcessRunner.RunAsync(
                executable,
                emulatorArguments,
                Path.GetDirectoryName(executable)!,
                environment,
                TimeSpan.FromSeconds(profile.TimeoutSeconds),
                stdoutPath,
                stderrPath,
                Sample);
        }
        catch (Exception exception)
        {
            await RunArtifactRedactor.RedactAsync(runDirectory, redactionRoots);
            var failed = new
            {
                schemaVersion = "1.0.0",
                runId,
                status = "launch-failed",
                error = exception.Message,
                repositorySha = repository.Commit,
                dirty = repository.IsDirty,
                targetId = profile.ExpectedTitleId,
                warnings = validation.Warnings,
                blockers = new[] { "environment: emulator process could not be launched" },
            };
            await File.WriteAllTextAsync(Path.Combine(runDirectory, "run.json"), JsonSerializer.Serialize(failed, Program.JsonOptions));
            Console.Error.WriteLine($"Run {runId} failed to launch: {exception.Message}");
            return 3;
        }

        await RunArtifactRedactor.RedactAsync(runDirectory, redactionRoots);
        var visual = await VisualCommand.AnalyzeRunAsync(runDirectory);
        var events = await ReadEventsAsync(eventsPath);
        var milestoneValues = events.Select(item => item.Milestone).Where(value => value.HasValue).Select(value => value!.Value).ToArray();
        var firstMilestone = milestoneValues.Length == 0 ? 0 : milestoneValues.Min();
        var highestMilestone = milestoneValues.Length == 0 ? 0 : milestoneValues.Max();
        var hasHostException = events.Any(item => string.Equals(item.Kind, "host.exception", StringComparison.OrdinalIgnoreCase));
        var exitStatus = processResult.TimedOut
            ? "timeout"
            : hasHostException || processResult.Crash
                ? "emulator-crash"
                : processResult.ExitCode == 0 ? "clean-exit" : "guest-failure";
        var blocker = ClassifyBlocker(events, processResult, visual, highestMilestone);
        var metrics = new
        {
            schemaVersion = "1.0.0",
            wallSeconds = processResult.ElapsedSeconds,
            processCpuSeconds = processResult.CpuSeconds,
            peakWorkingSetBytes = processResult.PeakWorkingSetBytes,
            resourceMeasurementScope = processResult.ResourceMeasurementScope,
        };
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "metrics.json"), JsonSerializer.Serialize(metrics, Program.JsonOptions));
        var warnings = validation.Warnings
            .Concat(processResult.Warnings)
            .Concat(windowStatuses.Select(value => "window-fallback: " + value))
            .ToArray();
        var result = new
        {
            schemaVersion = "1.0.0",
            runId,
            profile = $"<local-profile>/{Path.GetFileName(profileValue)}",
            repositorySha = repository.Commit,
            dirty = repository.IsDirty,
            buildConfiguration = profile.BuildConfiguration,
            executableSha256 = preliminary.executableSha256,
            targetId = profile.ExpectedTitleId,
            expectedVersion = profile.ExpectedVersion,
            verifiedVersion = profile.Metadata.VerifiedVersion,
            versionStatus = profile.Metadata.VersionStatus,
            commandArguments = preliminary.commandArguments,
            processResult.StartUtc,
            processResult.EndUtc,
            elapsedSeconds = processResult.ElapsedSeconds,
            exitCode = processResult.ExitCode,
            exitStatus,
            timedOut = processResult.TimedOut,
            crash = hasHostException || processResult.Crash,
            processTree = new { processResult.JobObjectOwned, processResult.ProcessTreeCleaned },
            firstObservedMilestone = firstMilestone,
            highestObservedMilestone = highestMilestone,
            firstFrameStatus = visual.FirstFrameStatus,
            captureStatus = visual.CaptureStatus,
            artifacts = new
            {
                run = "run.json",
                environment = "environment.json",
                events = "events.jsonl",
                stdout = "stdout.log",
                stderr = "stderr.log",
                emulatorLog = File.Exists(emulatorLogPath) ? "emulator.log" : null,
                metrics = "metrics.json",
                frames = "frames/",
                visual = "visual.json",
                contactSheet = visual.ContactSheet,
            },
            environmentFingerprint = environmentReport.Fingerprint,
            warnings,
            blockers = new[] { blocker },
            nextRunCommand = $".\\scripts\\agent-harness.ps1 run --profile .local\\profiles\\{Path.GetFileName(profileValue)}",
        };
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "run.json"), JsonSerializer.Serialize(result, Program.JsonOptions));
        Console.WriteLine($"Run ID: {runId}");
        Console.WriteLine($"Exit: {exitStatus}; elapsed {processResult.ElapsedSeconds:F1}s; highest milestone {highestMilestone}.");
        Console.WriteLine($"Frames: {visual.Frames.Count}; capture {visual.CaptureStatus}.");
        Console.WriteLine($"Blocker: {blocker}");
        Console.WriteLine(runDirectory);
        return processResult.TimedOut ? 124 : processResult.ExitCode ?? 3;
    }

    private static bool ContainsOption(IReadOnlyList<string> arguments, string option) =>
        arguments.Any(argument => string.Equals(argument, option, StringComparison.OrdinalIgnoreCase) || argument.StartsWith(option + "=", StringComparison.OrdinalIgnoreCase));

    private static string[] RedactArguments(IEnumerable<string> arguments, IReadOnlyList<string> roots) =>
        arguments.Select(argument => Redact(argument, roots)).ToArray();

    private static string Redact(string value, IReadOnlyList<string> roots)
    {
        var redacted = value;
        for (var index = 0; index < roots.Count; index++) redacted = redacted.Replace(roots[index], $"<private-root-{index + 1}>", StringComparison.OrdinalIgnoreCase);
        return redacted;
    }

    private static string Sanitize(string value) => new(value.Select(character => char.IsLetterOrDigit(character) || character is '-' or '_' ? character : '-').ToArray());

    private static async Task<(string Fingerprint, object Report)> WriteEnvironmentAsync(GitRepository repository, string runDirectory, string configuration)
    {
        var phaseZeroPath = Path.Combine(repository.LocalRoot, "reports", "phase-00-environment.json");
        JsonElement? phaseZeroWindows = null;
        JsonElement? phaseZeroHardware = null;
        JsonDocument? document = null;
        if (File.Exists(phaseZeroPath))
        {
            document = JsonDocument.Parse(await File.ReadAllTextAsync(phaseZeroPath));
            if (document.RootElement.TryGetProperty("windows", out var windows)) phaseZeroWindows = windows.Clone();
            if (document.RootElement.TryGetProperty("hardware", out var hardware)) phaseZeroHardware = hardware.Clone();
        }
        var fingerprintBasis = new
        {
            os = Environment.OSVersion.ToString(),
            architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            framework = RuntimeInformation.FrameworkDescription,
            configuration,
            phaseZeroWindows,
            phaseZeroHardware,
        };
        var fingerprintJson = JsonSerializer.Serialize(fingerprintBasis, Program.JsonOptions);
        var fingerprint = GitRepository.Sha256Bytes(System.Text.Encoding.UTF8.GetBytes(fingerprintJson));
        var report = new
        {
            schemaVersion = "1.0.0",
            generatedUtc = DateTimeOffset.UtcNow,
            fingerprintBasis.os,
            fingerprintBasis.architecture,
            fingerprintBasis.framework,
            fingerprintBasis.configuration,
            hardwareFingerprint = fingerprint,
            fingerprintBasis.phaseZeroWindows,
            fingerprintBasis.phaseZeroHardware,
        };
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "environment.json"), JsonSerializer.Serialize(report, Program.JsonOptions));
        document?.Dispose();
        return (fingerprint, report);
    }

    private static async Task<IReadOnlyList<HarnessEvent>> ReadEventsAsync(string path)
    {
        var events = new List<HarnessEvent>();
        foreach (var line in await File.ReadAllLinesAsync(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                events.Add(new HarnessEvent(
                    root.TryGetProperty("kind", out var kind) ? kind.GetString() ?? "unknown" : "unknown",
                    root.TryGetProperty("milestone", out var milestone) && milestone.TryGetInt32(out var value) ? value : null));
            }
            catch (JsonException)
            {
            }
        }
        return events;
    }

    private static string ClassifyBlocker(IReadOnlyList<HarnessEvent> events, BoundedProcessResult process, VisualReport visual, int milestone)
    {
        if (process.TimedOut) return "loader/runtime: hard timeout reached; inspect the last structured event";
        if (events.Any(item => item.Kind == "import.resolution-failed")) return "loader/runtime: unresolved import";
        if (events.Any(item => item.Kind == "shader.translation-failed")) return "graphics: shader translation failed";
        if (events.Any(item => item.Kind == "host.exception") || process.Crash) return "loader/runtime: unhandled host exception or abnormal emulator exit";
        if (visual.Frames.Count == 0 && milestone < 10) return "no-frame: no host frame was observed before execution ended";
        if (visual.Frames.Count > 0 && visual.Frames.All(frame => frame.Metrics.LikelyBlank)) return "graphics: captured frames are likely blank";
        return process.ExitCode == 0 ? "none: clean exit" : "loader/runtime: guest execution returned failure";
    }

    private sealed record HarnessEvent(string Kind, int? Milestone);
}
