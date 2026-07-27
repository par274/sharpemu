// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal static class DoctorCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        var phaseZeroPath = Path.Combine(repository.LocalRoot, "reports", "phase-00-environment.json");
        JsonDocument? phaseZero = null;
        if (File.Exists(phaseZeroPath))
        {
            await using var stream = File.OpenRead(phaseZeroPath);
            phaseZero = await JsonDocument.ParseAsync(stream);
        }

        var dotnet = ProcessUtility.RunCapture("dotnet", ["--version"], repository.Root);
        var vulkanRuntime = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "vulkan-1.dll")
            : "vulkan";
        var configuration = arguments.Value("--configuration") ?? "Debug";
        var executable = FindEmulator(repository, configuration);
        var profilePath = arguments.Value("--profile") ?? Path.Combine(repository.LocalRoot, "profiles", "demons-souls-01.004.000.json");
        ProfileValidation? profile = null;
        if (File.Exists(profilePath))
        {
            (_, profile) = await ProfileLoader.LoadAndValidateAsync(repository, profilePath, verifyHash: false);
        }

        var gpuNames = ReadGpuNames(phaseZero);
        var isAmd = gpuNames.Any(name => name.Contains("AMD", StringComparison.OrdinalIgnoreCase) || name.Contains("Radeon", StringComparison.OrdinalIgnoreCase));
        var isNvidia = gpuNames.Any(name => name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase));
        var optionalTools = new[]
        {
            Tool("vulkaninfo", "vulkaninfo", true, "Vulkan capability and driver investigation"),
            Tool("spirv-val", "spirv-val", true, "shader validation"),
            Tool("spirv-dis", "spirv-dis", true, "SPIR-V inspection"),
            Tool("glslangValidator", "glslangValidator", true, "shader validation"),
            Tool("RenderDoc", "renderdoccmd", true, "frame-level Vulkan investigation"),
            Tool("Radeon GPU Analyzer", "rga", isAmd, "AMD shader investigation"),
            Tool("Radeon GPU Profiler", "rgp", isAmd, "AMD GPU timing investigation"),
            Tool("Radeon GPU Detective", "rgd", isAmd, "AMD GPU fault investigation"),
            Tool("OCAT", "OCAT", isAmd, "AMD frame pacing investigation"),
            Tool("Nsight Graphics", "ngfx", isNvidia, "NVIDIA frame and shader investigation"),
            Tool("Nsight Systems", "nsys", isNvidia, "NVIDIA system-wide timing investigation"),
            Tool("dotnet-trace", "dotnet-trace", true, ".NET runtime trace investigation"),
            Tool("dotnet-counters", "dotnet-counters", true, ".NET live counter investigation"),
            Tool("dotnet-dump", "dotnet-dump", true, ".NET crash dump investigation"),
        };
        var privateScan = ScanTrackedPrivateData(repository, phaseZero);
        var outputDirectoryWritable = EnsureWritable(repository.LocalRoot);
        var vulkanAvailable = !OperatingSystem.IsWindows() || File.Exists(vulkanRuntime);
        var driveRoot = Path.GetPathRoot(repository.Root)!;
        var drive = new DriveInfo(driveRoot);
        var report = new
        {
            schemaVersion = "1.0.0",
            generatedUtc = DateTimeOffset.UtcNow,
            repository = "<repo>",
            repository.Branch,
            commit = repository.Commit,
            dirty = repository.IsDirty,
            dotnetSdk = dotnet.ExitCode == 0 ? dotnet.Stdout.Trim() : null,
            build = new { configuration, executableAvailable = executable is not null, executable = executable is null ? null : "<repo>/" + GitRepository.NormalizeRelativePath(Path.GetRelativePath(repository.Root, executable)) },
            vulkan = new { available = vulkanAvailable, runtime = OperatingSystem.IsWindows() ? "<windows>/System32/vulkan-1.dll" : vulkanRuntime },
            gpu = gpuNames,
            optionalTools,
            profile,
            outputDirectoryWritable,
            disk = new { root = drive.Name, freeBytes = drive.AvailableFreeSpace },
            privateDataScan = new { passed = privateScan.Count == 0, matches = privateScan },
            status = dotnet.ExitCode == 0 && executable is not null && vulkanAvailable && outputDirectoryWritable && privateScan.Count == 0 ? "ready" : "attention-required",
        };
        var reportDirectory = Path.Combine(repository.LocalRoot, "reports");
        Directory.CreateDirectory(reportDirectory);
        var reportPath = Path.Combine(reportDirectory, "agent-harness-doctor.json");
        await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(report, Program.JsonOptions));
        if (arguments.Has("--json"))
        {
            Program.WriteJson(report);
        }
        else
        {
            Console.WriteLine($"Doctor: {report.status}");
            Console.WriteLine($"Branch {repository.Branch}, commit {repository.Commit[..12]}, SDK {report.dotnetSdk ?? "missing"}.");
            Console.WriteLine(executable is null ? "Emulator build: missing" : $"Emulator build: {report.build.executable}");
            Console.WriteLine($"Vulkan runtime: {(report.vulkan.available ? "available" : "missing")}");
            Console.WriteLine($"Private-data scan: {(privateScan.Count == 0 ? "passed" : "FAILED")}");
            Console.WriteLine($"Optional tools: {optionalTools.Count(tool => tool.Status == "available")} available, {optionalTools.Count(tool => tool.Status == "missing")} missing, {optionalTools.Count(tool => tool.Status == "unsupported-on-current-hardware")} unsupported on current hardware.");
            Console.WriteLine($"Report: {reportPath}");
        }
        phaseZero?.Dispose();
        return report.status == "ready" ? 0 : 2;
    }

    internal static string? FindEmulator(GitRepository repository, string configuration)
    {
        var candidates = new[]
        {
            Path.Combine(repository.Root, "artifacts", "bin", configuration, "net10.0", "win-x64", "SharpEmu.exe"),
            Path.Combine(repository.Root, "artifacts", "publish", "win-x64", "SharpEmu.exe"),
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static ToolStatus Tool(string name, string command, bool supported, string recommendation)
    {
        if (!supported) return new ToolStatus(name, "unsupported-on-current-hardware", null, recommendation);
        var result = ProcessUtility.RunCapture("where.exe", [command], Environment.CurrentDirectory, timeoutMilliseconds: 5_000);
        var path = result.ExitCode == 0 ? result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() : null;
        return new ToolStatus(name, path is null ? "missing" : "available", path, recommendation);
    }

    private static IReadOnlyList<string> ReadGpuNames(JsonDocument? phaseZero)
    {
        if (phaseZero is null ||
            !phaseZero.RootElement.TryGetProperty("hardware", out var hardware) ||
            !hardware.TryGetProperty("gpus", out var gpus)) return [];
        return gpus.EnumerateArray()
            .Select(gpu => gpu.TryGetProperty("model", out var model) ? model.GetString() : null)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Cast<string>()
            .ToArray();
    }

    private static List<string> ScanTrackedPrivateData(GitRepository repository, JsonDocument? phaseZero)
    {
        var needles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile)) needles.Add(userProfile);
        if (phaseZero is not null && phaseZero.RootElement.TryGetProperty("archive", out var archive) && archive.TryGetProperty("path", out var archivePath))
        {
            var value = archivePath.GetString();
            if (!string.IsNullOrWhiteSpace(value)) needles.Add(value);
        }
        var matches = new List<string>();
        foreach (var needle in needles)
        {
            var result = ProcessUtility.RunCapture("git", ["-C", repository.Root, "grep", "-I", "-l", "-F", needle, "--"], repository.Root);
            if (result.ExitCode == 0)
            {
                matches.AddRange(result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
            }
        }
        return matches.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool EnsureWritable(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var probe = Path.Combine(path, $".write-probe-{Environment.ProcessId}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private sealed record ToolStatus(string Name, string Status, string? Path, string RecommendedFor);
}
