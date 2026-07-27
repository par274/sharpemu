// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness.Tests;

public sealed class SafetyTests
{
    [Fact]
    public void SkillFrontmatterRequiresExactNameAndPreciseDescription()
    {
        var errors = new List<string>();
        SkillCommand.ValidateFrontmatter(
            "example-skill",
            "---\nname: example-skill\ndescription: Use for a precise bounded workflow, and do not use for unrelated requests.\n---\n# Example\n",
            errors);
        Assert.Empty(errors);

        SkillCommand.ValidateFrontmatter("other-name", "---\nname: wrong\ndescription: short\n---\n", errors);
        Assert.NotEmpty(errors);
    }

    [Fact]
    public void RunArtifactRedactionHandlesPlainAndJsonEncodedRoots()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "private", "game"));
        var jsonRoot = System.Text.Json.JsonEncodedText.Encode(root).ToString();
        var redacted = RunArtifactRedactor.RedactText($"plain={root}\njson={jsonRoot}", [root]);
        Assert.DoesNotContain(root, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(jsonRoot, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, redacted.Split("<private-root-1>", StringSplitOptions.None).Length - 1);
    }

    [Theory]
    [InlineData("..\\escape.bin")]
    [InlineData("C:\\escape.bin")]
    [InlineData("\\\\server\\share\\escape.bin")]
    [InlineData("safe\\stream:secret")]
    public void ArchiveValidatorRejectsUnsafePaths(string path) => Assert.NotNull(GameInputCommand.ValidateArchivePath(path));

    [Fact]
    public void ArchiveValidatorAcceptsOrdinaryRelativePath()
    {
        Assert.Null(GameInputCommand.ValidateArchivePath("game\\sce_sys\\param.json"));
        Assert.NotNull(GameInputCommand.ValidateArchivePath("game\\link", "reparse"));
        Assert.False(GameInputCommand.HasArchiveLinkTarget("Symbolic Link = "));
        Assert.False(GameInputCommand.HasArchiveLinkTarget("Hard Link =    "));
        Assert.True(GameInputCommand.HasArchiveLinkTarget("Symbolic Link = ..\\target"));
    }

    [Fact]
    public async Task TimeoutTerminatesTheWindowsProcessTree()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var pidPath = System.IO.Path.Combine(directory, "child.pid");
        var stdout = System.IO.Path.Combine(directory, "stdout.log");
        var stderr = System.IO.Path.Combine(directory, "stderr.log");
        var script = $"$child = Start-Process powershell.exe -PassThru -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30'; Set-Content -LiteralPath '{pidPath.Replace("'", "''", StringComparison.Ordinal)}' -Value $child.Id; Start-Sleep -Seconds 30";
        try
        {
            var result = await BoundedProcessRunner.RunAsync(
                "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-Command", script],
                directory,
                new Dictionary<string, string?>(),
                TimeSpan.FromSeconds(2),
                stdout,
                stderr);

            Assert.True(result.TimedOut);
            Assert.True(result.JobObjectOwned);
            Assert.True(result.ProcessTreeCleaned);
            Assert.Equal(0u, result.ActiveProcessCountAfterCleanup);
            Assert.Equal("windows-job-object-process-tree", result.ResourceMeasurementScope);
            Assert.True(File.Exists(pidPath));
            var childPid = int.Parse((await File.ReadAllTextAsync(pidPath)).Trim());
            await Task.Delay(250);
            Assert.Throws<ArgumentException>(() => Process.GetProcessById(childPid));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CancellationTerminatesImmediateChildAndIsNotReportedAsTimeout()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var pidPath = Path.Combine(directory, "child.pid");
        try
        {
            var script = $"$child = Start-Process powershell.exe -PassThru -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30'; Set-Content -LiteralPath '{pidPath.Replace("'", "''", StringComparison.Ordinal)}' -Value $child.Id; Start-Sleep -Seconds 30";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            var result = await BoundedProcessRunner.RunAsync(
                "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-Command", script],
                directory,
                new Dictionary<string, string?>(),
                TimeSpan.FromSeconds(10),
                Path.Combine(directory, "stdout.log"),
                Path.Combine(directory, "stderr.log"),
                cancellationToken: cancellation.Token);
            Assert.True(result.Canceled);
            Assert.False(result.TimedOut);
            Assert.True(result.ProcessTreeCleaned);
            Assert.Equal(0u, result.ActiveProcessCountAfterCleanup);
            Assert.True(File.Exists(pidPath));
            var childPid = int.Parse((await File.ReadAllTextAsync(pidPath)).Trim());
            Assert.Throws<ArgumentException>(() => Process.GetProcessById(childPid));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void WindowsArgumentQuotingPreservesSpacesQuotesAndTrailingSlashes()
    {
        Assert.Equal("plain", WindowsSuspendedProcess.QuoteArgument("plain"));
        Assert.Equal("\"two words\"", WindowsSuspendedProcess.QuoteArgument("two words"));
        Assert.Equal("\"quoted\\\"value\"", WindowsSuspendedProcess.QuoteArgument("quoted\"value"));
        Assert.Equal("\"C:\\path with space\\\\\"", WindowsSuspendedProcess.QuoteArgument("C:\\path with space\\"));
    }

    [Fact]
    public async Task MalformedEventsAreCountedWithSafeLineCategories()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "events.jsonl");
        try
        {
            await File.WriteAllLinesAsync(path,
            [
                "{\"kind\":\"metadata.loaded\",\"milestone\":1}",
                "not-json private-value",
                "[]",
                "{\"milestone\":2}",
                "{\"kind\":\"bad\",\"milestone\":\"two\"}",
            ]);
            var evidence = await RunCommand.ReadEventsAsync(path);
            Assert.Single(evidence.Events);
            Assert.Equal(4, evidence.ParseErrorCount);
            Assert.Equal(new[] { 2, 3, 4, 5 }, evidence.ParseErrors.Select(error => error.Line));
            Assert.Equal(new[] { "invalid-json", "non-object-json", "missing-or-invalid-kind", "invalid-milestone" }, evidence.ParseErrors.Select(error => error.Category));
            Assert.DoesNotContain(evidence.ParseErrors, error => error.Category.Contains("private-value", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RedactionUsesStandardTokensAndSanitizesFailureArtifacts()
    {
        using var fixture = TemporaryGitRepository.Create();
        var repository = GitRepository.Discover(fixture.Path);
        var privateRoot = Path.Combine(fixture.Path, "private", "games", "TARGET", "VERSION");
        var run = Path.Combine(fixture.Path, ".local", "runs", "failed");
        Directory.CreateDirectory(run);
        var map = RunArtifactRedactor.CreateStandardMap(repository, [privateRoot]);
        var originalInput = Path.Combine(privateRoot, "eboot.bin");
        Directory.CreateDirectory(privateRoot);
        await File.WriteAllTextAsync(originalInput, "private-input-must-not-change");
        await File.WriteAllTextAsync(Path.Combine(run, "run.json"), JsonSerializer.Serialize(new { error = $"failed at {originalInput} under {repository.Root} and {Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}" }));
        await RunArtifactRedactor.RedactAsync(run, map);
        var redacted = await File.ReadAllTextAsync(Path.Combine(run, "run.json"));
        Assert.Contains("<private-game-root>", redacted);
        Assert.Contains("<repo>", redacted);
        Assert.Contains("<user-home>", redacted);
        Assert.Equal("private-input-must-not-change", await File.ReadAllTextAsync(originalInput));
    }

    [Fact]
    public void PrivateScannerCoversTrackedPathsValuesHashesAndCredentialPatterns()
    {
        using var fixture = TemporaryGitRepository.Create();
        var privateRoot = Path.GetFullPath(Path.Combine(fixture.Path, "..", "private-root"));
        var privateHash = new string('a', 64);
        var credential = "gh" + "p_" + new string('Z', 24);
        fixture.Write(".local/profile.json", "{}");
        fixture.Write("artifacts/game.zip", "synthetic");
        fixture.Write("captures/demons-souls-new.png", "synthetic");
        fixture.Write("config.txt", $"root={privateRoot}\nhash={privateHash}\ntoken={credential}");
        fixture.Git("add", ".");
        var result = PrivateDataScanner.Scan(GitRepository.Discover(fixture.Path), [privateRoot], [privateHash]);
        Assert.False(result.Passed);
        Assert.Equal("tracked paths plus non-binary current working-tree contents up to 5242880 bytes per Git-indexed file", result.Scope);
        Assert.Contains(result.Findings, finding => finding.Category == "tracked-local-path");
        Assert.Contains(result.Findings, finding => finding.Category == "prohibited-artifact-extension");
        Assert.Contains(result.Findings, finding => finding.Category == "unapproved-tracked-image");
        Assert.Contains(result.Findings, finding => finding.Category == "configured-private-value");
        Assert.Contains(result.Findings, finding => finding.Category == "credential-pattern");
        Assert.Empty(result.ExecutionFailures);
        Assert.Equal("no-match", PrivateDataScanner.ClassifyGitGrepExitCode(1));
        Assert.Equal("failure", PrivateDataScanner.ClassifyGitGrepExitCode(2));
    }

    [Fact]
    public void ExtractionProvenanceAndCanonicalContainmentRejectMismatches()
    {
        var root = Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        var expected = new ExtractionProvenance("1.0.0", DateTimeOffset.UtcNow, "archive-hash", 123, "7-Zip", Path.Combine(root, "7z.exe"), "24.0", root);
        Assert.True(GameInputCommand.ProvenanceMatches(expected, expected with { CreatedUtc = expected.CreatedUtc.AddHours(1) }));
        Assert.False(GameInputCommand.ProvenanceMatches(expected, expected with { ArchiveSha256 = "stale" }));
        Assert.False(GameInputCommand.ProvenanceMatches(expected, expected with { ArchiveSizeBytes = 124 }));
        Assert.False(GameInputCommand.ProvenanceMatches(expected, expected with { ExtractionUtilityVersion = "old" }));
        Assert.True(GameInputCommand.IsCanonicalDescendant(root, Path.Combine(root, "game", "eboot.bin")));
        Assert.False(GameInputCommand.IsCanonicalDescendant(root, Path.Combine(root, "..", "escape", "eboot.bin")));
    }

    [Fact]
    public async Task ReuseMetadataIsReparsedFromSyntheticExtractedFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        var game = Path.Combine(root, "game");
        var eboot = Path.Combine(game, "eboot.bin");
        Directory.CreateDirectory(Path.Combine(game, "sce_sys"));
        try
        {
            await File.WriteAllBytesAsync(eboot, [1, 2, 3]);
            await File.WriteAllTextAsync(Path.Combine(game, "sce_sys", "param.json"), "{\"titleId\":\"TARGET00001\",\"contentVersion\":\"01.000.000\"}");
            var metadata = GameInputCommand.TryFindMetadata(eboot, root);
            Assert.Equal("TARGET00001", metadata.TitleId);
            Assert.Equal("01.000.000", metadata.Version);
            Assert.True(GameInputCommand.IsCanonicalDescendant(root, metadata.SourcePath!));
            Assert.False(GameInputCommand.HasReparsePoint(root, eboot));
            Assert.True(GameInputCommand.HasReparsePoint(root, Path.Combine(root, "missing", "eboot.bin")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SyntheticArchiveUtilityIsKilledAtItsHardTimeout()
    {
        if (!OperatingSystem.IsWindows()) return;
        await Assert.ThrowsAsync<TimeoutException>(() => GameInputCommand.RunUtilityAsync(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 10"],
            Path.GetTempPath(),
            TimeSpan.FromMilliseconds(250)));
    }

    [Fact]
    public async Task VulkanValidationMessagesAreCollectedWithoutOverclaimingAvailability()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllLinesAsync(path,
            [
                "[LOADER][INFO] Vulkan Validation Layers active (SHARPEMU_VK_VALIDATION=1).",
                "[VULKAN][WARN] synthetic validation warning",
            ]);
            var evidence = await RunCommand.CollectVulkanValidationAsync(path, new Dictionary<string, string?> { ["SHARPEMU_VK_VALIDATION"] = "1" });
            Assert.True(evidence.Requested);
            Assert.Equal("active", evidence.Status);
            Assert.Equal(1, evidence.MessageCount);
            Assert.Single(evidence.Messages);

            await File.WriteAllTextAsync(path, "[LOADER][WARN] validation layer not found");
            evidence = await RunCommand.CollectVulkanValidationAsync(path, new Dictionary<string, string?> { ["SHARPEMU_VK_VALIDATION"] = "1" });
            Assert.Equal("unavailable", evidence.Status);
            Assert.Empty(evidence.Messages);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
