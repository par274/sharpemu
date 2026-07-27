// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;

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
}
