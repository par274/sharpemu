// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SharpEmu.Tools.AgentHarness;

internal sealed class GitRepository
{
    private GitRepository(string root)
    {
        Root = Path.GetFullPath(root);
        LocalRoot = Path.Combine(Root, ".local");
    }

    public string Root { get; }

    public string LocalRoot { get; }

    public string Commit => RunGit("rev-parse", "HEAD").Trim();

    public string Branch => RunGit("branch", "--show-current").Trim();

    public bool IsDirty => RunGit("status", "--porcelain=v1").Length != 0;

    public static GitRepository Discover(string startDirectory)
    {
        var result = ProcessUtility.RunCapture(
            "git",
            ["-C", Path.GetFullPath(startDirectory), "rev-parse", "--show-toplevel"],
            startDirectory);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Stdout))
        {
            throw new InvalidOperationException("Run the harness from inside the SharpEmu Git repository.");
        }

        return new GitRepository(result.Stdout.Trim());
    }

    public string RunGit(params string[] arguments)
    {
        var result = ProcessUtility.RunCapture("git", ["-C", Root, .. arguments], Root);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"git {string.Join(' ', arguments)} failed: {result.Stderr.Trim()}");
        }

        return result.Stdout;
    }

    public IReadOnlyList<string> TrackedFiles()
    {
        var output = RunGit("ls-files", "-z");
        return output.Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Select(NormalizeRelativePath)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    public string ResolvePath(string path)
    {
        var fullPath = Path.IsPathFullyQualified(path)
            ? Path.GetFullPath(path)
            : Path.GetFullPath(path, Root);
        return fullPath;
    }

    public static string NormalizeRelativePath(string path) => path.Replace('\\', '/').TrimStart('/');

    public static string Sha256File(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    public static string Sha256Bytes(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));
}

internal static class ProcessUtility
{
    public static CapturedProcess RunCapture(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string?>? environment = null,
        int timeoutMilliseconds = 60_000)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var pair in environment)
            {
                process.StartInfo.Environment[pair.Key] = pair.Value;
            }
        }

        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeoutMilliseconds))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException($"{executable} exceeded {timeoutMilliseconds} ms.");
        }

        Task.WaitAll(stdout, stderr);
        return new CapturedProcess(process.ExitCode, stdout.Result, stderr.Result);
    }
}

internal sealed record CapturedProcess(int ExitCode, string Stdout, string Stderr);
