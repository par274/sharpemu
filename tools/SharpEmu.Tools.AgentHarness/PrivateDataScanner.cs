// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.RegularExpressions;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record PrivateScanFinding(string Category, string Path);

internal sealed record PrivateDataScanResult(
    string Scope,
    bool Passed,
    int FindingCount,
    IReadOnlyList<PrivateScanFinding> Findings,
    IReadOnlyList<string> ExecutionFailures);

internal static partial class PrivateDataScanner
{
    private const int DetailLimit = 100;
    private const long ContentScanLimitBytes = 5 * 1024 * 1024;
    private static readonly HashSet<string> AllowedRepositoryImages = new(StringComparer.OrdinalIgnoreCase)
    {
        ".github/images/614291356-95dc2b2a-4ed2-46b8-8875-2e0251529a35.jpg",
        ".github/images/dead-cells.jpg",
        ".github/images/demons-souls.jpg",
        ".github/images/dreaming-sarah.jpg",
        ".github/images/void-terrarium.jpg",
        "assets/images/commit-icon.png",
        "assets/images/discord.png",
        "assets/images/github.png",
        "assets/images/logo.png",
        "assets/images/pic0.png",
        "assets/images/update-icon.png",
        "tools/SharpEmu.DebuggerFrontend/web/sharpemu-logo.webp",
    };
    private static readonly HashSet<string> ProhibitedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".7z", ".bin", ".cap", ".dmp", ".dump", ".elf", ".etl", ".gz", ".iso", ".pcap", ".pkg", ".prx", ".pup", ".rar", ".raw", ".self", ".sprx", ".tar", ".tgz", ".trace", ".xz", ".zip", ".zst",
    };
    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp",
    };

    public static PrivateDataScanResult Scan(
        GitRepository repository,
        IEnumerable<string> privateRoots,
        IEnumerable<string> privateHashes)
    {
        var findings = new List<PrivateScanFinding>();
        var failures = new List<string>();
        var tracked = repository.TrackedFiles();
        foreach (var path in tracked)
        {
            if (path.Equals(".local", StringComparison.OrdinalIgnoreCase) || path.StartsWith(".local/", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new PrivateScanFinding("tracked-local-path", path));
            }
            if (ProhibitedExtensions.Contains(Path.GetExtension(path)))
            {
                findings.Add(new PrivateScanFinding("prohibited-artifact-extension", path));
            }
            if (ImageExtensions.Contains(Path.GetExtension(path)) && !AllowedRepositoryImages.Contains(path))
            {
                findings.Add(new PrivateScanFinding("unapproved-tracked-image", path));
            }
        }

        var needles = privateRoots.Concat(privateHashes)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        foreach (var needle in needles)
        {
            try
            {
                var result = ProcessUtility.RunCapture(
                    "git",
                    ["-C", repository.Root, "grep", "-I", "-l", "-F", needle, "--"],
                    repository.Root);
                if (ClassifyGitGrepExitCode(result.ExitCode) == "matches")
                {
                    foreach (var path in result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
                    {
                        findings.Add(new PrivateScanFinding("configured-private-value", GitRepository.NormalizeRelativePath(path)));
                    }
                }
                else if (ClassifyGitGrepExitCode(result.ExitCode) == "failure")
                {
                    failures.Add($"git-grep-fixed-string-exit-{result.ExitCode}");
                }
            }
            catch (Exception exception)
            {
                failures.Add("git-grep-fixed-string-failed-" + exception.GetType().Name);
            }
        }

        foreach (var path in tracked)
        {
            try
            {
                var fullPath = repository.ResolvePath(path);
                if (!File.Exists(fullPath) || new FileInfo(fullPath).Length > ContentScanLimitBytes) continue;
                var bytes = File.ReadAllBytes(fullPath);
                if (SourceIndexStore.IsBinary(bytes)) continue;
                var text = System.Text.Encoding.UTF8.GetString(bytes);
                if (CredentialPattern().IsMatch(text))
                {
                    findings.Add(new PrivateScanFinding("credential-pattern", path));
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                failures.Add($"tracked-content-read-failed:{path}:{exception.GetType().Name}");
            }
        }

        var distinct = findings.Distinct().OrderBy(item => item.Path, StringComparer.OrdinalIgnoreCase).ThenBy(item => item.Category, StringComparer.Ordinal).ToArray();
        return new PrivateDataScanResult(
            "tracked paths plus non-binary current working-tree contents up to 5242880 bytes per Git-indexed file",
            distinct.Length == 0 && failures.Count == 0,
            distinct.Length,
            distinct.Take(DetailLimit).ToArray(),
            failures.Take(DetailLimit).ToArray());
    }

    internal static string ClassifyGitGrepExitCode(int exitCode) => exitCode switch
    {
        0 => "matches",
        1 => "no-match",
        _ => "failure",
    };

    [GeneratedRegex("(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\\s*[:=]\\s*[\\\"'][A-Za-z0-9_./+=-]{16,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CredentialPattern();
}
