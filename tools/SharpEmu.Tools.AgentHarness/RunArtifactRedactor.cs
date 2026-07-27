// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record RedactionRoot(string Path, string Token);

internal static class RunArtifactRedactor
{
    private static readonly string[] TextArtifactNames =
    [
        "stdout.log",
        "stderr.log",
        "emulator.log",
        "events.jsonl",
        "run.json",
        "environment.json",
        "harness-config.json",
        "vulkan-validation.json",
    ];

    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (!arguments.Is("run")) return Program.Fail("redact requires run.");
        var value = arguments.Value("--run");
        if (string.IsNullOrWhiteSpace(value)) return Program.Fail("redact run requires --run.");
        var runDirectory = Path.IsPathFullyQualified(value)
            ? Path.GetFullPath(value)
            : Directory.Exists(repository.ResolvePath(value))
                ? repository.ResolvePath(value)
                : Path.Combine(repository.LocalRoot, "runs", value);
        if (!Directory.Exists(runDirectory)) return Program.Fail($"Run '{value}' was not found.");
        var roots = await ReadRootsAsync(runDirectory);
        if (roots.Count == 0) return Program.Fail("Run has no readable configured redaction roots.");
        var redacted = await RedactAsync(runDirectory, CreatePrivateMap(roots));
        var result = new { runId = Path.GetFileName(runDirectory), redactedFiles = redacted, rootCount = roots.Count };
        if (arguments.Has("--json")) Program.WriteJson(result); else Console.WriteLine($"Redacted {redacted.Count} artifact(s) for {result.runId}.");
        return 0;
    }

    public static async Task<IReadOnlyList<string>> RedactAsync(string runDirectory, IReadOnlyList<string> roots)
        => await RedactAsync(runDirectory, CreatePrivateMap(roots));

    public static async Task<IReadOnlyList<string>> RedactAsync(string runDirectory, IReadOnlyList<RedactionRoot> roots)
    {
        var redacted = new List<string>();
        foreach (var name in TextArtifactNames)
        {
            var path = Path.Combine(runDirectory, name);
            if (!File.Exists(path)) continue;
            var text = await File.ReadAllTextAsync(path);
            var updated = RedactText(text, roots);
            if (string.Equals(text, updated, StringComparison.Ordinal)) continue;
            await File.WriteAllTextAsync(path, updated);
            redacted.Add(name);
        }
        return redacted;
    }

    internal static string RedactText(string value, IReadOnlyList<string> roots) =>
        RedactText(value, CreatePrivateMap(roots));

    internal static string RedactText(string value, IReadOnlyList<RedactionRoot> roots)
    {
        var redacted = value;
        foreach (var item in roots.OrderByDescending(item => item.Path.Length))
        {
            foreach (var root in PathForms(item.Path))
            {
                redacted = redacted.Replace(root, item.Token, StringComparison.OrdinalIgnoreCase);
                redacted = redacted.Replace(JsonEncodedText.Encode(root).ToString(), item.Token, StringComparison.OrdinalIgnoreCase);
            }
        }
        return redacted;
    }

    internal static IReadOnlyList<RedactionRoot> CreateStandardMap(
        GitRepository repository,
        IEnumerable<string> privateRoots)
    {
        var result = new List<RedactionRoot>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var privateIndex = 0;
        foreach (var value in privateRoots.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            var root = Path.GetFullPath(value);
            if (!seen.Add(root)) continue;
            result.Add(new RedactionRoot(root, privateIndex++ == 0 ? "<private-game-root>" : $"<private-root-{privateIndex}>"));
        }

        if (seen.Add(repository.Root)) result.Add(new RedactionRoot(repository.Root, "<repo>"));
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(home) && seen.Add(Path.GetFullPath(home)))
        {
            result.Add(new RedactionRoot(home, "<user-home>"));
        }
        return result;
    }

    internal static string SanitizeMessage(
        string message,
        GitRepository repository,
        IEnumerable<string>? privateRoots = null) =>
        RedactText(message, CreateStandardMap(repository, privateRoots ?? []));

    private static IReadOnlyList<RedactionRoot> CreatePrivateMap(IReadOnlyList<string> roots) =>
        roots.Select((root, index) => new RedactionRoot(Path.GetFullPath(root), $"<private-root-{index + 1}>")).ToArray();

    private static IEnumerable<string> PathForms(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        yield return full;
        var forward = full.Replace('\\', '/');
        if (!string.Equals(forward, full, StringComparison.Ordinal)) yield return forward;
    }

    private static async Task<IReadOnlyList<string>> ReadRootsAsync(string runDirectory)
    {
        var path = Path.Combine(runDirectory, "harness-config.json");
        if (!File.Exists(path)) return [];
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        return document.RootElement.TryGetProperty("redactionRoots", out var roots)
            ? roots.EnumerateArray().Select(root => root.GetString()).Where(root => !string.IsNullOrWhiteSpace(root)).Cast<string>().ToArray()
            : [];
    }
}
