// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

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
        var redacted = await RedactAsync(runDirectory, roots);
        var result = new { runId = Path.GetFileName(runDirectory), redactedFiles = redacted, rootCount = roots.Count };
        if (arguments.Has("--json")) Program.WriteJson(result); else Console.WriteLine($"Redacted {redacted.Count} artifact(s) for {result.runId}.");
        return 0;
    }

    public static async Task<IReadOnlyList<string>> RedactAsync(string runDirectory, IReadOnlyList<string> roots)
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

    internal static string RedactText(string value, IReadOnlyList<string> roots)
    {
        var redacted = value;
        for (var index = 0; index < roots.Count; index++)
        {
            var replacement = $"<private-root-{index + 1}>";
            var root = Path.GetFullPath(roots[index]);
            redacted = redacted.Replace(root, replacement, StringComparison.OrdinalIgnoreCase);
            redacted = redacted.Replace(JsonEncodedText.Encode(root).ToString(), replacement, StringComparison.OrdinalIgnoreCase);
        }
        return redacted;
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
