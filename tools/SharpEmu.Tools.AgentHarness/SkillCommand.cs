// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Tools.AgentHarness;

internal sealed record SkillValidation(string Name, string Path, bool Valid, IReadOnlyList<string> Errors);

internal static class SkillCommand
{
    private static readonly string[] RequiredNames =
    [
        "sharpemu-boot-triage",
        "sharpemu-clean-room-research",
        "sharpemu-code-navigation",
        "sharpemu-performance-investigation",
        "sharpemu-visual-regression",
    ];

    public static int Run(GitRepository repository, CommandArguments arguments)
    {
        if (!arguments.Is("validate")) return Program.Fail("skills requires validate.");
        var root = Path.Combine(repository.Root, ".agents", "skills");
        var results = new List<SkillValidation>();
        foreach (var requiredName in RequiredNames)
        {
            var directory = Path.Combine(root, requiredName);
            var errors = new List<string>();
            if (!Directory.Exists(directory))
            {
                errors.Add("Required skill directory is missing.");
            }
            else
            {
                var files = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).ToArray();
                if (files.Length != 1 || !string.Equals(Path.GetFileName(files.SingleOrDefault()), "SKILL.md", StringComparison.Ordinal))
                {
                    errors.Add("A repository skill must contain exactly one SKILL.md file.");
                }
                var skillPath = Path.Combine(directory, "SKILL.md");
                if (File.Exists(skillPath)) ValidateFrontmatter(requiredName, File.ReadAllText(skillPath), errors);
            }
            results.Add(new SkillValidation(requiredName, $".agents/skills/{requiredName}/SKILL.md", errors.Count == 0, errors));
        }
        if (Directory.Exists(root))
        {
            foreach (var unexpected in Directory.EnumerateDirectories(root).Select(Path.GetFileName).Where(name => !RequiredNames.Contains(name, StringComparer.Ordinal)))
            {
                results.Add(new SkillValidation(unexpected!, $".agents/skills/{unexpected}", false, ["Unexpected repository skill directory."]));
            }
        }
        var valid = results.Count == RequiredNames.Length && results.All(result => result.Valid);
        if (arguments.Has("--json")) Program.WriteJson(new { valid, skills = results });
        else
        {
            foreach (var result in results) Console.WriteLine($"{(result.Valid ? "PASS" : "FAIL")} {result.Name}");
            foreach (var result in results) foreach (var error in result.Errors) Console.Error.WriteLine($"{result.Name}: {error}");
        }
        return valid ? 0 : 2;
    }

    internal static void ValidateFrontmatter(string expectedName, string contents, List<string> errors)
    {
        using var reader = new StringReader(contents);
        if (!string.Equals(reader.ReadLine(), "---", StringComparison.Ordinal))
        {
            errors.Add("YAML frontmatter must begin on the first line.");
            return;
        }
        string? name = null;
        string? description = null;
        var closed = false;
        while (reader.ReadLine() is { } line)
        {
            if (line == "---")
            {
                closed = true;
                break;
            }
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (key == "name") name = value;
            if (key == "description") description = value;
        }
        if (!closed) errors.Add("YAML frontmatter is not closed.");
        if (!string.Equals(name, expectedName, StringComparison.Ordinal)) errors.Add($"Frontmatter name must be '{expectedName}'.");
        if (string.IsNullOrWhiteSpace(description) || description.Length < 40) errors.Add("Frontmatter description must precisely describe triggers and exclusions.");
    }
}
