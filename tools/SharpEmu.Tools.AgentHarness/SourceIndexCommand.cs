// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;
using System.Xml.Linq;

namespace SharpEmu.Tools.AgentHarness;

internal static class SourceIndexCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (arguments.Count == 0)
        {
            return Program.Fail("index requires build, status, query, outline, text, or map.");
        }

        var store = new SourceIndexStore(repository);
        return arguments[0].ToLowerInvariant() switch
        {
            "build" => await BuildAsync(store, arguments.Slice(1)),
            "status" => await StatusAsync(repository, store, arguments.Slice(1)),
            "query" => await QueryAsync(store, arguments.Slice(1)),
            "outline" => await OutlineAsync(store, arguments.Slice(1)),
            "text" => await TextAsync(repository, store, arguments.Slice(1)),
            "map" => await MapAsync(repository, store, arguments.Slice(1)),
            _ => Program.Fail($"Unknown index command '{arguments[0]}'."),
        };
    }

    private static async Task<int> BuildAsync(SourceIndexStore store, CommandArguments arguments)
    {
        var index = await store.BuildAsync();
        var result = new
        {
            index.SchemaVersion,
            index.Commit,
            index.GeneratedUtc,
            path = store.IndexPath,
            fileCount = index.Files.Count,
            symbolCount = index.Symbols.Count,
        };
        if (arguments.Has("--json"))
        {
            Program.WriteJson(result);
        }
        else
        {
            Console.WriteLine($"Index built: {index.Files.Count} text files, {index.Symbols.Count} C# symbols.");
            Console.WriteLine(store.IndexPath);
        }
        return 0;
    }

    private static async Task<int> StatusAsync(GitRepository repository, SourceIndexStore store, CommandArguments arguments)
    {
        var status = await store.GetStatusAsync();
        if (!status.Exists)
        {
            var missing = new { exists = false, path = store.IndexPath, commit = repository.Commit };
            if (arguments.Has("--json")) Program.WriteJson(missing); else Console.WriteLine("Index is missing; run index build.");
            return 2;
        }

        var index = status.Index;
        if (index is null || index.SchemaVersion != SourceIndexStore.SchemaVersion)
        {
            var invalid = new { exists = true, path = store.IndexPath, current = false, reason = "unsupported-or-invalid-schema" };
            if (arguments.Has("--json")) Program.WriteJson(invalid); else Console.WriteLine("Index schema is invalid; run index build.");
            return 2;
        }

        const int detailLimit = 20;
        var result = new
        {
            exists = true,
            path = store.IndexPath,
            index.Commit,
            currentCommit = repository.Commit,
            fileCount = index.Files.Count,
            symbolCount = index.Symbols.Count,
            addedTrackedTextFileCount = status.AddedTrackedTextFiles.Count,
            removedTrackedFileCount = status.RemovedTrackedFiles.Count,
            contentModifiedTrackedFileCount = status.ContentModifiedTrackedFiles.Count,
            addedTrackedTextFiles = status.AddedTrackedTextFiles.Take(detailLimit).ToArray(),
            removedTrackedFiles = status.RemovedTrackedFiles.Take(detailLimit).ToArray(),
            contentModifiedTrackedFiles = status.ContentModifiedTrackedFiles.Take(detailLimit).ToArray(),
            truncated = status.AddedTrackedTextFiles.Count > detailLimit || status.RemovedTrackedFiles.Count > detailLimit || status.ContentModifiedTrackedFiles.Count > detailLimit,
            current = status.Current,
        };
        if (arguments.Has("--json"))
        {
            Program.WriteJson(result);
        }
        else
        {
            Console.WriteLine($"Index: {index.Files.Count} files, {index.Symbols.Count} symbols, commit {index.Commit[..12]}.");
            Console.WriteLine(result.current ? "Status: current" : "Status: refresh recommended");
        }
        return result.current ? 0 : 2;
    }

    private static async Task<int> QueryAsync(SourceIndexStore store, CommandArguments arguments)
    {
        var index = await LoadForQueryAsync(store);
        if (index is null) return 2;
        var symbol = arguments.Value("--symbol");
        var namespaceName = arguments.Value("--namespace");
        var kind = arguments.Value("--kind");
        var limit = arguments.IntValue("--limit", 20, 1, 160);
        IEnumerable<IndexedSymbol> query = index.Symbols;
        if (!string.IsNullOrWhiteSpace(symbol))
        {
            query = query.Where(item =>
                item.Name.Contains(symbol, StringComparison.OrdinalIgnoreCase) ||
                item.FullyQualifiedName.Contains(symbol, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrWhiteSpace(namespaceName))
        {
            query = query.Where(item => item.Namespace?.Contains(namespaceName, StringComparison.OrdinalIgnoreCase) == true);
        }
        if (!string.IsNullOrWhiteSpace(kind))
        {
            var normalizedKind = string.Equals(kind, "type", StringComparison.OrdinalIgnoreCase) ? null : kind;
            query = normalizedKind is null
                ? query.Where(item => item.Kind is "class" or "record" or "struct" or "interface" or "enum" or "delegate")
                : query.Where(item => string.Equals(item.Kind, normalizedKind, StringComparison.OrdinalIgnoreCase));
        }

        var ordered = query
            .OrderBy(item => ExactRank(item, symbol))
            .ThenBy(item => item.FullyQualifiedName, StringComparer.Ordinal)
            .ToArray();
        return WriteBounded(ordered, limit, arguments.Has("--json"), item =>
            $"{item.Path}:{item.StartLine}-{item.EndLine} [{item.Project ?? "no-project"}] {item.FullyQualifiedName} — {item.Signature}");
    }

    private static async Task<int> OutlineAsync(SourceIndexStore store, CommandArguments arguments)
    {
        var index = await LoadForQueryAsync(store);
        if (index is null) return 2;
        var path = arguments.Value("--path");
        var symbol = arguments.Value("--symbol");
        if (string.IsNullOrWhiteSpace(path) == string.IsNullOrWhiteSpace(symbol))
        {
            return Program.Fail("index outline requires exactly one of --path or --symbol.");
        }

        IEnumerable<IndexedSymbol> query = index.Symbols;
        if (!string.IsNullOrWhiteSpace(path))
        {
            var normalized = GitRepository.NormalizeRelativePath(path);
            query = query.Where(item => string.Equals(item.Path, normalized, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            query = query.Where(item =>
                item.Name.Contains(symbol!, StringComparison.OrdinalIgnoreCase) ||
                item.FullyQualifiedName.Contains(symbol!, StringComparison.OrdinalIgnoreCase));
        }

        var values = query.OrderBy(item => item.Path, StringComparer.Ordinal).ThenBy(item => item.StartLine).ToArray();
        var limit = arguments.IntValue("--limit", 20, 1, 160);
        return WriteBounded(values, limit, arguments.Has("--json"), item =>
            $"{item.Path}:{item.StartLine}-{item.EndLine} {item.Kind} {item.FullyQualifiedName} — {item.Signature}");
    }

    private static async Task<int> TextAsync(GitRepository repository, SourceIndexStore store, CommandArguments arguments)
    {
        var pattern = arguments.Value("--pattern");
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return Program.Fail("index text requires --pattern.");
        }
        var index = await LoadForQueryAsync(store);
        if (index is null) return 2;
        var limit = arguments.IntValue("--limit", 20, 1, 160);
        var matches = new List<TextMatch>();
        var total = 0;
        foreach (var file in index.Files)
        {
            var lines = await File.ReadAllLinesAsync(repository.ResolvePath(file.Path));
            for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                var column = lines[lineIndex].IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (column < 0)
                {
                    continue;
                }
                total++;
                if (matches.Count < limit)
                {
                    var excerpt = lines[lineIndex].Trim();
                    if (excerpt.Length > 180) excerpt = excerpt[..177] + "...";
                    matches.Add(new TextMatch(file.Path, lineIndex + 1, column + 1, excerpt));
                }
            }
        }
        return WriteBounded(matches.ToArray(), limit, arguments.Has("--json"), item =>
            $"{item.Path}:{item.Line}:{item.Column} {item.Excerpt}", total);
    }

    private static async Task<int> MapAsync(GitRepository repository, SourceIndexStore store, CommandArguments arguments)
    {
        if (await LoadForQueryAsync(store) is null) return 2;
        var requested = arguments.Value("--project");
        if (string.IsNullOrWhiteSpace(requested))
        {
            return Program.Fail("index map requires --project.");
        }
        var projects = new List<ProjectMap>();
        foreach (var path in repository.TrackedFiles().Where(path => path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)))
        {
            var document = XDocument.Load(repository.ResolvePath(path));
            var references = document.Descendants("ProjectReference")
                .Select(element => element.Attribute("Include")?.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => Path.GetFileNameWithoutExtension(value!))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            projects.Add(new ProjectMap(Path.GetFileNameWithoutExtension(path), path, references));
        }
        var selected = projects.Where(project => project.Name.Contains(requested, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (arguments.Has("--json"))
        {
            Program.WriteJson(new { results = selected, total = selected.Length, relationship = "MSBuild ProjectReference (declared)" });
        }
        else
        {
            foreach (var project in selected)
            {
                Console.WriteLine($"{project.Name} ({project.Path})");
                Console.WriteLine(project.References.Count == 0
                    ? "  references: none"
                    : $"  references: {string.Join(", ", project.References)}");
            }
            Console.WriteLine("Relationship: declared MSBuild ProjectReference; this is not a semantic runtime call graph.");
        }
        return selected.Length == 0 ? 2 : 0;
    }

    private static int WriteBounded<T>(
        IReadOnlyList<T> values,
        int limit,
        bool json,
        Func<T, string> render,
        int? knownTotal = null)
    {
        var total = knownTotal ?? values.Count;
        var selected = values.Take(limit).ToArray();
        if (json)
        {
            Program.WriteJson(new { results = selected, total, returned = selected.Length, truncated = total > selected.Length, limit });
        }
        else
        {
            foreach (var value in selected) Console.WriteLine(render(value));
            Console.WriteLine(total > selected.Length
                ? $"Showing {selected.Length} of {total}; use --limit to expand (maximum 160)."
                : $"{selected.Length} result(s).");
        }
        return selected.Length == 0 ? 2 : 0;
    }

    private static int ExactRank(IndexedSymbol item, string? requested) =>
        !string.IsNullOrWhiteSpace(requested) &&
        (string.Equals(item.Name, requested, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(item.FullyQualifiedName, requested, StringComparison.OrdinalIgnoreCase)) ? 0 : 1;

    private static async Task<SourceIndexDocument?> LoadForQueryAsync(SourceIndexStore store)
    {
        try
        {
            return await store.LoadCurrentAsync();
        }
        catch (SourceIndexStaleException)
        {
            Console.Error.WriteLine("The source index is stale; run index build before querying.");
            return null;
        }
    }

    private sealed record TextMatch(string Path, int Line, int Column, string Excerpt);

    private sealed record ProjectMap(string Name, string Path, IReadOnlyList<string> References);
}
