// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness.Tests;

public sealed class SourceIndexTests
{
    [Fact]
    public void RoslynIndexerCoversModernAndMalformedCSharp()
    {
        const string source = """
            using System;
            namespace Demo.Tools;

            public partial record Root<T>(T Value)
            {
                public Root() : this(default!) { }
                public T Item { get; init; }
                public static Root<T> operator +(Root<T> left, Root<T> right) => left;
                public TResult Convert<TResult>(Func<T, TResult> convert) => convert(Value);

                private struct Nested { public int Number; }
            }

            public interface IService { void Run(); }
            public enum Mode { First }
            public class Broken { public void Missing(
            """;

        var result = CSharpFileIndexer.Index("src/Demo.cs", "Demo", "hash", source);

        Assert.Contains("Demo.Tools", result.File.Namespaces);
        Assert.Contains("Root", result.File.TopLevelDeclarations);
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "Root", Kind: "record", Accessibility: "public" });
        Assert.Contains(result.Symbols, symbol => symbol is { Kind: "constructor", ContainingType: "Root" });
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "Item", Kind: "property" });
        Assert.Contains(result.Symbols, symbol => symbol is { Kind: "operator", Name: "operator +" });
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "Convert", Kind: "method" } && symbol.Signature.Contains("TResult", StringComparison.Ordinal));
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "Nested", Kind: "struct", ContainingType: "Root" });
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "IService", Kind: "interface" });
        Assert.Contains(result.Symbols, symbol => symbol is { Name: "Mode", Kind: "enum" });
        Assert.Contains(result.Symbols, symbol => symbol.Name == "Broken");
        Assert.All(result.Symbols, symbol => Assert.True(symbol.StartLine > 0 && symbol.EndLine >= symbol.StartLine));
    }

    [Fact]
    public async Task IndexUsesTrackedFilesAndRefreshesDirtyFileByHash()
    {
        using var repository = TemporaryGitRepository.Create();
        repository.Write("src/App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />");
        repository.Write("src/App/Tracked.cs", "namespace App; public class Before { }");
        repository.Write(".gitignore", "ignored.cs\n");
        repository.Git("add", ".");
        repository.Git("-c", "user.name=Harness Tests", "-c", "user.email=harness@example.invalid", "commit", "-m", "fixture");
        repository.Write("untracked.cs", "public class Untracked { }");
        repository.Write("ignored.cs", "public class Ignored { }");

        var git = GitRepository.Discover(repository.Path);
        var store = new SourceIndexStore(git);
        var first = await store.BuildAsync();
        Assert.Contains(first.Files, file => file.Path == "src/App/Tracked.cs" && file.Project == "App");
        Assert.DoesNotContain(first.Files, file => file.Path is "untracked.cs" or "ignored.cs");
        var oldHash = first.Files.Single(file => file.Path == "src/App/Tracked.cs").Sha256;

        repository.Write("src/App/Tracked.cs", "namespace App; public class After { public void Changed() { } }");
        var stale = await store.GetStatusAsync();
        Assert.False(stale.Current);
        Assert.Empty(stale.AddedTrackedTextFiles);
        Assert.Empty(stale.RemovedTrackedFiles);
        Assert.Equal(["src/App/Tracked.cs"], stale.ContentModifiedTrackedFiles);
        await Assert.ThrowsAsync<SourceIndexStaleException>(() => store.LoadCurrentAsync());

        var second = await store.BuildAsync();
        Assert.NotEqual(oldHash, second.Files.Single(file => file.Path == "src/App/Tracked.cs").Sha256);
        Assert.Contains(second.Symbols, symbol => symbol.Name == "Changed");
        Assert.DoesNotContain(second.Symbols, symbol => symbol.Name == "Before");
        Assert.Equal(first.Commit, second.Commit);
        var current = await store.GetStatusAsync();
        Assert.True(current.Current);
        var queryable = await store.LoadCurrentAsync();
        var changed = Assert.Single(queryable.Symbols, symbol => symbol.Name == "Changed");
        Assert.Equal(1, changed.StartLine);

        var json = await File.ReadAllTextAsync(store.IndexPath);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(SourceIndexStore.SchemaVersion, document.RootElement.GetProperty("schemaVersion").GetString());
    }

    [Fact]
    public void QueryLimitsAreBounded()
    {
        Assert.Equal(20, new CommandArguments([]).IntValue("--limit", 20, 1, 160));
        Assert.Equal(160, new CommandArguments(["--limit", "9999"]).IntValue("--limit", 20, 1, 160));
        Assert.Equal(1, new CommandArguments(["--limit=0"]).IntValue("--limit", 20, 1, 160));
    }
}

internal sealed class TemporaryGitRepository : IDisposable
{
    private TemporaryGitRepository(string path) => Path = path;

    public string Path { get; }

    public static TemporaryGitRepository Create()
    {
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sharpemu-harness-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        var repository = new TemporaryGitRepository(path);
        repository.Git("init", "--quiet");
        return repository;
    }

    public void Write(string relativePath, string contents)
    {
        var fullPath = System.IO.Path.Combine(Path, relativePath.Replace('/', System.IO.Path.DirectorySeparatorChar));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, contents);
    }

    public void Git(params string[] arguments)
    {
        var result = ProcessUtility.RunCapture("git", ["-C", Path, .. arguments], Path);
        Assert.True(result.ExitCode == 0, result.Stderr);
    }

    public void Dispose()
    {
        if (!Directory.Exists(Path)) return;
        foreach (var file in Directory.EnumerateFiles(Path, "*", SearchOption.AllDirectories)) File.SetAttributes(file, FileAttributes.Normal);
        Directory.Delete(Path, recursive: true);
    }
}
