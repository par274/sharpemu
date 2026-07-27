// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record SourceIndexDocument(
    string SchemaVersion,
    string Commit,
    DateTimeOffset GeneratedUtc,
    IReadOnlyList<IndexedFile> Files,
    IReadOnlyList<IndexedSymbol> Symbols);

internal sealed record IndexedFile(
    string Path,
    string? Project,
    string Language,
    string Sha256,
    int LineCount,
    IReadOnlyList<string> Namespaces,
    IReadOnlyList<string> TopLevelDeclarations,
    bool Generated,
    IReadOnlyList<string> Imports);

internal sealed record IndexedSymbol(
    string FullyQualifiedName,
    string Name,
    string Kind,
    string Accessibility,
    string? Namespace,
    string? ContainingType,
    string? Project,
    string Signature,
    int StartLine,
    int EndLine,
    string Path);

internal sealed record SourceIndexStatus(
    bool Exists,
    string Path,
    string CurrentCommit,
    SourceIndexDocument? Index,
    IReadOnlyList<string> AddedTrackedTextFiles,
    IReadOnlyList<string> RemovedTrackedFiles,
    IReadOnlyList<string> ContentModifiedTrackedFiles)
{
    public bool Current =>
        Exists &&
        Index is { SchemaVersion: SourceIndexStore.SchemaVersion } &&
        Index.Commit == CurrentCommit &&
        AddedTrackedTextFiles.Count == 0 &&
        RemovedTrackedFiles.Count == 0 &&
        ContentModifiedTrackedFiles.Count == 0;
}

internal sealed class SourceIndexStaleException(SourceIndexStatus status)
    : InvalidOperationException("The source index is stale; run index build before querying.")
{
    public SourceIndexStatus Status { get; } = status;
}

internal sealed class SourceIndexStore
{
    public const string SchemaVersion = "1.0.0";

    private readonly GitRepository _repository;

    public SourceIndexStore(GitRepository repository) => _repository = repository;

    public string IndexDirectory => Path.Combine(_repository.LocalRoot, "index", _repository.Commit);

    public string IndexPath => Path.Combine(IndexDirectory, "index.json");

    public async Task<SourceIndexDocument> BuildAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(IndexDirectory);
        var tracked = _repository.TrackedFiles();
        var projects = tracked
            .Where(path => path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
            .Select(path => new ProjectLocation(
                Path.GetFileNameWithoutExtension(path),
                GitRepository.NormalizeRelativePath(Path.GetDirectoryName(path) ?? string.Empty)))
            .OrderByDescending(project => project.Directory.Length)
            .ToArray();

        SourceIndexDocument? previous = null;
        if (File.Exists(IndexPath))
        {
            await using var oldStream = File.OpenRead(IndexPath);
            previous = await JsonSerializer.DeserializeAsync<SourceIndexDocument>(
                oldStream,
                Program.JsonOptions,
                cancellationToken);
            if (previous?.SchemaVersion != SchemaVersion)
            {
                previous = null;
            }
        }

        var previousFiles = previous?.Files.ToDictionary(file => file.Path, StringComparer.Ordinal)
            ?? new Dictionary<string, IndexedFile>(StringComparer.Ordinal);
        var previousSymbols = previous?.Symbols
            .GroupBy(symbol => symbol.Path, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal)
            ?? new Dictionary<string, IndexedSymbol[]>(StringComparer.Ordinal);

        var files = new List<IndexedFile>(tracked.Count);
        var symbols = new List<IndexedSymbol>();
        foreach (var relativePath in tracked)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fullPath = _repository.ResolvePath(relativePath);
            if (!File.Exists(fullPath))
            {
                continue;
            }

            var bytes = await File.ReadAllBytesAsync(fullPath, cancellationToken);
            if (IsBinary(bytes))
            {
                continue;
            }

            var hash = GitRepository.Sha256Bytes(bytes);
            if (previousFiles.TryGetValue(relativePath, out var cached) && cached.Sha256 == hash)
            {
                files.Add(cached);
                if (previousSymbols.TryGetValue(relativePath, out var cachedSymbols))
                {
                    symbols.AddRange(cachedSymbols);
                }
                continue;
            }

            var text = DecodeText(bytes);
            var project = FindProject(relativePath, projects);
            if (relativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            {
                var parsed = CSharpFileIndexer.Index(relativePath, project, hash, text);
                files.Add(parsed.File);
                symbols.AddRange(parsed.Symbols);
            }
            else
            {
                files.Add(new IndexedFile(
                    relativePath,
                    project,
                    LanguageFromPath(relativePath),
                    hash,
                    CountLines(text),
                    [],
                    [],
                    IsGenerated(relativePath, text),
                    []));
            }
        }

        var document = new SourceIndexDocument(
            SchemaVersion,
            _repository.Commit,
            DateTimeOffset.UtcNow,
            files.OrderBy(file => file.Path, StringComparer.Ordinal).ToArray(),
            symbols
                .OrderBy(symbol => symbol.Path, StringComparer.Ordinal)
                .ThenBy(symbol => symbol.StartLine)
                .ThenBy(symbol => symbol.Name, StringComparer.Ordinal)
                .ToArray());
        var temporaryPath = IndexPath + $".{Environment.ProcessId}.tmp";
        await using (var stream = File.Create(temporaryPath))
        {
            await JsonSerializer.SerializeAsync(stream, document, Program.JsonOptions, cancellationToken);
        }
        File.Move(temporaryPath, IndexPath, overwrite: true);
        return document;
    }

    public async Task<SourceIndexDocument> LoadOrBuildAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(IndexPath))
        {
            return await BuildAsync(cancellationToken);
        }

        await using var stream = File.OpenRead(IndexPath);
        var document = await JsonSerializer.DeserializeAsync<SourceIndexDocument>(stream, Program.JsonOptions, cancellationToken);
        return document is { SchemaVersion: SchemaVersion }
            ? document
            : await BuildAsync(cancellationToken);
    }

    public async Task<SourceIndexDocument> LoadCurrentAsync(CancellationToken cancellationToken = default)
    {
        var status = await GetStatusAsync(cancellationToken);
        if (!status.Current || status.Index is null)
        {
            throw new SourceIndexStaleException(status);
        }

        return status.Index;
    }

    public async Task<SourceIndexStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(IndexPath))
        {
            return new SourceIndexStatus(false, IndexPath, _repository.Commit, null, [], [], []);
        }

        SourceIndexDocument? index;
        try
        {
            await using var stream = File.OpenRead(IndexPath);
            index = await JsonSerializer.DeserializeAsync<SourceIndexDocument>(stream, Program.JsonOptions, cancellationToken);
        }
        catch (JsonException)
        {
            index = null;
        }

        if (index is null || index.SchemaVersion != SchemaVersion)
        {
            return new SourceIndexStatus(true, IndexPath, _repository.Commit, index, [], [], []);
        }

        var tracked = _repository.TrackedFiles().ToHashSet(StringComparer.Ordinal);
        var indexed = index.Files.ToDictionary(file => file.Path, StringComparer.Ordinal);
        var added = new List<string>();
        var modified = new List<string>();
        foreach (var relativePath in tracked)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fullPath = _repository.ResolvePath(relativePath);
            if (!File.Exists(fullPath))
            {
                continue;
            }

            var bytes = await File.ReadAllBytesAsync(fullPath, cancellationToken);
            if (IsBinary(bytes))
            {
                if (indexed.ContainsKey(relativePath))
                {
                    modified.Add(relativePath);
                }
                continue;
            }

            if (!indexed.TryGetValue(relativePath, out var indexedFile))
            {
                added.Add(relativePath);
            }
            else if (!string.Equals(GitRepository.Sha256Bytes(bytes), indexedFile.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                modified.Add(relativePath);
            }
        }

        var removed = indexed.Keys.Where(path => !tracked.Contains(path) || !File.Exists(_repository.ResolvePath(path))).ToArray();
        return new SourceIndexStatus(
            true,
            IndexPath,
            _repository.Commit,
            index,
            added.Order(StringComparer.Ordinal).ToArray(),
            removed.Order(StringComparer.Ordinal).ToArray(),
            modified.Order(StringComparer.Ordinal).ToArray());
    }

    internal static bool IsBinary(ReadOnlySpan<byte> bytes)
    {
        var sampleLength = Math.Min(bytes.Length, 8192);
        for (var index = 0; index < sampleLength; index++)
        {
            if (bytes[index] == 0)
            {
                return true;
            }
        }
        return false;
    }

    internal static int CountLines(string text)
    {
        if (text.Length == 0)
        {
            return 0;
        }
        return text.Count(character => character == '\n') + (text[^1] == '\n' ? 0 : 1);
    }

    private static string DecodeText(byte[] bytes)
    {
        using var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static string? FindProject(string path, IReadOnlyList<ProjectLocation> projects)
    {
        foreach (var project in projects)
        {
            if (path.StartsWith(project.Directory + "/", StringComparison.Ordinal) ||
                string.Equals(path, project.Directory, StringComparison.Ordinal))
            {
                return project.Name;
            }
        }
        return null;
    }

    private static bool IsGenerated(string path, string text) =>
        path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) ||
        path.EndsWith(".generated.cs", StringComparison.OrdinalIgnoreCase) ||
        text.AsSpan(0, Math.Min(text.Length, 512)).Contains("<auto-generated", StringComparison.OrdinalIgnoreCase);

    private static string LanguageFromPath(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".cs" => "C#",
        ".ps1" => "PowerShell",
        ".py" => "Python",
        ".sh" => "Shell",
        ".json" => "JSON",
        ".yml" or ".yaml" => "YAML",
        ".xml" or ".props" or ".csproj" or ".slnx" => "XML",
        ".md" => "Markdown",
        _ => "text",
    };

    private sealed record ProjectLocation(string Name, string Directory);
}

internal static class CSharpFileIndexer
{
    public static (IndexedFile File, IReadOnlyList<IndexedSymbol> Symbols) Index(
        string path,
        string? project,
        string hash,
        string text)
    {
        var tree = CSharpSyntaxTree.ParseText(text, new CSharpParseOptions(LanguageVersion.Latest));
        var root = tree.GetCompilationUnitRoot();
        var namespaces = root.DescendantNodes()
            .OfType<BaseNamespaceDeclarationSyntax>()
            .Select(node => node.Name.ToString())
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var imports = root.DescendantNodes()
            .OfType<UsingDirectiveSyntax>()
            .Select(node => node.Name?.ToString() ?? node.ToString())
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var collector = new SymbolCollector(path, project, tree);
        collector.Visit(root);
        var topLevel = collector.Symbols
            .Where(symbol => symbol.ContainingType is null &&
                symbol.Kind is "class" or "record" or "struct" or "interface" or "enum" or "delegate")
            .Select(symbol => symbol.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var file = new IndexedFile(
            path,
            project,
            "C#",
            hash,
            SourceIndexStore.CountLines(text),
            namespaces,
            topLevel,
            path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) ||
                text.AsSpan(0, Math.Min(text.Length, 512)).Contains("<auto-generated", StringComparison.OrdinalIgnoreCase),
            imports);
        return (file, collector.Symbols);
    }

    private sealed class SymbolCollector : CSharpSyntaxWalker
    {
        private readonly string _path;
        private readonly string? _project;
        private readonly SyntaxTree _tree;
        private readonly Stack<string> _types = new();

        public SymbolCollector(string path, string? project, SyntaxTree tree)
            : base(SyntaxWalkerDepth.Node)
        {
            _path = path;
            _project = project;
            _tree = tree;
        }

        public List<IndexedSymbol> Symbols { get; } = [];

        public override void VisitClassDeclaration(ClassDeclarationSyntax node) => VisitType(node, "class", node.Identifier.Text, () => base.VisitClassDeclaration(node));

        public override void VisitStructDeclaration(StructDeclarationSyntax node) => VisitType(node, "struct", node.Identifier.Text, () => base.VisitStructDeclaration(node));

        public override void VisitInterfaceDeclaration(InterfaceDeclarationSyntax node) => VisitType(node, "interface", node.Identifier.Text, () => base.VisitInterfaceDeclaration(node));

        public override void VisitEnumDeclaration(EnumDeclarationSyntax node) => VisitType(node, "enum", node.Identifier.Text, () => base.VisitEnumDeclaration(node));

        public override void VisitRecordDeclaration(RecordDeclarationSyntax node) => VisitType(node, "record", node.Identifier.Text, () => base.VisitRecordDeclaration(node));

        public override void VisitDelegateDeclaration(DelegateDeclarationSyntax node)
        {
            Add(node, node.Identifier.Text, "delegate", $"{Modifiers(node.Modifiers)}delegate {node.ReturnType} {node.Identifier}{node.TypeParameterList}{node.ParameterList}");
            base.VisitDelegateDeclaration(node);
        }

        public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            Add(node, node.Identifier.Text, "method", $"{Modifiers(node.Modifiers)}{node.ReturnType} {node.Identifier}{node.TypeParameterList}{node.ParameterList}");
            base.VisitMethodDeclaration(node);
        }

        public override void VisitConstructorDeclaration(ConstructorDeclarationSyntax node)
        {
            Add(node, node.Identifier.Text, "constructor", $"{Modifiers(node.Modifiers)}{node.Identifier}{node.ParameterList}");
            base.VisitConstructorDeclaration(node);
        }

        public override void VisitDestructorDeclaration(DestructorDeclarationSyntax node)
        {
            Add(node, "~" + node.Identifier.Text, "destructor", $"~{node.Identifier}{node.ParameterList}");
            base.VisitDestructorDeclaration(node);
        }

        public override void VisitPropertyDeclaration(PropertyDeclarationSyntax node)
        {
            Add(node, node.Identifier.Text, "property", $"{Modifiers(node.Modifiers)}{node.Type} {node.Identifier}");
            base.VisitPropertyDeclaration(node);
        }

        public override void VisitIndexerDeclaration(IndexerDeclarationSyntax node)
        {
            Add(node, "this", "indexer", $"{Modifiers(node.Modifiers)}{node.Type} this{node.ParameterList}");
            base.VisitIndexerDeclaration(node);
        }

        public override void VisitOperatorDeclaration(OperatorDeclarationSyntax node)
        {
            Add(node, "operator " + node.OperatorToken.Text, "operator", $"{Modifiers(node.Modifiers)}{node.ReturnType} operator {node.OperatorToken}{node.ParameterList}");
            base.VisitOperatorDeclaration(node);
        }

        public override void VisitConversionOperatorDeclaration(ConversionOperatorDeclarationSyntax node)
        {
            Add(node, "operator " + node.Type, "conversion", $"{Modifiers(node.Modifiers)}{node.ImplicitOrExplicitKeyword} operator {node.Type}{node.ParameterList}");
            base.VisitConversionOperatorDeclaration(node);
        }

        public override void VisitEventDeclaration(EventDeclarationSyntax node)
        {
            Add(node, node.Identifier.Text, "event", $"{Modifiers(node.Modifiers)}event {node.Type} {node.Identifier}");
            base.VisitEventDeclaration(node);
        }

        private void VisitType(MemberDeclarationSyntax node, string kind, string name, Action visitChildren)
        {
            var signature = node switch
            {
                TypeDeclarationSyntax type => $"{Modifiers(type.Modifiers)}{kind} {type.Identifier}{type.TypeParameterList}{type.BaseList}",
                EnumDeclarationSyntax enumeration => $"{Modifiers(enumeration.Modifiers)}enum {enumeration.Identifier}{enumeration.BaseList}",
                _ => $"{kind} {name}",
            };
            Add(node, name, kind, signature);
            _types.Push(name);
            visitChildren();
            _types.Pop();
        }

        private void Add(SyntaxNode node, string name, string kind, string signature)
        {
            var namespaceName = node.Ancestors().OfType<BaseNamespaceDeclarationSyntax>().FirstOrDefault()?.Name.ToString();
            var containingType = _types.Count == 0 ? null : string.Join('.', _types.Reverse());
            var fullName = string.Join('.', new[] { namespaceName, containingType, name }.Where(value => !string.IsNullOrWhiteSpace(value)));
            var span = _tree.GetLineSpan(node.Span);
            var modifiers = node switch
            {
                MemberDeclarationSyntax member => member.Modifiers,
                _ => default,
            };
            Symbols.Add(new IndexedSymbol(
                fullName,
                name,
                kind,
                Accessibility(modifiers),
                namespaceName,
                containingType,
                _project,
                Compact(signature),
                span.StartLinePosition.Line + 1,
                span.EndLinePosition.Line + 1,
                _path));
        }

        private static string Modifiers(SyntaxTokenList modifiers) => modifiers.Count == 0 ? string.Empty : string.Join(' ', modifiers.Select(token => token.Text)) + " ";

        private static string Accessibility(SyntaxTokenList modifiers)
        {
            var values = modifiers.Select(token => token.Text).ToHashSet(StringComparer.Ordinal);
            if (values.Contains("public")) return "public";
            if (values.Contains("private") && values.Contains("protected")) return "private protected";
            if (values.Contains("protected") && values.Contains("internal")) return "protected internal";
            if (values.Contains("protected")) return "protected";
            if (values.Contains("internal")) return "internal";
            if (values.Contains("private")) return "private";
            return "default";
        }

        private static string Compact(string value) => string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }
}
