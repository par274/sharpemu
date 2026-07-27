// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HarfBuzzSharp;

namespace SharpEmu.GUI.FontSubsetter;

internal static class Program
{
    private const int ManifestVersion = 2;
    private const string HarfBuzzVersion = "14.2.1.1";
    private const string ManifestFileName = "NotoSans.subset.json";

    private static readonly IReadOnlyDictionary<string, int> Weights =
        new Dictionary<string, int>
        {
            ["Light"] = 300,
            ["Regular"] = 400,
            ["Medium"] = 500,
            ["SemiBold"] = 600,
            ["Bold"] = 700,
        };

    private static readonly FontFamilySource[] Families =
    [
        new(
            Region: "JP",
            Language: "ja",
            Url: "https://raw.githubusercontent.com/google/fonts/main/ofl/notosansjp/NotoSansJP%5Bwght%5D.ttf",
            Sha256: "c2f3b4d463500a2ddcd3849cded1fceeb9fd6d1c32e6cbecd568453ba50fc68f"),
        new(
            Region: "KR",
            Language: "ko",
            Url: "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanskr/NotoSansKR%5Bwght%5D.ttf",
            Sha256: "194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252"),
    ];

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var repositoryRoot = ResolveRepositoryRoot(args);
            var force = args.Skip(1).Any(argument =>
                string.Equals(argument, "--force", StringComparison.Ordinal));
            var guiDirectory = Path.Combine(repositoryRoot, "src", "SharpEmu.GUI");
            var fontDirectory = Path.Combine(guiDirectory, "Assets", "Fonts");
            var languageDirectory = Path.Combine(guiDirectory, "Languages");
            var generatorDirectory = Path.Combine(guiDirectory, "Build", "FontSubsetter");
            var manifestPath = Path.Combine(fontDirectory, ManifestFileName);
            var outputs = OutputPaths(fontDirectory);
            var inputHash = ComputeInputHash(generatorDirectory, languageDirectory);

            if (!force && GeneratedFontsAreCurrent(manifestPath, inputHash, outputs))
            {
                return 0;
            }

            Console.WriteLine("Noto subsets: translations or generated fonts changed; rebuilding");
            Directory.CreateDirectory(fontDirectory);
            await RebuildFontsAsync(fontDirectory, languageDirectory);
            WriteManifest(manifestPath, inputHash, outputs);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Noto subset generation failed: {exception.Message}");
            return 1;
        }
    }

    private static string ResolveRepositoryRoot(string[] args)
    {
        if (args.Length is < 1 or > 2
            || string.IsNullOrWhiteSpace(args[0])
            || args.Skip(1).Any(argument =>
                !string.Equals(argument, "--force", StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                "Expected the repository root followed by optional --force.");
        }

        var root = Path.GetFullPath(args[0]);
        if (!File.Exists(Path.Combine(root, "Directory.Build.props")))
        {
            throw new DirectoryNotFoundException($"Not a SharpEmu repository root: {root}");
        }

        return root;
    }

    private static Dictionary<string, string> OutputPaths(string fontDirectory) =>
        Families
            .SelectMany(
                family => Weights.Keys,
                (family, style) => $"NotoSans{family.Region}-{style}.ttf")
            .ToDictionary(
                fileName => fileName,
                fileName => Path.Combine(fontDirectory, fileName),
                StringComparer.Ordinal);

    private static string ComputeInputHash(string generatorDirectory, string languageDirectory)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in Directory
                     .EnumerateFiles(generatorDirectory)
                     .Where(path => path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                                    || path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
                     .Concat(Families.Select(
                         family => Path.Combine(languageDirectory, $"{family.Language}.json")))
                     .Order(StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(Path.GetFileName(path)));
            using var source = File.OpenRead(path);
            var buffer = new byte[1024 * 1024];
            int count;
            while ((count = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer.AsSpan(0, count));
            }
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static bool GeneratedFontsAreCurrent(
        string manifestPath,
        string inputHash,
        IReadOnlyDictionary<string, string> outputs)
    {
        try
        {
            var manifest = JsonSerializer.Deserialize<SubsetManifest>(
                File.ReadAllText(manifestPath),
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                });
            return manifest is not null
                   && manifest.Version == ManifestVersion
                   && manifest.InputSha256 == inputHash
                   && manifest.HarfBuzzVersion == HarfBuzzVersion
                   && outputs.All(output =>
                       File.Exists(output.Value)
                       && manifest.Outputs.TryGetValue(output.Key, out var recordedHash)
                       && recordedHash == Sha256File(output.Value));
        }
        catch (IOException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static async Task RebuildFontsAsync(
        string fontDirectory,
        string languageDirectory)
    {
        var temporaryDirectory = Path.Combine(
            fontDirectory,
            $".sharpemu-noto-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            using var httpClient = new HttpClient();
            foreach (var family in Families)
            {
                var sourcePath = Path.Combine(
                    temporaryDirectory,
                    $"NotoSans{family.Region}-Variable.ttf");
                var sourceBytes = await httpClient.GetByteArrayAsync(family.Url);
                if (Convert.ToHexStringLower(SHA256.HashData(sourceBytes)) != family.Sha256)
                {
                    throw new InvalidDataException(
                        $"Unexpected SHA-256 for {family.Url}");
                }

                await File.WriteAllBytesAsync(sourcePath, sourceBytes);
                var codepoints = TranslationCodepoints(
                    Path.Combine(languageDirectory, $"{family.Language}.json"));

                foreach (var (style, weight) in Weights)
                {
                    var fileName = $"NotoSans{family.Region}-{style}.ttf";
                    var temporaryOutput = Path.Combine(temporaryDirectory, fileName);
                    HarfBuzzSubsetter.CreateStaticSubset(
                        sourcePath,
                        temporaryOutput,
                        weight,
                        codepoints);
                    OpenTypeNameEditor.Rewrite(
                        temporaryOutput,
                        familyName: $"Noto Sans {family.Region}",
                        postScriptFamilyName: $"NotoSans{family.Region}",
                        style);
                }
            }

            foreach (var temporaryOutput in Families.SelectMany(
                         family => Weights.Keys,
                         (family, style) => Path.Combine(
                             temporaryDirectory,
                             $"NotoSans{family.Region}-{style}.ttf")))
            {
                var destination = Path.Combine(
                    fontDirectory,
                    Path.GetFileName(temporaryOutput));
                File.Move(temporaryOutput, destination, overwrite: true);
                Console.WriteLine(
                    $"{Path.GetRelativePath(
                        Directory.GetParent(Directory.GetParent(fontDirectory)!.FullName)!.FullName,
                        destination)}: {new FileInfo(destination).Length:N0} bytes");
            }
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static HashSet<uint> TranslationCodepoints(string languagePath)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(languagePath));
        var codepoints = new HashSet<uint>(Enumerable.Range(0x20, 0x7F - 0x20)
            .Select(value => (uint)value));
        CollectCodepoints(document.RootElement, codepoints);
        return codepoints;
    }

    private static void CollectCodepoints(JsonElement element, HashSet<uint> codepoints)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                foreach (var rune in element.GetString()!.EnumerateRunes())
                {
                    if (rune.Value is not ('\n' or '\r' or '\t'))
                    {
                        codepoints.Add((uint)rune.Value);
                    }
                }

                break;
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    CollectCodepoints(property.Value, codepoints);
                }

                break;
            case JsonValueKind.Array:
                foreach (var child in element.EnumerateArray())
                {
                    CollectCodepoints(child, codepoints);
                }

                break;
        }
    }

    private static void WriteManifest(
        string manifestPath,
        string inputHash,
        IReadOnlyDictionary<string, string> outputs)
    {
        var manifest = new SubsetManifest(
            Version: ManifestVersion,
            InputSha256: inputHash,
            HarfBuzzVersion: HarfBuzzVersion,
            Outputs: outputs.ToDictionary(
                output => output.Key,
                output => Sha256File(output.Value),
                StringComparer.Ordinal));
        var temporaryPath = $"{manifestPath}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(
            temporaryPath,
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            }) + Environment.NewLine);
        File.Move(temporaryPath, manifestPath, overwrite: true);
    }

    private static string Sha256File(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private sealed record FontFamilySource(
        string Region,
        string Language,
        string Url,
        string Sha256);

    private sealed record SubsetManifest(
        int Version,
        string InputSha256,
        string HarfBuzzVersion,
        Dictionary<string, string> Outputs);
}

internal static partial class HarfBuzzSubsetter
{
    private const string HarfBuzzLibrary = "libHarfBuzzSharp";
    private static readonly uint WeightTag = MakeTag('w', 'g', 'h', 't');

    public static void CreateStaticSubset(
        string sourcePath,
        string outputPath,
        int weight,
        IReadOnlySet<uint> codepoints)
    {
        using var sourceBlob = Blob.FromFile(sourcePath);
        using var sourceFace = new Face(sourceBlob, 0);
        var input = HbSubsetInputCreateOrFail();
        if (input == IntPtr.Zero)
        {
            throw new InvalidOperationException("HarfBuzz could not create subset input.");
        }

        try
        {
            var unicodeSet = HbSubsetInputUnicodeSet(input);
            foreach (var codepoint in codepoints)
            {
                HbSetAdd(unicodeSet, codepoint);
            }

            if (HbSubsetInputPinAxisLocation(
                    input,
                    sourceFace.Handle,
                    WeightTag,
                    weight) == 0)
            {
                throw new InvalidOperationException(
                    $"HarfBuzz could not pin the weight axis to {weight}.");
            }

            var outputFace = HbSubsetOrFail(sourceFace.Handle, input);
            if (outputFace == IntPtr.Zero)
            {
                throw new InvalidOperationException("HarfBuzz could not subset the font.");
            }

            try
            {
                var outputBlob = HbFaceReferenceBlob(outputFace);
                if (outputBlob == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        "HarfBuzz did not return subset font data.");
                }

                try
                {
                    var data = HbBlobGetData(outputBlob, out var length);
                    var bytes = new byte[checked((int)length)];
                    Marshal.Copy(data, bytes, 0, bytes.Length);
                    File.WriteAllBytes(outputPath, bytes);
                }
                finally
                {
                    HbBlobDestroy(outputBlob);
                }
            }
            finally
            {
                HbFaceDestroy(outputFace);
            }
        }
        finally
        {
            HbSubsetInputDestroy(input);
        }
    }

    private static uint MakeTag(char a, char b, char c, char d) =>
        ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_subset_input_create_or_fail")]
    private static partial IntPtr HbSubsetInputCreateOrFail();

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_subset_input_destroy")]
    private static partial void HbSubsetInputDestroy(IntPtr input);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_subset_input_unicode_set")]
    private static partial IntPtr HbSubsetInputUnicodeSet(IntPtr input);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_set_add")]
    private static partial void HbSetAdd(IntPtr set, uint codepoint);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_subset_input_pin_axis_location")]
    private static partial int HbSubsetInputPinAxisLocation(
        IntPtr input,
        IntPtr face,
        uint axisTag,
        float axisValue);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_subset_or_fail")]
    private static partial IntPtr HbSubsetOrFail(IntPtr source, IntPtr input);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_face_reference_blob")]
    private static partial IntPtr HbFaceReferenceBlob(IntPtr face);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_blob_get_data")]
    private static partial IntPtr HbBlobGetData(IntPtr blob, out uint length);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_blob_destroy")]
    private static partial void HbBlobDestroy(IntPtr blob);

    [LibraryImport(HarfBuzzLibrary, EntryPoint = "hb_face_destroy")]
    private static partial void HbFaceDestroy(IntPtr face);
}
