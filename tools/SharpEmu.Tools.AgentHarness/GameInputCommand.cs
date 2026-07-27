// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record GameInputMetadata(
    string ArchivePath,
    long ArchiveSizeBytes,
    string ArchiveSha256,
    string ExpectedTitleId,
    string ExpectedVersion,
    string ArchiveUtilityPath);

internal sealed record ArchiveInspection(
    string SchemaVersion,
    DateTimeOffset GeneratedUtc,
    long ArchiveSizeBytes,
    string ArchiveSha256,
    bool HashMatchesPhaseZero,
    string Utility,
    string UtilityVersion,
    int IntegrityExitCode,
    string IntegrityStatus,
    int EntryCount,
    long ExpectedUncompressedBytes,
    bool PathsValid,
    IReadOnlyList<string> Blockers,
    IReadOnlyList<string> Warnings);

internal sealed record GameBootstrapResult(
    string SchemaVersion,
    string ValidationResult,
    string? ExtractionRoot,
    string? SelectedEboot,
    string? EbootSha256,
    string? TitleId,
    string? VerifiedVersion,
    string VersionStatus,
    bool ArchiveExtracted,
    IReadOnlyList<string> Blockers,
    IReadOnlyList<string> Warnings);

internal sealed record ExtractionProvenance(
    string SchemaVersion,
    DateTimeOffset CreatedUtc,
    string ArchiveSha256,
    long ArchiveSizeBytes,
    string ExtractionUtility,
    string ExtractionUtilityPath,
    string ExtractionUtilityVersion,
    string IntendedFinalRoot);

internal static class GameInputCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (arguments.Count == 0 || arguments[0].ToLowerInvariant() is not ("inspect" or "extract" or "resume")) return Program.Fail("game requires inspect, extract, or resume.");
        var metadataPath = arguments.Value("--metadata") ?? Path.Combine(repository.LocalRoot, "game-input", "PPSA01341.json");
        var metadata = await ReadMetadataAsync(repository.ResolvePath(metadataPath));
        var inspection = arguments[0].Equals("resume", StringComparison.OrdinalIgnoreCase)
            ? await LoadRecentInspectionAsync(repository, metadata)
            : await InspectAsync(repository, metadata);
        if (arguments[0] == "inspect" || inspection.Blockers.Count > 0)
        {
            if (arguments.Has("--json")) Program.WriteJson(inspection);
            else PrintInspection(inspection);
            return inspection.Blockers.Count == 0 ? 0 : 2;
        }

        var result = await ExtractAsync(
            repository,
            metadata,
            inspection,
            allowStagingRecovery: arguments[0].Equals("resume", StringComparison.OrdinalIgnoreCase));
        if (arguments.Has("--json")) Program.WriteJson(result);
        else
        {
            Console.WriteLine($"Game bootstrap: {result.ValidationResult}");
            Console.WriteLine($"Title ID: {result.TitleId}; version: {result.VersionStatus}.");
            Console.WriteLine($"Extraction root: <private-game-root>/{metadata.ExpectedTitleId}/{metadata.ExpectedVersion}");
            Console.WriteLine($"Profile: .local/profiles/demons-souls-01.004.000.json");
            foreach (var blocker in result.Blockers) Console.Error.WriteLine($"blocker: {blocker}");
        }
        return result.Blockers.Count == 0 ? 0 : 2;
    }

    private static async Task<ArchiveInspection> LoadRecentInspectionAsync(GitRepository repository, GameInputMetadata metadata)
    {
        var path = Path.Combine(repository.LocalRoot, "game-input", "phase-01-archive-inspection.json");
        if (!File.Exists(path)) throw new InvalidOperationException("No Phase 01 archive inspection is available to resume.");
        var inspection = JsonSerializer.Deserialize<ArchiveInspection>(await File.ReadAllTextAsync(path), Program.JsonOptions)
            ?? throw new InvalidDataException("The Phase 01 archive inspection is empty.");
        var actualSize = File.Exists(metadata.ArchivePath) ? new FileInfo(metadata.ArchivePath).Length : -1;
        var actualHash = actualSize >= 0 ? await HashFileAsync(metadata.ArchivePath) : null;
        var utilityVersion = File.Exists(metadata.ArchiveUtilityPath)
            ? ParseUtilityVersion((await RunUtilityAsync(metadata.ArchiveUtilityPath, ["i"], repository.Root, TimeSpan.FromMinutes(1))).Stdout)
            : null;
        if (inspection.GeneratedUtc < DateTimeOffset.UtcNow.AddHours(-4) ||
            inspection.Blockers.Count > 0 ||
            !inspection.HashMatchesPhaseZero ||
            !inspection.PathsValid ||
            inspection.IntegrityExitCode != 0 ||
            !string.Equals(inspection.ArchiveSha256, metadata.ArchiveSha256, StringComparison.OrdinalIgnoreCase) ||
            inspection.ArchiveSizeBytes != metadata.ArchiveSizeBytes ||
            actualSize != metadata.ArchiveSizeBytes ||
            !string.Equals(actualHash, metadata.ArchiveSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(utilityVersion, inspection.UtilityVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The cached archive inspection is absent, stale, or inconsistent; run game extract for full revalidation.");
        }
        return inspection;
    }

    private static async Task<ArchiveInspection> InspectAsync(GitRepository repository, GameInputMetadata metadata)
    {
        var blockers = new List<string>();
        var warnings = new List<string>();
        if (!File.Exists(metadata.ArchivePath))
        {
            blockers.Add("archive: source archive does not exist");
            return new ArchiveInspection("1.0.0", DateTimeOffset.UtcNow, 0, string.Empty, false, "7-Zip", "unknown", -1, "not-run", 0, 0, false, blockers, warnings);
        }
        if (!File.Exists(metadata.ArchiveUtilityPath))
        {
            blockers.Add("environment: recorded official archive utility does not exist");
            return new ArchiveInspection("1.0.0", DateTimeOffset.UtcNow, new FileInfo(metadata.ArchivePath).Length, string.Empty, false, "7-Zip", "unknown", -1, "not-run", 0, 0, false, blockers, warnings);
        }

        var archiveSize = new FileInfo(metadata.ArchivePath).Length;
        if (archiveSize != metadata.ArchiveSizeBytes) blockers.Add("archive: byte size differs from the Phase 00 record");
        var archiveHash = await HashFileAsync(metadata.ArchivePath);
        var hashMatches = string.Equals(archiveHash, metadata.ArchiveSha256, StringComparison.OrdinalIgnoreCase);
        if (!hashMatches) blockers.Add("archive: SHA-256 differs from the Phase 00 record");
        var versionResult = await RunUtilityAsync(metadata.ArchiveUtilityPath, ["i"], repository.Root, TimeSpan.FromMinutes(1));
        var utilityVersion = ParseUtilityVersion(versionResult.Stdout);

        var listing = await ListAndValidateAsync(metadata.ArchiveUtilityPath, metadata.ArchivePath, repository.Root);
        blockers.AddRange(listing.Blockers);
        var drive = new DriveInfo(Path.GetPathRoot(repository.Root)!);
        var requiredFree = checked((long)Math.Ceiling(listing.TotalUncompressedBytes * 1.10) + 5L * 1024 * 1024 * 1024);
        if (drive.AvailableFreeSpace < requiredFree) blockers.Add($"archive: insufficient free space; need at least {requiredFree} bytes");
        var integrity = await RunUtilityAsync(
            metadata.ArchiveUtilityPath,
            ["t", "-bb0", "-bd", "-bso0", "-bsp0", "--", metadata.ArchivePath],
            repository.Root,
            TimeSpan.FromHours(2));
        if (integrity.ExitCode != 0)
        {
            var classification = (integrity.Stdout + integrity.Stderr).Contains("password", StringComparison.OrdinalIgnoreCase)
                ? "archive: password-protected or encrypted content cannot be tested without an already-authorized password"
                : $"archive: integrity test failed with exit {integrity.ExitCode}";
            blockers.Add(classification);
        }
        var inspection = new ArchiveInspection(
            "1.0.0",
            DateTimeOffset.UtcNow,
            archiveSize,
            archiveHash,
            hashMatches,
            "7-Zip",
            utilityVersion,
            integrity.ExitCode,
            integrity.ExitCode == 0 ? "passed" : "failed",
            listing.EntryCount,
            listing.TotalUncompressedBytes,
            listing.Blockers.Count == 0,
            blockers,
            warnings);
        var outputDirectory = Path.Combine(repository.LocalRoot, "game-input");
        Directory.CreateDirectory(outputDirectory);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "phase-01-archive-inspection.json"), JsonSerializer.Serialize(inspection, Program.JsonOptions));
        return inspection;
    }

    private static async Task<GameBootstrapResult> ExtractAsync(
        GitRepository repository,
        GameInputMetadata metadata,
        ArchiveInspection inspection,
        bool allowStagingRecovery)
    {
        var blockers = new List<string>();
        var warnings = new List<string>();
        var workspace = Directory.GetParent(repository.Root)?.FullName ?? throw new InvalidOperationException("Repository has no workspace parent.");
        var finalRoot = Path.GetFullPath(Path.Combine(workspace, "private", "games", metadata.ExpectedTitleId, metadata.ExpectedVersion));
        var privateParent = Path.GetDirectoryName(finalRoot)!;
        Directory.CreateDirectory(privateParent);
        if (!string.Equals(Path.GetPathRoot(finalRoot), Path.GetPathRoot(metadata.ArchivePath), StringComparison.OrdinalIgnoreCase))
        {
            blockers.Add("archive: staging and source are not on the same fixed local drive");
        }

        var existingManifestPath = Path.Combine(finalRoot, ".sharpemu-extraction.json");
        if (Directory.Exists(finalRoot))
        {
            if (File.Exists(existingManifestPath))
            {
                using var existing = JsonDocument.Parse(await File.ReadAllTextAsync(existingManifestPath));
                var root = existing.RootElement;
                var sourceMatches = string.Equals(StringProperty(root, "sourceArchiveSha256"), inspection.ArchiveSha256, StringComparison.OrdinalIgnoreCase);
                var sizeMatches = root.TryGetProperty("sourceArchiveSizeBytes", out var sourceSize) && sourceSize.TryGetInt64(out var manifestSize) && manifestSize == inspection.ArchiveSizeBytes;
                var utilityMatches = string.Equals(StringProperty(root, "extractionUtility"), inspection.Utility, StringComparison.Ordinal) &&
                    StringProperty(root, "extractionUtilityPath") is { } utilityPath && string.Equals(CanonicalPath(utilityPath), CanonicalPath(metadata.ArchiveUtilityPath), StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(StringProperty(root, "extractionUtilityVersion"), inspection.UtilityVersion, StringComparison.Ordinal);
                var rootMatches = StringProperty(root, "extractionRoot") is { } extractionRoot && string.Equals(CanonicalPath(extractionRoot), finalRoot, StringComparison.OrdinalIgnoreCase);
                var ebootExists = root.TryGetProperty("selectedEbootPath", out var ebootElement) &&
                    ebootElement.ValueKind == JsonValueKind.String &&
                    IsCanonicalDescendant(finalRoot, ebootElement.GetString()!) &&
                    File.Exists(CanonicalPath(ebootElement.GetString()!)) &&
                    !HasReparsePoint(finalRoot, ebootElement.GetString()!);
                if (sourceMatches && sizeMatches && utilityMatches && rootMatches && ebootExists)
                {
                    warnings.Add("Existing extraction was reused after manifest and selected-eboot validation.");
                    return await CreateProfileFromExistingAsync(repository, metadata, existing.RootElement.Clone(), blockers, warnings);
                }
            }
            blockers.Add("archive: final extraction destination already exists but could not be safely reused");
        }
        if (blockers.Count > 0) return Result("blocked", null, null, null, null, null, blockers, warnings);

        var stagingCandidates = Directory.EnumerateDirectories(
            privateParent,
            Path.GetFileName(finalRoot) + ".staging-*",
            SearchOption.TopDirectoryOnly).ToArray();
        if (stagingCandidates.Length > 1)
        {
            blockers.Add("archive: multiple staging directories exist; automatic recovery is ambiguous");
            return Result("blocked", null, null, null, null, null, blockers, warnings);
        }
        if (stagingCandidates.Length == 1 && !allowStagingRecovery)
        {
            blockers.Add("archive: an isolated staging tree exists; use the explicit game resume command after reviewing its provenance");
            return Result("blocked", stagingCandidates[0], null, null, null, null, blockers, warnings);
        }
        var staging = stagingCandidates.SingleOrDefault()
            ?? finalRoot + $".staging-{DateTime.UtcNow:yyyyMMddTHHmmssZ}-{Environment.ProcessId}";
        staging = CanonicalPath(staging);
        var provenancePath = Path.Combine(staging, ".sharpemu-staging-provenance.json");
        var expectedProvenance = new ExtractionProvenance(
            "1.0.0",
            DateTimeOffset.UtcNow,
            inspection.ArchiveSha256,
            inspection.ArchiveSizeBytes,
            inspection.Utility,
            CanonicalPath(metadata.ArchiveUtilityPath),
            inspection.UtilityVersion,
            finalRoot);
        var recoveredStaging = stagingCandidates.Length == 1;
        if (recoveredStaging)
        {
            if (!File.Exists(provenancePath))
            {
                blockers.Add("archive: staging provenance is missing; resume was refused");
                return Result("blocked", staging, null, null, null, null, blockers, warnings);
            }
            ExtractionProvenance? actualProvenance;
            try
            {
                actualProvenance = JsonSerializer.Deserialize<ExtractionProvenance>(await File.ReadAllTextAsync(provenancePath), Program.JsonOptions);
            }
            catch (JsonException)
            {
                actualProvenance = null;
            }
            if (actualProvenance is null || !ProvenanceMatches(expectedProvenance, actualProvenance))
            {
                blockers.Add("archive: staging provenance is invalid or does not match the validated archive; resume was refused");
                return Result("blocked", staging, null, null, null, null, blockers, warnings);
            }
            warnings.Add("A single isolated staging tree from the current validated archive was recovered and fully revalidated.");
        }
        else
        {
            Directory.CreateDirectory(staging);
            await File.WriteAllTextAsync(provenancePath, JsonSerializer.Serialize(expectedProvenance, Program.JsonOptions));
            var extraction = await RunUtilityAsync(
                metadata.ArchiveUtilityPath,
                ["x", "-bb0", "-bd", "-bso0", "-bsp0", "-y", $"-o{staging}", "--", metadata.ArchivePath],
                workspace,
                TimeSpan.FromHours(4));
            if (extraction.ExitCode != 0)
            {
                var combined = extraction.Stdout + extraction.Stderr;
                blockers.Add(combined.Contains("password", StringComparison.OrdinalIgnoreCase)
                    ? "archive: extraction requires a password that was not supplied or guessed"
                    : $"archive: extraction failed with exit {extraction.ExitCode}");
                return Result("failed", staging, null, null, null, null, blockers, warnings);
            }
        }

        foreach (var entry in Directory.EnumerateFileSystemEntries(staging, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                blockers.Add("archive: extracted content contains a symlink, junction, or reparse point");
                break;
            }
            if (!IsCanonicalDescendant(staging, entry))
            {
                blockers.Add("archive: extracted path escaped staging");
                break;
            }
        }
        if (blockers.Count > 0) return Result("failed-validation", staging, null, null, null, null, blockers, warnings);

        var candidates = Directory.EnumerateFiles(staging, "eboot.bin", SearchOption.AllDirectories).Select(CanonicalPath).Where(path => IsCanonicalDescendant(staging, path)).ToArray();
        var selections = new List<Candidate>();
        foreach (var candidate in candidates)
        {
            var metadataResult = TryFindMetadata(candidate, staging);
            if (metadataResult.TitleId is not null)
            {
                selections.Add(new Candidate(candidate, metadataResult));
            }
        }
        var matching = selections.Where(candidate => string.Equals(candidate.Metadata.TitleId, metadata.ExpectedTitleId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matching.Length != 1)
        {
            blockers.Add(matching.Length == 0
                ? "archive: no unambiguous eboot with verified target Title ID was found"
                : "archive: multiple eboot candidates match the target Title ID");
            return Result("failed-validation", staging, null, null, null, null, blockers, warnings);
        }
        var selected = matching[0];
        var verifiedVersion = selected.Metadata.Version;
        var versionStatus = string.IsNullOrWhiteSpace(verifiedVersion) ? "unverified" : "verified";
        if (!string.IsNullOrWhiteSpace(verifiedVersion) && !string.Equals(verifiedVersion, metadata.ExpectedVersion, StringComparison.OrdinalIgnoreCase))
        {
            blockers.Add($"target version: metadata proves '{verifiedVersion}', not expected '{metadata.ExpectedVersion}'");
            return Result("version-mismatch", staging, selected.Path, null, selected.Metadata.TitleId, verifiedVersion, blockers, warnings);
        }
        var ebootHash = await HashFileAsync(selected.Path);
        try
        {
            await MoveDirectoryWithRetryAsync(staging, finalRoot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            var safeMessage = RunArtifactRedactor.SanitizeMessage(
                exception.Message,
                repository,
                [finalRoot, staging, Path.GetDirectoryName(metadata.ArchivePath)!]);
            blockers.Add($"archive: validated staging could not be promoted to the final root: {safeMessage}");
            return Result("promotion-failed", staging, selected.Path, ebootHash, selected.Metadata.TitleId, verifiedVersion, blockers, warnings, versionStatus);
        }
        var finalEboot = CanonicalPath(Path.Combine(finalRoot, Path.GetRelativePath(staging, selected.Path)));
        var finalMetadata = selected.Metadata.SourcePath is null ? null : CanonicalPath(Path.Combine(finalRoot, Path.GetRelativePath(staging, selected.Metadata.SourcePath)));
        if (!IsCanonicalDescendant(finalRoot, finalEboot) || finalMetadata is not null && !IsCanonicalDescendant(finalRoot, finalMetadata))
        {
            blockers.Add("archive: selected eboot or metadata escaped the canonical final root");
            return Result("failed-validation", finalRoot, null, null, null, null, blockers, warnings);
        }
        var manifest = new
        {
            schemaVersion = "1.0.0",
            sourceArchivePath = metadata.ArchivePath,
            sourceArchiveSha256 = inspection.ArchiveSha256,
            sourceArchiveSizeBytes = inspection.ArchiveSizeBytes,
            extractionUtcTimestamp = DateTimeOffset.UtcNow,
            extractionUtility = inspection.Utility,
            extractionUtilityPath = CanonicalPath(metadata.ArchiveUtilityPath),
            extractionUtilityVersion = inspection.UtilityVersion,
            extractionRoot = finalRoot,
            selectedEbootPath = finalEboot,
            ebootSha256 = ebootHash,
            titleId = selected.Metadata.TitleId,
            expectedVersion = metadata.ExpectedVersion,
            verifiedVersion,
            versionStatus,
            metadataSource = finalMetadata,
            validationResult = "passed",
            archiveExtracted = true,
            blockers,
            warnings,
        };
        await File.WriteAllTextAsync(existingManifestPath, JsonSerializer.Serialize(manifest, Program.JsonOptions));
        await WriteProfileAsync(repository, metadata, finalRoot, finalEboot, ebootHash, selected.Metadata.TitleId!, verifiedVersion, versionStatus, finalMetadata);
        return Result("passed", finalRoot, finalEboot, ebootHash, selected.Metadata.TitleId, verifiedVersion, blockers, warnings, versionStatus);
    }

    private static async Task MoveDirectoryWithRetryAsync(string source, string destination)
    {
        Exception? lastError = null;
        for (var attempt = 1; attempt <= 15; attempt++)
        {
            try
            {
                Directory.Move(source, destination);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                lastError = exception;
                if (Directory.Exists(destination) || attempt == 15) break;
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }
        throw lastError ?? new IOException("Directory promotion failed without diagnostics.");
    }

    private static async Task<GameBootstrapResult> CreateProfileFromExistingAsync(GitRepository repository, GameInputMetadata metadata, JsonElement manifest, List<string> blockers, List<string> warnings)
    {
        var eboot = CanonicalPath(manifest.GetProperty("selectedEbootPath").GetString()!);
        var extractionRoot = CanonicalPath(manifest.GetProperty("extractionRoot").GetString()!);
        if (!IsCanonicalDescendant(extractionRoot, eboot))
        {
            blockers.Add("archive: reusable extraction eboot is outside the canonical extraction root");
            return Result("blocked", extractionRoot, null, null, null, null, blockers, warnings);
        }
        var expectedEbootHash = manifest.GetProperty("ebootSha256").GetString()!;
        var ebootHash = await HashFileAsync(eboot);
        var reparsed = TryFindMetadata(eboot, extractionRoot);
        var titleId = reparsed.TitleId;
        var verifiedVersion = reparsed.Version;
        var versionStatus = string.IsNullOrWhiteSpace(verifiedVersion) ? "unverified" : "verified";
        var metadataSource = reparsed.SourcePath;
        if (metadataSource is null ||
            !IsCanonicalDescendant(extractionRoot, metadataSource) ||
            HasReparsePoint(extractionRoot, metadataSource)) blockers.Add("archive: reusable extraction metadata is missing or outside the canonical extraction root");
        if (HasReparsePoint(extractionRoot, eboot)) blockers.Add("archive: reusable extraction eboot traverses a reparse point");
        if (!string.Equals(ebootHash, expectedEbootHash, StringComparison.OrdinalIgnoreCase)) blockers.Add("archive: reusable extraction eboot hash mismatch");
        if (!string.Equals(titleId, metadata.ExpectedTitleId, StringComparison.OrdinalIgnoreCase)) blockers.Add("archive: reusable extraction Title ID mismatch");
        if (!string.IsNullOrWhiteSpace(verifiedVersion) && !string.Equals(verifiedVersion, metadata.ExpectedVersion, StringComparison.OrdinalIgnoreCase)) blockers.Add("target version: reusable extraction version mismatch");
        if (blockers.Count == 0) await WriteProfileAsync(repository, metadata, extractionRoot, eboot, ebootHash, titleId!, verifiedVersion, versionStatus, metadataSource);
        return Result(blockers.Count == 0 ? "reused" : "blocked", extractionRoot, eboot, ebootHash, titleId, verifiedVersion, blockers, warnings, versionStatus);
    }

    private static async Task WriteProfileAsync(GitRepository repository, GameInputMetadata metadata, string extractionRoot, string eboot, string hash, string titleId, string? verifiedVersion, string versionStatus, string? metadataSource)
    {
        var profile = new LocalRunProfile
        {
            TargetName = "Demon's Souls 01.004.000",
            ExpectedTitleId = metadata.ExpectedTitleId,
            ExpectedVersion = metadata.ExpectedVersion,
            EbootPath = eboot,
            EbootSha256 = hash,
            BuildConfiguration = "Debug",
            TimeoutSeconds = 180,
            LogLevel = "debug",
            ImportTraceLimit = 64,
            Capture = new CapturePolicy
            {
                NativeEnabled = true,
                WindowFallbackEnabled = true,
                FirstFrame = true,
                FrameNumbers = [30, 120],
                Interval = 300,
                MaxFrames = 8,
                WindowSampleSeconds = [15, 45, 90, 150],
            },
            RedactionRoots = [CanonicalPath(extractionRoot)],
            Metadata = new TargetMetadata
            {
                TitleIdVerified = true,
                VerifiedTitleId = titleId,
                VersionVerified = string.Equals(versionStatus, "verified", StringComparison.OrdinalIgnoreCase),
                VerifiedVersion = verifiedVersion,
                MetadataSource = metadataSource,
                VersionStatus = versionStatus,
            },
        };
        var profileDirectory = Path.Combine(repository.LocalRoot, "profiles");
        Directory.CreateDirectory(profileDirectory);
        await File.WriteAllTextAsync(Path.Combine(profileDirectory, "demons-souls-01.004.000.json"), JsonSerializer.Serialize(profile, Program.JsonOptions));
    }

    internal static (string? TitleId, string? Version, string? SourcePath) TryFindMetadata(string eboot, string staging)
    {
        staging = CanonicalPath(staging);
        var directory = Path.GetDirectoryName(CanonicalPath(eboot))!;
        for (var level = 0; level < 4 && IsCanonicalDescendant(staging, directory, allowRoot: true); level++)
        {
            foreach (var candidate in new[] { Path.Combine(directory, "sce_sys", "param.json"), Path.Combine(directory, "param.json") })
            {
                if (!File.Exists(candidate)) continue;
                try
                {
                    using var document = JsonDocument.Parse(File.ReadAllText(candidate));
                    var root = document.RootElement;
                    var titleId = StringProperty(root, "titleId") ?? StringProperty(root, "titleID") ?? StringProperty(root, "TITLE_ID");
                    var version = StringProperty(root, "contentVersion") ?? StringProperty(root, "masterVersion") ?? StringProperty(root, "targetContentVersion") ?? StringProperty(root, "version");
                    return (titleId, version, candidate);
                }
                catch (JsonException)
                {
                }
            }
            var parent = Directory.GetParent(directory);
            if (parent is null) break;
            directory = parent.FullName;
        }
        return (null, null, null);
    }

    private static string? StringProperty(JsonElement root, string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static async Task<(int EntryCount, long TotalUncompressedBytes, IReadOnlyList<string> Blockers)> ListAndValidateAsync(string utility, string archive, string workingDirectory)
    {
        var blockers = new List<string>();
        using var process = StartUtility(utility, ["l", "-slt", "-ba", "--", archive], workingDirectory);
        var stderrTask = process.StandardError.ReadToEndAsync();
        string? currentPath = null;
        string? currentAttributes = null;
        long currentSize = 0;
        var entryCount = 0;
        long total = 0;
        async Task FinishEntry()
        {
            if (currentPath is null) return;
            entryCount++;
            total = checked(total + Math.Max(0, currentSize));
            var reason = ValidateArchivePath(currentPath, currentAttributes);
            if (reason is not null && blockers.Count < 20) blockers.Add($"archive path rejected: {reason}");
            currentPath = null;
            currentAttributes = null;
            currentSize = 0;
            await Task.CompletedTask;
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            while (await process.StandardOutput.ReadLineAsync(timeout.Token) is { } line)
            {
                if (line.Length == 0)
                {
                    await FinishEntry();
                    continue;
                }
                if (line.StartsWith("Path = ", StringComparison.Ordinal)) currentPath = line[7..];
                else if (line.StartsWith("Size = ", StringComparison.Ordinal) && long.TryParse(line[7..], out var size)) currentSize = size;
                else if (line.StartsWith("Attributes = ", StringComparison.Ordinal)) currentAttributes = line[13..];
                else if (HasArchiveLinkTarget(line)) currentAttributes = (currentAttributes ?? string.Empty) + " link";
            }
            await FinishEntry();
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
            blockers.Add("archive: directory listing exceeded the 10-minute hard timeout");
            _ = await stderrTask;
            return (entryCount, total, blockers);
        }
        var stderr = await stderrTask;
        if (process.ExitCode != 0) blockers.Add($"archive: directory listing failed with exit {process.ExitCode}");
        return (entryCount, total, blockers);
    }

    internal static string? ValidateArchivePath(string path, string? attributes = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return "empty entry path";
        var normalized = path.Replace('/', '\\');
        if (normalized.StartsWith("\\\\", StringComparison.Ordinal)) return "UNC path";
        if (normalized.StartsWith('\\')) return "absolute rooted path";
        if (normalized.Length >= 2 && char.IsLetter(normalized[0]) && normalized[1] == ':') return "drive-qualified path";
        if (normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries).Any(segment => segment == "..")) return "parent traversal";
        if (normalized.Contains(':')) return "alternate data stream path";
        if (attributes?.Contains("link", StringComparison.OrdinalIgnoreCase) == true || attributes?.Contains("reparse", StringComparison.OrdinalIgnoreCase) == true) return "link or reparse entry";
        var root = Path.Combine(Path.GetTempPath(), "sharpemu-archive-validation-root");
        var resolved = Path.GetFullPath(Path.Combine(root, normalized));
        if (!resolved.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return "path escapes staging";
        return null;
    }

    internal static bool HasArchiveLinkTarget(string metadataLine)
    {
        const string symbolicPrefix = "Symbolic Link = ";
        const string hardPrefix = "Hard Link = ";
        var target = metadataLine.StartsWith(symbolicPrefix, StringComparison.Ordinal)
            ? metadataLine[symbolicPrefix.Length..]
            : metadataLine.StartsWith(hardPrefix, StringComparison.Ordinal) ? metadataLine[hardPrefix.Length..] : null;
        return !string.IsNullOrWhiteSpace(target);
    }

    internal static bool ProvenanceMatches(ExtractionProvenance expected, ExtractionProvenance actual) =>
        actual.SchemaVersion == "1.0.0" &&
        string.Equals(expected.ArchiveSha256, actual.ArchiveSha256, StringComparison.OrdinalIgnoreCase) &&
        expected.ArchiveSizeBytes == actual.ArchiveSizeBytes &&
        string.Equals(expected.ExtractionUtility, actual.ExtractionUtility, StringComparison.Ordinal) &&
        string.Equals(CanonicalPath(expected.ExtractionUtilityPath), CanonicalPath(actual.ExtractionUtilityPath), StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.ExtractionUtilityVersion, actual.ExtractionUtilityVersion, StringComparison.Ordinal) &&
        string.Equals(CanonicalPath(expected.IntendedFinalRoot), CanonicalPath(actual.IntendedFinalRoot), StringComparison.OrdinalIgnoreCase);

    internal static bool IsCanonicalDescendant(string root, string path, bool allowRoot = false)
    {
        var canonicalRoot = CanonicalPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var canonicalPath = CanonicalPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (allowRoot && string.Equals(canonicalRoot, canonicalPath, StringComparison.OrdinalIgnoreCase)) return true;
        return canonicalPath.StartsWith(canonicalRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    internal static bool HasReparsePoint(string root, string path)
    {
        if (!IsCanonicalDescendant(root, path, allowRoot: true)) return true;
        try
        {
            var current = CanonicalPath(root);
            if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint)) return true;
            foreach (var segment in Path.GetRelativePath(current, CanonicalPath(path)).Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint)) return true;
            }
            return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static string CanonicalPath(string path) => Path.GetFullPath(path);

    private static async Task<GameInputMetadata> ReadMetadataAsync(string path)
    {
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = document.RootElement;
        var archivePath = root.TryGetProperty("archive_path", out var directPath) ? directPath.GetString()! : root.GetProperty("archive").GetProperty("path").GetString()!;
        var size = root.TryGetProperty("archive_size_bytes", out var directSize) ? directSize.GetInt64() : root.GetProperty("archive").GetProperty("size_bytes").GetInt64();
        var hash = root.TryGetProperty("archive_sha256", out var directHash) ? directHash.GetString()! : root.GetProperty("archive").GetProperty("sha256").GetString()!;
        var title = root.TryGetProperty("title_id", out var directTitle) ? directTitle.GetString()! : root.GetProperty("archive").GetProperty("expected_title_id").GetString()!;
        var version = root.TryGetProperty("expected_game_version", out var directVersion) ? directVersion.GetString()! : root.GetProperty("archive").GetProperty("expected_game_version").GetString()!;
        string utility;
        if (root.TryGetProperty("archive_utility", out var utilityObject)) utility = utilityObject.GetProperty("path").GetString()!;
        else utility = root.GetProperty("tools").EnumerateArray().First(tool => tool.GetProperty("name").GetString() == "7-Zip").GetProperty("path").GetString()!;
        return new GameInputMetadata(CanonicalPath(archivePath), size, hash, title, version, CanonicalPath(utility));
    }

    private static async Task<string> HashFileAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream));
    }

    private static Process StartUtility(string executable, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var process = new Process
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
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        return process;
    }

    internal static async Task<CapturedProcess> RunUtilityAsync(string executable, IReadOnlyList<string> arguments, string workingDirectory, TimeSpan timeout)
    {
        using var process = StartUtility(executable, arguments, workingDirectory);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exitTask = process.WaitForExitAsync();
        var completed = await Task.WhenAny(exitTask, Task.Delay(timeout));
        if (completed != exitTask)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw new TimeoutException($"Archive utility exceeded {timeout}.");
        }
        return new CapturedProcess(process.ExitCode, await stdout, await stderr);
    }

    private static string ParseUtilityVersion(string output) =>
        output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(line => line.Contains("7-Zip", StringComparison.OrdinalIgnoreCase))?.Trim() ?? "unknown";

    private static void PrintInspection(ArchiveInspection inspection)
    {
        Console.WriteLine($"Archive inspection: {inspection.IntegrityStatus}; {inspection.EntryCount} entries; paths {(inspection.PathsValid ? "valid" : "REJECTED")}.");
        Console.WriteLine($"Archive size: {inspection.ArchiveSizeBytes}; expected uncompressed: {inspection.ExpectedUncompressedBytes} bytes.");
        foreach (var blocker in inspection.Blockers) Console.Error.WriteLine($"blocker: {blocker}");
    }

    private static GameBootstrapResult Result(string validationResult, string? extractionRoot, string? selectedEboot, string? ebootSha256, string? titleId, string? verifiedVersion, IReadOnlyList<string> blockers, IReadOnlyList<string> warnings, string versionStatus = "unknown") => new(
        "1.0.0",
        validationResult,
        extractionRoot is null ? null : "<private-game-root>",
        selectedEboot is null ? null : "<private-game-root>/" + Path.GetFileName(selectedEboot),
        ebootSha256,
        titleId,
        verifiedVersion,
        versionStatus,
        validationResult is "passed" or "reused",
        blockers,
        warnings);

    private sealed record Candidate(string Path, (string? TitleId, string? Version, string? SourcePath) Metadata);
}
