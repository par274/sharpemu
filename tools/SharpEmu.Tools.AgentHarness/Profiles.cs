// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record LocalRunProfile
{
    public string SchemaVersion { get; init; } = "1.0.0";

    public string TargetName { get; init; } = string.Empty;

    public string ExpectedTitleId { get; init; } = string.Empty;

    public string ExpectedVersion { get; init; } = string.Empty;

    public string EbootPath { get; init; } = string.Empty;

    public string EbootSha256 { get; init; } = string.Empty;

    public string BuildConfiguration { get; init; } = "Debug";

    public string? EmulatorExecutable { get; init; }

    public IReadOnlyList<string> EmulatorArguments { get; init; } = [];

    public int TimeoutSeconds { get; init; } = 180;

    public string LogLevel { get; init; } = "debug";

    public int ImportTraceLimit { get; init; } = 64;

    public CapturePolicy Capture { get; init; } = new();

    public IReadOnlyDictionary<string, string?> Environment { get; init; } = new Dictionary<string, string?>();

    public IReadOnlyList<string> RedactionRoots { get; init; } = [];

    public TargetMetadata Metadata { get; init; } = new();
}

internal sealed record CapturePolicy
{
    public bool NativeEnabled { get; init; } = true;

    public bool WindowFallbackEnabled { get; init; }

    public bool FirstFrame { get; init; } = true;

    public IReadOnlyList<long> FrameNumbers { get; init; } = [];

    public int Interval { get; init; }

    public int MaxFrames { get; init; } = 8;

    public IReadOnlyList<int> WindowSampleSeconds { get; init; } = [];
}

internal sealed record TargetMetadata
{
    public bool TitleIdVerified { get; init; }

    public string? VerifiedTitleId { get; init; }

    public bool VersionVerified { get; init; }

    public string? VerifiedVersion { get; init; }

    public string? MetadataSource { get; init; }

    public string VersionStatus { get; init; } = "unverified";
}

internal sealed record ProfileValidation(
    bool Valid,
    string ProfilePath,
    string? TargetName,
    string? ExpectedTitleId,
    string? ExpectedVersion,
    bool EbootExists,
    bool EbootHashMatches,
    string HashStatus,
    bool TitleIdVerified,
    string? VerifiedTitleId,
    string VersionStatus,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);

internal static class ProfileLoader
{
    public static async Task<(LocalRunProfile? Profile, ProfileValidation Validation)> LoadAndValidateAsync(
        GitRepository repository,
        string path,
        bool verifyHash = true,
        CancellationToken cancellationToken = default)
    {
        var fullPath = repository.ResolvePath(path);
        var errors = new List<string>();
        var warnings = new List<string>();
        if (!File.Exists(fullPath))
        {
            errors.Add("Profile file does not exist.");
            return (null, InvalidProfile(repository, fullPath, errors, warnings));
        }

        LocalRunProfile? profile;
        try
        {
            await using var stream = File.OpenRead(fullPath);
            profile = await JsonSerializer.DeserializeAsync<LocalRunProfile>(stream, Program.JsonOptions, cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or IOException)
        {
            errors.Add($"Profile JSON is invalid: {RunArtifactRedactor.SanitizeMessage(exception.Message, repository)}");
            return (null, InvalidProfile(repository, fullPath, errors, warnings));
        }

        if (profile is null)
        {
            errors.Add("Profile JSON was empty.");
            return (null, InvalidProfile(repository, fullPath, errors, warnings));
        }

        if (profile.SchemaVersion != "1.0.0") errors.Add($"Unsupported profile schema '{profile.SchemaVersion}'.");
        if (string.IsNullOrWhiteSpace(profile.TargetName)) errors.Add("targetName is required.");
        if (string.IsNullOrWhiteSpace(profile.ExpectedTitleId)) errors.Add("expectedTitleId is required.");
        if (string.IsNullOrWhiteSpace(profile.ExpectedVersion)) errors.Add("expectedVersion is required.");
        if (profile.TimeoutSeconds is <= 0 or > 180) errors.Add("timeoutSeconds must be between 1 and 180.");
        if (profile.ImportTraceLimit is < 0 or > 10_000) errors.Add("importTraceLimit must be between 0 and 10000.");
        if (profile.Capture.MaxFrames is < 0 or > 8) errors.Add("capture.maxFrames must be between 0 and 8.");

        var ebootPath = Path.IsPathFullyQualified(profile.EbootPath)
            ? Path.GetFullPath(profile.EbootPath)
            : repository.ResolvePath(profile.EbootPath);
        var ebootExists = File.Exists(ebootPath);
        if (!ebootExists)
        {
            errors.Add("Selected eboot does not exist.");
        }
        var hashMatches = false;
        var hashStatus = "not-verified";
        if (ebootExists && verifyHash)
        {
            hashMatches = string.Equals(
                GitRepository.Sha256File(ebootPath),
                profile.EbootSha256,
                StringComparison.OrdinalIgnoreCase);
            hashStatus = hashMatches ? "matched" : "mismatched";
            if (!hashMatches) errors.Add("Selected eboot SHA-256 does not match the profile.");
        }

        var (metadataTitleId, metadataVersion) = ReadMetadataIdentity(repository, profile.Metadata.MetadataSource);
        if (!string.IsNullOrWhiteSpace(metadataTitleId) &&
            !string.IsNullOrWhiteSpace(profile.Metadata.VerifiedTitleId) &&
            !string.Equals(metadataTitleId, profile.Metadata.VerifiedTitleId, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Actual target metadata Title ID contradicts the profile verification record.");
        }
        if (!string.IsNullOrWhiteSpace(metadataVersion) &&
            !string.IsNullOrWhiteSpace(profile.Metadata.VerifiedVersion) &&
            !string.Equals(metadataVersion, profile.Metadata.VerifiedVersion, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Actual target metadata version contradicts the profile verification record.");
        }
        var verifiedTitleId = metadataTitleId ?? profile.Metadata.VerifiedTitleId;
        var verifiedVersion = metadataVersion ?? profile.Metadata.VerifiedVersion;
        if (!profile.Metadata.TitleIdVerified || string.IsNullOrWhiteSpace(verifiedTitleId))
        {
            errors.Add("The target Title ID is not independently verified.");
        }
        else if (!string.Equals(verifiedTitleId, profile.ExpectedTitleId, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Verified target Title ID contradicts expectedTitleId.");
        }
        if (!profile.Metadata.VersionVerified || string.IsNullOrWhiteSpace(verifiedVersion))
        {
            errors.Add("The target version is not independently verified.");
        }
        if (profile.Metadata.VersionVerified &&
            !string.Equals(verifiedVersion, profile.ExpectedVersion, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Verified target version contradicts expectedVersion.");
        }
        if (profile.EmulatorArguments.Any(argument => string.Equals(argument, "--strict", StringComparison.OrdinalIgnoreCase)))
        {
            warnings.Add("Strict dynamic-library resolution is enabled by the profile; confirm this is intentional evidence, not a faster-failure shortcut.");
        }
        profile = profile with
        {
            Metadata = profile.Metadata with
            {
                VerifiedTitleId = verifiedTitleId,
                VerifiedVersion = verifiedVersion,
            },
        };

        return (profile, new ProfileValidation(
            errors.Count == 0,
            Redact(repository, fullPath),
            profile.TargetName,
            profile.ExpectedTitleId,
            profile.ExpectedVersion,
            ebootExists,
            hashMatches,
            hashStatus,
            profile.Metadata.TitleIdVerified && !string.IsNullOrWhiteSpace(verifiedTitleId),
            verifiedTitleId,
            profile.Metadata.VersionStatus,
            errors,
            warnings));
    }

    private static string Redact(GitRepository repository, string path) =>
        path.StartsWith(repository.Root, StringComparison.OrdinalIgnoreCase)
            ? "<repo>/" + GitRepository.NormalizeRelativePath(Path.GetRelativePath(repository.Root, path))
            : "<private>/" + Path.GetFileName(path);

    private static ProfileValidation InvalidProfile(
        GitRepository repository,
        string path,
        IReadOnlyList<string> errors,
        IReadOnlyList<string> warnings) =>
        new(false, Redact(repository, path), null, null, null, false, false, "not-verified", false, null, "unknown", errors, warnings);

    private static (string? TitleId, string? Version) ReadMetadataIdentity(GitRepository repository, string? source)
    {
        if (string.IsNullOrWhiteSpace(source)) return (null, null);
        try
        {
            var path = Path.IsPathFullyQualified(source) ? Path.GetFullPath(source) : repository.ResolvePath(source);
            if (!File.Exists(path)) return (null, null);
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            return (
                StringProperty(root, "titleId") ?? StringProperty(root, "titleID") ?? StringProperty(root, "TITLE_ID"),
                StringProperty(root, "contentVersion") ?? StringProperty(root, "masterVersion") ?? StringProperty(root, "targetContentVersion") ?? StringProperty(root, "version"));
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    private static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

internal static class ProfileCommand
{
    public static async Task<int> RunAsync(GitRepository repository, CommandArguments arguments)
    {
        if (!arguments.Is("validate")) return Program.Fail("profile requires validate.");
        var path = arguments.Value("--profile");
        if (string.IsNullOrWhiteSpace(path)) return Program.Fail("profile validate requires --profile.");
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(repository, path, verifyHash: !arguments.Has("--fast"));
        if (arguments.Has("--json"))
        {
            Program.WriteJson(validation);
        }
        else
        {
            Console.WriteLine(validation.Valid ? "Profile is valid." : "Profile is invalid.");
            foreach (var warning in validation.Warnings) Console.WriteLine($"warning: {warning}");
            foreach (var error in validation.Errors) Console.Error.WriteLine($"error: {error}");
        }
        return validation.Valid ? 0 : 2;
    }
}
