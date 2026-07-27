// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness.Tests;

public sealed class DoctorTests
{
    [Fact]
    public async Task MissingProfileIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "missing.json");
        Assert.False(validation.Valid);
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
        Assert.True(DoctorCommand.IsTargetReady(validation, environmentOnly: true));
    }

    [Fact]
    public async Task MalformedProfileIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.GitFixture.Write("profile.json", "{");
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.False(validation.Valid);
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task MissingEbootIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile(ebootPath: Path.Combine(fixture.GitFixture.Path, "missing-eboot.bin"));
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.False(validation.EbootExists);
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task ChangedEbootWithStaleExpectedHashIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile();
        await File.AppendAllTextAsync(fixture.EbootPath, "changed");
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.Equal("mismatched", validation.HashStatus);
        Assert.False(validation.EbootHashMatches);
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task WrongTitleIdIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile(verifiedTitleId: "WRONG00000");
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.Contains(validation.Errors, error => error.Contains("Title ID contradicts", StringComparison.Ordinal));
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task WrongVersionIsNotTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile(verifiedVersion: "99.999.999");
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.Contains(validation.Errors, error => error.Contains("version contradicts", StringComparison.Ordinal));
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task ValidProfileAndMatchingHashAreTargetReady()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile();
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json");
        Assert.True(validation.Valid);
        Assert.True(validation.EbootHashMatches);
        Assert.Equal("matched", validation.HashStatus);
        Assert.True(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    [Fact]
    public async Task FastModeReportsUnverifiedAndNeverMatched()
    {
        using var fixture = ProfileFixture.Create();
        fixture.WriteProfile();
        var (_, validation) = await ProfileLoader.LoadAndValidateAsync(fixture.Repository, "profile.json", verifyHash: false);
        Assert.True(validation.Valid);
        Assert.False(validation.EbootHashMatches);
        Assert.Equal("not-verified", validation.HashStatus);
        Assert.False(DoctorCommand.IsTargetReady(validation, environmentOnly: false));
    }

    private sealed class ProfileFixture : IDisposable
    {
        private ProfileFixture(TemporaryGitRepository gitFixture)
        {
            GitFixture = gitFixture;
            Repository = GitRepository.Discover(gitFixture.Path);
            EbootPath = Path.Combine(gitFixture.Path, "private", "eboot.bin");
            Directory.CreateDirectory(Path.GetDirectoryName(EbootPath)!);
            File.WriteAllBytes(EbootPath, [1, 2, 3, 4]);
        }

        public TemporaryGitRepository GitFixture { get; }
        public GitRepository Repository { get; }
        public string EbootPath { get; }

        public static ProfileFixture Create() => new(TemporaryGitRepository.Create());

        public void WriteProfile(string? ebootPath = null, string verifiedTitleId = "PPSA01341", string verifiedVersion = "01.004.000")
        {
            var selectedEboot = ebootPath ?? EbootPath;
            var profile = new LocalRunProfile
            {
                TargetName = "Synthetic target",
                ExpectedTitleId = "PPSA01341",
                ExpectedVersion = "01.004.000",
                EbootPath = selectedEboot,
                EbootSha256 = File.Exists(selectedEboot) ? GitRepository.Sha256File(selectedEboot) : new string('0', 64),
                Metadata = new TargetMetadata
                {
                    TitleIdVerified = true,
                    VerifiedTitleId = verifiedTitleId,
                    VersionVerified = true,
                    VerifiedVersion = verifiedVersion,
                    VersionStatus = "verified",
                },
            };
            GitFixture.Write("profile.json", JsonSerializer.Serialize(profile, Program.JsonOptions));
        }

        public void Dispose() => GitFixture.Dispose();
    }
}
