// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Ampr;
using Xunit;

namespace SharpEmu.Libs.Tests.Ampr;

// AmprFileRegistry is process-global static state, so the classes that index
// or clear it must not run concurrently with each other.
[Collection("AmprFileRegistry")]
public class AmprFileRegistryTests
{
    [Fact]
    public void ComputeFileId_matches_utf8_fnv1a()
    {
        const string relative = "CoreData/foo/bar.bin";
        Assert.Equal(FnvUtf8("$/" + relative), AmprFileRegistry.ComputeFileId("$/" + relative));
        Assert.Equal(FnvUtf8("/app0/" + relative), AmprFileRegistry.ComputeFileId("/app0/" + relative));
        Assert.Equal(FnvUtf8("app0/" + relative), AmprFileRegistry.ComputeFileId("app0/" + relative));
        Assert.Equal(FnvUtf8(relative), AmprFileRegistry.ComputeFileId(relative));
    }

    [Fact]
    public void RegisterApp0Relative_publishes_same_ids_as_string_hashes()
    {
        AmprFileRegistry.ClearForTests();
        const string relative = "misc/loadouts/test.txt";
        var host = Path.Combine(Path.GetTempPath(), "sharpemu-ampr-test", relative);
        AmprFileRegistry.RegisterApp0RelativeForTests(relative, host);

        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("$/" + relative), out var a));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("/app0/" + relative), out var b));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("app0/" + relative), out var c));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId(relative), out var d));
        Assert.Equal(host, a);
        Assert.Equal(host, b);
        Assert.Equal(host, c);
        Assert.Equal(host, d);
    }

    [Fact]
    public void Register_publishes_all_app0_path_aliases()
    {
        AmprFileRegistry.ClearForTests();
        const string relative = "scripts/cp11/cp11main.script";
        var host = Path.Combine(Path.GetTempPath(), "sharpemu-ampr-test2", relative);
        AmprFileRegistry.Register("$/" + relative, host);

        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("$/" + relative), out var a));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("/app0/" + relative), out var b));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId("app0/" + relative), out var c));
        Assert.True(AmprFileRegistry.TryGetHostPath(
            AmprFileRegistry.ComputeFileId(relative), out var d));
        Assert.Equal(host, a);
        Assert.Equal(host, b);
        Assert.Equal(host, c);
        Assert.Equal(host, d);
    }

    [Fact]
    public void App0_index_cache_keeps_files_that_differ_only_by_case()
    {
        var root = Path.Combine(Path.GetTempPath(), "sharpemu-ampr-case-" + Guid.NewGuid().ToString("N"));
        var cacheDir = Path.Combine(root, "..", "sharpemu-ampr-cache-" + Guid.NewGuid().ToString("N"));
        var upper = Path.Combine(root, "data", "ASSET.bin");
        var lower = Path.Combine(root, "data", "asset.bin");
        var previousCacheDir = Environment.GetEnvironmentVariable("SHARPEMU_AMPR_INDEX_CACHE");
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "sce_sys"));
            Directory.CreateDirectory(Path.Combine(root, "data"));
            File.WriteAllText(Path.Combine(root, "sce_sys", "param.json"), "{}");
            File.WriteAllBytes(upper, [1, 2, 3]);
            if (File.Exists(lower))
            {
                // Case-insensitive host: the two names are one file, so there is
                // nothing for an ignore-case index to lose.
                return;
            }

            File.WriteAllBytes(lower, [4, 5, 6]);
            Environment.SetEnvironmentVariable("SHARPEMU_AMPR_INDEX_CACHE", cacheDir);

            var normalizedRoot = Path.GetFullPath(root);
            var expectedUpper = Path.Combine(normalizedRoot, "data", "ASSET.bin");
            var expectedLower = Path.Combine(normalizedRoot, "data", "asset.bin");

            // Fresh tree walk, which also writes the on-disk index cache.
            AmprFileRegistry.ClearForTests();
            AmprFileRegistry.EnsureApp0Indexed(root);
            AssertResolves(expectedUpper, expectedLower);

            // Second boot: served from the cache the walk just wrote.
            AmprFileRegistry.ClearForTests();
            AmprFileRegistry.EnsureApp0Indexed(root);
            AssertResolves(expectedUpper, expectedLower);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SHARPEMU_AMPR_INDEX_CACHE", previousCacheDir);
            AmprFileRegistry.ClearForTests();
            TryDeleteDirectory(cacheDir);
            TryDeleteDirectory(root);
        }

        static void AssertResolves(string expectedUpper, string expectedLower)
        {
            Assert.True(
                AmprFileRegistry.TryGetHostPath(
                    AmprFileRegistry.ComputeFileId("$/data/ASSET.bin"), out var actualUpper),
                "data/ASSET.bin is missing from the app0 index.");
            Assert.True(
                AmprFileRegistry.TryGetHostPath(
                    AmprFileRegistry.ComputeFileId("$/data/asset.bin"), out var actualLower),
                "data/asset.bin is missing from the app0 index.");
            Assert.Equal(expectedUpper, actualUpper);
            Assert.Equal(expectedLower, actualLower);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception)
        {
            // Temp cleanup is best-effort.
        }
    }

    private static uint FnvUtf8(string text)
    {
        const uint offset = 2166136261;
        const uint prime = 16777619;
        var hash = offset;
        foreach (var b in System.Text.Encoding.UTF8.GetBytes(text))
        {
            hash ^= b;
            hash *= prime;
        }

        return hash;
    }
}
