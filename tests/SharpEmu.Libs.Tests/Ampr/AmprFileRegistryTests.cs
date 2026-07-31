// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Ampr;
using Xunit;

namespace SharpEmu.Libs.Tests.Ampr;

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
