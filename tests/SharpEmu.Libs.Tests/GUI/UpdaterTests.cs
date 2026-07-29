// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.GUI;
using Xunit;

namespace SharpEmu.Libs.Tests.GUI;

public sealed class UpdaterTests
{
    [Fact]
    public void ParseReleases_PreservesNewestToOldestVersionedChangelog()
    {
        const string json = """
            [
              {
                "tag_name": "v0.0.3-hotfix-2",
                "body": "Build for commit [`d5108e8`](https://example.test/d5108e8).\n\nNewest changes.",
                "assets": [{
                  "name": "sharpemu-0.0.3-hotfix-2-win-x64.zip",
                  "browser_download_url": "https://example.test/new.zip",
                  "size": 42,
                  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "created_at": "2026-07-28T00:00:00Z"
                }]
              },
              {
                "tag_name": "v0.0.3-hotfix-1",
                "body": "Build for commit [`a3130e3`](https://example.test/a3130e3).\n\nOlder changes.",
                "assets": [{
                  "name": "sharpemu-0.0.3-hotfix-1-win-x64.zip",
                  "browser_download_url": "https://example.test/old.zip",
                  "size": 24,
                  "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                  "created_at": "2026-07-20T00:00:00Z"
                }]
              }
            ]
            """;

        var releases = Updater.ParseReleases(json, "win-x64", ".zip");

        Assert.Collection(
            releases,
            newest =>
            {
                Assert.Equal("d5108e8", newest.Sha);
                Assert.Equal("v0.0.3-hotfix-2", newest.TagName);
                Assert.Equal("Newest changes.", newest.Changelog.Single().Notes.Split("\n\n")[1]);
            },
            oldest =>
            {
                Assert.Equal("a3130e3", oldest.Sha);
                Assert.Equal("v0.0.3-hotfix-1", oldest.TagName);
                Assert.Equal("Older changes.", oldest.Changelog.Single().Notes.Split("\n\n")[1]);
            });
    }
}
