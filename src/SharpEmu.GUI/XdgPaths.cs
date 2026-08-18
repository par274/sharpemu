// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI;

/// <summary>
/// Resolves XDG Base Directory locations on Linux, falling back to the
/// conventional ~/.config, ~/.local/share, and ~/.cache paths when the
/// corresponding XDG_* environment variable isn't set. Only used on Linux;
/// Windows and macOS keep the existing portable (next-to-executable) layout.
/// </summary>
internal static class XdgPaths
{
    internal static string ConfigHome =>
        Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");

    internal static string DataHome =>
        Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");

    internal static string CacheHome =>
        Environment.GetEnvironmentVariable("XDG_CACHE_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache");
}
