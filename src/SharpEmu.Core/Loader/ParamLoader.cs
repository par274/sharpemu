// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;
using SharpEmu.Core;

namespace SharpEmu.Core.Loader;

public sealed record ParamLoader(
    string? TitleId,
    string? ContentId,
    string? ContentVersion,
    string? MasterVersion,
    string? TargetContentVersion,
    LocalizedParameters? LocalizedParameters,
    Disc? Disc
);

public sealed record LocalizedParameters(
    string? DefaultLanguage,
    Dictionary<string, LocalizedLanguage>? Languages
);

public sealed record LocalizedLanguage(string? TitleName);

public sealed record Disc(LocalizedParameters? LocalizedParameters);

public static class Ps5ParamJsonReader
{
    public static (string? Title, string? TitleId, string? Version) TryReadPs5Param(IFileSystem fs, string paramJsonPath)
    {
        if (!fs.Exists(paramJsonPath))
            return (null, null, null);

        if (!fs.TryReadAllBytes(paramJsonPath, out var data))
            return (null, null, null);

        return TryReadPs5Param(data);
    }

    public static (string? Title, string? TitleId, string? Version) TryReadPs5Param(byte[] data)
    {
        if (data == null || data.Length == 0)
            return (null, null, null);

        try
        {
            using var doc = JsonDocument.Parse(data);
            return TryReadPs5Param(doc.RootElement);
        }
        catch (JsonException)
        {
            return (null, null, null);
        }
    }

    private static (string? Title, string? TitleId, string? Version) TryReadPs5Param(JsonElement root)
    {
        string? titleId = root.TryGetProperty("titleId", out var eTid) ? eTid.GetString() : null;

        string? ver =
            (root.TryGetProperty("contentVersion", out var cv) ? cv.GetString() : null)
            ?? (root.TryGetProperty("masterVersion", out var mv) ? mv.GetString() : null)
            ?? (root.TryGetProperty("targetContentVersion", out var tv) ? tv.GetString() : null);

        string? title = ExtractTitleName(root);

        return (title, titleId, ver);
    }

    private static string? ExtractTitleName(JsonElement root)
    {
        if (!root.TryGetProperty("localizedParameters", out var lp))
        {
            if (root.TryGetProperty("disc", out var disc) && disc.ValueKind == JsonValueKind.Object)
            {
                disc.TryGetProperty("localizedParameters", out lp);
            }
        }

        if (lp.ValueKind != JsonValueKind.Object)
            return null;

        string? defLang = lp.TryGetProperty("defaultLanguage", out var dl) ? dl.GetString() : null;

        if (!string.IsNullOrEmpty(defLang))
        {
            if (lp.TryGetProperty(defLang, out var langObj) && langObj.ValueKind == JsonValueKind.Object)
            {
                if (langObj.TryGetProperty("titleName", out var tn))
                    return tn.GetString();
            }
        }

        if (lp.TryGetProperty("en-US", out var en) && en.ValueKind == JsonValueKind.Object)
        {
            if (en.TryGetProperty("titleName", out var tn2))
                return tn2.GetString();
        }

        return null;
    }
}
