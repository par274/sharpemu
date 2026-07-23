// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.GUI.Services.Abstractions;

namespace SharpEmu.GUI;

/// <summary>
/// The single bridge between the NativeWebView-hosted Vue frontend and the
/// launcher's C# services. Every UI action is a JSON message from JS routed
/// here by <see cref="NativeWebView.WebMessageReceived"/>; every piece of state
/// the UI needs is pushed back via <see cref="PushToJs"/>.
///
/// The bridge owns no UI controls except the WebView itself — game surface
/// hosting, session popups and launch wiring stay in <c>MainWindow</c>, which
/// subscribes to the bridge's events (<see cref="LaunchRequested"/>,
/// <see cref="StopRequested"/>, …) for the actions that need native surfaces.
/// </summary>
public sealed class LauncherBridge
{
    private readonly NativeWebView _web;
    private readonly IServiceProvider _services;

    // Resolved lazily so the bridge can be constructed before the services are
    // fully wired (it is created alongside the WebView in MainWindow).
    private IGameLibraryService Library => _services.GetRequiredService<IGameLibraryService>();
    private ISettingsService Settings => _services.GetRequiredService<ISettingsService>();
    private ILogService Log => _services.GetRequiredService<ILogService>();
    private IEmulatorService Emulator => _services.GetRequiredService<IEmulatorService>();
    private ILocalizationService LocalizationSvc => _services.GetRequiredService<ILocalizationService>();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public LauncherBridge(NativeWebView web, IServiceProvider services)
    {
        _web = web;
        _services = services;
        _web.WebMessageReceived += OnWebMessage;
    }

    // ---- Events the MainWindow handles (anything needing a native surface) ----

    /// <summary>Raised when the frontend asks to launch a game.</summary>
    public event Action<string>? LaunchRequested;

    /// <summary>Raised when the frontend asks to stop the running game.</summary>
    public event Action? StopRequested;

    /// <summary>Raised when the frontend asks to rescan the library folders.</summary>
    public event Action? RescanRequested;

    /// <summary>Raised when the frontend asks to add a game folder.</summary>
    public event Action? AddFolderRequested;

    /// <summary>Raised when the frontend asks to open a file picker for an eboot.</summary>
    public event Action? OpenFileRequested;

    /// <summary>Raised when the frontend asks to open a game's install folder.</summary>
    public event Action<string>? OpenGameFolderRequested;

    /// <summary>Raised when the frontend asks to open the per-game settings dialog.</summary>
    public event Action<string>? GameSettingsRequested;

    /// <summary>Raised when the frontend asks to remove a game from the library.</summary>
    public event Action<string>? RemoveGameRequested;

    /// <summary>Raised when the frontend asks to check for updates.</summary>
    public event Action? CheckUpdatesRequested;

    /// <summary>Raised when the frontend asks to open an external URL.</summary>
    public event Action<string>? OpenExternalRequested;

    /// <summary>Raised when the frontend asks to clear the log buffer.</summary>
    public event Action? ClearLogRequested;

    /// <summary>Raised when the frontend asks to copy all visible log lines.</summary>
    public event Action? CopyLogRequested;

    /// <summary>Raised when the frontend asks to open the detached console window.</summary>
    public event Action? DetachConsoleRequested;

    /// <summary>Raised when the frontend asks to pick a custom log file path.</summary>
    public event Action? SelectLogFilePathRequested;

    /// <summary>Raised when the frontend toggles an environment variable.</summary>
    public event Action<string, bool>? EnvironmentToggleRequested;

    /// <summary>Raised when the frontend asks to copy text to the clipboard.</summary>
    public event Action<string>? CopyRequested;

    /// <summary>Raised when the frontend needs the selected game's full-size key art.</summary>
    public event Action<string>? BackgroundRequested;

    /// <summary>
    /// Detaches the message handler. Call when the WebView is being torn down so
    /// a late message does not dispatch into a disposed host.
    /// </summary>
    public void Detach() => _web.WebMessageReceived -= OnWebMessage;

    // ---- JS → C# command dispatch ----

    private void OnWebMessage(object? sender, WebMessageReceivedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(e.Body))
        {
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(e.Body);
            if (!doc.RootElement.TryGetProperty("type", out var typeProp))
            {
                return;
            }

            var type = typeProp.GetString();
            var root = doc.RootElement;
            switch (type)
            {
                case "launch":
                    LaunchRequested?.Invoke(root.GetProperty("ebootPath").GetString() ?? "");
                    break;
                case "stop":
                    StopRequested?.Invoke();
                    break;
                case "rescan":
                    RescanRequested?.Invoke();
                    break;
                case "addFolder":
                    AddFolderRequested?.Invoke();
                    break;
                case "openFile":
                    OpenFileRequested?.Invoke();
                    break;
                case "openGameFolder":
                    OpenGameFolderRequested?.Invoke(root.GetProperty("ebootPath").GetString() ?? "");
                    break;
                case "gameSettings":
                    GameSettingsRequested?.Invoke(root.GetProperty("ebootPath").GetString() ?? "");
                    break;
                case "removeGame":
                    RemoveGameRequested?.Invoke(root.GetProperty("ebootPath").GetString() ?? "");
                    break;
                case "checkUpdates":
                    CheckUpdatesRequested?.Invoke();
                    break;
                case "openExternal":
                    OpenExternalRequested?.Invoke(root.GetProperty("url").GetString() ?? "");
                    break;
                case "clearLog":
                    ClearLogRequested?.Invoke();
                    break;
                case "copyLog":
                    CopyLogRequested?.Invoke();
                    break;
                case "detachConsole":
                    DetachConsoleRequested?.Invoke();
                    break;
                case "selectLogFilePath":
                    SelectLogFilePathRequested?.Invoke();
                    break;
                case "toggleEnv":
                    EnvironmentToggleRequested?.Invoke(
                        root.GetProperty("name").GetString() ?? "",
                        root.GetProperty("enabled").GetBoolean());
                    break;
                case "copyToClipboard":
                    CopyToClipboard(root.GetProperty("text").GetString() ?? "");
                    break;
                case "setSettings":
                    ApplySettings(root.GetProperty("settings"));
                    break;
                case "searchLibrary":
                    // Filtering happens client-side; the host only needs the
                    // query if it wants to mirror selection. No-op for now.
                    break;
                case "requestBackground":
                    BackgroundRequested?.Invoke(root.GetProperty("ebootPath").GetString() ?? "");
                    break;
                case "requestState":
                    _ = PushInitialStateAsync();
                    break;
            }
        }
        catch (JsonException)
        {
            // A malformed message from the page is ignored, not fatal.
        }
    }

    private void CopyToClipboard(string text)
    {
        // Clipboard access needs the Window; forward to the host which owns it.
        if (!string.IsNullOrEmpty(text))
        {
            CopyRequested?.Invoke(text);
        }
    }

    private void ApplySettings(JsonElement settingsEl)
    {
        var s = Settings.Settings;

        if (settingsEl.TryGetProperty("logLevel", out var ll) && ll.ValueKind == JsonValueKind.String)
        {
            s.LogLevel = ll.GetString() ?? s.LogLevel;
        }
        if (settingsEl.TryGetProperty("importTraceLimit", out var ti) && ti.TryGetInt32(out var trace))
        {
            s.ImportTraceLimit = trace;
        }
        if (TryGetBool(settingsEl, "strictDynlibResolution", out var strict))
        {
            s.StrictDynlibResolution = strict;
        }
        if (TryGetBool(settingsEl, "logToFile", out var logToFile))
        {
            s.LogToFile = logToFile;
        }
        if (TryGetBool(settingsEl, "overrideLogFile", out var overrideLogFile))
        {
            s.OverrideLogFile = overrideLogFile;
        }
        if (TryGetBool(settingsEl, "playTitleMusic", out var playTitleMusic))
        {
            s.PlayTitleMusic = playTitleMusic;
        }
        if (TryGetBool(settingsEl, "discordRichPresence", out var discordRichPresence))
        {
            s.DiscordRichPresence = discordRichPresence;
        }
        if (TryGetBool(settingsEl, "checkForUpdatesOnStartup", out var checkUpdates))
        {
            s.CheckForUpdatesOnStartup = checkUpdates;
        }
        if (settingsEl.TryGetProperty("renderResolutionScale", out var rr) && rr.TryGetDouble(out var scale))
        {
            s.RenderResolutionScale = scale;
        }
        if (settingsEl.TryGetProperty("language", out var lang) && lang.ValueKind == JsonValueKind.String)
        {
            s.Language = lang.GetString() ?? s.Language;
        }

        Settings.Save();
    }

    private static bool TryGetBool(JsonElement obj, string name, out bool value)
    {
        if (obj.TryGetProperty(name, out var el) && el.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            value = el.GetBoolean();
            return true;
        }

        value = default;
        return false;
    }

    // ---- C# → JS state push ----

    /// <summary>Pushes the initial library/settings/localization after the page loads.</summary>
    public async Task PushInitialStateAsync()
    {
        await PushSettingsAsync();
        await PushLocalizationAsync();
        await PushSessionAsync();
    }

    /// <summary>Pushes the scanned library (covers inlined as base64 data URIs).</summary>
    public async Task PushLibraryAsync(IReadOnlyList<GameEntry> games)
    {
        var dtos = new List<GameEntryDto>(games.Count);
        foreach (var game in games)
        {
            dtos.Add(ToDto(game));
        }

        await PushToJs("__sharpemu.receive", "library", new { games = dtos });
    }

    public async Task PushSettingsAsync()
    {
        var s = Settings.Settings;
        var dto = new SettingsDto(
            s.LogLevel,
            s.ImportTraceLimit,
            s.RenderResolutionScale,
            s.StrictDynlibResolution,
            s.LogToFile,
            s.LogFilePath,
            s.OverrideLogFile,
            s.PlayTitleMusic,
            s.DiscordRichPresence,
            s.CheckForUpdatesOnStartup,
            s.Language,
            s.EnvironmentToggles);
        await PushToJs("__sharpemu.receive", "settings", dto);
    }

    public async Task PushLocalizationAsync()
    {
        // Hand the frontend the current language's full dictionary (merged with
        // the English fallback) so it can resolve keys locally without a
        // round-trip per string.
        var code = LocalizationSvc.CurrentCode;
        var strings = Localization.Instance.GetAllStrings();
        await PushToJs("__sharpemu.receive", "localization", new { code, strings });
    }

    public async Task PushSessionAsync(bool isRunning = false, bool isStopping = false, string? title = null, int? exitCode = null)
    {
        var dto = new SessionStateDto(isRunning, isStopping, title, exitCode);
        await PushToJs("__sharpemu.receive", "session", dto);
    }

    public async Task PushScanningAsync(bool isScanning)
        => await PushToJs("__sharpemu.receive", "scanning", new { isScanning });

    /// <summary>
    /// Reads and pushes only the selected game's full-resolution key art.
    /// Backgrounds can be several megabytes, so they are deliberately excluded
    /// from the initial library payload and requested lazily by the frontend.
    /// </summary>
    public async Task PushBackgroundAsync(GameEntry game)
    {
        var background = game.BackgroundPath is not null
            ? await Task.Run(() => TryReadAsDataUri(game.BackgroundPath))
            : null;

        await PushToJs(
            "__sharpemu.receive",
            "background",
            new { ebootPath = game.Path, backgroundDataUri = background });
    }

    /// <summary>Pushes buffered log lines as a batch (call from a flush timer).</summary>
    public async Task PushLogBatchAsync(IEnumerable<(string Text, bool IsError)> lines)
    {
        var dtos = new List<LogLineDto>();
        foreach (var (text, isError) in lines)
        {
            dtos.Add(new LogLineDto(text, isError));
        }

        await PushToJs("__sharpemu.receive", "logBatch", new { lines = dtos });
    }

    private async Task PushToJs(string globalFn, string eventArg, object payload)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        // Call window.__sharpemu.receive("event", {...}). JSON is embedded as a
        // raw JS object literal (not a quoted string) so the receiver gets an
        // object directly — matching the bridge.ts contract.
        var script = $"{globalFn}({JsonSerializer.Serialize(eventArg)}, {json})";
        try
        {
            await _web.InvokeScript(script);
        }
        catch
        {
            // The page may not be ready yet (navigation still in flight). The
            // initial state push is retried on NavigationCompleted.
        }
    }

    private static GameEntryDto ToDto(GameEntry game)
    {
        var cover = game.CoverPath is not null
            ? TryReadAsDataUri(game.CoverPath)
            : null;

        return new GameEntryDto(
            game.Path,
            game.Name,
            game.TitleId,
            game.Version,
            FormatSize(game.SizeBytes),
            cover,
            HasBackground: game.BackgroundPath is not null,
            LastPlayedText: null,
            HasPlayed: false);
    }

    /// <summary>Reads a small image file and returns it as a base64 data URI.</summary>
    private static string? TryReadAsDataUri(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
            var mime = ext switch { "png" => "image/png", "jpg" or "jpeg" => "image/jpeg", "webp" => "image/webp", _ => "image/png" };
            return $"data:{mime};base64,{System.Convert.ToBase64String(bytes)}";
        }
        catch
        {
            return null;
        }
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GiB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MiB",
        >= 1L << 10 => $"{bytes / (double)(1L << 10):0.0} KiB",
        _ => $"{bytes} B",
    };

    // ---- DTOs (camelCase to match the TypeScript types.ts) ----

    private sealed record GameEntryDto(
        string EbootPath,
        string Name,
        string? TitleId,
        string? Version,
        string SizeText,
        string? CoverDataUri,
        bool HasBackground,
        string? LastPlayedText,
        bool HasPlayed);

    private sealed record SettingsDto(
        string LogLevel,
        int ImportTraceLimit,
        double RenderResolutionScale,
        bool StrictDynlibResolution,
        bool LogToFile,
        string? LogFilePath,
        bool OverrideLogFile,
        bool PlayTitleMusic,
        bool DiscordRichPresence,
        bool CheckForUpdatesOnStartup,
        string Language,
        IReadOnlyList<string> EnvironmentToggles);

    private sealed record SessionStateDto(bool IsRunning, bool IsStopping, string? Title, int? ExitCode);

    private sealed record LogLineDto(string Text, bool IsError);
}
