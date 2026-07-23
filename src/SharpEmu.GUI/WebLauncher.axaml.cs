// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.GUI.Services.Abstractions;
using SharpEmu.Libs.VideoOut;
using SharpEmu.Logging;
using System.Diagnostics;
using System.Reflection;

namespace SharpEmu.GUI;

/// <summary>
/// WebView-hosted launcher. The entire launcher UI (library, options, console)
/// renders inside the <see cref="NativeWebView"/> via a bundled Vue app; this
/// window owns only the WebView, the native game surface, and the session
/// popups (which must stay native to float above the game's child HWND).
///
/// The launch pipeline and native-surface lifecycle were lifted verbatim from
/// the legacy <c>MainWindow</c> so game hosting keeps working unchanged; the UI
/// reactions that used to touch named Avalonia controls instead call back into
/// the WebView through <see cref="LauncherBridge"/>.
/// </summary>
public partial class WebLauncher : Window
{
    // Resolved from the shared DI container (same singletons as the ViewModels).
    private readonly IEmulatorService _emulatorService;
    private readonly ILogService _logService;
    private readonly ISettingsService _settingsService;
    private readonly IGameLibraryService _libraryService;
    private readonly LauncherBridge _bridge;

    private readonly List<GameEntry> _allGames = new();
    private GameSurfaceHost? _gameSurfaceHost;
    private ConsoleWindow? _consoleWindow;
    private GuiConsoleMirror? _consoleMirror;
    private readonly DispatcherTimer _logFlushTimer;

    // Emulator session state.
    private bool _isRunning;
    private bool _isStopping;
    private bool _awaitingFirstFrame;
    private bool _gameFullscreen;
    private bool _sessionLoadingActive;
    private string? _runningGameName;
    private string? _runningGameTitleId;
    private string? _runningEbootPath;
    private long _runningSinceUnixSeconds;

    private static readonly StringComparer FilePathComparer = OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private static readonly StringComparison FilePathComparison = OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    /// <summary>Design-time / XAML-loader constructor.</summary>
    public WebLauncher() : this(GuiLauncher.Services) { }

    public WebLauncher(IServiceProvider services)
    {
        InitializeComponent();
        _emulatorService = services.GetRequiredService<IEmulatorService>();
        _logService = services.GetRequiredService<ILogService>();
        _settingsService = services.GetRequiredService<ISettingsService>();
        _libraryService = services.GetRequiredService<IGameLibraryService>();
        _bridge = new LauncherBridge(WebView, services);

        _logService.SetEmulatorExePath(_emulatorService.EmulatorExePath);
        _emulatorService.OutputReceived += OnEmulatorOutput;
        _emulatorService.Exited += code => OnEmulatorExited(code);

        _consoleMirror = GuiConsoleMirror.Install((line, isError) => _logService.Enqueue(line, isError));

        Closed += (_, _) => OnWindowClosing();

        _logFlushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(80) };
        _logFlushTimer.Tick += OnLogFlushTick;
        _logFlushTimer.Start();

        // Native popups follow the launcher into the background / out of it.
        Activated += (_, _) =>
        {
            UpdateSessionBarVisibility();
            SessionLoadingPopup.IsOpen = _sessionLoadingActive;
        };
        Deactivated += (_, _) =>
        {
            SessionBarPopup.IsOpen = false;
            SessionLoadingPopup.IsOpen = false;
        };

        LoadLauncherDocument();

        // ---- Bridge → host wiring (actions needing native surfaces / dialogs) ----
        _bridge.LaunchRequested += path => Dispatcher.UIThread.Post(() => Launch(path));
        _bridge.StopRequested += () => Dispatcher.UIThread.Post(StopEmulator);
        _bridge.RescanRequested += () => _ = RescanLibraryAsync();
        _bridge.AddFolderRequested += () => _ = AddFolderAsync();
        _bridge.OpenFileRequested += () => _ = OpenFileAsync();
        _bridge.OpenGameFolderRequested += path => Dispatcher.UIThread.Post(() => OpenGameFolder(path));
        _bridge.GameSettingsRequested += path => Dispatcher.UIThread.Post(() => OpenGameSettings(path));
        _bridge.RemoveGameRequested += path => Dispatcher.UIThread.Post(() => RemoveGame(path));
        _bridge.CopyRequested += text => _ = CopyToClipboardAsync(text);
        _bridge.BackgroundRequested += path => _ = PushBackgroundAsync(path);
        _bridge.SelectLogFilePathRequested += () => _ = SelectLogFilePathAsync();
        _bridge.EnvironmentToggleRequested += (name, enabled) => Dispatcher.UIThread.Post(() =>
        {
            _settingsService.SetEnvironmentToggle(name, enabled);
            _settingsService.Save();
            _ = _bridge.PushSettingsAsync();
        });
        _bridge.OpenExternalRequested += url => Dispatcher.UIThread.Post(() =>
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch
            {
                // Best-effort.
            }
        });
        _bridge.CheckUpdatesRequested += () => _ = CheckForUpdatesAsync();
        _bridge.ClearLogRequested += () => Dispatcher.UIThread.Post(() => _logService.Clear());
        _bridge.CopyLogRequested += () => _ = CopyConsoleAsync();
        _bridge.DetachConsoleRequested += () => Dispatcher.UIThread.Post(ShowConsoleWindow);

        Opened += async (_, _) => await OnOpenedAsync();
    }

    // ---- WebView document load ----

    /// <summary>
    /// Loads the bundled single-file launcher HTML. In DEBUG it prefers the
    /// Vite dev server (http://localhost:5173) so UI edits hot-reload without a
    /// rebuild; otherwise the embedded WebUI/dist/index.html is loaded as a
    /// string via NavigateToString.
    /// </summary>
    private void LoadLauncherDocument()
    {
#if DEBUG
        try
        {
            using var probe = new HttpClient { Timeout = TimeSpan.FromMilliseconds(400) };
            if (probe.GetAsync("http://localhost:5173").Result.IsSuccessStatusCode)
            {
                WebView.Source = new Uri("http://localhost:5173");
                return;
            }
        }
        catch
        {
            // Dev server not running — fall through to the bundled document.
        }
#endif
        try
        {
            using var stream = AssetLoader.Open(new Uri("avares://SharpEmu.GUI/WebUI/index.html"));
            using var reader = new StreamReader(stream);
            WebView.NavigateToString(reader.ReadToEnd(), new Uri("about:blank"));
        }
        catch (Exception ex)
        {
            WebView.NavigateToString(
                $"<body style='background:#0b0d14;color:#e8ecf4;font-family:sans-serif;padding:40px'>" +
                $"<h2>Failed to load launcher</h2><pre>{System.Net.WebUtility.HtmlEncode(ex.Message)}</pre></body>",
                new Uri("about:blank"));
        }
    }

    private async void OnNavigationCompleted(object? sender, WebViewNavigationCompletedEventArgs e)
    {
        if (e.IsSuccess)
        {
            await _bridge.PushInitialStateAsync();
            await _bridge.PushLocalizationAsync();
            await RescanLibraryAsync();
        }
    }

    // ---- Startup ----

    private async Task OnOpenedAsync()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        var display = version is not null ? $"v{version.ToString(3)}" : "v0.0.1";
        display += BuildInfo.CommitSha is null ? " · dev"
            : BuildInfo.IsOfficialRelease ? $" · {BuildInfo.CommitSha}"
            : $" · UNOFFICIAL {BuildInfo.CommitSha}";
        Title = $"SharpEmu {display}";

        var settings = _settingsService.Settings;
        Localization.Instance.Load(settings.Language);
        // The initial localization push happens in OnNavigationCompleted once
        // the page is ready to receive InvokeScript calls.

        // Kick off background tasks that the old Options page used to run.
        LocateEmulator();
        _ = CheckForUpdatesAsync();
    }

    private void LocateEmulator()
    {
        if (_emulatorService.LocateEmulator())
        {
            _logService.SetEmulatorExePath(_emulatorService.EmulatorExePath);
        }
    }

    // ---- Library scan ----

    private async Task RescanLibraryAsync()
    {
        await _bridge.PushScanningAsync(true);
        var settings = _settingsService.Settings;
        var folders = settings.GameFolders.ToArray();
        var excluded = new HashSet<string>(settings.ExcludedGames, FilePathComparer);

        var games = await Task.Run(() => _libraryService.ScanFolders(folders, excluded));
        _allGames.Clear();
        _allGames.AddRange(games);

        await _bridge.PushLibraryAsync(games);
        await _bridge.PushScanningAsync(false);
    }

    private async Task PushBackgroundAsync(string ebootPath)
    {
        var game = _allGames.FirstOrDefault(candidate =>
            string.Equals(candidate.Path, ebootPath, FilePathComparison));
        if (game is not null)
        {
            await _bridge.PushBackgroundAsync(game);
        }
    }

    private async Task AddFolderAsync()
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = Localization.Instance.Get("Dialog.ChooseGameFolder"),
            AllowMultiple = false,
        });

        var path = folders.FirstOrDefault()?.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var settings = _settingsService.Settings;
        var changed = false;
        if (!settings.GameFolders.Contains(path, FilePathComparer))
        {
            settings.GameFolders.Add(path);
            changed = true;
        }

        var prefix = Path.TrimEndingDirectorySeparator(path) + Path.DirectorySeparatorChar;
        changed |= settings.ExcludedGames.RemoveAll(excluded =>
            excluded.StartsWith(prefix, FilePathComparison)) > 0;

        if (changed)
        {
            settings.Save();
        }

        await RescanLibraryAsync();
    }

    private async Task OpenFileAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Localization.Instance.Get("Dialog.OpenExecutable"),
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType(Localization.Instance.Get("Dialog.PsExecutables")) { Patterns = new[] { "eboot.bin" } },
            },
        });

        var path = files.FirstOrDefault()?.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var game = _allGames.FirstOrDefault(g => g.Path.Equals(path, FilePathComparison));
        Launch(path, game?.Name ?? Path.GetFileName(Path.GetDirectoryName(path)!), game?.TitleId);
    }

    // ---- Library actions (forwarded from the web UI via the bridge) ----

    private void OpenGameFolder(string ebootPath)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{ebootPath}\"",
                    UseShellExecute = false,
                });
            }
            else if (Path.GetDirectoryName(ebootPath) is { } directory)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = OperatingSystem.IsMacOS() ? "open" : "xdg-open",
                    Arguments = $"\"{directory}\"",
                    UseShellExecute = false,
                });
            }
        }
        catch
        {
            // Best-effort.
        }
    }

    private void OpenGameSettings(string ebootPath)
    {
        var game = _allGames.FirstOrDefault(g => g.Path.Equals(ebootPath, FilePathComparison));
        if (game is null || string.IsNullOrWhiteSpace(game.TitleId))
        {
            return;
        }

        var vm = new ViewModels.PerGameSettingsViewModel(game.TitleId, game.Name, _settingsService.Settings);
        _ = new PerGameSettingsDialog(vm).ShowDialog(this);
    }

    private void RemoveGame(string ebootPath)
    {
        var settings = _settingsService.Settings;
        if (!settings.ExcludedGames.Contains(ebootPath, FilePathComparer))
        {
            settings.ExcludedGames.Add(ebootPath);
            settings.Save();
        }

        _allGames.RemoveAll(g => g.Path.Equals(ebootPath, FilePathComparison));
        _ = RescanLibraryAsync();
    }

    private async Task CopyToClipboardAsync(string? text)
    {
        if (string.IsNullOrEmpty(text) || Clipboard is null)
        {
            return;
        }

        await Clipboard.SetTextAsync(text);
    }

    private async Task SelectLogFilePathAsync()
    {
        var files = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = Localization.Instance.Get("Dialog.SaveLogFile"),
            DefaultExtension = "log",
            FileTypeChoices = new[]
            {
                new FilePickerFileType(Localization.Instance.Get("Dialog.LogFiles")) { Patterns = new[] { "*.log" } },
                new FilePickerFileType(Localization.Instance.Get("Dialog.PlainTextFiles")) { Patterns = new[] { "*.txt" } },
            },
        });

        var path = files?.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        _settingsService.Settings.LogFilePath = path;
        _settingsService.Save();
        await _bridge.PushSettingsAsync();
    }

    // ---- Launch pipeline (lifted from the legacy MainWindow) ----

    private void Launch(string ebootPath, string? displayName = null, string? titleId = null)
    {
        if (_isRunning)
        {
            return;
        }

        var game = _allGames.FirstOrDefault(g => g.Path.Equals(ebootPath, FilePathComparison));
        var name = displayName ?? game?.Name ?? Path.GetFileName(Path.GetDirectoryName(ebootPath))!;
        var resolvedTitleId = string.IsNullOrWhiteSpace(titleId) ? game?.TitleId : titleId;

        _logService.Clear();
        _emulatorService.PrepareLaunch(ebootPath, name, resolvedTitleId);

        _isRunning = true;
        _runningGameName = name;
        _runningEbootPath = ebootPath;
        _runningGameTitleId = resolvedTitleId;
        _runningSinceUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        SessionGameTitle.Text = name;

        _ = _bridge.PushSessionAsync(isRunning: true, title: name);

        ShowGameView();
        UpdateRunButtons();

        if (_gameSurfaceHost?.Surface is { } surface)
        {
            StartPendingSession(surface);
        }
    }

    /// <summary>
    /// Toggles the session-bar Stop button from a single place. The button
    /// starts disabled in XAML; it must be enabled once a game is running and
    /// disabled again while stopping / after exit.
    /// </summary>
    private void UpdateRunButtons()
    {
        SessionStopButton.IsEnabled = _isRunning && !_isStopping;
    }

    private void StopEmulator()
    {
        if (!_isRunning || _isStopping)
        {
            return;
        }

        if (_emulatorService.CancelPendingLaunch())
        {
            OnEmulatorExited(0);
            return;
        }

        _isStopping = true;
        _ = _bridge.PushSessionAsync(isRunning: true, isStopping: true, title: _runningGameName);
        SessionStopButton.IsEnabled = false;
        SessionHintText.Text = Localization.Instance.Get("Launch.Stopping");
        SessionF11Badge.IsVisible = false;
        ShowSessionLoading("Closing game", "Waiting for the emulation session to exit...");
        _emulatorService.Stop();
        _runningGameName = null;
        _runningGameTitleId = null;
        UpdateSessionBarVisibility();
        ReturnToLibraryWhileStopping();
    }

    private void OnEmulatorExited(int exitCode)
    {
        _logService.Flush();
        _isRunning = false;
        _isStopping = false;
        DisposeGameSurfaceHost();
        HideGameView();

        CloseFileLogSoon();

        _runningGameName = null;
        _runningGameTitleId = null;
        _runningEbootPath = null;
        UpdateRunButtons();
        _ = _bridge.PushSessionAsync(isRunning: false, exitCode: exitCode);

        // Refresh the library so the hero / "recently played" reflect the run.
        _ = RescanLibraryAsync();
    }

    private void StartPendingSession(VulkanHostSurface surface)
    {
        string? descriptor = null;
        if (surface.TryGetChildProcessDescriptor(out var d))
        {
            descriptor = d;
        }
        _emulatorService.StartPendingSession(descriptor);
    }

    private void OnEmulatorOutput(string line, bool isError)
    {
        _logService.Enqueue(line, isError);

        // Buffer raw (text,isError) pairs for the bridge's batched log push.
        _pendingLogLines.Add((line, isError));

        if (!line.Contains("[VIDEOOUT][INFO] Hosted splash ready.", StringComparison.Ordinal) &&
            !line.Contains("[VIDEOOUT][INFO] Hosted first frame presented.", StringComparison.Ordinal))
        {
            return;
        }

        Dispatcher.UIThread.Post(() =>
        {
            if (_isRunning && !_isStopping)
            {
                _awaitingFirstFrame = false;
                RestoreGameViewToFull();
                GameView.Background = Brushes.Black;
                GameView.IsHitTestVisible = true;
                WebView.IsVisible = false; // hide the launcher, show the game
                HideSessionLoading();
                UpdateSessionBarVisibility();

                Dispatcher.UIThread.Post(() =>
                {
                    if (!_isRunning || _isStopping)
                    {
                        return;
                    }

                    _gameSurfaceHost?.RefreshSurfaceSize();
                    _gameSurfaceHost?.SetPresentationVisible(true);
                    _gameSurfaceHost?.SetCursorAutoHide(true);
                });
            }
        });
    }

    private readonly List<(string Text, bool IsError)> _pendingLogLines = new();

    private async void OnLogFlushTick(object? sender, EventArgs e)
    {
        _logService.Flush();

        if (_pendingLogLines.Count > 0)
        {
            var snapshot = _pendingLogLines.ToArray();
            _pendingLogLines.Clear();
            try
            {
                await _bridge.PushLogBatchAsync(snapshot);
            }
            catch
            {
                // The page may not be ready; drop this batch (lines are in the
                // log buffer already for the in-window console).
            }
        }
    }

    // ---- Native game surface lifecycle (lifted verbatim) ----

    private GameSurfaceHost EnsureGameSurfaceHost()
    {
        if (_gameSurfaceHost is not null)
        {
            return _gameSurfaceHost;
        }

        var host = new GameSurfaceHost();
        host.SetPresentationVisible(false);
        host.SurfaceAvailable += (_, surface) =>
        {
            if (ReferenceEquals(_gameSurfaceHost, host))
            {
                StartPendingSession(surface);
            }
        };
        host.SurfaceDestroyed += (_, surface) => OnGameSurfaceDestroyed(host, surface);
        _gameSurfaceHost = host;
        GameSurfaceContainer.Children.Add(host);
        return host;
    }

    private void DisposeGameSurfaceHost()
    {
        var host = _gameSurfaceHost;
        if (host is null)
        {
            return;
        }

        _gameSurfaceHost = null;
        host.SetPresentationVisible(false);
        GameSurfaceContainer.Children.Remove(host);
    }

    private void OnGameSurfaceDestroyed(GameSurfaceHost host, VulkanHostSurface surface)
    {
        if (ReferenceEquals(_gameSurfaceHost, host) && _isRunning)
        {
            StopEmulator();
        }
    }

    // The native host is a real child window sitting above every Avalonia
    // control; while the library must stay interactive we park it offscreen at
    // FULL SIZE (never shrunk — the emulator polls the HWND client size and
    // would deadlock the load handshake at 1px).
    private void ParkGameViewOffscreen() => GameView.Margin = new Thickness(-20000, 0, 20000, 0);
    private void RestoreGameViewToFull() => GameView.Margin = new Thickness(0);

    private void ShowGameView()
    {
        _isStopping = false;
        _awaitingFirstFrame = true;
        var host = EnsureGameSurfaceHost();
        ParkGameViewOffscreen();
        GameView.IsVisible = true;
        GameView.Background = Brushes.Transparent;
        GameView.IsHitTestVisible = false;
        host.SetPresentationVisible(false);
        SessionHintText.Text = "Fullscreen";
        SessionF11Badge.IsVisible = true;
        UpdateSessionBarVisibility();
        ShowSessionLoading("Loading game", "Preparing the emulation session...");
    }

    private void HideGameView()
    {
        if (_gameFullscreen && WindowState == WindowState.FullScreen)
        {
            OnWindowFullScreen(this, new RoutedEventArgs());
        }

        _gameSurfaceHost?.SetCursorAutoHide(false);
        _gameSurfaceHost?.SetPresentationVisible(false);
        _awaitingFirstFrame = false;
        GameView.IsVisible = false;
        GameView.IsHitTestVisible = true;
        WebView.IsVisible = true; // restore the launcher
        SessionBarPopup.IsOpen = false;
        HideSessionLoading();
    }

    private void ReturnToLibraryWhileStopping()
    {
        if (_gameFullscreen && WindowState == WindowState.FullScreen)
        {
            OnWindowFullScreen(this, new RoutedEventArgs());
        }

        _gameSurfaceHost?.SetPresentationVisible(false);
        _awaitingFirstFrame = false;
        ParkGameViewOffscreen();
        GameView.Background = Brushes.Transparent;
        GameView.IsHitTestVisible = false;
        SessionBarPopup.IsOpen = false;
        WebView.IsVisible = true;
        UpdateRunButtons();
        Console.Error.WriteLine("[GUI][INFO] Library restored while embedded session is closing.");
    }

    private void UpdateSessionBarVisibility()
    {
        SessionBarPopup.IsOpen = _isRunning && !_isStopping && !_awaitingFirstFrame && GameView.IsVisible &&
            !_gameFullscreen && WindowState != WindowState.FullScreen;
    }

    private void ShowSessionLoading(string title, string detail)
    {
        SessionLoadingTitle.Text = title;
        SessionLoadingDetail.Text = detail;
        _sessionLoadingActive = true;
        SessionLoadingPopup.IsOpen = IsActive && WindowState != WindowState.Minimized;
    }

    private void HideSessionLoading()
    {
        _sessionLoadingActive = false;
        SessionLoadingPopup.IsOpen = false;
    }

    // ---- Window / session controls ----

    private void OnKeyDown(object sender, KeyEventArgs args)
    {
        if (args.Key == Key.F11)
        {
            OnWindowFullScreen(this, new RoutedEventArgs());
            args.Handled = true;
        }
    }

    private void OnWindowFullScreen(object sender, RoutedEventArgs args)
    {
        if (WindowState == WindowState.FullScreen)
        {
            WindowState = WindowState.Maximized;
            WindowDecorations = WindowDecorations.Full;
            _gameFullscreen = false;
            QueueGameSurfaceResize();
            UpdateSessionBarVisibility();
        }
        else if (_isRunning && GameView.IsVisible)
        {
            WindowState = WindowState.FullScreen;
            WindowDecorations = WindowDecorations.None;
            _gameFullscreen = true;
            _gameSurfaceHost?.SetCursorAutoHide(true);
            QueueGameSurfaceResize();
            UpdateSessionBarVisibility();
        }
    }

    private void QueueGameSurfaceResize()
    {
        Dispatcher.UIThread.Post(
            () => _gameSurfaceHost?.RefreshSurfaceSize(),
            DispatcherPriority.Render);
    }

    private void OnSessionConsole(object? sender, RoutedEventArgs e) => ShowConsoleWindow();
    private void OnSessionStop(object? sender, RoutedEventArgs e) => StopEmulator();

    private async Task CopyConsoleAsync()
    {
        if (Clipboard is null)
        {
            return;
        }

        var text = string.Join(Environment.NewLine, _logService.VisibleLines.Select(line => line.Text));
        if (!string.IsNullOrEmpty(text))
        {
            await Clipboard.SetTextAsync(text);
        }
    }

    private void ShowConsoleWindow()
    {
        if (_consoleWindow is { } window)
        {
            window.Activate();
            return;
        }

        _consoleWindow = new ConsoleWindow(
            _logService.VisibleLines,
            () => _logService.Clear(),
            autoScroll: true);
        _consoleWindow.Closed += (_, _) => _consoleWindow = null;
        _consoleWindow.Show(this);
    }

    private void CloseFileLogSoon() => _logService.CloseFileLogSoon();

    // ---- Updates (lightweight; the web UI shows status via the bridge) ----

    private async Task CheckForUpdatesAsync()
    {
        try
        {
            _ = await Updater.CheckAsync(BuildInfo.CommitSha);
        }
        catch
        {
            // Best-effort; status surfaces in the Options view later.
        }
    }

    private void OnWindowClosing()
    {
        _logFlushTimer.Stop();
        _bridge.Detach();
        _consoleWindow?.Close();
        _emulatorService.Stop();
        _consoleMirror?.Dispose();
        _logService.DropFileLog();
    }

    // Pause the loading popup while minimized (it is desktop-topmost).
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty && SessionLoadingPopup is { } popup)
        {
            popup.IsOpen = WindowState == WindowState.Minimized ? false : _sessionLoadingActive;
        }
    }
}
