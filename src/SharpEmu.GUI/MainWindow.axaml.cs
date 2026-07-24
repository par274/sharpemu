// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.Core.Cpu;
using SharpEmu.Core.Runtime;
using SharpEmu.HLE.Host;
using SharpEmu.HLE.Host.Windows;
using SharpEmu.Libs.VideoOut;
using SharpEmu.Logging;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Net.Http.Headers;

namespace SharpEmu.GUI;

public partial class MainWindow : Window
{
    private const double LaunchBlurRadius = 12;
    private const double BlurTransitionSeconds = 0.24;

    private static readonly IBrush DefaultLineBrush = new SolidColorBrush(Color.Parse("#C7CFDE"));
    private static readonly IBrush DimLineBrush = new SolidColorBrush(Color.Parse("#6B7488"));
    private static readonly IBrush InfoLineBrush = new SolidColorBrush(Color.Parse("#6FA8FF"));
    private static readonly IBrush WarningLineBrush = new SolidColorBrush(Color.Parse("#E8B341"));
    private static readonly IBrush ErrorLineBrush = new SolidColorBrush(Color.Parse("#F2777C"));
    private static readonly IBrush SuccessLineBrush = new SolidColorBrush(Color.Parse("#63D489"));
    private static readonly StringComparer FilePathComparer = OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;
    private static readonly StringComparison FilePathComparison = OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private readonly List<GameEntry> _allGames = new();
    private readonly ObservableCollection<GameEntry> _visibleGames;
    // Console buffer is owned by ILogService; aliased here for the XAML-bound
    // ConsoleList and the few remaining imperative reads.
    private AvaloniaList<LogLine> _consoleLines = new();
    private readonly DispatcherTimer _consoleFlushTimer;
    private readonly DispatcherTimer _libraryBlurTimer;
    private readonly DispatcherTimer _clockTimer;
    private BlurEffect? _libraryBlur;
    private double _libraryBlurStartRadius;
    private double _libraryBlurTargetRadius;
    private long _libraryBlurStartedAt;
    private bool _clearLibraryBlurWhenComplete;

    // Backed by the shared ISettingsService so the OptionsViewModel and the
    // window mutate the same instance; resolved from the container in OnOpened.
    private GuiSettings _settings = GuiSettings.Load();
    private GameSurfaceHost? _gameSurfaceHost;
    private ConsoleWindow? _consoleWindow;
    private GuiConsoleMirror? _consoleMirror;
    private readonly SndPreviewPlayer _sndPreview = new();
    private string? _emulatorExePath;
    private bool _gameFullscreen;
    private bool _isRunning;
    private bool _isStopping;
    private bool _awaitingFirstFrame;
    private int _autoScrollTicks;
    private int _activePageIndex;
    private Updater.UpdateInfo? _availableUpdate;
    private string _updateStatusKey = "Updater.Status.Ready";
    private object?[] _updateStatusArgs = [BuildInfo.CommitSha ?? "dev"];

    // Discord Rich Presence state.
    private readonly long _launcherStartUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private DiscordRichPresence? _discord;
    private string? _runningGameName;
    private string? _runningGameTitleId;
    private long _runningSinceUnixSeconds;
    private int _backdropGeneration;

    // Bundled key art shown whenever no game-specific backdrop applies; the
    // plain window color remains the fallback when the asset fails to load.
    private Bitmap? _defaultBackdrop;

    // Whether the native loading/closing popup should be showing; it is a
    // desktop-topmost popup, so it closes while the launcher is in the
    // background or minimized and reopens from this flag on activation.
    private bool _sessionLoadingActive;
    private bool _isGameSettingsOpen;
    private bool _isLoadingGameSettings;
    private int _gameOptionsSectionIndex;
    private int _selectedDetailsAnimationGeneration;
    private ViewModels.PerGameSettingsViewModel? _gameSettingsViewModel;

    // Controller navigation state.
    private readonly DispatcherTimer _gamepadTimer;

    //Github http client for latest commit
    private static readonly HttpClient GithubHttpClient = CreateGithubHttpClient();
    private string? _latestCommitSha;

    private readonly ViewModels.MainViewModel _main;
    private readonly ViewModels.LibraryViewModel _library;
    private readonly Services.Abstractions.IEmulatorService _emulatorService;
    private readonly Services.Abstractions.ILogService _logService;
    private readonly ViewModels.SessionViewModel _session;
    private readonly Services.Abstractions.IGamepadInputService _gamepad;

    /// <summary>
    /// Design-time / runtime-loader constructor. Resolves the shell view-model
    /// and services from the DI container so the window stays constructible
    /// without parameters (Avalonia's XAML runtime loader requires this).
    /// </summary>
    public MainWindow()
        : this(GuiLauncher.Services.GetRequiredService<ViewModels.MainViewModel>())
    {
    }

    public MainWindow(ViewModels.MainViewModel main)
    {
        InitializeComponent();
        _main = main;
        _library = main.Library;
        _session = main.Session;
        _visibleGames = _library.Games;
        // Resolve the remaining services the launch pipeline needs. They share
        // the same container-scoped singletons as the view-models.
        _emulatorService = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IEmulatorService>();
        _logService = GuiLauncher.Services.GetRequiredService<Services.Abstractions.ILogService>();
        _gamepad = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGamepadInputService>();
        _logService.SetEmulatorExePath(_emulatorService.EmulatorExePath);

        // Forward emulator process events to the window's UI reactions.
        _emulatorService.OutputReceived += OnEmulatorOutput;
        _emulatorService.Exited += code => OnEmulatorExited(code);

        // Translate gamepad navigation intents into UI actions.
        _gamepad.PageRequested += page => Dispatcher.UIThread.Post(() => SetActivePage(page));
        _gamepad.MoveHorizontal += delta => Dispatcher.UIThread.Post(() => MoveSelection(delta));
        _gamepad.MoveVertical += dir => Dispatcher.UIThread.Post(() => MoveSelection(dir * TilesPerRow()));
        _gamepad.Activate += () => Dispatcher.UIThread.Post(LaunchSelected);

        try
        {
            _defaultBackdrop = new Bitmap(
                AssetLoader.Open(new Uri("avares://SharpEmu.GUI/Assets/pic0.png")));
            BackdropImage.Source = _defaultBackdrop;
            BackdropImage.Opacity = 1.0;
        }
        catch (Exception)
        {
            _defaultBackdrop = null; // color background remains the fallback
        }

        GameList.ItemsSource = _visibleGames;
        _consoleLines = _logService.VisibleLines;
        ConsoleList.ItemsSource = _consoleLines;
        _consoleMirror = GuiConsoleMirror.Install((line, isError) =>
            _logService.Enqueue(line, isError));
        _consoleFlushTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(80),
        };
        _consoleFlushTimer.Tick += (_, _) =>
        {
            _logService.Flush();
            MaybeAutoScroll();
        };
        _consoleFlushTimer.Start();

        _libraryBlurTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(16),
        };
        _libraryBlurTimer.Tick += (_, _) => AdvanceLibraryBlur();

        _clockTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(15),
        };
        _clockTimer.Tick += (_, _) => UpdateClock();
        UpdateClock();
        _clockTimer.Start();
        Closed += (_, _) =>
        {
            _clockTimer.Stop();
            _emulatorService.Stop();
        };

        // Native popups float above every window on the desktop; they must
        // follow the launcher into the background or a minimized state.
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

        TitleBar.PointerPressed += OnTitleBarPointerPressed;
        GameList.SelectionChanged += (_, _) =>
        {
            _library.SelectedGame = GameList.SelectedItem as GameEntry;
            UpdateSelectedGame();
        };
        GameList.DoubleTapped += (_, _) => LaunchSelected();
        SearchBox.TextChanged += (_, _) =>
        {
            _library.SearchText = SearchBox.Text ?? string.Empty;
            // The filtered list refresh happens in the VM (throttled); keep
            // the empty-state and selection sync immediate for responsiveness.
            RefreshVisibleGames();
        };
        ConsoleSearchBox.TextChanged += (_, _) => RefreshVisibleConsoleLines();
        AddFolderButton.Click += async (_, _) => await AddFolderAsync();
        EmptyAddFolderButton.Click += async (_, _) => await AddFolderAsync();
        RescanButton.Click += async (_, _) => await RescanLibraryAsync();
        OpenFileButton.Click += async (_, _) => await OpenFileAsync();
        LaunchButton.Click += (_, _) => LaunchSelected();
        ClearLogButton.Click += (_, _) => _logService.Clear();
        StopButton.Click += (_, _) => StopEmulator();
        SessionStopButton.Click += (_, _) => StopEmulator();
        SessionConsoleButton.Click += (_, _) => ShowConsoleWindow();
        CopyLogButton.Click += async (_, _) => await CopyConsoleAsync();
        DetachConsoleButton.Click += (_, _) => ShowConsoleWindow();
        LibraryTabButton.Click += (_, _) => SetActivePage(0);
        OptionsTabButton.Click += (_, _) => SetActivePage(1);
        ConsoleNavButton.Click += (_, _) => SetActivePage(2);
        ConsoleToggle.Click += (_, _) => OpenSelectedGameSettings();
        var gameOptionsNavButtons = new[]
        {
            GameOptionsGeneralNav,
            GameOptionsLoggingNav,
            GameOptionsEnvironmentNav,
            GameOptionsBackNav,
        };
        for (var index = 0; index < gameOptionsNavButtons.Length; index++)
        {
            var section = index;
            var button = gameOptionsNavButtons[index];
            if (section < 3)
            {
                button.Click += (_, _) => SetGameOptionsSection(section);
            }
            else
            {
                button.Click += (_, _) => CloseGameSettings();
            }

            button.PointerEntered += (_, _) =>
            {
                if (_isGameSettingsOpen)
                {
                    SetGameOptionsNavIndicator(section);
                }
            };
            button.GotFocus += (_, _) => SetGameOptionsNavIndicator(section);
        }
        GameOptionsNavHost.PointerExited += (_, _) =>
        {
            if (_isGameSettingsOpen)
            {
                SetGameOptionsNavIndicator(_gameOptionsSectionIndex);
            }
        };
        GameOptionsLaunchButton.Click += (_, _) =>
        {
            CloseGameSettings();
            LaunchSelected();
        };
        GameOptionsOpenFolderButton.Click += (_, _) => OpenSelectedGameFolder();
        GameOptionsCopyPathButton.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.Path, "Clipboard.Path");
        GameOptionsCopyTitleIdButton.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.TitleId, "Clipboard.TitleId");
        GameOptionsRemoveButton.Click += (_, _) =>
        {
            CloseGameSettings();
            RemoveSelectedFromLibrary();
        };
        GameLogLevelBox.ItemsSource = ViewModels.PerGameSettingsViewModel.LogLevels;
        GameLogLevelBox.SelectionChanged += (_, _) => PersistOpenGameSettings();
        GameTraceBox.ValueChanged += (_, _) => PersistOpenGameSettings();
        GameStrictToggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        GameLogToFileToggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        foreach (var (_, toggle) in GameEnvironmentToggles())
        {
            toggle.IsCheckedChanged += (_, _) => PersistOpenGameSettings();
        }

        MinimizeButton.Click += (_, _) => WindowState = WindowState.Minimized;
        MaximizeButton.Click += (_, _) =>
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        CloseButton.Click += (_, _) => Close();

        // The settings page edits _settings live, so a launch started while
        // it is open already uses the new values.
        LogLevelBox.SelectionChanged += (_, _) => _settings.LogLevel = SelectedLogLevel();
        TraceImportsBox.ValueChanged += (_, _) => _settings.ImportTraceLimit = (int)(TraceImportsBox.Value ?? 0);
        RenderResolutionBox.SelectionChanged += (_, _) =>
        {
            if (RenderResolutionBox.SelectedItem is ComboBoxItem { Tag: string tag } &&
                double.TryParse(
                    tag,
                    System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var scale))
            {
                _settings.RenderResolutionScale = scale;
            }
        };
        StrictToggle.IsCheckedChanged += (_, _) => _settings.StrictDynlibResolution = StrictToggle.IsChecked == true;
        LogToFileToggle.IsCheckedChanged += (_, _) => _settings.LogToFile = LogToFileToggle.IsChecked == true;
        OverrideLogFileToggle.IsCheckedChanged += (_, _) =>
            _settings.OverrideLogFile = OverrideLogFileToggle.IsChecked == true;
        TitleMusicToggle.IsCheckedChanged += (_, _) =>
        {
            _settings.PlayTitleMusic = TitleMusicToggle.IsChecked == true;
            OnTitleMusicSettingChanged();
        };
        DiscordToggle.IsCheckedChanged += (_, _) =>
        {
            _settings.DiscordRichPresence = DiscordToggle.IsChecked == true;
            UpdateDiscordPresence();
        };
        AutoUpdateToggle.IsCheckedChanged += (_, _) =>
            _settings.CheckForUpdatesOnStartup = AutoUpdateToggle.IsChecked == true;
        UpdateButton.Click += async (_, _) => await OnUpdateButtonAsync();
        SelectLogFilePathButton.Click += async (_, _) => await SelectLogFilePathAsync();
        EnvBthidToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_BTHID_UNAVAILABLE", EnvBthidToggle.IsChecked == true);
        EnvLoopGuardToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD", EnvLoopGuardToggle.IsChecked == true);
        EnvWritableApp0Toggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_WRITABLE_APP0", EnvWritableApp0Toggle.IsChecked == true);
        EnvVkValidationToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_VK_VALIDATION", EnvVkValidationToggle.IsChecked == true);
        EnvDumpSpirvToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_DUMP_SPIRV", EnvDumpSpirvToggle.IsChecked == true);
        EnvLogDirectMemoryToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_DIRECT_MEMORY", EnvLogDirectMemoryToggle.IsChecked == true);
        EnvLogIoToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_IO", EnvLogIoToggle.IsChecked == true);
        EnvLogNpToggle.IsCheckedChanged += (_, _) =>
            SetEnvironmentToggle("SHARPEMU_LOG_NP", EnvLogNpToggle.IsChecked == true);
        LanguageBox.SelectionChanged += (_, _) => OnLanguageChanged();

        GameList.AddHandler(ContextRequestedEvent, OnGameContextRequested, RoutingStrategies.Tunnel);
        AddHandler(KeyDownEvent, OnPreviewKeyDown, RoutingStrategies.Tunnel);
        CtxLaunch.Click += (_, _) => LaunchSelected();
        CtxOpenFolder.Click += (_, _) => OpenSelectedGameFolder();
        CtxCopyPath.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.Path, "Clipboard.Path");
        CtxCopyTitleId.Click += async (_, _) =>
            await CopyToClipboardAsync((GameList.SelectedItem as GameEntry)?.TitleId, "Clipboard.TitleId");
        CtxGameSettings.Click += (_, _) => OpenSelectedGameSettings();
        CtxRemove.Click += (_, _) => RemoveSelectedFromLibrary();

        Opened += async (_, _) => await OnOpenedAsync();
        Closing += (_, _) => OnWindowClosing();

        WindowsDualSenseReader.EnsureStarted();
        WindowsXInputReader.EnsureStarted();
        _gamepadTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(50),
        };
        _gamepadTimer.Tick += (_, _) => PollGamepad();
        _gamepadTimer.Start();


        GithubButton.Click += (_, _) =>
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://github.com/sharpemu/sharpemu",
                UseShellExecute = true
            });
        };

        DiscordButton.Click += (_, _) =>
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://discord.com/invite/6GejPEDqpc",
                UseShellExecute = true
            });
        };

        LatestCommitHashText.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_latestCommitSha))
            {
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName =
                    $"https://github.com/sharpemu/sharpemu/commit/{_latestCommitSha}",
                UseShellExecute = true
            });
        };
    }

    /// <summary>
    /// Switches between the Library, Options and Console pages. Library and
    /// Options are also reachable via
    /// the gamepad's shoulder buttons (LB/RB, L1/R1) from <see cref="PollGamepad"/>.
    /// </summary>
    private void SetActivePage(int index)
    {
        if (index != 0 && _isGameSettingsOpen)
        {
            CloseGameSettings();
        }

        // The shell view-model owns the active-page state (and the save-on-leave
        // side effect); the window only mirrors it into control visibility.
        _main.NavigateTo(index);
        _activePageIndex = _main.ActivePage;

        SetActiveClass(LibraryTabButton, _activePageIndex == 0);
        SetActiveClass(OptionsTabButton, _activePageIndex == 1);
        SetActiveClass(ConsoleNavButton, _activePageIndex == 2);
        if (_activePageIndex is 0 or 1)
        {
            if (TopNavigationIndicator.RenderTransform is TranslateTransform transform)
            {
                transform.X = _activePageIndex * 132;
            }

            TopNavigationIndicator.Opacity = 1;
        }
        else
        {
            TopNavigationIndicator.Opacity = 0;
        }

        LibraryPage.IsVisible = _activePageIndex == 0;
        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;
        OptionsPage.IsVisible = _activePageIndex == 1;
        ConsolePanel.IsVisible = _activePageIndex == 2 && _consoleWindow is null;
    }

    private static void SetActiveClass(Button button, bool active)
    {
        if (active)
        {
            if (!button.Classes.Contains("active"))
            {
                button.Classes.Add("active");
            }
        }
        else
        {
            button.Classes.Remove("active");
        }
    }

    private void UpdateClock()
    {
        ClockText.Text = DateTime.Now.ToString("HH:mm");
    }

    // ---- Github http client config ----
    // This is for getting lash commit id
    private static HttpClient CreateGithubHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd("SharpEmu/1.0");
        client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github.sha"));

        client.DefaultRequestHeaders.Add(
            "X-GitHub-Api-Version",
            "2026-03-10");

        return client;
    }
    private async Task LoadLatestCommitAsync()
    {
        const string apiUrl =
            "https://api.github.com/repos/sharpemu/sharpemu/commits/main";

        _latestCommitSha = null;
        LatestCommitHashText.Content = "Loading…";
        LatestCommitHashText.IsEnabled = false;

        try
        {
            using var response = await GithubHttpClient.GetAsync(apiUrl);
            var responseBody =
                (await response.Content.ReadAsStringAsync()).Trim();

            if (!response.IsSuccessStatusCode)
            {
                LatestCommitHashText.Content =
                    $"HTTP {(int)response.StatusCode}";

                ToolTip.SetTip(
                    LatestCommitHashText,
                    string.IsNullOrWhiteSpace(responseBody)
                        ? response.ReasonPhrase
                        : responseBody);

                return;
            }

            if (responseBody.Length < 7)
            {
                LatestCommitHashText.Content = "Invalid response";
                ToolTip.SetTip(LatestCommitHashText, responseBody);
                return;
            }

            // Keep the complete SHA for the URL.
            _latestCommitSha = responseBody;

            // Display only the short SHA.
            LatestCommitHashText.Content =
                responseBody[..Math.Min(7, responseBody.Length)];

            LatestCommitHashText.IsEnabled = true;

            ToolTip.SetTip(
                LatestCommitHashText,
                $"Open commit {_latestCommitSha}");
        }
        catch (TaskCanceledException ex)
        {
            LatestCommitHashText.Content = "Timeout";
            ToolTip.SetTip(LatestCommitHashText, ex.Message);
        }
        catch (HttpRequestException ex)
        {
            LatestCommitHashText.Content = "Connection error";
            ToolTip.SetTip(LatestCommitHashText, ex.Message);
        }
        catch (Exception ex)
        {
            LatestCommitHashText.Content = "Error";
            ToolTip.SetTip(LatestCommitHashText, ex.Message);
        }
    }

    // ---- Controller navigation ----

    private void PollGamepad()
    {
        // The gamepad service polls the controller and raises navigation
        // intents; the window only feeds it the current UI context. Intents
        // are marshalled to the UI thread via the event subscriptions set up
        // in the constructor.
        _gamepad.Poll(IsActive, _isRunning || _isStopping, _activePageIndex);
    }

    private void MoveSelection(int delta)
    {
        if (_visibleGames.Count == 0)
        {
            return;
        }

        var index = GameList.SelectedIndex < 0
            ? 0
            : Math.Clamp(GameList.SelectedIndex + delta, 0, _visibleGames.Count - 1);
        GameList.SelectedIndex = index;
        GameList.ScrollIntoView(index);
    }

    private int TilesPerRow()
    {
        // Tile footprint: 128 content + 20 item padding + 10 item margin.
        const double TileOuterWidth = 158;
        var width = GameList.Bounds.Width;
        return width > TileOuterWidth ? (int)(width / TileOuterWidth) : 1;
    }

    private async Task OnOpenedAsync()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        var display = version is not null ? $"v{version.ToString(3)}" : "v0.0.1";
        display += BuildInfo.CommitSha is null
            ? " · dev"
            : BuildInfo.IsOfficialRelease
                ? $" · {BuildInfo.CommitSha}"
                : $" · UNOFFICIAL {BuildInfo.CommitSha}";
        VersionText.Text = display;
        Title = $"SharpEmu {display}";
        ToolTip.SetTip(VersionText, BuildInfo.Banner);

        _settings = GuiLauncher.Services.GetRequiredService<Services.Abstractions.ISettingsService>().Settings;
        Localization.Instance.Load(_settings.Language);
        PopulateLanguageBox();
        ApplyLocalization();
        ApplySettingsToControls();
        LocateEmulator();
        UpdateDiscordPresence();
        _ = LoadLatestCommitAsync();

        if (_settings.CheckForUpdatesOnStartup)
        {
            _ = CheckForUpdatesAsync();
        }
        await RescanLibraryAsync();
    }

    private void PopulateLanguageBox()
    {
        var languages = Localization.Instance.DiscoverLanguages();
        LanguageBox.ItemsSource = languages;
        LanguageBox.SelectedItem = languages.FirstOrDefault(language =>
            string.Equals(language.Code, _settings.Language, StringComparison.OrdinalIgnoreCase))
            ?? languages.FirstOrDefault();
    }

    private void OnLanguageChanged()
    {
        if (LanguageBox.SelectedItem is not Localization.LanguageInfo language)
        {
            return;
        }

        _settings.Language = language.Code;
        Localization.Instance.Load(language.Code);
        ApplyLocalization();
    }

    /// <summary>
    /// Re-applies every UI string from the current language, so switching
    /// languages in Options takes effect immediately without reopening the
    /// window.
    /// </summary>
    private void ApplyLocalization()
    {
        var loc = Localization.Instance;

        LibraryTabButton.Content = loc.Get("Page.Library");
        OptionsTabButton.Content = loc.Get("Page.Options");
        SearchBox.PlaceholderText = loc.Get("Library.SearchWatermark");
        AddFolderButtonLabel.Text = loc.Get("Library.AddFolder");
        RescanButtonLabel.Text = loc.Get("Library.Rescan");
        OpenFileButtonLabel.Text = loc.Get("Library.OpenFile");

        CtxLaunch.Header = loc.Get("Library.Context.Launch");
        CtxOpenFolder.Header = loc.Get("Library.Context.OpenFolder");
        CtxCopyPath.Header = loc.Get("Library.Context.CopyPath");
        CtxCopyTitleId.Header = loc.Get("Library.Context.CopyTitleId");
        CtxGameSettings.Header = loc.Get("Library.Context.GameSettings");
        CtxRemove.Header = loc.Get("Library.Context.Remove");

        EmptyAddFolderButtonLabel.Text = loc.Get("Library.Empty.AddFolder");
        LoadingStateText.Text = loc.Get("Library.Loading");
        LastPlayedLabel.Text = loc.Get("Library.Stat.LastPlayed");
        VersionLabel.Text = loc.Get("Library.Stat.Version");
        InstalledLabel.Text = loc.Get("Library.Stat.Installed");
        TitleIdLabel.Text = loc.Get("Library.Stat.TitleId");
        LastPlayedValue.Text = loc.Get("Library.Stat.NotPlayed");

        GameOptionsLastPlayedLabel.Text = loc.Get("Library.Stat.LastPlayed");
        GameOptionsVersionLabel.Text = loc.Get("Library.Stat.Version");
        GameOptionsInstalledLabel.Text = loc.Get("Library.Stat.Installed");
        GameOptionsTitleIdLabel.Text = loc.Get("Library.Stat.TitleId");
        GameOptionsLastPlayedValue.Text = loc.Get("Library.Stat.NotPlayed");
        GameOptionsGeneralNavLabel.Text = loc.Get("Options.General");
        GameOptionsLoggingNavLabel.Text = loc.Get("Options.Logging");
        GameOptionsEnvironmentNavLabel.Text = loc.Get("Options.Env.Tab");
        GameOptionsBackNavLabel.Text = loc.Get("Common.Back");
        GameOptionsEnvironmentDescription.Text = loc.Get("Options.Env.Desc");
        GameOptionsLaunchLabel.Text = loc.Get("Library.Context.Launch");
        GameOptionsOpenFolderLabel.Text = loc.Get("Library.Context.OpenFolder");
        GameOptionsCopyPathLabel.Text = loc.Get("Library.Context.CopyPath");
        GameOptionsCopyTitleIdLabel.Text = loc.Get("Library.Context.CopyTitleId");
        GameOptionsRemoveLabel.Text = loc.Get("Library.Context.Remove");

        GameStrictRow.Label = loc.Get("Options.Strict.Label");
        GameStrictRow.Description = loc.Get("Options.Strict.Desc");
        GameLogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        GameLogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        GameTraceRow.Label = loc.Get("Options.TraceImports.Label");
        GameTraceRow.Description = loc.Get("Options.TraceImports.Desc");
        GameLogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        GameLogToFileRow.Description = loc.Get("Options.LogToFile.Desc");

        EnvSectionTitle.Text = loc.Get("Options.Section.Environment");
        EnvDesc.Text = loc.Get("Options.Env.Desc");
        EnvBthidRow.Description = loc.Get("Options.Env.Bthid.Desc");
        EnvLoopGuardRow.Description = loc.Get("Options.Env.LoopGuard.Desc");
        EnvWritableApp0Row.Description = loc.Get("Options.Env.WritableApp0.Desc");
        EnvVkValidationRow.Description = loc.Get("Options.Env.VkValidation.Desc");
        EnvDumpSpirvRow.Description = loc.Get("Options.Env.DumpSpirv.Desc");
        EnvLogDirectMemoryRow.Description = loc.Get("Options.Env.LogDirectMemory.Desc");
        EnvLogIoRow.Description = loc.Get("Options.Env.LogIo.Desc");
        EnvLogNpRow.Description = loc.Get("Options.Env.LogNp.Desc");
        EmulationSectionTitle.Text = loc.Get("Options.Section.Emulation");
        LoggingSectionTitle.Text = loc.Get("Options.Section.Logging");
        LauncherSectionTitle.Text = loc.Get("Options.Section.Launcher");

        CpuEngineRow.Label = loc.Get("Options.CpuEngine.Label");
        CpuEngineRow.Description = loc.Get("Options.CpuEngine.Desc");
        CpuEngineNativeItem.Content = loc.Get("Options.CpuEngine.Native");

        StrictRow.Label = loc.Get("Options.Strict.Label");
        StrictRow.Description = loc.Get("Options.Strict.Desc");

        LogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        LogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        LogLevelTraceItem.Content = loc.Get("Options.LogLevel.Trace");
        LogLevelDebugItem.Content = loc.Get("Options.LogLevel.Debug");
        LogLevelInfoItem.Content = loc.Get("Options.LogLevel.Info");
        LogLevelWarningItem.Content = loc.Get("Options.LogLevel.Warning");
        LogLevelErrorItem.Content = loc.Get("Options.LogLevel.Error");
        LogLevelCriticalItem.Content = loc.Get("Options.LogLevel.Critical");

        TraceImportsRow.Label = loc.Get("Options.TraceImports.Label");
        TraceImportsRow.Description = loc.Get("Options.TraceImports.Desc");

        LogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        LogToFileRow.Description = loc.Get("Options.LogToFile.Desc");

        LogFilePathRow.Label = loc.Get("Options.LogFilePath.Label");
        SelectLogFilePathButton.Content = loc.Get("Options.LogFilePath.Select");
        UpdateLogFilePathText();

        OverrideLogFileRow.Label = loc.Get("Options.OverrideLogFile.Label");
        OverrideLogFileRow.Description = loc.Get("Options.OverrideLogFile.Desc");

        LanguageRow.Label = loc.Get("Options.Language.Label");
        LanguageRow.Description = loc.Get("Options.Language.Desc");

        RenderingSectionTitle.Text = loc.Get("Options.Graphics.Rendering");
        RenderResolutionRow.Label = loc.Get("Options.RenderResolution.Label");
        RenderResolutionRow.Description = loc.Get("Options.RenderResolution.Desc");

        TitleMusicRow.Label = loc.Get("Options.TitleMusic.Label");
        TitleMusicRow.Description = loc.Get("Options.TitleMusic.Desc");

        DiscordRow.Label = loc.Get("Options.Discord.Label");
        DiscordRow.Description = loc.Get("Options.Discord.Desc");
        AutoUpdateRow.Label = loc.Get("Updater.Auto.Label");
        AutoUpdateRow.Description = loc.Get("Updater.Auto.Desc");

        foreach (var toggle in new[]
                 {
                     StrictToggle, LogToFileToggle, OverrideLogFileToggle, TitleMusicToggle, DiscordToggle,
                     AutoUpdateToggle, GameStrictToggle, GameLogToFileToggle,
                 })
        {
            toggle.OnContent = loc.Get("Common.On");
            toggle.OffContent = loc.Get("Common.Off");
        }

        ConsoleSectionTitle.Text = loc.Get("Console.Title");
        ConsoleSearchBox.PlaceholderText = loc.Get("Console.SearchWatermark");
        AutoScrollCheck.Content = loc.Get("Console.AutoScroll");
        DetachConsoleButton.Content = loc.Get("Console.Split");
        CopyLogButton.Content = loc.Get("Console.Copy");
        ClearLogButton.Content = loc.Get("Console.Clear");

        ConsoleToggleLabel.Text = loc.Get("Page.Options");
        LaunchButtonLabel.Text = loc.Get("Launch.Launch");
        StopButtonLabel.Text = loc.Get("Launch.Stop");
        SessionConsoleButtonLabel.Text = loc.Get("Launch.Console");
        SessionStopButtonLabel.Text = loc.Get("Launch.Stop");

        AboutSectionTitle.Text = loc.Get("Options.About");
        GithubLabel.Text = loc.Get("About.Github.Label");
        GithubDesc.Text = loc.Get("About.Github.Desc");
        DiscordServerLabel.Text = loc.Get("About.Discord.Label");
        DiscordServerDesc.Text = loc.Get("About.Discord.Desc");
        GithubButton.Content = loc.Get("About.GithubButton");
        DiscordButton.Content = loc.Get("About.DiscordButton");
        UpdateLabel.Text = loc.Get("Updater.Label");
        LatestCommitLabel.Text = loc.Get("About.Github.LatestCommitLabel");
        LatestCommitDescription.Text = loc.Get("About.Github.LatestCommitDescription");
        RefreshUpdateText();

        UpdateEmptyStateTexts();
        UpdateSelectedGameTexts();
    }

    // ---- Discord Rich Presence ----

    /// <summary>
    /// Publishes the launcher state to Discord: browsing while idle, the
    /// running game (with elapsed time) during emulation. No-ops when
    /// disabled or when no Discord application ID is configured.
    /// </summary>
    private void UpdateDiscordPresence()
    {
        if (!_settings.DiscordRichPresence || _settings.DiscordClientId.Length == 0)
        {
            _discord?.Dispose();
            _discord = null;
            return;
        }

        _discord ??= new DiscordRichPresence(_settings.DiscordClientId);
        if (_isRunning && _runningGameName is { } gameName)
        {
            _discord.SetPresence(
                Localization.Instance.Format("Discord.Playing", gameName),
                _runningGameTitleId,
                _runningSinceUnixSeconds);
        }
        else
        {
            // Discord does not render activities without timestamps, so the
            // browsing state carries the launcher's start time.
            var count = _allGames.Count == 1
                ? Localization.Instance.Get("Page.GameCount.One")
                : Localization.Instance.Format("Page.GameCount.Other", _allGames.Count);
            _discord.SetPresence(
                Localization.Instance.Get("Discord.Browsing"),
                count,
                _launcherStartUnixSeconds);
        }
    }

    private void OnKeyDown(object sender, KeyEventArgs args)
    {
        args.Handled = true;
        switch (args.Key)
        {
            case Key.F11:
                OnWindowFullScreen(this, new RoutedEventArgs());
                break;
            default:
                args.Handled = false;
                break;
        }
    }

    private void OnPreviewKeyDown(object? sender, KeyEventArgs args)
    {
        if (_isGameSettingsOpen && args.Key == Key.Escape)
        {
            CloseGameSettings();
            args.Handled = true;
            return;
        }

        if (!_isRunning &&
            _activePageIndex == 0 &&
            !_isGameSettingsOpen &&
            !SearchBox.IsKeyboardFocusWithin &&
            args.Key is Key.Left or Key.Right)
        {
            MoveSelection(args.Key == Key.Left ? -1 : 1);
            GameList.Focus();
            args.Handled = true;
            return;
        }

        // While a session is on screen, Enter and Space are game input
        // (Cross button). Keyboard focus stays on the launcher window, so a
        // previously clicked, still-focused button (console toggle, session
        // bar) would also activate and reshape the game view. Swallow the
        // keys before button activation; the emulator process reads raw key
        // state and is unaffected. Fullscreen hides those buttons, which is
        // why this only manifested in windowed sessions.
        if (_isRunning && GameView.IsVisible &&
            args.Key is Key.Enter or Key.Space)
        {
            args.Handled = true;
        }
    }

    private void OnWindowFullScreen(object sender, RoutedEventArgs args)
    {
        if (WindowState == WindowState.FullScreen)
        {
            // Leaving F11 should restore a monitor-sized window with the
            // launcher chrome, not fall back to the design-time window size.
            WindowState = WindowState.Maximized;
            WindowDecorations = WindowDecorations.None;
            TitleBar.IsVisible = true;
            StatusBar.IsVisible = true;
            if (_gameFullscreen)
            {
                _gameFullscreen = false;
                Grid.SetRow(MainContent, 0);
                Grid.SetRowSpan(MainContent, 2);
                MainContent.Margin = new Thickness(0);
                ContentToolbar.IsVisible = !_isRunning;
                ConsolePanel.IsVisible = _activePageIndex == 2 && _consoleWindow is null;
                LaunchBar.IsVisible = true;
                QueueGameSurfaceResize();
                UpdateSessionBarVisibility();
            }
        }
        else
        {
            WindowState = WindowState.FullScreen;
            WindowDecorations = WindowDecorations.None;
            TitleBar.IsVisible = false;
            StatusBar.IsVisible = false;
            if (_isRunning && !_isStopping && !_awaitingFirstFrame && GameView.IsVisible)
            {
                // The native child receives its new physical Bounds as soon
                // as this grid spans the monitor. The presenter recreates its
                // swapchain from that size, rather than stretching 720p.
                _gameFullscreen = true;
                // Re-arming restarts the idle countdown, so the cursor also
                // hides a moment after F11 even without further mouse motion.
                _gameSurfaceHost?.SetCursorAutoHide(true);
                Grid.SetRow(MainContent, 0);
                Grid.SetRowSpan(MainContent, 3);
                MainContent.Margin = new Thickness(0);
                ContentToolbar.IsVisible = false;
                ConsolePanel.IsVisible = false;
                LaunchBar.IsVisible = false;
                QueueGameSurfaceResize();
                UpdateSessionBarVisibility();
            }
        }
    }

    private void QueueGameSurfaceResize()
    {
        Dispatcher.UIThread.Post(
            () => _gameSurfaceHost?.RefreshSurfaceSize(),
            DispatcherPriority.Render);
    }

    private void OnWindowClosing()
    {
        _settings.Save();
        _consoleFlushTimer.Stop();
        _libraryBlurTimer.Stop();
        _gamepadTimer.Stop();
        _sndPreview.Stop();
        _discord?.Dispose();
        _consoleWindow?.Close();
        _emulatorService.Stop();
        _consoleMirror?.Dispose();
        _logService.DropFileLog();
    }

    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        var source = e.Source as Visual;
        if (source?.FindAncestorOfType<Button>(includeSelf: true) is null &&
            source?.FindAncestorOfType<TextBox>(includeSelf: true) is null &&
            e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            BeginMoveDrag(e);
        }
    }

    private void OnResizeHandlePointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (WindowState != WindowState.Normal ||
            !e.GetCurrentPoint(this).Properties.IsLeftButtonPressed ||
            sender is not Control { Tag: string edgeName } ||
            !Enum.TryParse<WindowEdge>(edgeName, out var edge))
        {
            return;
        }

        BeginResizeDrag(edge, e);
        e.Handled = true;
    }

    // ---- Settings ----

    private void ApplySettingsToControls()
    {
        LogLevelBox.SelectedIndex = _settings.LogLevel.ToLowerInvariant() switch
        {
            "trace" => 0,
            "debug" => 1,
            "info" => 2,
            "warning" or "warn" => 3,
            "error" => 4,
            "critical" or "fatal" => 5,
            _ => 2,
        };
        TraceImportsBox.Value = Math.Clamp(_settings.ImportTraceLimit, 0, 4096);
        RenderResolutionBox.SelectedIndex = _settings.RenderResolutionScale switch
        {
            >= 0.875 => 0,
            >= 0.625 => 1,
            >= 0.375 => 2,
            _ => 3,
        };
        StrictToggle.IsChecked = _settings.StrictDynlibResolution;
        LogToFileToggle.IsChecked = _settings.LogToFile;
        OverrideLogFileToggle.IsChecked = _settings.OverrideLogFile;
        TitleMusicToggle.IsChecked = _settings.PlayTitleMusic;
        DiscordToggle.IsChecked = _settings.DiscordRichPresence;
        AutoUpdateToggle.IsChecked = _settings.CheckForUpdatesOnStartup;
        EnvBthidToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_BTHID_UNAVAILABLE");
        EnvLoopGuardToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD");
        EnvWritableApp0Toggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_WRITABLE_APP0");
        EnvVkValidationToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_VK_VALIDATION");
        EnvDumpSpirvToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_DUMP_SPIRV");
        EnvLogDirectMemoryToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_DIRECT_MEMORY");
        EnvLogIoToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_IO");
        EnvLogNpToggle.IsChecked = _settings.EnvironmentToggles.Contains("SHARPEMU_LOG_NP");
        UpdateLogFilePathText();
    }

    private async Task OnUpdateButtonAsync()
    {
        if (_availableUpdate is null)
        {
            await CheckForUpdatesAsync();
            return;
        }

        UpdateButton.IsEnabled = false;
        try
        {
            var progress = new Progress<int>(value =>
                SetUpdateStatus("Updater.Status.Downloading", value));
            await Updater.DownloadAndRestartAsync(_availableUpdate, progress);
            SetUpdateStatus("Updater.Status.Installing");
            Close();
        }
        catch (InvalidDataException)
        {
            SetUpdateStatus("Updater.Status.ChecksumFailed");
            UpdateButton.IsEnabled = true;
        }
        catch
        {
            SetUpdateStatus("Updater.Status.Failed");
            UpdateButton.IsEnabled = true;
        }
    }

    private async Task CheckForUpdatesAsync()
    {
        _availableUpdate = null;
        UpdateButton.IsEnabled = false;
        SetUpdateStatus("Updater.Status.Checking");
        try
        {
            _availableUpdate = await Updater.CheckAsync(BuildInfo.CommitSha);
            SetUpdateStatus(
                _availableUpdate is null ? "Updater.Status.Current" : "Updater.Status.Available",
                _availableUpdate?.Sha ?? BuildInfo.CommitSha ?? "dev");
        }
        catch (OperationCanceledException)
        {
            SetUpdateStatus("Updater.Status.Timeout");
        }
        catch (PlatformNotSupportedException)
        {
            SetUpdateStatus("Updater.Status.Unsupported");
        }
        catch
        {
            SetUpdateStatus("Updater.Status.Failed");
        }
        finally
        {
            UpdateButton.IsEnabled = true;
            RefreshUpdateText();
        }
    }

    private void SetUpdateStatus(string key, params object?[] args)
    {
        _updateStatusKey = key;
        _updateStatusArgs = args;
        RefreshUpdateText();
    }

    private void RefreshUpdateText()
    {
        UpdateStatusText.Text = Localization.Instance.Format(_updateStatusKey, _updateStatusArgs);
        UpdateButton.Content = Localization.Instance.Get(
            _availableUpdate is null ? "Updater.Check" : "Updater.DownloadRestart");
    }

    private void SetEnvironmentToggle(string name, bool enabled)
    {
        if (enabled)
        {
            if (!_settings.EnvironmentToggles.Contains(name))
            {
                _settings.EnvironmentToggles.Add(name);
            }
        }
        else
        {
            _settings.EnvironmentToggles.Remove(name);
        }
    }

    private string SelectedLogLevel()
    {
        return LogLevelBox.SelectedIndex switch
        {
            0 => "Trace",
            1 => "Debug",
            2 => "Info",
            3 => "Warning",
            4 => "Error",
            5 => "Critical",
            _ => "Info",
        };
    }

    private void UpdateLogFilePathText()
    {
        LogFilePathRow.Description = string.IsNullOrWhiteSpace(_settings.LogFilePath)
            ? Localization.Instance.Get("Options.LogFilePath.Default")
            : _settings.LogFilePath;
    }

    private async Task SelectLogFilePathAsync()
    {
        var loc = Localization.Instance;
        SaveFilePickerResult result = await StorageProvider.SaveFilePickerWithResultAsync(new FilePickerSaveOptions
        {
            Title = loc.Get("Dialog.SaveLogFile"),
            SuggestedFileName = "SharpEmuLog",
            DefaultExtension = "log",
            FileTypeChoices =
                [
                    new FilePickerFileType(loc.Get("Dialog.PlainTextFiles")) { Patterns = ["*.txt"] },
                    new FilePickerFileType(loc.Get("Dialog.LogFiles")) { Patterns = ["*.log"] }
                ]
        });

        if (result.File is not null)
        {
            _settings.LogFilePath = result.File.Path.LocalPath;
            UpdateLogFilePathText();
        }
    }

    // ---- Emulator discovery ----

    private void LocateEmulator()
    {
        _emulatorService.LocateEmulator();
        _emulatorExePath = _emulatorService.EmulatorExePath;
        _logService.SetEmulatorExePath(_emulatorExePath);

        EmulatorPathText.Text = _emulatorExePath is not null
            ? Localization.Instance.Format("Status.EmulatorPath", _emulatorExePath)
            : Localization.Instance.Get("Status.EmulatorNotFound");
    }

    // ---- Game library ----

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

        var changed = false;
        if (!_settings.GameFolders.Contains(path, FilePathComparer))
        {
            _settings.GameFolders.Add(path);
            changed = true;
        }

        // Adding (or re-adding) a folder is an explicit signal to restore any
        // games beneath it that were removed from the library earlier.
        var prefix = Path.TrimEndingDirectorySeparator(path) + Path.DirectorySeparatorChar;
        changed |= _settings.ExcludedGames.RemoveAll(excluded =>
            excluded.StartsWith(prefix, FilePathComparison)) > 0;

        if (changed)
        {
            _settings.Save();
        }

        await RescanLibraryAsync();
    }

    private async Task RescanLibraryAsync()
    {
        var folders = _settings.GameFolders.ToArray();
        var excluded = new HashSet<string>(_settings.ExcludedGames, FilePathComparer);
        StatusBarRight.Text = Localization.Instance.Get("Status.ScanningLibrary");
        EmptyState.IsVisible = false;
        LoadingState.IsVisible = true;

        // The scan runs in the injected library service; the view-model owns
        // the resulting collection and kicks off cover/size enrichment.
        var library = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGameLibraryService>();
        var games = await Task.Run(() => library.ScanFolders(folders, excluded));

        _library.ApplyScannedGames(games);
        RefreshVisibleGames();
        _allGames.Clear();
        _allGames.AddRange(games);
        LoadingState.IsVisible = false;
        UpdateDiscordPresence();
        StatusBarRight.Text = folders.Length == 0
            ? Localization.Instance.Get("Status.AddFolderPrompt")
            : Localization.Instance.Format("Status.LibraryScanned", games.Count, folders.Length);
    }

    // Library scan and metadata parsing live in GameLibraryService now;
    // the legacy static helpers (ScanFolders, TryReadParamJson, FindCoverFor,
    // FindBackgroundFor, GameNameFor, ComputeInstallSize) were removed when
    // the logic moved behind IGameLibraryService.

    // ---- Game context menu ----

    /// <summary>
    /// Selects the tile under the pointer before its context menu opens, and
    /// suppresses the menu on empty grid space.
    /// </summary>
    private void OnGameContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        var item = (e.Source as Visual)?.FindAncestorOfType<ListBoxItem>(includeSelf: true);
        if (item?.DataContext is not GameEntry game)
        {
            e.Handled = true;
            return;
        }

        GameList.SelectedItem = game;
        CtxLaunch.IsEnabled = !_isRunning;
        CtxCopyTitleId.IsEnabled = game.TitleId is not null;
        CtxGameSettings.IsEnabled = !string.IsNullOrWhiteSpace(game.TitleId);
    }

    private void OpenSelectedGameSettings()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(game.TitleId))
        {
            AppendConsoleLine(
                "[GUI][WARN] Per-game settings require a title ID, which this game does not have.",
                WarningLineBrush);
            return;
        }

        var vm = new ViewModels.PerGameSettingsViewModel(game.TitleId, game.Name, _settings);
        _gameSettingsViewModel = vm;
        LoadGameSettings(vm);
        GameOptionsOverlay.DataContext = game;
        SetGameOptionsSection(0);
        GameOptionsLaunchButton.IsEnabled = !_isRunning;
        GameOptionsCopyTitleIdButton.IsEnabled = !string.IsNullOrWhiteSpace(game.TitleId);

        _selectedDetailsAnimationGeneration++;
        SelectedDetailsHost.Classes.Remove("detailsOut");
        SelectedDetailsHost.Classes.Remove("detailsInStart");
        SetStateClass(BackdropLayer, "gameOptionsOpen", active: true);
        SetStateClass(CarouselHost, "gameOptionsOpen", active: true);
        SetStateClass(SelectedDetailsHost, "gameOptionsOpen", active: true);
        SetStateClass(LaunchBar, "gameOptionsOpen", active: true);
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: true);

        _isGameSettingsOpen = true;
        ConsoleToggle.IsChecked = true;
        GameList.IsHitTestVisible = false;
        LaunchBar.IsHitTestVisible = false;
        GameOptionsOverlay.IsHitTestVisible = true;
        GameOptionsGeneralNav.Focus();
    }

    private void CloseGameSettings()
    {
        if (!_isGameSettingsOpen)
        {
            return;
        }

        _isGameSettingsOpen = false;
        SetStateClass(BackdropLayer, "gameOptionsOpen", active: false);
        SetStateClass(CarouselHost, "gameOptionsOpen", active: false);
        SetStateClass(SelectedDetailsHost, "gameOptionsOpen", active: false);
        SetStateClass(LaunchBar, "gameOptionsOpen", active: false);
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: false);
        GameOptionsOverlay.IsHitTestVisible = false;
        GameList.IsHitTestVisible = true;
        LaunchBar.IsHitTestVisible = true;
        ConsoleToggle.IsChecked = false;
        GameList.Focus();
    }

    private void LoadGameSettings(ViewModels.PerGameSettingsViewModel vm)
    {
        _isLoadingGameSettings = true;
        try
        {
            GameLogLevelBox.SelectedItem = vm.SelectedLogLevel;
            GameTraceBox.Value = vm.ImportTraceLimit;
            GameStrictToggle.IsChecked = vm.IsStrictDynlibResolution;
            GameLogToFileToggle.IsChecked = vm.IsLogToFile;

            foreach (var (name, toggle) in GameEnvironmentToggles())
            {
                toggle.IsChecked = vm.GetEnvironment(name);
            }
        }
        finally
        {
            _isLoadingGameSettings = false;
        }
    }

    private void PersistOpenGameSettings()
    {
        if (_isGameSettingsOpen &&
            !_isLoadingGameSettings &&
            _gameSettingsViewModel is { } vm)
        {
            PersistGameSettings(vm);
        }
    }

    private void PersistGameSettings(ViewModels.PerGameSettingsViewModel vm)
    {
        vm.SelectedLogLevel = (string?)GameLogLevelBox.SelectedItem ?? "Info";
        vm.IsLogLevelOverridden =
            !string.Equals(vm.SelectedLogLevel, _settings.LogLevel, StringComparison.Ordinal);
        vm.ImportTraceLimit = (int)(GameTraceBox.Value ?? 0);
        vm.IsImportTraceOverridden = vm.ImportTraceLimit != _settings.ImportTraceLimit;
        vm.IsStrictDynlibResolution = GameStrictToggle.IsChecked == true;
        vm.IsStrictOverridden =
            vm.IsStrictDynlibResolution != _settings.StrictDynlibResolution;
        vm.IsLogToFile = GameLogToFileToggle.IsChecked == true;
        vm.IsLogToFileOverridden = vm.IsLogToFile != _settings.LogToFile;

        var selectedEnvironment = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, toggle) in GameEnvironmentToggles())
        {
            var isEnabled = toggle.IsChecked == true;
            vm.SetEnvironment(name, isEnabled);
            if (isEnabled)
            {
                selectedEnvironment.Add(name);
            }
        }

        vm.IsEnvironmentOverridden =
            !_settings.EnvironmentToggles.ToHashSet(StringComparer.Ordinal).SetEquals(selectedEnvironment);
        vm.Save();
    }

    private void SetGameOptionsSection(int section)
    {
        var buttons = new[]
        {
            GameOptionsGeneralNav,
            GameOptionsLoggingNav,
            GameOptionsEnvironmentNav,
        };
        var panels = new Control[]
        {
            GameOptionsGeneralPanel,
            GameOptionsLoggingPanel,
            GameOptionsEnvironmentPanel,
        };

        _gameOptionsSectionIndex = section;
        SetGameOptionsNavIndicator(section);
        for (var index = 0; index < buttons.Length; index++)
        {
            SetActiveClass(buttons[index], index == section);
            panels[index].IsVisible = index == section;
        }
    }

    private void SetGameOptionsNavIndicator(int section)
    {
        if (GameOptionsNavIndicator.RenderTransform is TranslateTransform transform)
        {
            transform.Y = Math.Clamp(section, 0, 3) * 53;
        }
    }

    private (string Name, ToggleSwitch Toggle)[] GameEnvironmentToggles() =>
    [
        ("SHARPEMU_BTHID_UNAVAILABLE", GameEnvBthidToggle),
        ("SHARPEMU_DISABLE_IMPORT_LOOP_GUARD", GameEnvLoopGuardToggle),
        ("SHARPEMU_WRITABLE_APP0", GameEnvWritableApp0Toggle),
        ("SHARPEMU_VK_VALIDATION", GameEnvVkValidationToggle),
        ("SHARPEMU_DUMP_SPIRV", GameEnvDumpSpirvToggle),
        ("SHARPEMU_LOG_DIRECT_MEMORY", GameEnvLogDirectMemoryToggle),
        ("SHARPEMU_LOG_IO", GameEnvLogIoToggle),
        ("SHARPEMU_LOG_NP", GameEnvLogNpToggle),
    ];

    private static void SetStateClass(StyledElement element, string className, bool active)
    {
        if (active)
        {
            if (!element.Classes.Contains(className))
            {
                element.Classes.Add(className);
            }
        }
        else
        {
            element.Classes.Remove(className);
        }
    }

    private void OpenSelectedGameFolder()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{game.Path}\"",
                    UseShellExecute = false,
                });
            }
            else if (Path.GetDirectoryName(game.Path) is { } directory)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = OperatingSystem.IsMacOS() ? "open" : "xdg-open",
                    Arguments = $"\"{directory}\"",
                    UseShellExecute = false,
                });
            }
        }
        catch (Exception ex)
        {
            StatusBarRight.Text = Localization.Instance.Format("Status.CouldNotOpenFolder", ex.Message);
        }
    }

    /// <summary>Copies <paramref name="text"/> and reports it via <paramref name="whatKey"/>, e.g. "Clipboard.Path".</summary>
    private async Task CopyToClipboardAsync(string? text, string whatKey)
    {
        if (string.IsNullOrEmpty(text) || Clipboard is null)
        {
            return;
        }

        await Clipboard.SetTextAsync(text);
        StatusBarRight.Text = Localization.Instance.Format("Status.CopiedToClipboard", Localization.Instance.Get(whatKey));
    }

    private void RemoveSelectedFromLibrary()
    {
        if (GameList.SelectedItem is not GameEntry game)
        {
            return;
        }

        if (!_settings.ExcludedGames.Contains(game.Path, FilePathComparer))
        {
            _settings.ExcludedGames.Add(game.Path);
            _settings.Save();
        }

        // The view-model drops the game from its collection and re-applies the
        // search filter; mirror the legacy _allGames list for the few paths
        // (page count, launch lookup) still keyed off it.
        _library.Remove(game);
        _allGames.RemoveAll(g => string.Equals(g.Path, game.Path, FilePathComparison));
        GameList.SelectedItem = null;
        StatusBarRight.Text = Localization.Instance.Format("Status.RemovedFromLibrary", game.Name);
    }

    private void RefreshVisibleGames()
    {
        // Filtering lives in the view-model; here we only sync the UI state that
        // is still driven imperatively from the window (selection, empty state).
        _library.RefreshVisibleGames();

        var selectedPath = _library.SelectedGame?.Path;
        if (selectedPath is not null &&
            _visibleGames.FirstOrDefault(g => g.Path.Equals(selectedPath, FilePathComparison))
                is { } reselected)
        {
            GameList.SelectedItem = reselected;
        }
        else if (_visibleGames.Count > 0)
        {
            var first = _visibleGames[0];
            GameList.SelectedItem = first;
            _library.SelectedGame = first;
        }
        else
        {
            GameList.SelectedItem = null;
            _library.SelectedGame = null;
        }

        EmptyState.IsVisible = _visibleGames.Count == 0;
        UpdateEmptyStateTexts();

        UpdateSelectedGame();
    }

    /// <summary>
    /// Refreshes the empty-state title/hint from the current language and
    /// search text; a no-op while the empty state is not showing.
    /// </summary>
    private void UpdateEmptyStateTexts()
    {
        if (_visibleGames.Count != 0)
        {
            return;
        }

        var query = SearchBox.Text?.Trim() ?? string.Empty;
        var hasFilter = query.Length > 0;
        EmptyStateTitle.Text = hasFilter
            ? Localization.Instance.Get("Library.Empty.SearchTitle")
            : Localization.Instance.Get("Library.Empty.Title");
        EmptyStateHint.Text = hasFilter
            ? Localization.Instance.Format("Library.Empty.SearchHint", query)
            : Localization.Instance.Get("Library.Empty.Hint");
        EmptyAddFolderButton.IsVisible = !hasFilter;
    }

    private void UpdateSelectedGame()
    {
        var game = GameList.SelectedItem as GameEntry;
        _ = AnimateSelectedGameDetailsAsync(game);

        if (game is not null)
        {
            _ = UpdateBackdropAsync(game);
            PlaySelectedGamePreview(game);
        }
        else
        {
            _ = UpdateBackdropAsync(null);
            _sndPreview.Stop();
        }

        UpdateRunButtons();
    }

    private async Task AnimateSelectedGameDetailsAsync(GameEntry? game)
    {
        var generation = ++_selectedDetailsAnimationGeneration;
        SelectedDetailsHost.Classes.Remove("detailsInStart");
        SelectedDetailsHost.Classes.Add("detailsOut");
        await Task.Delay(110);

        if (generation != _selectedDetailsAnimationGeneration)
        {
            return;
        }

        ApplySelectedGameDetails(game);
        SelectedDetailsHost.Classes.Remove("detailsOut");
        SelectedDetailsHost.Classes.Add("detailsInStart");
        await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Render);

        if (generation != _selectedDetailsAnimationGeneration)
        {
            return;
        }

        SelectedDetailsHost.Classes.Remove("detailsInStart");
    }

    private void ApplySelectedGameDetails(GameEntry? game)
    {
        if (game is not null)
        {
            SelectedGameTitle.Text = game.Name;
            SelectedGamePath.Text = game.Path;
            SelectedCoverPanel.DataContext = game;
            SelectedBadgesRow.DataContext = game;
            SelectedBadgesRow.IsVisible = true;
        }
        else
        {
            SelectedGameTitle.Text = Localization.Instance.Get("Launch.NoGameSelected");
            SelectedGamePath.Text = Localization.Instance.Get("Launch.NoGameHint");
            SelectedCoverPanel.DataContext = null;
            SelectedBadgesRow.DataContext = null;
            SelectedBadgesRow.IsVisible = false;
        }
    }

    /// <summary>
    /// Text-only refresh of the launch bar's title/path, split out of
    /// <see cref="UpdateSelectedGame"/> so a language change can re-apply it
    /// without restarting the backdrop fade or preview music.
    /// </summary>
    private void UpdateSelectedGameTexts()
    {
        ApplySelectedGameDetails(GameList.SelectedItem as GameEntry);
    }

    /// <summary>
    /// Loops the selected game's sce_sys/snd0.at9 preview music, console
    /// home screen style. Silent while a game is running or when disabled
    /// in the options.
    /// </summary>
    private void PlaySelectedGamePreview(GameEntry game)
    {
        if (_isRunning || !_settings.PlayTitleMusic)
        {
            return;
        }

        var directory = Path.GetDirectoryName(game.Path);
        var sndPath = directory is null ? null : Path.Combine(directory, "sce_sys", "snd0.at9");
        if (sndPath is not null && File.Exists(sndPath))
        {
            _sndPreview.Play(sndPath);
        }
        else
        {
            _sndPreview.Stop();
        }
    }

    private void OnTitleMusicSettingChanged()
    {
        if (!_settings.PlayTitleMusic)
        {
            _sndPreview.Stop();
        }
        else if (GameList.SelectedItem is GameEntry game)
        {
            PlaySelectedGamePreview(game);
        }
    }

    /// <summary>Pauses the preview music while the window is minimized.</summary>
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty)
        {
            // The XAML WindowState="Maximized" assignment raises this change
            // during InitializeComponent, before named controls are wired up.
            if (WindowState == WindowState.Minimized)
            {
                _sndPreview.Pause();
                if (SessionLoadingPopup is { } popup)
                {
                    popup.IsOpen = false;
                }
            }
            else
            {
                _sndPreview.Resume();
                if (SessionLoadingPopup is { } popup)
                {
                    popup.IsOpen = _sessionLoadingActive;
                }
            }
        }
    }

    /// <summary>
    /// Fades the window backdrop to the selected game's key art. The image
    /// decodes off the UI thread and is cached on the entry; a newer
    /// selection cancels the fade-in of an older one.
    /// </summary>
    private async Task UpdateBackdropAsync(GameEntry? game)
    {
        var generation = ++_backdropGeneration;
        BackdropImage.Opacity = 0;
        CoverFallbackImage.Opacity = 0;

        // The bundled key art is the primary backdrop whenever the selection
        // has no art of its own; the window color stays as the last fallback.
        void ShowDefaultBackdrop()
        {
            if (generation == _backdropGeneration && _defaultBackdrop is not null)
            {
                BackdropImage.Source = _defaultBackdrop;
                BackdropImage.Opacity = 1.0;
            }
        }

        if (game is null)
        {
            ShowDefaultBackdrop();
            return;
        }

        if (game.BackgroundPath is null)
        {
            ShowDefaultBackdrop();
            if (game.CoverPath is null)
            {
                return;
            }

            if (game.Cover is null)
            {
                try
                {
                    var coverPath = game.CoverPath;
                    game.Cover = await Task.Run(() =>
                    {
                        using var stream = File.OpenRead(coverPath);
                        return Bitmap.DecodeToWidth(stream, 720);
                    });
                }
                catch (Exception)
                {
                    return;
                }
            }

            if (generation == _backdropGeneration)
            {
                CoverFallbackImage.Source = game.Cover;
                CoverFallbackImage.Opacity = 1.0;
            }

            return;
        }

        if (game.Background is null)
        {
            try
            {
                var path = game.BackgroundPath;
                game.Background = await Task.Run(() =>
                {
                    using var stream = File.OpenRead(path);
                    return Bitmap.DecodeToWidth(stream, 1600);
                });
            }
            catch (Exception)
            {
                ShowDefaultBackdrop(); // undecodable key art
                return;
            }
        }

        if (generation == _backdropGeneration)
        {
            BackdropImage.Source = game.Background;
            BackdropImage.Opacity = 1.0;
        }
    }

    // ---- Launching ----

    private async Task OpenFileAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Localization.Instance.Get("Dialog.OpenExecutable"),
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType(Localization.Instance.Get("Dialog.PsExecutables"))
                    { Patterns = new[] { "eboot.bin", "*.bin", "*.self", "*.elf" } },
                FilePickerFileTypes.All,
            },
        });

        var path = files.FirstOrDefault()?.TryGetLocalPath();
        if (!string.IsNullOrEmpty(path))
        {
            Launch(path, Path.GetFileName(path));
        }
    }

    private void LaunchSelected()
    {
        if (GameList.SelectedItem is GameEntry game)
        {
            Launch(game.Path, game.Name, game.TitleId);
        }
    }

    private void Launch(string ebootPath, string displayName, string? titleId = null)
    {
        if (_isRunning)
        {
            return;
        }

        var resolvedTitleId = string.IsNullOrWhiteSpace(titleId)
            ? _allGames.FirstOrDefault(game => game.Path.Equals(ebootPath, FilePathComparison))?.TitleId
            : titleId;
        var effective = EffectiveLaunchSettings.Resolve(_settings, PerGameSettings.Load(resolvedTitleId));

        _sndPreview.Stop();
        _logService.Clear();

        _logService.DropFileLog();
        if (effective.LogToFile)
        {
            _logService.OpenFileLog(resolvedTitleId);
        }

        // Effective settings, env vars and runtime options now live in the
        // emulator service; only the UI reaction remains here.
        _emulatorService.PrepareLaunch(ebootPath, displayName, resolvedTitleId);

        _isRunning = true;
        _runningGameName = displayName;
        SessionGameTitle.Text = displayName;
        _runningGameTitleId = resolvedTitleId;
        _runningSinceUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _session.OnLaunchPrepared(displayName, resolvedTitleId);
        StatusText.Text = Localization.Instance.Format("Launch.Running", displayName);
        StatusBarRight.Text = Localization.Instance.Format("Status.Running", displayName);
        UpdateRunButtons();
        UpdateDiscordPresence();

        ShowGameView();

        if (_gameSurfaceHost?.Surface is { } surface)
        {
            StartPendingSession(surface);
        }
    }

    /// <summary>
    /// Stops the running game and updates status/presence immediately. The
    /// process-exit path still runs when the corpse is collected, but a game
    /// wedged in a GPU driver call can keep its process alive for a long
    /// time after termination — the launcher should not look (or tell
    /// Discord it is) "playing" during that window.
    /// </summary>
    private void StopEmulator()
    {
        if (!_isRunning || _isStopping)
        {
            return;
        }

        // If a launch is still pending (surface not yet attached), cancel it
        // instead of letting the delayed callback start a session the user
        // already cancelled.
        if (_emulatorService.CancelPendingLaunch())
        {
            OnEmulatorExited(0);
            return;
        }

        _isStopping = true;
        _session.OnStopRequested();
        StopButton.IsEnabled = false;
        SessionStopButton.IsEnabled = false;
        SessionHintText.Text = Localization.Instance.Get("Launch.Stopping");
        SessionF11Badge.IsVisible = false;
        ShowSessionLoading("Closing game", "Waiting for the emulation session to exit...");
        _emulatorService.Stop();
        _runningGameName = null;
        _runningGameTitleId = null;
        StatusText.Text = Localization.Instance.Get("Launch.Stopping");
        StatusBarRight.Text = Localization.Instance.Get("Status.Stopping");
        UpdateDiscordPresence();
        UpdateSessionBarVisibility();
        ReturnToLibraryWhileStopping();
    }

    /// <summary>
    /// Builds "user/logs/&lt;titleId&gt;-&lt;timestamp&gt;.log" next to the emulator
    /// executable, following the same portable-data convention as savedata.
    /// </summary>
    private void OnEmulatorExited(int exitCode)
    {
        _logService.Flush();
        _isRunning = false;
        _isStopping = false;
        // The emulator service disposes its own process; the window only owns
        // the native surface host and view state.
        DisposeGameSurfaceHost();
        HideGameView();

        var meaningKey = exitCode switch
        {
            0 => "Exit.Ok",
            1 => "Exit.InvalidArguments",
            2 => "Exit.EbootNotFound",
            3 => "Exit.RuntimeException",
            4 => "Exit.EmulationError",
            -1073741819 => "Exit.EmulationError",
            _ => "Exit.Unknown",
        };
        var stoppedByUser = exitCode == EmulatorProcess.HostStopExitCode;
        var meaning = Localization.Instance.Get(meaningKey);
        var brush = exitCode == 0 || stoppedByUser ? SuccessLineBrush : ErrorLineBrush;
        AppendConsoleLine(
            stoppedByUser
                ? "Game closed by the user."
                : Localization.Instance.Format("Launch.ProcessExited", exitCode, meaning),
            brush);
        CloseFileLogSoon();

        StatusText.Text = stoppedByUser
            ? "Game closed by the user."
            : Localization.Instance.Format("Launch.Exited", exitCode, meaning);
        StatusBarRight.Text = Localization.Instance.Get("Status.Idle");
        _runningGameName = null;
        _runningGameTitleId = null;
        UpdateRunButtons();
        UpdateDiscordPresence();
    }

    private void StartPendingSession(VulkanHostSurface surface)
    {
        // Resolve the child-process descriptor here (the surface is a UI-bound
        // native handle) and hand it to the service, which owns the process.
        string? descriptor = null;
        if (surface.TryGetChildProcessDescriptor(out var d))
        {
            descriptor = d;
        }
        else
        {
            AppendConsoleLine(
                "[GUI][WARN] Embedded child surfaces are unavailable on this platform; opening a game window instead.",
                WarningLineBrush);
        }

        _emulatorService.StartPendingSession(descriptor);
    }

    private void OnEmulatorOutput(string line, bool isError)
    {
        _logService.Enqueue(line, isError);
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
                ClearLibraryBlur();
                MainContent.Margin = new Thickness(0);
                RestoreGameViewToFull();
                GameView.Background = Brushes.Black;
                GameView.IsHitTestVisible = true;
                LibraryPage.IsVisible = false;
                OptionsPage.IsVisible = false;
                LibraryToolbar.IsVisible = false;
                ContentToolbar.IsVisible = false;
                ConsolePanel.IsVisible = false;
                LaunchBar.IsVisible = false;
                HideSessionLoading();
                UpdateSessionBarVisibility();

                // Defer so the layout pass from the margin change above settles first.
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

    private GameSurfaceHost EnsureGameSurfaceHost()
    {
        if (_gameSurfaceHost is not null)
        {
            return _gameSurfaceHost;
        }

        var host = new GameSurfaceHost();
        // Configure this before attaching it to Avalonia so its first native
        // HWND is hidden while the child process starts.
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

    /// <summary>
    /// The native host attachment is a real child window: it sits above every
    /// Avalonia control it covers and swallows their mouse input regardless of
    /// hit-test settings. While the library must stay interactive (loading,
    /// closing), the surface is parked offscreen AT FULL SIZE via a negative
    /// margin. It must not be shrunk instead: the emulator child polls the
    /// HWND client size and its presenter defers swapchain creation while the
    /// surface is 1px, which would deadlock the loading handshake.
    /// </summary>
    private void ParkGameViewOffscreen()
    {
        GameView.Margin = new Thickness(-20000, 0, 20000, 0);
    }

    private void RestoreGameViewToFull()
    {
        GameView.Margin = new Thickness(0);
    }

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
        AnimateLibraryBlur(LaunchBlurRadius);
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
        SessionBarPopup.IsOpen = false;
        HideSessionLoading();
        AnimateLibraryBlur(0, clearWhenComplete: true);
        MainContent.Margin = new Thickness(0);
        ContentToolbar.IsVisible = true;
        ConsolePanel.IsVisible = _activePageIndex == 2 && _consoleWindow is null;
        LaunchBar.IsVisible = true;
        LibraryPage.IsVisible = _activePageIndex == 0;
        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;
        OptionsPage.IsVisible = _activePageIndex == 1;
        // Game art when the source still holds it, otherwise the bundled
        // default; a bare color only when neither is available.
        BackdropImage.Opacity = BackdropImage.Source is not null ? 1 : 0;
    }

    private void AnimateLibraryBlur(double targetRadius, bool clearWhenComplete = false)
    {
        _libraryBlur ??= new BlurEffect();
        PagesHost.Effect = _libraryBlur;

        _libraryBlurStartRadius = _libraryBlur.Radius;
        _libraryBlurTargetRadius = Math.Max(0, targetRadius);
        _libraryBlurStartedAt = Stopwatch.GetTimestamp();
        _clearLibraryBlurWhenComplete = clearWhenComplete && _libraryBlurTargetRadius == 0;

        if (Math.Abs(_libraryBlurStartRadius - _libraryBlurTargetRadius) < 0.01)
        {
            CompleteLibraryBlur();
            return;
        }

        _libraryBlurTimer.Start();
    }

    private void AdvanceLibraryBlur()
    {
        if (_libraryBlur is null)
        {
            _libraryBlurTimer.Stop();
            return;
        }

        var elapsed = (Stopwatch.GetTimestamp() - _libraryBlurStartedAt) /
                      (double)Stopwatch.Frequency;
        var progress = Math.Clamp(elapsed / BlurTransitionSeconds, 0, 1);
        // Cubic ease-out gives the loading transition a quick response while
        // keeping the final change of sharpness unobtrusive.
        var easedProgress = 1 - Math.Pow(1 - progress, 3);
        _libraryBlur.Radius = _libraryBlurStartRadius +
                              ((_libraryBlurTargetRadius - _libraryBlurStartRadius) * easedProgress);

        if (progress >= 1)
        {
            CompleteLibraryBlur();
        }
    }

    private void CompleteLibraryBlur()
    {
        _libraryBlurTimer.Stop();
        if (_libraryBlur is not null)
        {
            _libraryBlur.Radius = _libraryBlurTargetRadius;
        }

        if (_clearLibraryBlurWhenComplete)
        {
            PagesHost.Effect = null;
            _libraryBlur = null;
            _clearLibraryBlurWhenComplete = false;
        }
    }

    private void ClearLibraryBlur()
    {
        _libraryBlurTimer.Stop();
        _libraryBlur = null;
        _clearLibraryBlurWhenComplete = false;
        PagesHost.Effect = null;
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

    private void ReturnToLibraryWhileStopping()
    {
        if (_gameFullscreen && WindowState == WindowState.FullScreen)
        {
            OnWindowFullScreen(this, new RoutedEventArgs());
        }

        // Keep the native child alive until the session exits, but hide it
        // immediately. Destroying it while Vulkan still owns the surface can
        // crash the GUI; parking it in the 1x1 corner lets the library
        // recover — and stay clickable — while the native closing popup
        // reports teardown progress.
        _gameSurfaceHost?.SetPresentationVisible(false);
        _awaitingFirstFrame = false;
        ParkGameViewOffscreen();
        GameView.Background = Brushes.Transparent;
        GameView.IsHitTestVisible = false;
        SessionBarPopup.IsOpen = false;
        AnimateLibraryBlur(LaunchBlurRadius);
        MainContent.Margin = new Thickness(0);
        ContentToolbar.IsVisible = true;
        ConsolePanel.IsVisible = _activePageIndex == 2 && _consoleWindow is null;
        LaunchBar.IsVisible = true;
        LibraryPage.IsVisible = _activePageIndex == 0;
        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;
        OptionsPage.IsVisible = _activePageIndex == 1;
        BackdropImage.Opacity = BackdropImage.Source is not null ? 1 : 0;
        UpdateRunButtons();
        Console.Error.WriteLine("[GUI][INFO] Library restored while embedded session is closing.");
    }

    private void UpdateRunButtons()
    {
        LaunchButton.IsEnabled = !_isRunning && GameList.SelectedItem is GameEntry;
        StopButton.IsEnabled = _isRunning && !_isStopping;
        SessionStopButton.IsEnabled = _isRunning && !_isStopping;
        OpenFileButton.IsEnabled = !_isRunning;
    }

    private void UpdateSessionBarVisibility()
    {
        SessionBarPopup.IsOpen = _isRunning && !_isStopping && !_awaitingFirstFrame && GameView.IsVisible &&
            !_gameFullscreen && WindowState != WindowState.FullScreen;
    }

    // ---- Console ----
    // The buffer, file mirroring and brush mapping live in ILogService now;
    // the methods below are thin pass-throughs for the few call sites that
    // still route through the window (e.g. GUI-authored lines with a UI brush).

    private void AppendConsoleLine(string text, IBrush brush)
    {
        _logService.Append(text, brush);
        _autoScrollTicks = 3;
        MaybeAutoScroll();
    }

    private void RefreshVisibleConsoleLines()
    {
        _logService.SearchQuery = ConsoleSearchBox.Text ?? string.Empty;
        _logService.RefreshVisible();
    }

    private void CloseFileLogSoon() => _logService.CloseFileLogSoon();

    private void MaybeAutoScroll()
    {
        // ScrollToEnd is applied over a few flush-timer ticks because the
        // virtualizing panel re-estimates its extent after large batches, and
        // a single scroll can land short of the true end. A synchronous
        // ScrollIntoView during rapid adds is avoided entirely — it can crash
        // the panel with "Invalid Arrange rectangle".
        if (_autoScrollTicks <= 0 || AutoScrollCheck.IsChecked != true)
        {
            return;
        }

        _autoScrollTicks--;
        (ConsoleList.Scroll as ScrollViewer)?.ScrollToEnd();
    }

    private async Task CopyConsoleAsync()
    {
        if (_consoleLines.Count == 0 || Clipboard is null)
        {
            return;
        }

        var text = string.Join(Environment.NewLine, _consoleLines.Select(line => line.Text));
        await Clipboard.SetTextAsync(text);
    }

    private void ShowConsoleWindow()
    {
        if (_consoleWindow is { } window)
        {
            window.Activate();
            return;
        }

        ConsoleSearchBox.Text = string.Empty;
        ConsolePanel.IsVisible = false;
        // The detached window shares the same log buffer as the inline panel,
        // owned by ILogService; clearing it clears both views.
        _consoleWindow = new ConsoleWindow(
            _logService.VisibleLines,
            () => _logService.Clear(),
            AutoScrollCheck.IsChecked == true);
        _consoleWindow.Closed += (_, _) =>
        {
            _consoleWindow = null;
            ConsolePanel.IsVisible = _activePageIndex == 2;
        };
        _consoleWindow.Show(this);
    }
}
