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
using Avalonia.Styling;
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
    private enum UpdateActionState
    {
        Idle,
        Checking,
        Available,
    }

    // Shell navigation is ViewModel-owned. Remaining feature-specific event
    // handlers are kept here only until their corresponding view is extracted.
    private const int LaunchIndicatorExitMilliseconds = 220;
    private const int LaunchBlackoutEnterMilliseconds = 360;

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
    private readonly ObservableCollection<LibraryTile> _visibleGames;
    // Console buffer is owned by ILogService; aliased here for the XAML-bound
    // ConsoleList and the few remaining imperative reads.
    private AvaloniaList<LogLine> _consoleLines = new();
    private readonly DispatcherTimer _consoleFlushTimer;
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
    private bool _isGameSurfaceTransitioning;
    private int _launchPresentationGeneration;
    private int _autoScrollTicks;
    private Updater.UpdateInfo? _availableUpdate;
    private string _updateStatusKey = "Updater.Status.Ready";
    private object?[] _updateStatusArgs = [BuildInfo.CommitSha ?? "dev"];
    private bool _isUpdateOperationRunning;

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

    private bool _isGameSettingsOpen;
    private bool _isLoadingGameSettings;
    private bool _addFolderInProgress;
    private bool _suppressSelectionChanged;
    private int _gameOptionsSectionIndex;
    private int _optionsSectionIndex;
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
    private readonly Services.Abstractions.IGameLibraryService _libraryService;
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
        DataContext = main;
        _library = main.Library;
        _session = main.Session;
        _visibleGames = _library.Games;
        // Resolve the remaining services the launch pipeline needs. They share
        // the same container-scoped singletons as the view-models.
        _emulatorService = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IEmulatorService>();
        _logService = GuiLauncher.Services.GetRequiredService<Services.Abstractions.ILogService>();
        _libraryService = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGameLibraryService>();
        _gamepad = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGamepadInputService>();
        _logService.SetEmulatorExePath(_emulatorService.EmulatorExePath);

        // Forward emulator process events to the window's UI reactions.
        _emulatorService.OutputReceived += OnEmulatorOutput;
        _emulatorService.Exited += code => OnEmulatorExited(code);

        // The library watcher raises from a background thread when a game is
        // added/removed on disk; re-scan on the UI thread so the carousel updates
        // without a manual refresh.
        _libraryService.LibraryChanged += (_, _) =>
            Dispatcher.UIThread.Post(() => _ = RescanLibraryAsync());

        // Translate gamepad navigation intents into UI actions.
        _gamepad.PageRequested += page => Dispatcher.UIThread.Post(() => SetActivePage(page));
        _gamepad.MoveHorizontal += delta => Dispatcher.UIThread.Post(() => HandleGamepadHorizontal(delta));
        _gamepad.MoveVertical += direction => Dispatcher.UIThread.Post(() => HandleGamepadVertical(direction));
        _gamepad.Activate += () => Dispatcher.UIThread.Post(HandleGamepadActivate);
        _main.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(ViewModels.MainViewModel.ActivePage))
            {
                OnActivePageChanged();
            }
        };

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

        Closed += (_, _) => _emulatorService.Stop();

        // Native popups float above every window on the desktop; they must
        // follow the launcher into the background or a minimized state.
        Activated += (_, _) => UpdateSessionBarVisibility();
        Deactivated += (_, _) =>
        {
            SessionBarPopup.IsOpen = false;
        };

        TitleBar.PointerPressed += OnTitleBarPointerPressed;
        GameList.SelectionChanged += (_, _) =>
        {
            // A re-entrant raise from cancelling a selection below must not
            // reset the visible game.
            if (_suppressSelectionChanged)
            {
                return;
            }

            // The trailing "add folder" card is an action, not a selectable
            // game: it must never become active. Cancel the selection (keeping
            // any previously selected game highlighted) and open the picker.
            if (GameList.SelectedItem is AddFolderTile)
            {
                var previous = _library.SelectedGame;
                _suppressSelectionChanged = true;
                try
                {
                    GameList.SelectedItem = previous;
                }
                finally
                {
                    _suppressSelectionChanged = false;
                }

                if (!_addFolderInProgress)
                {
                    _addFolderInProgress = true;
                    _ = AddFolderAsync().ContinueWith(_ => _addFolderInProgress = false);
                }
                return;
            }

            var current = GameList.SelectedItem as GameEntry;
            // ListBox raises SelectionChanged asynchronously (on its layout pass)
            // whenever its items collection is rebuilt — including the moment
            // Games.Clear() runs during a rescan, when the selection is
            // transiently null even though we have a chosen game. Do NOT mirror
            // a null selection back into the view-model or the details panel;
            // that echo would clobber the game we just picked and surface the
            // welcome state. Only honor a null selection when the view-model
            // agrees there really is no selected game.
            if (current is null && _library.SelectedGame is not null)
            {
                return;
            }

            _library.SelectedGame = current;
            UpdateSelectedGame(current);
        };
        GameList.DoubleTapped += (_, _) =>
        {
            if (GameList.SelectedItem is AddFolderTile)
            {
                if (!_addFolderInProgress)
                {
                    _addFolderInProgress = true;
                    _ = AddFolderAsync().ContinueWith(_ => _addFolderInProgress = false);
                }
                return;
            }

            LaunchSelected();
        };
        SearchBox.TextChanged += (_, _) =>
        {
            _library.SearchText = SearchBox.Text ?? string.Empty;
            // The filtered list refresh happens in the VM (throttled); keep
            // the empty-state and selection sync immediate for responsiveness.
            RefreshVisibleGames();
        };
        ConsoleSearchBox.TextChanged += (_, _) => RefreshVisibleConsoleLines();
        LaunchButton.Click += (_, _) => LaunchSelected();
        ClearLogButton.Click += (_, _) => _logService.Clear();
        SessionStopButton.Click += (_, _) => StopEmulator();
        SessionConsoleButton.Click += (_, _) => ShowConsoleWindow();
        CopyLogButton.Click += async (_, _) => await CopyConsoleAsync();
        DetachConsoleButton.Click += (_, _) => ShowConsoleWindow();
        ConsoleToggle.Click += (_, _) => OpenSelectedGameSettings();
        var gameOptionsNavButtons = GameOptionsNavButtons();
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

        var optionsNavButtons = OptionsNavButtons();
        for (var index = 0; index < optionsNavButtons.Length; index++)
        {
            var section = index;
            var button = optionsNavButtons[index];
            button.Click += (_, _) => SetOptionsSection(section);
            button.PointerEntered += (_, _) => SetOptionsNavIndicator(section);
            button.GotFocus += (_, _) => SetOptionsNavIndicator(section);
        }
        OptionsNavHost.PointerExited += (_, _) => SetOptionsNavIndicator(_optionsSectionIndex);
        SetOptionsSection(0);

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
            _settings.RenderResolutionScale = RenderResolutionScaleAt(RenderResolutionBox.SelectedIndex);
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

        LatestCommitButton.Click += (_, _) =>
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

    /// <summary>Compatibility adapter for controller and keyboard navigation.</summary>
    private void SetActivePage(int index)
    {
        _main.NavigateTo(index);
    }

    private void OnActivePageChanged()
    {
        if (_main.ActivePage != Navigation.ShellPage.Library && _isGameSettingsOpen)
        {
            CloseGameSettings();
        }

        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;

        if (_main.ActivePage == Navigation.ShellPage.Options)
        {
            Dispatcher.UIThread.Post(
                () => OptionsNavButtons()[_optionsSectionIndex].Focus(NavigationMethod.Directional),
                DispatcherPriority.Input);
        }
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
        LatestCommitHashText.Text = "Loading…";
        LatestCommitButton.IsEnabled = false;

        try
        {
            using var response = await GithubHttpClient.GetAsync(apiUrl);
            var responseBody =
                (await response.Content.ReadAsStringAsync()).Trim();

            if (!response.IsSuccessStatusCode)
            {
                LatestCommitHashText.Text =
                    $"HTTP {(int)response.StatusCode}";

                ToolTip.SetTip(
                    LatestCommitButton,
                    string.IsNullOrWhiteSpace(responseBody)
                        ? response.ReasonPhrase
                        : responseBody);

                return;
            }

            if (responseBody.Length < 7)
            {
                LatestCommitHashText.Text = "Invalid response";
                ToolTip.SetTip(LatestCommitButton, responseBody);
                return;
            }

            // Keep the complete SHA for the URL.
            _latestCommitSha = responseBody;

            // Display only the short SHA.
            LatestCommitHashText.Text =
                responseBody[..Math.Min(7, responseBody.Length)];

            LatestCommitButton.IsEnabled = true;

            ToolTip.SetTip(
                LatestCommitButton,
                $"Open commit {_latestCommitSha}");
        }
        catch (TaskCanceledException ex)
        {
            LatestCommitHashText.Text = "Timeout";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
        catch (HttpRequestException ex)
        {
            LatestCommitHashText.Text = "Connection error";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
        catch (Exception ex)
        {
            LatestCommitHashText.Text = "Error";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
    }

    // ---- Controller navigation ----

    private void PollGamepad()
    {
        // The gamepad service polls the controller and raises navigation
        // intents; the window only feeds it the current UI context. Intents
        // are marshalled to the UI thread via the event subscriptions set up
        // in the constructor.
        _gamepad.Poll(IsActive, _isRunning || _isStopping, _main.ActivePageIndex);
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

    private void HandleGamepadHorizontal(int direction)
    {
        if (_main.ActivePage == Navigation.ShellPage.Library)
        {
            MoveSelection(direction);
            return;
        }

        if (_main.ActivePage != Navigation.ShellPage.Options)
        {
            return;
        }

        if (OptionsNavButtons().Any(button => button.IsKeyboardFocusWithin))
        {
            if (direction > 0)
            {
                FocusOptionsControl(0);
            }

            return;
        }

        if (!AdjustFocusedOption(direction) && direction < 0)
        {
            OptionsNavButtons()[_optionsSectionIndex].Focus(NavigationMethod.Directional);
        }
    }

    private void HandleGamepadVertical(int direction)
    {
        if (_main.ActivePage == Navigation.ShellPage.Library)
        {
            MoveSelection(direction * TilesPerRow());
            return;
        }

        if (_main.ActivePage != Navigation.ShellPage.Options)
        {
            return;
        }

        if (OptionsNavButtons().Any(button => button.IsKeyboardFocusWithin))
        {
            SetOptionsSection(_optionsSectionIndex + direction, focusNavigation: true);
            return;
        }

        var controls = FocusableOptionsControls();
        var currentIndex = Array.FindIndex(controls, control => control.IsKeyboardFocusWithin);
        FocusOptionsControl(currentIndex < 0 ? 0 : currentIndex + direction);
    }

    private void HandleGamepadActivate()
    {
        if (_main.ActivePage == Navigation.ShellPage.Library)
        {
            LaunchSelected();
            return;
        }

        if (_main.ActivePage != Navigation.ShellPage.Options)
        {
            return;
        }

        if (OptionsNavButtons().Any(button => button.IsKeyboardFocusWithin))
        {
            FocusOptionsControl(0);
            return;
        }

        var focused = ActiveOptionsControls().FirstOrDefault(control => control.IsKeyboardFocusWithin);
        switch (focused)
        {
            case ToggleSwitch toggle:
                toggle.IsChecked = toggle.IsChecked != true;
                break;
            case ComboBox combo:
                combo.IsDropDownOpen = !combo.IsDropDownOpen;
                break;
            case Button button:
                button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                break;
        }
    }

    private bool AdjustFocusedOption(int direction)
    {
        var focused = ActiveOptionsControls().FirstOrDefault(control => control.IsKeyboardFocusWithin);
        switch (focused)
        {
            case ToggleSwitch toggle:
                toggle.IsChecked = direction > 0;
                return true;
            case ComboBox combo when combo.ItemCount > 0:
                combo.SelectedIndex = Math.Clamp(combo.SelectedIndex + direction, 0, combo.ItemCount - 1);
                return true;
            case NumericUpDown number:
                var current = number.Value ?? number.Minimum;
                number.Value = Math.Clamp(
                    current + (number.Increment * direction),
                    number.Minimum,
                    number.Maximum);
                return true;
            default:
                return false;
        }
    }

    private void FocusOptionsControl(int requestedIndex)
    {
        var controls = FocusableOptionsControls();
        if (controls.Length == 0)
        {
            OptionsNavButtons()[_optionsSectionIndex].Focus(NavigationMethod.Directional);
            return;
        }

        var index = Math.Clamp(requestedIndex, 0, controls.Length - 1);
        controls[index].Focus(NavigationMethod.Directional);
        controls[index].BringIntoView();
    }

    private Control[] FocusableOptionsControls() =>
        ActiveOptionsControls()
            .Where(control => control.IsEnabled && control.IsVisible)
            .ToArray();

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
        _libraryService.Watch(_settings.GameFolders);
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
        ConsoleTabButton.Content = loc.Get("Page.Console");
        SearchBox.PlaceholderText = loc.Get("Library.SearchWatermark");

        CtxLaunch.Header = loc.Get("Library.Context.Launch");
        CtxOpenFolder.Header = loc.Get("Library.Context.OpenFolder");
        CtxCopyPath.Header = loc.Get("Library.Context.CopyPath");
        CtxCopyTitleId.Header = loc.Get("Library.Context.CopyTitleId");
        CtxGameSettings.Header = loc.Get("Library.Context.GameSettings");
        CtxRemove.Header = loc.Get("Library.Context.Remove");

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
        GameOptionsLaunchLabel.Text = loc.Get("Library.Context.Launch");
        GameOptionsOpenFolderLabel.Text = loc.Get("Library.Context.OpenFolder");
        GameOptionsCopyPathLabel.Text = loc.Get("Library.Context.CopyPath");
        GameOptionsCopyTitleIdLabel.Text = loc.Get("Library.Context.CopyTitleId");
        GameOptionsRemoveLabel.Text = loc.Get("Library.Context.Remove");

        OptionsGeneralNavLabel.Text = SectionNavigationLabel(loc.Get("Options.General"));
        OptionsLoggingNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Logging"));
        OptionsLauncherNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Section.Launcher"));
        OptionsRenderingNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Graphics.Rendering"));
        OptionsEnvironmentNavLabel.Text = SectionNavigationLabel(loc.Get("Options.Env.Tab"));
        OptionsAboutNavLabel.Text = SectionNavigationLabel(loc.Get("Options.About"));

        GameStrictRow.Label = loc.Get("Options.Strict.Label");
        GameStrictRow.Description = loc.Get("Options.Strict.Desc");
        GameLogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        GameLogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        GameTraceRow.Label = loc.Get("Options.TraceImports.Label");
        GameTraceRow.Description = loc.Get("Options.TraceImports.Desc");
        GameLogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        GameLogToFileRow.Description = loc.Get("Options.LogToFile.Desc");

        ApplyEnvironmentDescription(EnvBthidRow, GameEnvBthidRow, "Options.Env.Bthid.Desc");
        ApplyEnvironmentDescription(EnvLoopGuardRow, GameEnvLoopGuardRow, "Options.Env.LoopGuard.Desc");
        ApplyEnvironmentDescription(EnvWritableApp0Row, GameEnvWritableApp0Row, "Options.Env.WritableApp0.Desc");
        ApplyEnvironmentDescription(EnvVkValidationRow, GameEnvVkValidationRow, "Options.Env.VkValidation.Desc");
        ApplyEnvironmentDescription(EnvDumpSpirvRow, GameEnvDumpSpirvRow, "Options.Env.DumpSpirv.Desc");
        ApplyEnvironmentDescription(
            EnvLogDirectMemoryRow,
            GameEnvLogDirectMemoryRow,
            "Options.Env.LogDirectMemory.Desc");
        ApplyEnvironmentDescription(EnvLogIoRow, GameEnvLogIoRow, "Options.Env.LogIo.Desc");
        ApplyEnvironmentDescription(EnvLogNpRow, GameEnvLogNpRow, "Options.Env.LogNp.Desc");
        CpuEngineRow.Label = loc.Get("Options.CpuEngine.Label");
        CpuEngineRow.Description = loc.Get("Options.CpuEngine.Desc");
        CpuEngineBox.ItemsSource = new[] { loc.Get("Options.CpuEngine.Native") };
        CpuEngineBox.SelectedIndex = 0;

        StrictRow.Label = loc.Get("Options.Strict.Label");
        StrictRow.Description = loc.Get("Options.Strict.Desc");

        LogLevelRow.Label = loc.Get("Options.LogLevel.Label");
        LogLevelRow.Description = loc.Get("Options.LogLevel.Desc");
        var globalLogLevel = _settings.LogLevel;
        var gameLogLevel = _gameSettingsViewModel?.SelectedLogLevel ?? globalLogLevel;
        var localizedLogLevels = new[]
        {
            loc.Get("Options.LogLevel.Trace"),
            loc.Get("Options.LogLevel.Debug"),
            loc.Get("Options.LogLevel.Info"),
            loc.Get("Options.LogLevel.Warning"),
            loc.Get("Options.LogLevel.Error"),
            loc.Get("Options.LogLevel.Critical"),
        };

        LogLevelBox.ItemsSource = localizedLogLevels;
        LogLevelBox.SelectedIndex = LogLevelIndex(globalLogLevel);

        var wasLoadingGameSettings = _isLoadingGameSettings;
        _isLoadingGameSettings = true;
        try
        {
            GameLogLevelBox.ItemsSource = localizedLogLevels;
            GameLogLevelBox.SelectedIndex = LogLevelIndex(gameLogLevel);
        }
        finally
        {
            _isLoadingGameSettings = wasLoadingGameSettings;
        }

        TraceImportsRow.Label = loc.Get("Options.TraceImports.Label");
        TraceImportsRow.Description = loc.Get("Options.TraceImports.Desc");

        LogToFileRow.Label = loc.Get("Options.LogToFile.Label");
        LogToFileRow.Description = loc.Get("Options.LogToFile.Desc");

        LogFilePathRow.Label = loc.Get("Options.LogFilePath.Label");
        SelectLogFilePathButtonLabel.Text = loc.Get("Options.LogFilePath.Select");
        UpdateLogFilePathText();

        OverrideLogFileRow.Label = loc.Get("Options.OverrideLogFile.Label");
        OverrideLogFileRow.Description = loc.Get("Options.OverrideLogFile.Desc");

        LanguageRow.Label = loc.Get("Options.Language.Label");
        LanguageRow.Description = loc.Get("Options.Language.Desc");

        RenderResolutionRow.Label = loc.Get("Options.RenderResolution.Label");
        RenderResolutionRow.Description = loc.Get("Options.RenderResolution.Desc");
        var renderResolutionScale = _settings.RenderResolutionScale;
        RenderResolutionBox.ItemsSource = new[]
        {
            loc.Get("Options.RenderResolution.Native"),
            "75%",
            "50%",
            "25%",
        };
        RenderResolutionBox.SelectedIndex = RenderResolutionIndex(renderResolutionScale);

        TitleMusicRow.Label = loc.Get("Options.TitleMusic.Label");
        TitleMusicRow.Description = loc.Get("Options.TitleMusic.Desc");

        DiscordRow.Label = loc.Get("Options.Discord.Label");
        DiscordRow.Description = loc.Get("Options.Discord.Desc");
        AutoUpdateRow.Label = loc.Get("Updater.Auto.Label");
        AutoUpdateRow.Description = loc.Get("Updater.Auto.Desc");

        ConsoleSearchBox.PlaceholderText = loc.Get("Console.SearchWatermark");
        AutoScrollCheck.Content = loc.Get("Console.AutoScroll");
        DetachConsoleButtonLabel.Text = loc.Get("Console.Split");
        CopyLogButtonLabel.Text = loc.Get("Console.Copy");
        ClearLogButtonLabel.Text = loc.Get("Console.Clear");

        LaunchButtonLabel.Text = loc.Get("Launch.Launch");
        LaunchLoadingLabel.Text = loc.Get("Launch.Loading");
        SessionConsoleButtonLabel.Text = loc.Get("Launch.Console");
        SessionStopButtonLabel.Text = loc.Get("Launch.Stop");

        GithubLabel.Text = loc.Get("About.Github.Label");
        GithubDesc.Text = loc.Get("About.Github.Desc");
        DiscordServerLabel.Text = loc.Get("About.Discord.Label");
        DiscordServerDesc.Text = loc.Get("About.Discord.Desc");
        AboutTagline.Text = loc.Get("About.Tagline");
        GithubButtonLabel.Text = loc.Get("About.GithubButton");
        DiscordButtonLabel.Text = loc.Get("About.DiscordButton");
        UpdateLabel.Text = loc.Get("Updater.Label");
        LatestCommitLabel.Text = loc.Get("About.Github.LatestCommitLabel");
        LatestCommitDescription.Text = loc.Get("About.Github.LatestCommitDescription");
        RefreshUpdateText();

        UpdateSelectedGameTexts();
    }

    private static string SectionNavigationLabel(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(char.IsLower))
        {
            return value;
        }

        var lower = value.ToLowerInvariant();
        return char.ToUpperInvariant(lower[0]) + lower[1..];
    }

    private static void ApplyEnvironmentDescription(
        SettingRow globalRow,
        SettingRow perGameRow,
        string localizationKey)
    {
        var description = Localization.Instance.Get(localizationKey);
        globalRow.Description = description;
        perGameRow.Description = description;
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
            _main.ActivePage == Navigation.ShellPage.Library &&
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
        RenderResolutionBox.SelectedIndex = RenderResolutionIndex(_settings.RenderResolutionScale);
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
        if (_isUpdateOperationRunning)
        {
            return;
        }

        if (_availableUpdate is null)
        {
            await CheckForUpdatesAsync();
            return;
        }

        _isUpdateOperationRunning = true;
        UpdateButton.IsHitTestVisible = false;
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
        }
        catch
        {
            SetUpdateStatus("Updater.Status.Failed");
        }
        finally
        {
            _isUpdateOperationRunning = false;
            UpdateButton.IsHitTestVisible = true;
        }
    }

    private async Task CheckForUpdatesAsync()
    {
        if (_isUpdateOperationRunning)
        {
            return;
        }

        _isUpdateOperationRunning = true;
        _availableUpdate = null;
        UpdateButton.IsHitTestVisible = false;
        SetUpdateActionState(UpdateActionState.Checking);
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
            _isUpdateOperationRunning = false;
            UpdateButton.IsHitTestVisible = true;
            SetUpdateActionState(
                _availableUpdate is null ? UpdateActionState.Idle : UpdateActionState.Available);
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
        var loc = Localization.Instance;
        UpdateStatusText.Text = loc.Format(_updateStatusKey, _updateStatusArgs);
        UpdateCheckLabel.Text = loc.Get("Updater.Check");
        UpdateCheckingLabel.Text = loc.Get("Updater.Checking");
        UpdateInstallLabel.Text = loc.Get("Updater.Install");
    }

    private void SetUpdateActionState(UpdateActionState state)
    {
        UpdateButton.Classes.Set("idle", state == UpdateActionState.Idle);
        UpdateButton.Classes.Set("checking", state == UpdateActionState.Checking);
        UpdateButton.Classes.Set("available", state == UpdateActionState.Available);
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
        return LogLevelAt(LogLevelBox.SelectedIndex);
    }

    private static string LogLevelAt(int index)
    {
        return index switch
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

    private static int LogLevelIndex(string? logLevel)
    {
        return logLevel?.ToLowerInvariant() switch
        {
            "trace" => 0,
            "debug" => 1,
            "warning" or "warn" => 3,
            "error" => 4,
            "critical" or "fatal" => 5,
            _ => 2,
        };
    }

    private static int RenderResolutionIndex(double scale)
    {
        return scale switch
        {
            >= 0.875 => 0,
            >= 0.625 => 1,
            >= 0.375 => 2,
            _ => 3,
        };
    }

    private static double RenderResolutionScaleAt(int index)
    {
        return index switch
        {
            1 => 0.75,
            2 => 0.5,
            3 => 0.25,
            _ => 1.0,
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
            // Keep the filesystem watcher aligned with the new folder set so
            // future changes (games installed/removed on disk) are picked up.
            _libraryService.Watch(_settings.GameFolders);
        }

        await RescanLibraryAsync();
    }

    private async Task RescanLibraryAsync()
    {
        var folders = _settings.GameFolders.ToArray();
        var excluded = new HashSet<string>(_settings.ExcludedGames, FilePathComparer);
        StatusBarRight.Text = Localization.Instance.Get("Status.ScanningLibrary");
        LoadingState.IsVisible = true;

        // The scan runs in the injected library service; the view-model owns
        // the resulting collection and kicks off cover/size enrichment.
        var games = await Task.Run(() => _libraryService.ScanFolders(folders, excluded));

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
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: true);

        _isGameSettingsOpen = true;
        ConsoleToggle.IsChecked = true;
        GameList.IsHitTestVisible = false;
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
        SetStateClass(GameOptionsOverlay, "gameOptionsOpen", active: false);
        GameOptionsOverlay.IsHitTestVisible = false;
        GameList.IsHitTestVisible = true;
        ConsoleToggle.IsChecked = false;
        GameList.Focus();
    }

    private void LoadGameSettings(ViewModels.PerGameSettingsViewModel vm)
    {
        _isLoadingGameSettings = true;
        try
        {
            GameLogLevelBox.SelectedIndex = LogLevelIndex(vm.SelectedLogLevel);
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
        vm.SelectedLogLevel = LogLevelAt(GameLogLevelBox.SelectedIndex);
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
        var buttons = GameOptionsNavButtons();
        var panels = GameOptionsSectionPanels();

        section = Math.Clamp(section, 0, panels.Length - 1);
        _gameOptionsSectionIndex = section;
        SetGameOptionsNavIndicator(section);
        for (var index = 0; index < panels.Length; index++)
        {
            SetStateClass(buttons[index], "active", index == section);
            SetStateClass(panels[index], "active", index == section);
            SetPanelInteraction(panels[index], index == section);
        }

        SetStateClass(GameOptionsBackNav, "active", active: false);
    }

    private void SetGameOptionsNavIndicator(int section)
    {
        if (GameOptionsNavIndicator.RenderTransform is TranslateTransform transform)
        {
            var buttons = GameOptionsNavButtons();
            var index = Math.Clamp(section, 0, buttons.Length - 1);
            var button = buttons[index];
            transform.Y = button.TranslatePoint(default, GameOptionsNavHost)?.Y
                ?? index * button.Bounds.Height;
        }
    }

    private Button[] GameOptionsNavButtons() =>
    [
        GameOptionsGeneralNav,
        GameOptionsLoggingNav,
        GameOptionsEnvironmentNav,
        GameOptionsBackNav,
    ];

    private Control[] GameOptionsSectionPanels() =>
    [
        GameOptionsGeneralPanel,
        GameOptionsLoggingPanel,
        GameOptionsEnvironmentPanel,
    ];

    private Button[] OptionsNavButtons() =>
    [
        OptionsGeneralNav,
        OptionsLoggingNav,
        OptionsLauncherNav,
        OptionsRenderingNav,
        OptionsEnvironmentNav,
        OptionsAboutNav,
    ];

    private Control[] OptionsSectionPanels() =>
    [
        OptionsGeneralPanel,
        OptionsLoggingPanel,
        OptionsLauncherPanel,
        OptionsRenderingPanel,
        OptionsEnvironmentPanel,
        OptionsAboutPanel,
    ];

    private void SetOptionsSection(int section, bool focusNavigation = false)
    {
        var buttons = OptionsNavButtons();
        var panels = OptionsSectionPanels();
        section = Math.Clamp(section, 0, buttons.Length - 1);
        _optionsSectionIndex = section;
        SetOptionsNavIndicator(section);

        for (var index = 0; index < buttons.Length; index++)
        {
            var active = index == section;
            SetStateClass(buttons[index], "active", active);
            SetStateClass(panels[index], "active", active);
            SetPanelInteraction(panels[index], active);
        }

        if (focusNavigation)
        {
            buttons[section].BringIntoView();
            buttons[section].Focus(NavigationMethod.Directional);
        }
    }

    private static void SetPanelInteraction(Control panel, bool isActive)
    {
        // Keep the visual tree enabled while it fades. IsEnabled propagates to
        // every descendant and activates Fluent's :disabled colors before the
        // transition has finished, which appears as a one-frame color flash.
        panel.IsHitTestVisible = isActive;
        KeyboardNavigation.SetTabNavigation(
            panel,
            isActive ? KeyboardNavigationMode.Continue : KeyboardNavigationMode.None);
    }

    private void SetOptionsNavIndicator(int section)
    {
        if (OptionsNavIndicator.RenderTransform is TranslateTransform transform)
        {
            var buttons = OptionsNavButtons();
            var index = Math.Clamp(section, 0, buttons.Length - 1);
            var button = buttons[index];

            // The navigation rows are contiguous hit targets. The 7 px visual
            // gap lives inside each 61 px row, so pointer traversal never
            // enters an ownerless area. Resolve the indicator position from
            // the arranged button instead of duplicating the row pitch here.
            transform.Y = button.TranslatePoint(default, OptionsNavHost)?.Y
                ?? index * button.Bounds.Height;
        }
    }

    private Control[] ActiveOptionsControls() => _optionsSectionIndex switch
    {
        0 => [CpuEngineBox, StrictToggle],
        1 => [LogLevelBox, TraceImportsBox, LogToFileToggle, SelectLogFilePathButton, OverrideLogFileToggle],
        2 => [LanguageBox, TitleMusicToggle, DiscordToggle, AutoUpdateToggle],
        3 => [RenderResolutionBox],
        4 =>
        [
            EnvBthidToggle,
            EnvLoopGuardToggle,
            EnvWritableApp0Toggle,
            EnvVkValidationToggle,
            EnvDumpSpirvToggle,
            EnvLogDirectMemoryToggle,
            EnvLogIoToggle,
            EnvLogNpToggle,
        ],
        5 => [UpdateButton, LatestCommitButton, GithubButton, DiscordButton],
        _ => [],
    };

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

        _library.Remove(game);
        _allGames.RemoveAll(g => string.Equals(g.Path, game.Path, FilePathComparison));
        GameList.SelectedItem = null;
        StatusBarRight.Text = Localization.Instance.Format("Status.RemovedFromLibrary", game.Name);
    }

    private void RefreshVisibleGames()
    {
        _library.RefreshVisibleGames();

        var selectedPath = _library.SelectedGame?.Path;
        GameEntry? toSelect;
        if (selectedPath is not null &&
            _visibleGames.OfType<GameEntry>().FirstOrDefault(g => g.Path.Equals(selectedPath, FilePathComparison))
                is { } reselected)
        {
            GameList.SelectedItem = reselected;
            toSelect = reselected;
        }
        else if (_visibleGames.OfType<GameEntry>().FirstOrDefault() is { } first)
        {
            GameList.SelectedItem = first;
            _library.SelectedGame = first;
            toSelect = first;
        }
        else
        {
            GameList.SelectedItem = null;
            _library.SelectedGame = null;
            toSelect = null;
        }

        UpdateSelectedGame(toSelect);

        var restore = toSelect;
        if (restore is not null)
        {
            Dispatcher.UIThread.Post(() =>
            {
                if (GameList.SelectedItem is null &&
                    _library.SelectedGame?.Path == restore.Path)
                {
                    GameList.SelectedItem = restore;
                }
            }, DispatcherPriority.Background);
        }
    }

    private void UpdateSelectedGame()
    {
        UpdateSelectedGame(GameList.SelectedItem as GameEntry);
    }

    /// <summary>
    /// Applies the selected game to the details panel, backdrop and preview.
    /// Takes the game explicitly (rather than re-reading <see cref="GameList"/>'s
    /// <see cref="SelectingItemsControl.SelectedItem"/>) because ListBox applies
    /// selection asynchronously on its next layout pass — reading it back right
    /// after assigning it can return the stale value, leaving the initial load
    /// showing the welcome state instead of the first game.
    /// </summary>
    private void UpdateSelectedGame(GameEntry? game)
    {
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
            SelectedEmptyHint.IsVisible = false;
            SelectedActionsHost.IsVisible = true;
            SelectedCoverPanel.DataContext = game;
            SelectedBadgesRow.DataContext = game;
            SelectedBadgesRow.IsVisible = true;
        }
        else
        {
            // Empty library: a welcome state rather than "no game selected".
            // The launch/options actions have nothing to act on, so they stay hidden.
            SelectedGameTitle.Text = Localization.Instance.Get("Library.Welcome.Title");
            SelectedGamePath.Text = Localization.Instance.Get("Library.Welcome.Hint");
            SelectedEmptyHint.Text = Localization.Instance.Get("Library.Welcome.Hint");
            SelectedEmptyHint.IsVisible = true;
            SelectedActionsHost.IsVisible = false;
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
            }
            else
            {
                _sndPreview.Resume();
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
        BeginLaunchPresentation();
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
        SessionStopButton.IsEnabled = false;
        SessionHintText.Text = Localization.Instance.Get("Launch.Stopping");
        SessionF11Badge.IsVisible = false;
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
            if (_isRunning &&
                !_isStopping &&
                _awaitingFirstFrame &&
                !_isGameSurfaceTransitioning)
            {
                _isGameSurfaceTransitioning = true;
                _ = TransitionToGameSurfaceAsync(_launchPresentationGeneration);
            }
        });
    }

    private async Task TransitionToGameSurfaceAsync(int generation)
    {
        // First let the loading label and progress bar leave as one unit.
        CompleteLaunchPresentation();
        await Task.Delay(LaunchIndicatorExitMilliseconds);
        if (!IsLaunchTransitionCurrent(generation))
        {
            return;
        }

        // The game surface is still hidden here. Fade only the retained key art
        // and its masks to black so no launcher or native frame can flash.
        LaunchBlackout.Opacity = 1;
        await Task.Delay(LaunchBlackoutEnterMilliseconds);
        if (!IsLaunchTransitionCurrent(generation))
        {
            return;
        }

        // Opacity transitions are evaluated by the compositor. Waiting only
        // for their nominal duration can still reveal the native child before
        // the fully black frame has actually been presented. Two animation
        // frames guarantee that at least one opaque frame reaches the screen.
        await WaitForAnimationFramesAsync(2);
        if (!IsLaunchTransitionCurrent(generation))
        {
            return;
        }

        MainContent.Margin = new Thickness(0);
        RestoreGameViewToFull();
        GameView.Background = Brushes.Black;
        GameView.IsHitTestVisible = true;
        PagesHost.IsVisible = false;
        LibraryToolbar.IsVisible = false;
        ContentToolbar.IsVisible = false;

        // Let the full-size native child receive its final layout before it is
        // mapped. It has already rendered a frame while hidden.
        await Dispatcher.UIThread.InvokeAsync(
            () => _gameSurfaceHost?.RefreshSurfaceSize(),
            DispatcherPriority.Render);
        if (!IsLaunchTransitionCurrent(generation))
        {
            return;
        }

        _gameSurfaceHost?.SetPresentationVisible(true);
        _gameSurfaceHost?.SetCursorAutoHide(true);
        _awaitingFirstFrame = false;
        _isGameSurfaceTransitioning = false;
        // Keep a black frame behind the native child. On Stop/exit the child
        // disappears first, then this bridge fades out to the launcher.
        UpdateSessionBarVisibility();
    }

    private async Task WaitForAnimationFramesAsync(int frameCount)
    {
        for (var frame = 0; frame < frameCount; frame++)
        {
            var completion = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            RequestAnimationFrame(_ => completion.TrySetResult(true));
            await completion.Task;
        }
    }

    private bool IsLaunchTransitionCurrent(int generation) =>
        generation == _launchPresentationGeneration &&
        _isRunning &&
        !_isStopping;

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
        SessionHintText.Text = "Fullscreen";
        SessionF11Badge.IsVisible = true;
        UpdateSessionBarVisibility();
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
        MainContent.Margin = new Thickness(0);
        ContentToolbar.IsVisible = true;
        PagesHost.IsVisible = true;
        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;
        RestoreLaunchPresentation();
        // Game art when the source still holds it, otherwise the bundled
        // default; a bare color only when neither is available.
        BackdropImage.Opacity = BackdropImage.Source is not null ? 1 : 0;
    }

    /// <summary>
    /// Turns the launcher into a quiet loading canvas while the native surface
    /// is still parked offscreen. Opacity and scale transitions live in XAML,
    /// so changing state here never removes the pre-rendered pages from the
    /// visual tree or pushes their controls through a disabled theme state.
    /// </summary>
    private void BeginLaunchPresentation()
    {
        _launchPresentationGeneration++;
        _isGameSurfaceTransitioning = false;
        PagesHost.IsVisible = true;
        PagesHost.IsHitTestVisible = false;
        PagesHost.Opacity = 0;
        TitleBar.IsHitTestVisible = false;
        TitleBar.Opacity = 0;
        SetBackdropLaunchScale(1.035);
        LaunchBlackout.Opacity = 0;
        LaunchProgressHost.Opacity = 1;
    }

    /// <summary>
    /// Starts the exit half of the launch sequence. The native surface remains
    /// hidden while this group fades; the blackout bridge follows only after
    /// the transition duration has elapsed.
    /// </summary>
    private void CompleteLaunchPresentation()
    {
        LaunchProgressHost.Opacity = 0;
    }

    private void RestoreLaunchPresentation()
    {
        _launchPresentationGeneration++;
        _isGameSurfaceTransitioning = false;
        LaunchProgressHost.Opacity = 0;
        LaunchBlackout.Opacity = 0;
        SetBackdropLaunchScale(1);
        PagesHost.Opacity = 1;
        PagesHost.IsHitTestVisible = true;
        TitleBar.Opacity = 1;
        TitleBar.IsHitTestVisible = true;
    }

    private void SetBackdropLaunchScale(double scale)
    {
        if (BackdropLayer.RenderTransform is not ScaleTransform backdropScale)
        {
            return;
        }

        backdropScale.ScaleX = scale;
        backdropScale.ScaleY = scale;
    }

    private void ReturnToLibraryWhileStopping()
    {
        if (_gameFullscreen && WindowState == WindowState.FullScreen)
        {
            OnWindowFullScreen(this, new RoutedEventArgs());
        }

        // Keep the native child alive until the session exits, but hide it
        // immediately. The already-opaque blackout remains behind it, then
        // RestoreLaunchPresentation fades that bridge away to the library.
        // Destroying the native child while Vulkan owns it can crash the GUI.
        _gameSurfaceHost?.SetPresentationVisible(false);
        _awaitingFirstFrame = false;
        ParkGameViewOffscreen();
        GameView.Background = Brushes.Transparent;
        GameView.IsHitTestVisible = false;
        SessionBarPopup.IsOpen = false;
        MainContent.Margin = new Thickness(0);
        ContentToolbar.IsVisible = true;
        PagesHost.IsVisible = true;
        LibraryToolbar.IsVisible = true;
        SearchBox.IsVisible = false;
        RestoreLaunchPresentation();
        BackdropImage.Opacity = BackdropImage.Source is not null ? 1 : 0;
        UpdateRunButtons();
        Console.Error.WriteLine("[GUI][INFO] Library restored while embedded session is closing.");
    }

    private void UpdateRunButtons()
    {
        LaunchButton.IsEnabled = !_isRunning && GameList.SelectedItem is GameEntry;
        SessionStopButton.IsEnabled = _isRunning && !_isStopping;
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
        // The detached window shares the same log buffer as the inline panel,
        // owned by ILogService; clearing it clears both views.
        _consoleWindow = new ConsoleWindow(
            _logService.VisibleLines,
            () => _logService.Clear(),
            AutoScrollCheck.IsChecked == true);
        _consoleWindow.Closed += (_, _) =>
        {
            _consoleWindow = null;
        };
        _consoleWindow.Show(this);
    }
}
