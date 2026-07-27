// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.Logging;
using System.Collections.ObjectModel;
using System.Reflection;

namespace SharpEmu.GUI;

public partial class MainWindow : Window
{
    // Shell navigation is ViewModel-owned. Remaining feature-specific event
    // handlers are kept here only until their corresponding view is extracted.
    private const int LaunchIndicatorExitMilliseconds = 220;

    private const int LaunchBlackoutEnterMilliseconds = 360;

    private const double GameWindowDragHeight = 32;

    private const double GameWindowResizeInset = 6;

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

    private readonly GameOverlayView _gameOverlay;

    private GuiConsoleMirror? _consoleMirror;

    private readonly SndPreviewPlayer _sndPreview = new();

    private string? _emulatorExePath;

    private bool _gameFullscreen;

    private bool _isRunning;

    private bool _isStopping;

    private bool _awaitingFirstFrame;

    private bool _isGameSurfaceTransitioning;

    private int _launchPresentationGeneration;

    private bool _overlayBoundsSyncQueued;

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

    private int _libraryScanGeneration;

    private int _gameOptionsSectionIndex;

    private int _optionsSectionIndex;

    private int _selectedDetailsAnimationGeneration;

    private ViewModels.PerGameSettingsViewModel? _gameSettingsViewModel;

    // Controller navigation state.
    private readonly DispatcherTimer _gamepadTimer;

    // Set true once the window begins closing so the background-poll suspend/
    // resume handlers never try to restart timers on a torn-down window.
    private bool _isClosing;

    //Github http client for latest commit
    private static readonly HttpClient GithubHttpClient = CreateGithubHttpClient();

    private string? _latestCommitSha;

    private readonly ViewModels.MainViewModel _main;

    private readonly ViewModels.LibraryViewModel _library;

    private readonly Services.Abstractions.IEmulatorService _emulatorService;

    private readonly Services.Abstractions.ILogService _logService;

    private readonly Services.Abstractions.IGameLibraryService _libraryService;

    private readonly Services.Abstractions.IGameActivityService _gameActivity;

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
        _gameActivity = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGameActivityService>();
        _gamepad = GuiLauncher.Services.GetRequiredService<Services.Abstractions.IGamepadInputService>();
        // The overlay instance is created here (readonly field) and wired in
        // WireGameSurface, which also attaches it to GameSurfaceContainer.
        _gameOverlay = new GameOverlayView(
            GuiLauncher.Services.GetRequiredService<ViewModels.GameOverlayViewModel>());
        _logService.SetEmulatorExePath(_emulatorService.EmulatorExePath);

        // Forward emulator process events to the window's UI reactions.
        _emulatorService.OutputReceived += OnEmulatorOutput;
        _emulatorService.Exited += code => OnEmulatorExited(code);

        // Both timers are readonly, so they are constructed here; each feature
        // attaches its own tick handler and starts them from its Wire method.
        _consoleFlushTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(80),
        };
        _gamepadTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(50),
        };

        // Each feature owns the wiring of the controls it drives. Grouping is
        // by page, and the order below preserves the original sequence: within
        // a group, item sources are still assigned before their change handlers
        // are attached.
        WireNavigation();
        WireChrome();
        WireGameSurface();
        WireLibrary();
        WireConsole();
        WireGameOptions();
        WireOptions();
        WireUpdates();
        WireGamepad();

        Closed += (_, _) => _emulatorService.Stop();
        Opened += async (_, _) => await OnOpenedAsync();
        Closing += (_, _) => OnWindowClosing();
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

    private void OnWindowClosing()
    {
        _isClosing = true;
        _session.OnApplicationClosing();
        _settings.Save();
        _consoleFlushTimer.Stop();
        _gamepadTimer.Stop();
        _sndPreview.Stop();
        _discord?.Dispose();
        _gameOverlay.Dispose();
        _consoleWindow?.Close();
        _emulatorService.Stop();
        _consoleMirror?.Dispose();
        _logService.DropFileLog();
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
                _gameOverlay.HideOverlay(activateOwner: false);
            }
            else
            {
                _sndPreview.Resume();
            }

            // Re-evaluate after the new window state has completed one render
            // pass so the owned overlay follows the actual native GameView,
            // including when the launcher crosses monitor boundaries.
            if (GameView is not null)
            {
                UpdateGameWindowFrame();
                QueueGameOverlayBoundsSync();
            }
        }
    }
}
