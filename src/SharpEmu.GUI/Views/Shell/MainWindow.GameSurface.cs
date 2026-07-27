// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using SharpEmu.Libs.VideoOut;

namespace SharpEmu.GUI;

/// <summary>Native game surface presentation, launch transition and overlay bounds.</summary>
public partial class MainWindow
{
    private void WireGameSurface()
    {
        GameSurfaceContainer.Children.Add(_gameOverlay);
        _gameOverlay.ConsoleRequested += () =>
        {
            _gameOverlay.HideOverlay();
            ShowConsoleWindow();
        };
        _gameOverlay.ExitRequested += async () =>
        {
            await _gameOverlay.HideOverlayAsync(activateOwner: false);
            StopEmulator();
        };
        _gameOverlay.VisibilityChanged += visible =>
        {
            _gameSurfaceHost?.SetOverlayInputEnabled(visible);
            _gameSurfaceHost?.SetCursorAutoHide(!visible);
        };

        GameView.LayoutUpdated += (_, _) => QueueGameOverlayBoundsSync();
    }

    private void ApplyGameSurfaceLocalization()
    {
        LaunchLoadingLabel.Text = Localization.Instance.Get("Launch.Loading");
    }

    private void QueueGameSurfaceResize()
    {
        Dispatcher.UIThread.Post(
            () => _gameSurfaceHost?.RefreshSurfaceSize(),
            DispatcherPriority.Render);
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
        UpdateGameWindowFrame();
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
        QueueGameOverlayBoundsSync();
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
        host.ToggleOverlayRequested += (_, _) => ToggleGameOverlay();
        host.OverlayPointerInput += (_, pointer) =>
            _gameOverlay.HandlePointer(pointer.X, pointer.Y, pointer.Activate);
        host.OverlayKeyInput += (_, key) =>
        {
            switch (key)
            {
                case GameSurfaceOverlayKey.Left:
                    _gameOverlay.MoveFocus(-1);
                    break;
                case GameSurfaceOverlayKey.Right:
                    _gameOverlay.MoveFocus(1);
                    break;
                case GameSurfaceOverlayKey.Activate:
                    _gameOverlay.ActivateFocused();
                    break;
                case GameSurfaceOverlayKey.Cancel:
                    _gameOverlay.HideOverlay();
                    break;
            }
        };
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

    /// <summary>
    /// Keeps a small part of the frameless parent window outside the native
    /// child surface while a session is windowed. NativeControlHost children
    /// sit above Avalonia and would otherwise swallow both the title drag
    /// target and every resize handle. Fullscreen deliberately removes all
    /// insets so the presentation surface still covers the monitor.
    /// </summary>
    private void UpdateGameWindowFrame()
    {
        var useWindowFrame =
            _isRunning &&
            !_isStopping &&
            GameView.IsVisible &&
            !_gameFullscreen &&
            WindowState is not WindowState.FullScreen and not WindowState.Minimized;

        GameWindowDragRegion.IsVisible = useWindowFrame;
        GameView.Margin = useWindowFrame
            ? new Thickness(
                GameWindowResizeInset,
                GameWindowDragHeight,
                GameWindowResizeInset,
                GameWindowResizeInset)
            : new Thickness(0);
    }

    private void ShowGameView()
    {
        _isStopping = false;
        _awaitingFirstFrame = true;
        var host = EnsureGameSurfaceHost();
        GameWindowDragRegion.IsVisible = false;
        ParkGameViewOffscreen();
        GameView.IsVisible = true;
        GameView.Background = Brushes.Transparent;
        GameView.IsHitTestVisible = false;
        host.SetPresentationVisible(false);
        QueueGameOverlayBoundsSync();
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
        GameWindowDragRegion.IsVisible = false;
        _gameOverlay.HideOverlay(activateOwner: false);
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
        GameWindowDragRegion.IsVisible = false;
        _gameOverlay.HideOverlay(activateOwner: false);
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

    private void ToggleGameOverlay()
    {
        if (!_isRunning ||
            _isStopping ||
            _awaitingFirstFrame ||
            !GameView.IsVisible ||
            WindowState == WindowState.Minimized)
        {
            return;
        }

        _gameOverlay.Toggle(GameView);
    }

    private void QueueGameOverlayBoundsSync()
    {
        if (!_gameOverlay.IsOverlayVisible || _overlayBoundsSyncQueued)
        {
            return;
        }

        _overlayBoundsSyncQueued = true;
        Dispatcher.UIThread.Post(
            () => RequestAnimationFrame(_ =>
            {
                _overlayBoundsSyncQueued = false;
                if (_gameOverlay.IsOverlayVisible)
                {
                    _gameOverlay.SyncTo(GameView);
                }
            }),
            DispatcherPriority.Render);
    }
}
