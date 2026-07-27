// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;

namespace SharpEmu.GUI;

/// <summary>Frameless window chrome: full screen, drag, resize and background polling.</summary>
public partial class MainWindow
{
    private void WireChrome()
    {
        TitleBar.PointerPressed += OnTitleBarPointerPressed;

        MinimizeButton.Click += (_, _) => WindowState = WindowState.Minimized;
        MaximizeButton.Click += (_, _) =>
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        CloseButton.Click += (_, _) => Close();

        // Avalonia has no dedicated state-changed event; minimize/restore is
        // observed via Resized, which the game surface also needs for overlay
        // bounds, so both reactions share this one subscription.
        PositionChanged += (_, _) => QueueGameOverlayBoundsSync();
        Resized += (_, _) =>
        {
            QueueGameOverlayBoundsSync();
            UpdateBackgroundPollingForState();
        };

        // The gamepad poll (50 ms) and console flush (80 ms) timers only matter
        // while the window is foreground and interactive. Suspending them while
        // minimized or unfocused removes two always-on dispatcher pulses that
        // otherwise keep the UI thread busy for the entire window lifetime.
        Activated += (_, _) => ResumeBackgroundPolling();
        Deactivated += (_, _) => SuspendBackgroundPolling();
    }

    private void ApplyChromeLocalization()
    {
        var loc = Localization.Instance;

        LibraryTabButton.Content = loc.Get("Page.Library");
        OptionsTabButton.Content = loc.Get("Page.Options");
        ConsoleTabButton.Content = loc.Get("Page.Console");
        SearchBox.PlaceholderText = loc.Get("Library.SearchWatermark");
    }

    private void OnWindowFullScreen(object sender, RoutedEventArgs args)
    {
        _gameOverlay.HideOverlay(activateOwner: false);

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
                UpdateGameWindowFrame();
                QueueGameSurfaceResize();
                QueueGameOverlayBoundsSync();
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
                UpdateGameWindowFrame();
                QueueGameSurfaceResize();
                QueueGameOverlayBoundsSync();
            }
        }
    }

    private void SuspendBackgroundPolling()
    {
        if (_isClosing)
        {
            return;
        }

        _gamepadTimer.Stop();
        _consoleFlushTimer.Stop();
    }

    private void ResumeBackgroundPolling()
    {
        if (_isClosing)
        {
            return;
        }

        if (!_gamepadTimer.IsEnabled)
        {
            _gamepadTimer.Start();
        }

        if (!_consoleFlushTimer.IsEnabled)
        {
            _consoleFlushTimer.Start();
        }
    }

    private void UpdateBackgroundPollingForState()
    {
        if (_isClosing)
        {
            return;
        }

        // A minimized window is neither interactive nor painted, so the polling
        // timers are pure overhead there. Restore re-enables them via the
        // Activated handler when the window regains the foreground.
        if (WindowState == WindowState.Minimized)
        {
            SuspendBackgroundPolling();
        }
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
}
