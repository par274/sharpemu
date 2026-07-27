// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace SharpEmu.GUI;

/// <summary>Shell page activation and keyboard navigation.</summary>
public partial class MainWindow
{
    private void WireNavigation()
    {
        _main.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(ViewModels.MainViewModel.ActivePage))
            {
                OnActivePageChanged();
            }
        };

        AddHandler(KeyDownEvent, OnPreviewKeyDown, RoutingStrategies.Tunnel);
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

    private void OnKeyDown(object sender, KeyEventArgs args)
    {
        if (_isRunning &&
            args.Key == Key.Tab &&
            args.KeyModifiers.HasFlag(KeyModifiers.Shift))
        {
            ToggleGameOverlay();
            args.Handled = true;
            return;
        }

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
        if (_isRunning &&
            args.Key == Key.Tab &&
            args.KeyModifiers.HasFlag(KeyModifiers.Shift))
        {
            ToggleGameOverlay();
            args.Handled = true;
            return;
        }

        if (_gameOverlay.IsOverlayVisible)
        {
            switch (args.Key)
            {
                case Key.Left:
                    _gameOverlay.MoveFocus(-1);
                    args.Handled = true;
                    return;
                case Key.Right:
                    _gameOverlay.MoveFocus(1);
                    args.Handled = true;
                    return;
                case Key.Enter:
                case Key.Space:
                    _gameOverlay.ActivateFocused();
                    args.Handled = true;
                    return;
                case Key.Escape:
                    _gameOverlay.HideOverlay();
                    args.Handled = true;
                    return;
            }
        }

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
}
