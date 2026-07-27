// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpEmu.HLE.Host.Windows;

namespace SharpEmu.GUI;

/// <summary>Controller navigation: tile movement, option focus and activation.</summary>
public partial class MainWindow
{
    // ---- Controller navigation ----

    private void WireGamepad()
    {
        // Translate gamepad navigation intents into UI actions.
        _gamepad.PageRequested += page => Dispatcher.UIThread.Post(() => SetActivePage(page));
        _gamepad.MoveHorizontal += delta => Dispatcher.UIThread.Post(() => HandleGamepadHorizontal(delta));
        _gamepad.MoveVertical += direction => Dispatcher.UIThread.Post(() => HandleGamepadVertical(direction));
        _gamepad.Activate += () => Dispatcher.UIThread.Post(HandleGamepadActivate);
        _gamepad.Cancel += () => Dispatcher.UIThread.Post(() => _gameOverlay.HideOverlay());
        _gamepad.ToggleOverlay += () => Dispatcher.UIThread.Post(ToggleGameOverlay);

        WindowsDualSenseReader.EnsureStarted();
        WindowsXInputReader.EnsureStarted();
        _gamepadTimer.Tick += (_, _) => PollGamepad();
        _gamepadTimer.Start();
    }

    private void PollGamepad()
    {
        // The gamepad service polls the controller and raises navigation
        // intents; the window only feeds it the current UI context. Intents
        // are marshalled to the UI thread via the event subscriptions set up
        // in the constructor.
        _gamepad.Poll(
            IsActive,
            _isRunning || _isStopping,
            _gameOverlay.IsOverlayVisible,
            _main.ActivePageIndex);
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
        if (_gameOverlay.IsOverlayVisible)
        {
            _gameOverlay.MoveFocus(direction);
            return;
        }

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
        if (_gameOverlay.IsOverlayVisible)
        {
            _gameOverlay.MoveFocus(direction);
            return;
        }

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
        if (_gameOverlay.IsOverlayVisible)
        {
            _gameOverlay.ActivateFocused();
            return;
        }

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
}
