// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.GUI.ViewModels;

namespace SharpEmu.GUI;

/// <summary>
/// Persistent owned window rendered above the native game child. It is never
/// topmost at desktop level: ownership keeps it above MainWindow while normal
/// window-manager z-order lets every other application cover both together.
/// </summary>
public partial class GameOverlayWindow : Window
{
    private const int ExitAnimationMilliseconds = 240;

    private readonly GameOverlayViewModel _viewModel;
    private readonly DispatcherTimer _clockTimer;
    private bool _shownOnce;
    private bool _isPresented;
    private int _presentationGeneration;
    private int _focusedAction;

    public GameOverlayWindow()
        : this(GuiLauncher.Services.GetRequiredService<GameOverlayViewModel>())
    {
    }

    public GameOverlayWindow(GameOverlayViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;

        _clockTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _clockTimer.Tick += (_, _) => _viewModel.Refresh(DateTimeOffset.Now);

        ConsoleButton.Click += (_, _) => ConsoleRequested?.Invoke();
        ExitButton.Click += (_, _) => ExitRequested?.Invoke();
        AddHandler(KeyDownEvent, OnOverlayKeyDown, RoutingStrategies.Tunnel);
        Deactivated += (_, _) =>
        {
            Dispatcher.UIThread.Post(() =>
            {
                if (_isPresented && !IsActive && Owner?.IsActive != true)
                {
                    HideOverlay(activateOwner: false);
                }
            });
        };
    }

    public event Action? ConsoleRequested;

    public event Action? ExitRequested;

    public bool IsOverlayVisible => _isPresented;

    public void ShowOverlay(Window owner, Control gameView)
    {
        var generation = ++_presentationGeneration;
        SyncTo(gameView);
        _viewModel.UpdateLocalization();
        _viewModel.Refresh(DateTimeOffset.Now);

        OverlayRoot.Classes.Set("visible", false);
        if (!IsVisible)
        {
            if (_shownOnce)
            {
                Show();
            }
            else
            {
                _shownOnce = true;
                Show(owner);
            }
        }

        _isPresented = true;
        _clockTimer.Start();
        Activate();
        FocusAction(0);
        RequestAnimationFrame(_ =>
        {
            // A second render callback guarantees that the transparent initial
            // state reached the compositor before the cubic fade starts.
            RequestAnimationFrame(_ =>
            {
                if (generation == _presentationGeneration && _isPresented)
                {
                    OverlayRoot.Classes.Set("visible", true);
                }
            });
        });
    }

    public void HideOverlay(bool activateOwner = true)
    {
        _ = HideOverlayAsync(activateOwner);
    }

    public async Task HideOverlayAsync(bool activateOwner = true)
    {
        if (!_isPresented)
        {
            return;
        }

        var generation = ++_presentationGeneration;
        _isPresented = false;
        _clockTimer.Stop();
        OverlayRoot.Classes.Set("visible", false);
        await HideAfterAnimationAsync(generation, activateOwner);
    }

    public void Toggle(Window owner, Control gameView)
    {
        if (_isPresented)
        {
            HideOverlay();
        }
        else
        {
            ShowOverlay(owner, gameView);
        }
    }

    public void SyncTo(Control gameView)
    {
        if (!gameView.IsVisible || gameView.Bounds.Width <= 0 || gameView.Bounds.Height <= 0)
        {
            return;
        }

        Position = gameView.PointToScreen(default);
        Width = gameView.Bounds.Width;
        Height = gameView.Bounds.Height;
    }

    public void MoveFocus(int direction)
    {
        FocusAction(Math.Clamp(_focusedAction + Math.Sign(direction), 0, 1));
    }

    public void ActivateFocused()
    {
        if (_focusedAction == 0)
        {
            ConsoleRequested?.Invoke();
        }
        else if (_viewModel.CanExit)
        {
            ExitRequested?.Invoke();
        }
    }

    private void FocusAction(int index)
    {
        _focusedAction = Math.Clamp(index, 0, 1);
        (_focusedAction == 0 ? ConsoleButton : ExitButton).Focus();
    }

    private void OnOverlayKeyDown(object? sender, KeyEventArgs args)
    {
        if (args.Key == Key.Tab &&
            args.KeyModifiers.HasFlag(KeyModifiers.Shift))
        {
            HideOverlay();
            args.Handled = true;
            return;
        }

        if (args.Key is Key.Left or Key.Right)
        {
            MoveFocus(args.Key == Key.Left ? -1 : 1);
            args.Handled = true;
        }
    }

    private async Task HideAfterAnimationAsync(int generation, bool activateOwner)
    {
        await Task.Delay(ExitAnimationMilliseconds);
        if (generation != _presentationGeneration || _isPresented)
        {
            return;
        }

        Hide();
        if (activateOwner)
        {
            Owner?.Activate();
        }
    }
}
