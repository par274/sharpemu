// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.ComponentModel;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Threading;

namespace SharpEmu.GUI.Controls.Settings;

/// <summary>
/// Keeps Avalonia's native ComboBox interaction and accessibility behavior,
/// while leaving its popup alive briefly enough to render an exit transition.
/// </summary>
public sealed class AnimatedComboBox : ComboBox
{
    private const int CloseAnimationMilliseconds = 150;
    private const string PopupSurfaceClass = "animatedComboPopup";
    private const string PopupOpenClass = "open";

    private static readonly EventInfo? PopupClosingEvent =
        typeof(Popup).GetEvent("Closing", BindingFlags.Instance | BindingFlags.NonPublic);

    private readonly EventHandler<CancelEventArgs> _popupClosingHandler;
    private Popup? _popup;
    private Border? _popupSurface;
    private bool _allowPopupClose;
    private bool _isAnimatingClose;
    private int _animationGeneration;

    public AnimatedComboBox()
    {
        _popupClosingHandler = OnPopupClosing;
    }

    protected override Type StyleKeyOverride => typeof(ComboBox);

    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        DetachPopup();
        base.OnApplyTemplate(e);

        _popup = e.NameScope.Find<Popup>("PART_Popup");
        _popupSurface = e.NameScope.Find<Border>("PopupBorder");

        if (_popup is null || _popupSurface is null)
        {
            return;
        }

        _popup.VerticalOffset = 8;
        _popupSurface.Classes.Add(PopupSurfaceClass);
        _popup.Opened += OnPopupOpened;
        _popup.Closed += OnPopupClosed;
        ChangePopupClosingSubscription(_popup, add: true);
    }

    private void OnPopupOpened(object? sender, EventArgs e)
    {
        _animationGeneration++;
        _isAnimatingClose = false;
        _popupSurface?.Classes.Remove(PopupOpenClass);

        // The popup must be attached and rendered once at its initial state
        // before the open class is applied, otherwise there is no transition.
        var popup = _popup;
        var surface = _popupSurface;
        Dispatcher.UIThread.Post(
            () =>
            {
                if (popup == _popup && popup?.IsOpen == true && surface == _popupSurface)
                {
                    surface?.Classes.Add(PopupOpenClass);
                }
            },
            DispatcherPriority.Render);
    }

    private void OnPopupClosing(object? sender, CancelEventArgs e)
    {
        if (_allowPopupClose || sender is not Popup popup || _popupSurface is null)
        {
            return;
        }

        e.Cancel = true;
        _popupSurface.Classes.Remove(PopupOpenClass);

        if (_isAnimatingClose)
        {
            return;
        }

        _isAnimatingClose = true;
        var generation = ++_animationGeneration;

        DispatcherTimer.RunOnce(
            () =>
            {
                if (popup != _popup || generation != _animationGeneration)
                {
                    return;
                }

                _allowPopupClose = true;
                try
                {
                    popup.Close();
                }
                finally
                {
                    _allowPopupClose = false;
                    _isAnimatingClose = false;
                }
            },
            TimeSpan.FromMilliseconds(CloseAnimationMilliseconds));
    }

    private void OnPopupClosed(object? sender, EventArgs e)
    {
        _animationGeneration++;
        _isAnimatingClose = false;
        _popupSurface?.Classes.Remove(PopupOpenClass);
    }

    private void DetachPopup()
    {
        _animationGeneration++;
        _isAnimatingClose = false;

        if (_popup is not null)
        {
            _popup.Opened -= OnPopupOpened;
            _popup.Closed -= OnPopupClosed;
            ChangePopupClosingSubscription(_popup, add: false);
        }

        _popupSurface?.Classes.Remove(PopupOpenClass);
        _popup = null;
        _popupSurface = null;
    }

    private void ChangePopupClosingSubscription(Popup popup, bool add)
    {
        var accessor = add
            ? PopupClosingEvent?.GetAddMethod(nonPublic: true)
            : PopupClosingEvent?.GetRemoveMethod(nonPublic: true);

        accessor?.Invoke(popup, [_popupClosingHandler]);
    }
}
