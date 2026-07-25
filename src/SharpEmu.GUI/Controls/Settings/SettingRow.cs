// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Primitives;
using Avalonia.Data;

namespace SharpEmu.GUI;

public sealed class SettingRow : ContentControl
{
    public static readonly StyledProperty<string?> LabelProperty =
        AvaloniaProperty.Register<SettingRow, string?>(nameof(Label));

    public static readonly StyledProperty<string?> DescriptionProperty =
        AvaloniaProperty.Register<SettingRow, string?>(nameof(Description));

    public static readonly StyledProperty<bool> ShowOverrideProperty =
        AvaloniaProperty.Register<SettingRow, bool>(nameof(ShowOverride));

    public static readonly StyledProperty<bool> IsOverriddenProperty =
        AvaloniaProperty.Register<SettingRow, bool>(
            nameof(IsOverridden), defaultBindingMode: BindingMode.TwoWay);

    public static readonly StyledProperty<string?> OverrideTextProperty =
        AvaloniaProperty.Register<SettingRow, string?>(
            nameof(OverrideText), "Override");

    private ContentPresenter? _slot;

    public string? Label
    {
        get => GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public string? Description
    {
        get => GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    public bool ShowOverride
    {
        get => GetValue(ShowOverrideProperty);
        set => SetValue(ShowOverrideProperty, value);
    }

    public bool IsOverridden
    {
        get => GetValue(IsOverriddenProperty);
        set => SetValue(IsOverriddenProperty, value);
    }

    public string? OverrideText
    {
        get => GetValue(OverrideTextProperty);
        set => SetValue(OverrideTextProperty, value);
    }

    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        base.OnApplyTemplate(e);
        _slot = e.NameScope.Find<ContentPresenter>("PART_Slot");
        UpdateSlotEnabled();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ShowOverrideProperty || change.Property == IsOverriddenProperty)
        {
            UpdateSlotEnabled();
        }
    }

    private void UpdateSlotEnabled()
    {
        if (_slot is not null)
        {
            _slot.IsEnabled = !ShowOverride || IsOverridden;
        }
    }
}
