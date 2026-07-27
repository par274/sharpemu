// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Rendering.Composition;
using Avalonia.Rendering.Composition.Animations;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace SharpEmu.GUI.Controls.Navigation;

/// <summary>
/// Layers a small, fixed set of pages in one visual tree and switches their
/// presentation using an Avalonia subtree-opacity gate plus independently
/// animated foreground layers.
/// </summary>
/// <remarks>
/// Pages stay attached for the lifetime of the host, but an inactive page is
/// collapsed after its cross-fade so it no longer participates in layout,
/// rendering or animation ticks. Only the selected page participates in hit
/// testing. Avalonia opacity is intentionally used for the complete subtree:
/// applying composition opacity only to the root proxy can leave independently
/// composed descendants visible on some render backends. Page roots never move
/// or scale; marked content layers provide the depth motion without shifting
/// the page coordinate system.
/// </remarks>
public sealed class PersistentPageHost : Panel
{
    private static readonly TimeSpan PageTransitionDuration =
        TimeSpan.FromMilliseconds(260);

    public static readonly StyledProperty<int> SelectedIndexProperty =
        AvaloniaProperty.Register<PersistentPageHost, int>(
            nameof(SelectedIndex),
            defaultValue: 0,
            coerce: (_, value) => Math.Max(0, value));

    public static readonly StyledProperty<Visual?> ParallaxTargetProperty =
        AvaloniaProperty.Register<PersistentPageHost, Visual?>(
            nameof(ParallaxTarget));

    private bool _compositionReady;
    private int _presentedIndex = -1;
    private int _pageStateGeneration;

    public PersistentPageHost()
    {
        ClipToBounds = true;
    }

    /// <summary>Zero-based index of the page that owns input and the foreground plane.</summary>
    public int SelectedIndex
    {
        get => GetValue(SelectedIndexProperty);
        set => SetValue(SelectedIndexProperty, value);
    }

    /// <summary>Optional persistent backdrop that moves on the slowest depth plane.</summary>
    public Visual? ParallaxTarget
    {
        get => GetValue(ParallaxTargetProperty);
        set => SetValue(ParallaxTargetProperty, value);
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        InitializeComposition();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _compositionReady = false;
        base.OnDetachedFromVisualTree(e);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (!_compositionReady)
        {
            return;
        }

        if (change.Property == SelectedIndexProperty)
        {
            ApplyPageState(animate: true);
            ApplyBackdropState(animate: true);
        }
        else if (change.Property == ParallaxTargetProperty)
        {
            InitializeBackdropComposition();
            ApplyBackdropState(animate: false);
            if (ParallaxTarget is { } backdrop &&
                ElementComposition.GetElementVisual(backdrop) is { } visual)
            {
                visual.ImplicitAnimations = CreateBackdropAnimations(visual);
            }
        }
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var arranged = base.ArrangeOverride(finalSize);

        if (ParallaxTarget is { } backdrop &&
            ElementComposition.GetElementVisual(backdrop) is { } backdropVisual)
        {
            backdropVisual.CenterPoint = new(
                backdrop.Bounds.Width / 2,
                backdrop.Bounds.Height / 2,
                0);
        }

        return arranged;
    }

    private void InitializeComposition()
    {
        _compositionReady = false;

        foreach (var child in Children)
        {
            child.IsVisible = true;
            child.Transitions = null;
            if (ElementComposition.GetElementVisual(child) is not { } visual)
            {
                continue;
            }

            visual.ImplicitAnimations = null;
            // Opacity belongs to the Avalonia visual, not its composition
            // proxy. This guarantees that every descendant surface is gated
            // together (including scroll viewers and text editors).
            visual.Opacity = 1;
            // Page roots stay pinned to the exact arranged rectangle. Moving or
            // scaling this proxy produces a one-frame diagonal jump when a
            // descendant gets its own composition surface.
            visual.Scale = new(1, 1, 1);
            visual.Translation = default;
        }

        InitializeBackdropComposition();
        ApplyPageState(animate: false);
        ApplyBackdropState(animate: false);

        foreach (var child in Children)
        {
            child.Transitions = CreatePageTransitions();
        }

        if (ParallaxTarget is { } backdrop &&
            ElementComposition.GetElementVisual(backdrop) is { } backdropVisual)
        {
            backdropVisual.ImplicitAnimations = CreateBackdropAnimations(backdropVisual);
        }

        _compositionReady = true;
    }

    private void InitializeBackdropComposition()
    {
        if (ParallaxTarget is { } backdrop &&
            ElementComposition.GetElementVisual(backdrop) is { } visual)
        {
            visual.ImplicitAnimations = null;
        }
    }

    private void ApplyPageState(bool animate)
    {
        if (Children.Count == 0)
        {
            return;
        }

        var selected = Math.Clamp(SelectedIndex, 0, Children.Count - 1);
        var outgoing = animate ? _presentedIndex : -1;
        var generation = ++_pageStateGeneration;
        for (var index = 0; index < Children.Count; index++)
        {
            var child = Children[index];
            var isActive = index == selected;
            var isOutgoing = index == outgoing && outgoing != selected;

            child.IsVisible = isActive || isOutgoing;
            child.IsHitTestVisible = isActive;
            child.Focusable = isActive;
            KeyboardNavigation.SetTabNavigation(
                child,
                isActive ? KeyboardNavigationMode.Continue : KeyboardNavigationMode.None);
            child.ZIndex = isActive ? 2 : index == selected - 1 ? 1 : 0;
            child.Opacity = isActive ? 1 : 0;
            ApplyMotionLayerState(child, index, selected);
        }

        _presentedIndex = selected;
        if (outgoing < 0 || outgoing == selected)
        {
            return;
        }

        DispatcherTimer.RunOnce(
            () =>
            {
                if (generation != _pageStateGeneration ||
                    outgoing == _presentedIndex ||
                    outgoing >= Children.Count)
                {
                    return;
                }

                Children[outgoing].IsVisible = false;
            },
            PageTransitionDuration);
    }

    private static void ApplyMotionLayerState(Control page, int pageIndex, int selectedIndex)
    {
        foreach (var layer in page.GetVisualDescendants()
                     .OfType<Control>()
                     .Where(IsMotionLayer))
        {
            SetClass(layer, "pageBefore", pageIndex < selectedIndex);
            SetClass(layer, "pageAfter", pageIndex > selectedIndex);
        }
    }

    private static bool IsMotionLayer(Control control) =>
        control.Classes.Contains("pageMotionLead") ||
        control.Classes.Contains("pageMotionBody");

    private static void SetClass(Control control, string className, bool enabled)
    {
        if (enabled)
        {
            if (!control.Classes.Contains(className))
            {
                control.Classes.Add(className);
            }

            return;
        }

        control.Classes.Remove(className);
    }

    private void ApplyBackdropState(bool animate)
    {
        if (ParallaxTarget is not { } backdrop ||
            ElementComposition.GetElementVisual(backdrop) is not { } visual)
        {
            return;
        }

        if (!animate)
        {
            visual.ImplicitAnimations = null;
        }

        var index = Math.Clamp(SelectedIndex, 0, Math.Max(0, Children.Count - 1));
        visual.Opacity = 1;
        visual.Scale = index switch
        {
            0 => new(1.018, 1.018, 1),
            1 => new(1.028, 1.028, 1),
            _ => new(1.022, 1.022, 1),
        };
        visual.Translation = index switch
        {
            0 => new(-8, 0, 0),
            1 => new(0, -3, 0),
            _ => new(9, -1, 0),
        };
    }

    private static Transitions CreatePageTransitions()
    {
        return
        [
            new DoubleTransition
            {
                Property = OpacityProperty,
                Duration = PageTransitionDuration,
                Easing = new CubicEaseOut(),
            },
        ];
    }

    private static ImplicitAnimationCollection CreateBackdropAnimations(CompositionVisual visual)
    {
        var compositor = visual.Compositor;
        var animations = compositor.CreateImplicitAnimationCollection();

        var scale = compositor.CreateVector3KeyFrameAnimation();
        scale.Target = "Scale";
        scale.Duration = TimeSpan.FromMilliseconds(560);
        scale.InsertExpressionKeyFrame(1, "this.FinalValue", new SineEaseInOut());
        animations["Scale"] = scale;

        var translation = compositor.CreateVector3KeyFrameAnimation();
        translation.Target = "Translation";
        translation.Duration = TimeSpan.FromMilliseconds(560);
        translation.InsertExpressionKeyFrame(1, "this.FinalValue", new SineEaseInOut());
        animations["Translation"] = translation;

        return animations;
    }
}
