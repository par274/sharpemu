// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Skia.Helpers;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.GUI.ViewModels;
using SharpEmu.Libs.VideoOut;
using SkiaSharp;

namespace SharpEmu.GUI;

/// <summary>
/// Avalonia scene rendered into a shared premultiplied-BGRA surface. The
/// isolated emulator process samples that surface in its final Vulkan pass,
/// so the overlay is part of the game frame rather than another desktop
/// window.
/// </summary>
public partial class GameOverlayView : UserControl, IDisposable
{
    private static readonly TimeSpan EnterAnimationDuration =
        TimeSpan.FromMilliseconds(220);
    private static readonly TimeSpan ExitAnimationDuration =
        TimeSpan.FromMilliseconds(220);

    private const double BottomMargin = 28;
    private const double BottomRowHeight = 64;
    private const double ActionHeight = 38;
    private const double RightMargin = 34;
    private const double LogoWidth = 54;
    private const double ActionLogoSpacing = 10;
    private const double ActionWidth = 108;
    private const int ActionCount = 2;

    private readonly GameOverlayViewModel _viewModel;
    private readonly DispatcherTimer _clockTimer;
    private readonly VulkanOverlayFrameWriter _frameWriter = new();
    private bool _isPresented;
    private bool _isHiding;
    private bool _disposed;
    private int _focusedAction;
    private int _hoveredAction = -1;
    private bool _pointerNavigationActive;
    private int _presentationGeneration;
    private int _renderGeneration;
    private TaskCompletionSource<bool>? _hideCompletion;
    private int _surfacePixelWidth;
    private int _surfacePixelHeight;
    private int _framePixelWidth;
    private int _framePixelHeight;
    private double _renderScaling = 1;
    private double _drawingScale = 1;
    private double _overlayOpacity = 1;
    private SKBitmap? _renderBitmap;
    private SKCanvas? _renderCanvas;

    public GameOverlayView()
        : this(GuiLauncher.Services.GetRequiredService<GameOverlayViewModel>())
    {
    }

    public GameOverlayView(GameOverlayViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        IsVisible = false;

        _clockTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _clockTimer.Tick += (_, _) =>
        {
            var previousTime = _viewModel.CurrentTime;
            var previousSessionDuration = _viewModel.SessionDuration;
            var previousRecentDuration = _viewModel.RecentDuration;
            var previousCanExit = _viewModel.CanExit;
            _viewModel.Refresh(DateTimeOffset.Now);
            if (previousTime != _viewModel.CurrentTime ||
                previousSessionDuration != _viewModel.SessionDuration ||
                previousRecentDuration != _viewModel.RecentDuration ||
                previousCanExit != _viewModel.CanExit)
            {
                QueueRender();
            }
        };
    }

    public event Action? ConsoleRequested;

    public event Action? ExitRequested;

    public event Action<bool>? VisibilityChanged;

    public bool IsOverlayVisible => _isPresented;

    public string FrameDescriptor => _frameWriter.Descriptor;

    public void ShowOverlay(Control gameView)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var wasPresented = _isPresented;
        var generation = Interlocked.Increment(ref _presentationGeneration);
        _hideCompletion?.TrySetResult(false);
        _hideCompletion = null;
        _isHiding = false;
        _viewModel.UpdateLocalization();
        _viewModel.Refresh(DateTimeOffset.Now);
        if (!wasPresented)
        {
            _overlayOpacity = 0;
            _frameWriter.SetOpacity(0);
        }

        IsVisible = true;
        _isPresented = true;
        _clockTimer.Start();
        FocusAction(0);
        SyncTo(gameView);
        QueueRender();
        if (!wasPresented)
        {
            VisibilityChanged?.Invoke(true);
        }

        _ = AnimateShowAsync(generation);
    }

    public void HideOverlay(bool activateOwner = true)
    {
        _ = HideOverlayAsync(activateOwner);
    }

    public Task HideOverlayAsync(bool activateOwner = true)
    {
        _ = activateOwner;
        if (!_isPresented)
        {
            return Task.CompletedTask;
        }

        if (_isHiding)
        {
            return _hideCompletion?.Task ?? Task.CompletedTask;
        }

        _isHiding = true;
        _clockTimer.Stop();
        var generation = Interlocked.Increment(ref _presentationGeneration);
        var completion = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _hideCompletion = completion;
        _ = AnimateHideAsync(generation, completion);
        return completion.Task;
    }

    public void Toggle(Control gameView)
    {
        if (_isPresented && !_isHiding)
        {
            HideOverlay();
        }
        else
        {
            ShowOverlay(gameView);
        }
    }

    public void SyncTo(Control gameView)
    {
        if (!gameView.IsVisible ||
            gameView.Bounds.Width <= 0 ||
            gameView.Bounds.Height <= 0)
        {
            return;
        }

        var renderScaling = TopLevel.GetTopLevel(gameView)?.RenderScaling ?? 1;
        var surfacePixelWidth = Math.Max(
            1,
            (int)Math.Round(gameView.Bounds.Width * renderScaling));
        var surfacePixelHeight = Math.Max(
            1,
            (int)Math.Round(gameView.Bounds.Height * renderScaling));

        var (framePixelWidth, framePixelHeight) =
            VulkanOverlayFrameWriter.GetFrameSize(
                surfacePixelWidth,
                surfacePixelHeight);
        var frameScale = Math.Min(
            framePixelWidth / (double)surfacePixelWidth,
            framePixelHeight / (double)surfacePixelHeight);
        var drawingScale = renderScaling * frameScale;
        var changed =
            _surfacePixelWidth != surfacePixelWidth ||
            _surfacePixelHeight != surfacePixelHeight ||
            _framePixelWidth != framePixelWidth ||
            _framePixelHeight != framePixelHeight ||
            Math.Abs(_drawingScale - drawingScale) > double.Epsilon;

        _renderScaling = renderScaling;
        _surfacePixelWidth = surfacePixelWidth;
        _surfacePixelHeight = surfacePixelHeight;
        _framePixelWidth = framePixelWidth;
        _framePixelHeight = framePixelHeight;
        _drawingScale = drawingScale;

        if (_isPresented && changed)
        {
            QueueRender();
        }
    }

    public void MoveFocus(int direction)
    {
        FocusAction(Math.Clamp(
            _focusedAction + Math.Sign(direction),
            0,
            ActionCount - 1));
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

    /// <summary>
    /// Handles a pointer expressed in native child-surface pixels. The final
    /// Vulkan pass scales the shared frame to that surface, so hit testing is
    /// performed in the original Avalonia logical coordinate space.
    /// </summary>
    public bool HandlePointer(int x, int y, bool activate)
    {
        if (!_isPresented ||
            _surfacePixelWidth <= 0 ||
            _surfacePixelHeight <= 0)
        {
            return false;
        }

        var logicalX = x / _renderScaling;
        var logicalY = y / _renderScaling;
        var logicalWidth = _surfacePixelWidth / _renderScaling;
        var logicalHeight = _surfacePixelHeight / _renderScaling;
        var actionsLeft =
            logicalWidth -
            RightMargin -
            LogoWidth -
            ActionLogoSpacing -
            (ActionWidth * ActionCount);
        var actionsTop =
            logicalHeight -
            BottomMargin -
            ((BottomRowHeight + ActionHeight) / 2);

        if (logicalY < actionsTop ||
            logicalY > actionsTop + ActionHeight ||
            logicalX < actionsLeft ||
            logicalX > actionsLeft + (ActionWidth * ActionCount))
        {
            HoverAction(-1);
            return true;
        }

        var action = Math.Clamp(
            (int)((logicalX - actionsLeft) / ActionWidth),
            0,
            ActionCount - 1);
        HoverAction(action);
        if (activate)
        {
            ActivateFocused();
        }

        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _isPresented = false;
        _isHiding = false;
        Interlocked.Increment(ref _presentationGeneration);
        Interlocked.Increment(ref _renderGeneration);
        _hideCompletion?.TrySetResult(false);
        _hideCompletion = null;
        _clockTimer.Stop();
        _renderCanvas?.Dispose();
        _renderCanvas = null;
        _renderBitmap?.Dispose();
        _renderBitmap = null;
        _frameWriter.Dispose();
    }

    private async Task AnimateShowAsync(int generation)
    {
        await AnimateOpacityAsync(
            generation,
            1,
            EnterAnimationDuration,
            easeInOut: false);
    }

    private async Task AnimateHideAsync(
        int generation,
        TaskCompletionSource<bool> completion)
    {
        await AnimateOpacityAsync(
            generation,
            0,
            ExitAnimationDuration,
            easeInOut: true);
        if (!IsPresentationCurrent(generation))
        {
            completion.TrySetResult(false);
            return;
        }

        _isPresented = false;
        _isHiding = false;
        IsVisible = false;
        Interlocked.Increment(ref _renderGeneration);
        _frameWriter.SetVisible(false);
        VisibilityChanged?.Invoke(false);
        _hideCompletion = null;
        completion.TrySetResult(true);
    }

    private async Task AnimateOpacityAsync(
        int generation,
        double targetOpacity,
        TimeSpan duration,
        bool easeInOut)
    {
        var startOpacity = _overlayOpacity;
        var startedAt = System.Diagnostics.Stopwatch.GetTimestamp();
        double progress;
        do
        {
            await WaitForAnimationFrameAsync();
            if (!IsPresentationCurrent(generation))
            {
                return;
            }

            progress = Math.Clamp(
                System.Diagnostics.Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds /
                duration.TotalMilliseconds,
                0,
                1);
            var easedProgress = easeInOut
                ? EaseInOutCubic(progress)
                : EaseOutCubic(progress);
            _overlayOpacity =
                startOpacity +
                ((targetOpacity - startOpacity) * easedProgress);
            _frameWriter.SetOpacity((float)_overlayOpacity);
        }
        while (progress < 1);

        _overlayOpacity = targetOpacity;
        _frameWriter.SetOpacity((float)targetOpacity);
    }

    private Task WaitForAnimationFrameAsync()
    {
        var completion = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (TopLevel.GetTopLevel(this) is { } topLevel)
        {
            topLevel.RequestAnimationFrame(_ => completion.TrySetResult(true));
        }
        else
        {
            Dispatcher.UIThread.Post(
                () => completion.TrySetResult(true),
                DispatcherPriority.Render);
        }

        return completion.Task;
    }

    private bool IsPresentationCurrent(int generation) =>
        !_disposed &&
        _isPresented &&
        generation == _presentationGeneration;

    private static double EaseOutCubic(double progress) =>
        1 - Math.Pow(1 - progress, 3);

    private static double EaseInOutCubic(double progress) =>
        progress < 0.5
            ? 4 * progress * progress * progress
            : 1 - (Math.Pow((-2 * progress) + 2, 3) / 2);

    private void FocusAction(int index)
    {
        var next = Math.Clamp(index, 0, ActionCount - 1);
        var changed =
            next != _focusedAction ||
            _pointerNavigationActive ||
            _hoveredAction != -1;
        _focusedAction = next;
        _pointerNavigationActive = false;
        _hoveredAction = -1;
        UpdateActionClasses();
        if (changed && _isPresented)
        {
            QueueRender();
        }
    }

    private void HoverAction(int index)
    {
        var next = Math.Clamp(index, -1, ActionCount - 1);
        var changed =
            !_pointerNavigationActive ||
            next != _hoveredAction;
        _pointerNavigationActive = true;
        _hoveredAction = next;
        if (next >= 0)
        {
            _focusedAction = next;
        }

        UpdateActionClasses();
        if (changed && _isPresented)
        {
            QueueRender();
        }
    }

    private void UpdateActionClasses()
    {
        ConsoleButton.Classes.Set(
            "selected",
            !_pointerNavigationActive && _focusedAction == 0);
        ExitButton.Classes.Set(
            "selected",
            !_pointerNavigationActive && _focusedAction == 1);
        ConsoleButton.Classes.Set(
            "hovered",
            _pointerNavigationActive && _hoveredAction == 0);
        ExitButton.Classes.Set(
            "hovered",
            _pointerNavigationActive && _hoveredAction == 1);
    }

    private void QueueRender()
    {
        if (!_isPresented ||
            _framePixelWidth <= 0 ||
            _framePixelHeight <= 0)
        {
            return;
        }

        var generation = Interlocked.Increment(ref _renderGeneration);
        Dispatcher.UIThread.Post(
            () => _ = RenderFrameAsync(generation),
            DispatcherPriority.Render);
    }

    private async Task RenderFrameAsync(int generation)
    {
        if (!_isPresented ||
            generation != _renderGeneration ||
            _framePixelWidth <= 0 ||
            _framePixelHeight <= 0)
        {
            return;
        }

        var logicalSize = new Size(
            _framePixelWidth / _drawingScale,
            _framePixelHeight / _drawingScale);
        Width = logicalSize.Width;
        Height = logicalSize.Height;
        Measure(logicalSize);
        Arrange(new Rect(logicalSize));

        using var recorder = new SKPictureRecorder();
        var recordingCanvas = recorder.BeginRecording(new SKRect(
            0,
            0,
            (float)logicalSize.Width,
            (float)logicalSize.Height));
        await DrawingContextHelper.RenderAsync(
            recordingCanvas,
            this,
            new Rect(logicalSize),
            new Vector(96, 96));
        using var picture = recorder.EndRecording();

        EnsureRenderTarget();
        var bitmap = _renderBitmap!;
        var canvas = _renderCanvas!;
        canvas.Clear(SKColors.Transparent);
        canvas.Save();
        canvas.Scale(
            _framePixelWidth / (float)logicalSize.Width,
            _framePixelHeight / (float)logicalSize.Height);
        canvas.DrawPicture(picture);
        canvas.Restore();
        canvas.Flush();

        if (!_isPresented || generation != _renderGeneration)
        {
            return;
        }

        _frameWriter.PublishFrame(
            bitmap.GetPixels(),
            bitmap.Width,
            bitmap.Height,
            bitmap.RowBytes);
    }

    private void EnsureRenderTarget()
    {
        if (_renderBitmap is not null &&
            _renderBitmap.Width == _framePixelWidth &&
            _renderBitmap.Height == _framePixelHeight)
        {
            return;
        }

        _renderCanvas?.Dispose();
        _renderBitmap?.Dispose();
        _renderBitmap = new SKBitmap(new SKImageInfo(
            _framePixelWidth,
            _framePixelHeight,
            SKColorType.Bgra8888,
            SKAlphaType.Premul));
        _renderCanvas = new SKCanvas(_renderBitmap);
    }
}
