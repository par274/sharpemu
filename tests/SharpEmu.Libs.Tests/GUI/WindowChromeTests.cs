// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using SharpEmu.GUI;
using Xunit;

namespace SharpEmu.Libs.Tests.GUI;

public sealed class WindowChromeTests
{
    [Theory]
    [InlineData(WindowState.Normal, "crop_square", "Maximize", "Maximize window")]
    [InlineData(WindowState.Maximized, "filter_none", "Restore", "Restore window")]
    public void GetMaximizeButtonState_ReturnsConsistentVisualAndAccessibleState(
        WindowState windowState,
        string expectedGlyph,
        string expectedToolTip,
        string expectedAutomationName)
    {
        var state = MainWindow.GetMaximizeButtonState(windowState);

        Assert.Equal(expectedGlyph, state.Glyph);
        Assert.Equal(expectedToolTip, state.ToolTip);
        Assert.Equal(expectedAutomationName, state.AutomationName);
    }
}
