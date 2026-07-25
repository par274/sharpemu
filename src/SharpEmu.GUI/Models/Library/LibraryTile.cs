// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI;

/// <summary>
/// Base type for the library carousel items. The grid shows real games
/// (<see cref="GameEntry"/>) plus action tiles such as <see cref="AddFolderTile"/>;
/// deriving both from this shared base lets a single <c>ListBox.ItemsSource</c>
/// hold them and lets Avalonia pick the matching <c>DataTemplate</c> by type.
/// </summary>
public abstract class LibraryTile
{
}
