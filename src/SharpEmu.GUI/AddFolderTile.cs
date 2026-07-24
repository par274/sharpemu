// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI;

/// <summary>
/// Marker tile rendered as the trailing "add folder" card in the library
/// carousel. It carries no state of its own — its type is what selects the
/// dedicated <c>DataTemplate</c> and routes clicks to the folder picker.
/// </summary>
public sealed class AddFolderTile : LibraryTile
{
    /// <summary>Shared singleton; the carousel only ever needs one.</summary>
    public static AddFolderTile Instance { get; } = new();

    private AddFolderTile() { }
}
