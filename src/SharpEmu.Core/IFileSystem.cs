// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core;

public interface IFileSystem
{
    bool Exists(string path);

    bool TryReadAllBytes(string path, out byte[] data);
}
