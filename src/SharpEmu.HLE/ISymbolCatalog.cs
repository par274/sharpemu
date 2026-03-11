// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE;

public interface ISymbolCatalog
{
    bool TryGetByNid(string nid, out SysAbiSymbol symbol);

    bool TryGetByExportName(string exportName, out SysAbiSymbol symbol);
}
