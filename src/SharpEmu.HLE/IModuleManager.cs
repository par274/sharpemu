// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;

namespace SharpEmu.HLE;

public interface IModuleManager
{
    int RegisterFromAssembly(Assembly assembly, Generation generation, ISymbolCatalog? symbolCatalog = null);

    void Freeze();

    bool TryGetFunction(string nid, out Delegate function);

    bool TryGetExport(string nid, out ExportedFunction export);

    bool TryGetExportByName(string exportName, out ExportedFunction export);

    bool TryDispatch(string nid, CpuContext context, out OrbisGen2Result result);

    OrbisGen2Result Dispatch(string nid, CpuContext context);
}
