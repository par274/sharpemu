// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE;

public sealed class ExportedFunction
{
    public ExportedFunction(string libraryName, string nid, string name, Generation target, SysAbiFunction function)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryName);
        ArgumentException.ThrowIfNullOrWhiteSpace(nid);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(function);

        LibraryName = libraryName;
        Nid = nid;
        Name = name;
        Target = target;
        Function = function;
    }

    public string LibraryName { get; }

    public string Nid { get; }

    public string Name { get; }

    public Generation Target { get; }

    public SysAbiFunction Function { get; }
}
