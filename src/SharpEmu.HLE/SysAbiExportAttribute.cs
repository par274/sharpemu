// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE;

[AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
public sealed class SysAbiExportAttribute : Attribute
{
    public string LibraryName { get; set; } = "libKernel";

    public string Nid { get; set; } = string.Empty;

    public string ExportName { get; set; } = string.Empty;

    public Generation Target { get; set; } = Generation.None;
}
