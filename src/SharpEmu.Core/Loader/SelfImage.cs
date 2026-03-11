// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Memory;

namespace SharpEmu.Core.Loader;

public sealed class SelfImage
{
    private readonly ulong _imageBase;

    public SelfImage(
        bool isSelf,
        ElfHeader elfHeader,
        IReadOnlyList<ProgramHeader> programHeaders,
        IReadOnlyList<VirtualMemoryRegion> mappedRegions,
        IReadOnlyDictionary<ulong, string>? importStubs = null,
        IReadOnlyDictionary<string, ulong>? runtimeSymbols = null,
        ulong imageBase = 0,
        ulong procParamAddress = 0)
    {
        ArgumentNullException.ThrowIfNull(programHeaders);
        ArgumentNullException.ThrowIfNull(mappedRegions);

        IsSelf = isSelf;
        ElfHeader = elfHeader;
        ProgramHeaders = programHeaders;
        MappedRegions = mappedRegions;
        ImportStubs = importStubs ?? new Dictionary<ulong, string>();
        RuntimeSymbols = runtimeSymbols ?? new Dictionary<string, ulong>(StringComparer.Ordinal);
        _imageBase = imageBase;
        ProcParamAddress = procParamAddress;
    }

    public bool IsSelf { get; }

    public ElfHeader ElfHeader { get; }

    public IReadOnlyList<ProgramHeader> ProgramHeaders { get; }

    public IReadOnlyList<VirtualMemoryRegion> MappedRegions { get; }

    public IReadOnlyDictionary<ulong, string> ImportStubs { get; }

    public IReadOnlyDictionary<string, ulong> RuntimeSymbols { get; }

    public ulong EntryPoint => ElfHeader.EntryPoint + _imageBase;

    public ulong ProcParamAddress { get; }
}
