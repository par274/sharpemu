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
        IReadOnlyList<ImportedSymbolRelocation>? importedRelocations = null,
        IReadOnlyList<ulong>? preInitializerFunctions = null,
        IReadOnlyList<ulong>? initializerFunctions = null,
        ulong initFunctionEntryPoint = 0,
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
        ImportedRelocations = importedRelocations ?? Array.Empty<ImportedSymbolRelocation>();
        PreInitializerFunctions = preInitializerFunctions ?? Array.Empty<ulong>();
        InitializerFunctions = initializerFunctions ?? Array.Empty<ulong>();
        InitFunctionEntryPoint = initFunctionEntryPoint;
        _imageBase = imageBase;
        ProcParamAddress = procParamAddress;
    }

    public bool IsSelf { get; }

    public ElfHeader ElfHeader { get; }

    public IReadOnlyList<ProgramHeader> ProgramHeaders { get; }

    public IReadOnlyList<VirtualMemoryRegion> MappedRegions { get; }

    public IReadOnlyDictionary<ulong, string> ImportStubs { get; }

    public IReadOnlyDictionary<string, ulong> RuntimeSymbols { get; }

    public IReadOnlyList<ImportedSymbolRelocation> ImportedRelocations { get; }

    public IReadOnlyList<ulong> PreInitializerFunctions { get; }

    public IReadOnlyList<ulong> InitializerFunctions { get; }

    public ulong InitFunctionEntryPoint { get; }

    public ulong EntryPoint => ElfHeader.EntryPoint + _imageBase;

    public ulong ProcParamAddress { get; }
}
