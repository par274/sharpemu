// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;

namespace SharpEmu.Core.Loader;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct ElfHeader
{
    private readonly byte _ident0;
    private readonly byte _ident1;
    private readonly byte _ident2;
    private readonly byte _ident3;
    private readonly byte _ident4;
    private readonly byte _ident5;
    private readonly byte _ident6;
    private readonly byte _ident7;
    private readonly byte _ident8;
    private readonly byte _ident9;
    private readonly byte _ident10;
    private readonly byte _ident11;
    private readonly byte _ident12;
    private readonly byte _ident13;
    private readonly byte _ident14;
    private readonly byte _ident15;
    private readonly ushort _type;
    private readonly ushort _machine;
    private readonly uint _version;
    private readonly ulong _entryPoint;
    private readonly ulong _programHeaderOffset;
    private readonly ulong _sectionHeaderOffset;
    private readonly uint _flags;
    private readonly ushort _headerSize;
    private readonly ushort _programHeaderEntrySize;
    private readonly ushort _programHeaderCount;
    private readonly ushort _sectionHeaderEntrySize;
    private readonly ushort _sectionHeaderCount;
    private readonly ushort _sectionHeaderStringIndex;

    public bool HasElfMagic => _ident0 == 0x7F && _ident1 == (byte)'E' && _ident2 == (byte)'L' && _ident3 == (byte)'F';

    public bool Is64Bit => _ident4 == 2;

    public bool IsLittleEndian => _ident5 == 1;

    public byte Abi => _ident7;

    public byte AbiVersion => _ident8;

    public ushort Type => _type;

    public ushort Machine => _machine;

    public uint Version => _version;

    public ulong EntryPoint => _entryPoint;

    public ulong ProgramHeaderOffset => _programHeaderOffset;

    public ulong SectionHeaderOffset => _sectionHeaderOffset;

    public uint Flags => _flags;

    public ushort HeaderSize => _headerSize;

    public ushort ProgramHeaderEntrySize => _programHeaderEntrySize;

    public ushort ProgramHeaderCount => _programHeaderCount;

    public ushort SectionHeaderEntrySize => _sectionHeaderEntrySize;

    public ushort SectionHeaderCount => _sectionHeaderCount;

    public ushort SectionHeaderStringIndex => _sectionHeaderStringIndex;
}
