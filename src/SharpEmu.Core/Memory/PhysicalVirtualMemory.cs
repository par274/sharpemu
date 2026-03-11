// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;
using SharpEmu.Core.Loader;
using SharpEmu.HLE;

namespace SharpEmu.Core.Memory;

public sealed unsafe class PhysicalVirtualMemory : IVirtualMemory, IDisposable
{
    private readonly object _gate = new();
    private readonly List<MemoryRegion> _regions = new();
    private bool _disposed;
    private const ulong PageSize = 0x1000;
    private const ulong LargeDataReserveThreshold = 0x4000_0000UL; // 1 GiB
    private const ulong LazyReservePrimeBytes = 0x5000_0000UL; // 1.25 GiB
    private const ulong LazyReservePrimeChunkBytes = 0x0200_0000UL; // 32 MiB

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void* VirtualAlloc(void* lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFree(void* lpAddress, nuint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtect(void* lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern void FlushInstructionCache(void* hProcess, void* lpBaseAddress, nuint dwSize);

    public bool TryAllocateAtExact(ulong desiredAddress, ulong size, bool executable, out ulong actualAddress)
    {
        actualAddress = 0;
        if (size == 0)
        {
            return false;
        }

        var alignedSize = (size + 0xFFF) & ~0xFFFUL;
        var protection = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        var allocationType = MEM_COMMIT | MEM_RESERVE;
        var result = VirtualAlloc((void*)desiredAddress, (nuint)alignedSize, allocationType, protection);
        if (result == null)
        {
            return false;
        }

        actualAddress = (ulong)result;
        if (actualAddress != desiredAddress)
        {
            VirtualFree(result, 0, MEM_RELEASE);
            actualAddress = 0;
            return false;
        }

        lock (_gate)
        {
            _regions.Add(new MemoryRegion
            {
                VirtualAddress = actualAddress,
                Size = alignedSize,
                IsExecutable = executable,
                IsReservedOnly = false,
                Protection = protection
            });
        }

        var allocationKind = executable ? "executable memory" : "data memory";
        Console.Error.WriteLine($"[VMEM] Allocated exact {allocationKind}: 0x{actualAddress:X16} - 0x{actualAddress + alignedSize:X16} ({alignedSize} bytes)");
        return true;
    }

    public ulong AllocateAt(ulong desiredAddress, ulong size, bool executable = true, bool allowAlternative = true)
    {
        if (size == 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be greater than zero");

        var alignedSize = (size + 0xFFF) & ~0xFFFUL;

        var protection = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        var allocationType = MEM_COMMIT | MEM_RESERVE;
        var reservedOnly = false;
        var preferReserveOnly = !executable && alignedSize >= LargeDataReserveThreshold;

        void* result = null;
        if (preferReserveOnly)
        {
            result = VirtualAlloc((void*)desiredAddress, (nuint)alignedSize, MEM_RESERVE, PAGE_READWRITE);
            if (result == null && allowAlternative)
            {
                result = VirtualAlloc(null, (nuint)alignedSize, MEM_RESERVE, PAGE_READWRITE);
            }

            if (result != null)
            {
                reservedOnly = true;
            }
        }

        if (result == null)
        {
            result = VirtualAlloc((void*)desiredAddress, (nuint)alignedSize, allocationType, protection);
        }

        if (result == null)
        {
            if (!allowAlternative)
            {
                throw new InvalidOperationException($"Failed to allocate exact mapping at 0x{desiredAddress:X16} ({alignedSize} bytes)");
            }

            Console.Error.WriteLine($"[VMEM] Could not allocate at 0x{desiredAddress:X16}, trying any address...");
            result = VirtualAlloc(null, (nuint)alignedSize, allocationType, protection);
            
            if (result == null)
            {
                if (!executable)
                {
                    result = VirtualAlloc((void*)desiredAddress, (nuint)alignedSize, MEM_RESERVE, PAGE_READWRITE);
                    if (result == null && allowAlternative)
                    {
                        result = VirtualAlloc(null, (nuint)alignedSize, MEM_RESERVE, PAGE_READWRITE);
                    }

                    if (result != null)
                    {
                        reservedOnly = true;
                    }
                }

                if (result == null)
                {
                    throw new OutOfMemoryException($"Failed to allocate {alignedSize} bytes of virtual memory");
                }
            }
        }

        var actualAddress = (ulong)result;

        var lazyPrimeState = "n/a";
        if (reservedOnly)
        {
            var primeBytes = Math.Min(alignedSize, LazyReservePrimeBytes);
            if (primeBytes != 0)
            {
                ulong committedBytes = 0;
                while (committedBytes < primeBytes)
                {
                    var remaining = primeBytes - committedBytes;
                    var chunkBytes = Math.Min(remaining, LazyReservePrimeChunkBytes);
                    var commitAddress = (void*)(actualAddress + committedBytes);
                    var committed = VirtualAlloc(commitAddress, (nuint)chunkBytes, MEM_COMMIT, PAGE_READWRITE);
                    if (committed == null)
                    {
                        break;
                    }

                    committedBytes += chunkBytes;
                }

                if (committedBytes != 0)
                {
                    lazyPrimeState = committedBytes == primeBytes
                        ? $"ok:{committedBytes:X}"
                        : $"partial:{committedBytes:X}/{primeBytes:X}";
                    Console.Error.WriteLine($"[VMEM] Primed lazy region: 0x{actualAddress:X16} - 0x{actualAddress + committedBytes:X16} ({committedBytes} bytes)");
                }
                else
                {
                    lazyPrimeState = $"fail:{primeBytes:X}";
                    Console.Error.WriteLine($"[VMEM] Failed to prime lazy region at 0x{actualAddress:X16} ({primeBytes} bytes), continuing with on-demand commit");
                }
            }
            else
            {
                lazyPrimeState = "skip:0";
            }
        }

        lock (_gate)
        {
            _regions.Add(new MemoryRegion
            {
                VirtualAddress = actualAddress,
                Size = alignedSize,
                IsExecutable = executable,
                IsReservedOnly = reservedOnly,
                Protection = protection
            });
        }

        var allocationKind = reservedOnly
            ? "reserved data memory (lazy commit)"
            : (executable ? "executable memory" : "data memory");
        Console.Error.WriteLine($"[VMEM] Allocated {allocationKind}: 0x{actualAddress:X16} - 0x{actualAddress + alignedSize:X16} ({alignedSize} bytes) lazy_prime={lazyPrimeState}");

        return actualAddress;
    }

    public void Clear()
    {
        lock (_gate)
        {
            foreach (var region in _regions)
            {
                VirtualFree((void*)region.VirtualAddress, 0, MEM_RELEASE);
            }
            _regions.Clear();
        }
    }

    public void Map(ulong virtualAddress, ulong memorySize, ulong fileOffset, ReadOnlySpan<byte> fileData, ProgramHeaderFlags protection)
    {
        if (memorySize == 0)
            throw new ArgumentOutOfRangeException(nameof(memorySize));

        if ((ulong)fileData.Length > memorySize)
            throw new ArgumentOutOfRangeException(nameof(fileData), "File size cannot exceed memory size");

        var mapStart = AlignDown(virtualAddress, PageSize);
        var segmentEnd = checked(virtualAddress + memorySize);
        var mapEnd = AlignUp(segmentEnd, PageSize);
        var mapSize = checked(mapEnd - mapStart);

        lock (_gate)
        {
            var existingRegion = FindRegion(mapStart, mapSize);
            if (existingRegion == null)
            {
                var isExecutable = (protection & ProgramHeaderFlags.Execute) != 0;
                AllocateAt(mapStart, mapSize, isExecutable, allowAlternative: false);
            }

            var stageProtection = (protection & ProgramHeaderFlags.Execute) != 0
                ? ProgramHeaderFlags.Read | ProgramHeaderFlags.Write | ProgramHeaderFlags.Execute
                : ProgramHeaderFlags.Read | ProgramHeaderFlags.Write;
            SetProtection(mapStart, mapSize, stageProtection);

            if (!fileData.IsEmpty)
            {
                var destPtr = (void*)virtualAddress;
                fixed (byte* srcPtr = fileData)
                {
                    Buffer.MemoryCopy(srcPtr, destPtr, (nuint)memorySize, (nuint)fileData.Length);
                }
            }

            var zeroFillSize = memorySize - (ulong)fileData.Length;
            if (zeroFillSize != 0)
            {
                NativeMemory.Clear((void*)(virtualAddress + (ulong)fileData.Length), (nuint)zeroFillSize);
            }

            SetProtection(mapStart, mapSize, protection);

            Console.Error.WriteLine($"[VMEM] Mapped segment: 0x{virtualAddress:X16} - 0x{virtualAddress + memorySize:X16} (file: {fileData.Length} bytes, prot: {protection})");
        }
    }

    private void SetProtection(ulong address, ulong size, ProgramHeaderFlags flags)
    {
        uint protection;
        
        if ((flags & ProgramHeaderFlags.Execute) != 0)
        {
            protection = (flags & ProgramHeaderFlags.Write) != 0 
                ? PAGE_EXECUTE_READWRITE 
                : PAGE_EXECUTE_READ;
        }
        else if ((flags & ProgramHeaderFlags.Write) != 0)
        {
            protection = PAGE_READWRITE;
        }
        else
        {
            protection = PAGE_READONLY;
        }

        if (!VirtualProtect((void*)address, (nuint)size, protection, out _))
        {
            throw new InvalidOperationException($"Failed to set memory protection at 0x{address:X16}");
        }

        if ((flags & ProgramHeaderFlags.Execute) != 0)
        {
            FlushInstructionCache(null, (void*)address, (nuint)size);
        }
    }

    public IReadOnlyList<VirtualMemoryRegion> SnapshotRegions()
    {
        lock (_gate)
        {
            var snapshot = new VirtualMemoryRegion[_regions.Count];
            for (var i = 0; i < _regions.Count; i++)
            {
                var r = _regions[i];
                snapshot[i] = new VirtualMemoryRegion(
                    r.VirtualAddress, 
                    r.Size, 
                    0, 
                    r.Size, 
                    r.IsExecutable ? ProgramHeaderFlags.Execute | ProgramHeaderFlags.Read : ProgramHeaderFlags.Read);
            }
            return snapshot;
        }
    }

    public bool TryRead(ulong virtualAddress, Span<byte> destination)
    {
        lock (_gate)
        {
            foreach (var region in _regions)
            {
                if (TryResolveRegionOffset(virtualAddress, (ulong)destination.Length, region, out var offset))
                {
                    var srcPtr = (void*)(region.VirtualAddress + offset);
                    fixed (byte* destPtr = destination)
                    {
                        Buffer.MemoryCopy(srcPtr, destPtr, (nuint)destination.Length, (nuint)destination.Length);
                    }
                    return true;
                }
            }
            return false;
        }
    }

    public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source)
    {
        lock (_gate)
        {
            foreach (var region in _regions)
            {
                if (TryResolveRegionOffset(virtualAddress, (ulong)source.Length, region, out var offset))
                {
                    var destPtr = (void*)(region.VirtualAddress + offset);
                    if (source.IsEmpty)
                    {
                        return true;
                    }

                    if (!VirtualProtect(destPtr, (nuint)source.Length, PAGE_EXECUTE_READWRITE, out var oldProtect))
                    {
                        return false;
                    }

                    try
                    {
                        fixed (byte* srcPtr = source)
                        {
                            Buffer.MemoryCopy(srcPtr, destPtr, (nuint)source.Length, (nuint)source.Length);
                        }
                    }
                    finally
                    {
                        VirtualProtect(destPtr, (nuint)source.Length, oldProtect, out _);
                        if (IsExecutableProtection(oldProtect))
                        {
                            FlushInstructionCache(null, destPtr, (nuint)source.Length);
                        }
                    }

                    return true;
                }
            }
            return false;
        }
    }

    public bool TryWriteUInt64(ulong virtualAddress, ulong value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        BitConverter.TryWriteBytes(buffer, value);
        return TryWrite(virtualAddress, buffer);
    }

    public void* GetPointer(ulong virtualAddress)
    {
        lock (_gate)
        {
            foreach (var region in _regions)
            {
                if (virtualAddress >= region.VirtualAddress && 
                    virtualAddress < region.VirtualAddress + region.Size)
                {
                    return (void*)virtualAddress;
                }
            }
            return null;
        }
    }

    public bool IsAccessible(ulong virtualAddress, ulong size)
    {
        lock (_gate)
        {
            foreach (var region in _regions)
            {
                if (TryResolveRegionOffset(virtualAddress, size, region, out _))
                {
                    return true;
                }
            }
            return false;
        }
    }

    private MemoryRegion? FindRegion(ulong address, ulong size)
    {
        foreach (var region in _regions)
        {
            if (TryResolveRegionOffset(address, size, region, out _))
            {
                return region;
            }
        }
        return null;
    }

    private static bool TryResolveRegionOffset(ulong address, ulong size, MemoryRegion region, out ulong offset)
    {
        offset = 0;
        if (address < region.VirtualAddress)
        {
            return false;
        }

        offset = address - region.VirtualAddress;
        if (offset > region.Size)
        {
            return false;
        }

        if (size > region.Size - offset)
        {
            return false;
        }

        return true;
    }

    private static bool IsExecutableProtection(uint protection)
    {
        return protection is PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
    }

    private static ulong AlignDown(ulong value, ulong alignment)
    {
        var mask = alignment - 1;
        return value & ~mask;
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        var mask = alignment - 1;
        return checked((value + mask) & ~mask);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Clear();
            _disposed = true;
        }
    }

    private class MemoryRegion
    {
        public ulong VirtualAddress { get; set; }
        public ulong Size { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsReservedOnly { get; set; }
        public uint Protection { get; set; }
    }
}
