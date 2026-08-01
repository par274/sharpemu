// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Logging;
using Silk.NET.Vulkan;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Counts explicit Vulkan device-memory objects and currently mapped host
/// ranges. Vulkan allocation callbacks are intentionally not used here: those
/// callbacks describe implementation host allocations, not the explicit
/// <see cref="Vk.AllocateMemory"/> objects tracked by this seam.
/// </summary>
internal static unsafe class VulkanMemoryDiagnostics
{
    private static readonly object Gate = new();
    private static readonly Dictionary<ulong, ulong> DeviceAllocations = new();
    private static readonly Dictionary<ulong, ulong> MappedAllocations = new();

    public static Result Allocate(
        Vk vk,
        Device device,
        MemoryAllocateInfo* allocationInfo,
        out DeviceMemory memory,
        string label)
    {
        _ = label;
        if (!MemoryDiagnostics.IsEnabled)
        {
            return vk.AllocateMemory(device, allocationInfo, null, out memory);
        }

        var result = vk.AllocateMemory(device, allocationInfo, null, out memory);
        if (result != Result.Success)
        {
            return result;
        }

        var size = allocationInfo->AllocationSize;
        lock (Gate)
        {
            DeviceAllocations[memory.Handle] = size;
        }

        MemoryDiagnostics.Adjust("vulkan.device-memory", checked((long)size), countDelta: 1);
        return result;
    }

    public static void Free(Vk vk, Device device, DeviceMemory memory)
    {
        if (!MemoryDiagnostics.IsEnabled)
        {
            vk.FreeMemory(device, memory, null);
            return;
        }

        vk.FreeMemory(device, memory, null);

        ulong size = 0;
        var found = false;
        lock (Gate)
        {
            found = DeviceAllocations.Remove(memory.Handle, out size);
        }

        if (found)
        {
            MemoryDiagnostics.Adjust("vulkan.device-memory", -checked((long)size), countDelta: -1);
        }
    }

    public static Result Map(
        Vk vk,
        Device device,
        DeviceMemory memory,
        ulong offset,
        ulong size,
        MemoryMapFlags flags,
        void** data,
        string label)
    {
        _ = label;
        if (!MemoryDiagnostics.IsEnabled)
        {
            return vk.MapMemory(device, memory, offset, size, flags, data);
        }

        var result = vk.MapMemory(device, memory, offset, size, flags, data);
        if (result != Result.Success)
        {
            return result;
        }

        var mappedSize = size;
        if (size == ulong.MaxValue)
        {
            lock (Gate)
            {
                if (DeviceAllocations.TryGetValue(memory.Handle, out var allocationSize) && offset < allocationSize)
                {
                    mappedSize = allocationSize - offset;
                }
            }
        }

        lock (Gate)
        {
            MappedAllocations[memory.Handle] = mappedSize;
        }

        MemoryDiagnostics.Adjust("vulkan.mapped-host-visible", checked((long)mappedSize), countDelta: 1);
        return result;
    }

    public static void Unmap(Vk vk, Device device, DeviceMemory memory)
    {
        if (!MemoryDiagnostics.IsEnabled)
        {
            vk.UnmapMemory(device, memory);
            return;
        }

        vk.UnmapMemory(device, memory);

        ulong size = 0;
        var found = false;
        lock (Gate)
        {
            found = MappedAllocations.Remove(memory.Handle, out size);
        }

        if (found)
        {
            MemoryDiagnostics.Adjust("vulkan.mapped-host-visible", -checked((long)size), countDelta: -1);
        }
    }
}
