// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Logging;
using Silk.NET.Vulkan;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// Counts explicit Vulkan device-memory objects and currently mapped host
/// ranges. The separate <see cref="VulkanHostAllocationDiagnostics"/> probe
/// reports pfnAllocation/pfnReallocation/pfnFree requests and informational
/// internal notifications supplied at the Vulkan instance/device roots. It is
/// not complete coverage of child-object or implementation allocations, and
/// those callbacks do not describe the explicit <see cref="Vk.AllocateMemory"/>
/// objects tracked by this seam.
/// </summary>
internal static unsafe class VulkanMemoryDiagnostics
{
    private static readonly object Gate = new();
    private readonly record struct AllocationInfo(ulong Size, string Label);
    private readonly record struct MappedAllocationInfo(
        ulong Size,
        string Label,
        nint Address);

    private static readonly Dictionary<ulong, AllocationInfo> DeviceAllocations = new();
    private static readonly Dictionary<ulong, MappedAllocationInfo> MappedAllocations = new();

    public static Result Allocate(
        Vk vk,
        Device device,
        MemoryAllocateInfo* allocationInfo,
        out DeviceMemory memory,
        string label)
    {
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
            DeviceAllocations[memory.Handle] = new AllocationInfo(size, NormalizeLabel(label));
        }

        AdjustDeviceMemory(label, size, countDelta: 1);
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

        AllocationInfo allocation = default;
        var found = false;
        lock (Gate)
        {
            found = DeviceAllocations.Remove(memory.Handle, out allocation);
        }

        if (found)
        {
            AdjustDeviceMemory(allocation.Label, allocation.Size, countDelta: -1);
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
                if (DeviceAllocations.TryGetValue(memory.Handle, out var allocation) && offset < allocation.Size)
                {
                    mappedSize = allocation.Size - offset;
                }
            }
        }

        MappedAllocationInfo? previous = null;
        var mappedAddress = (nint)(*data);
        lock (Gate)
        {
            if (MappedAllocations.TryGetValue(memory.Handle, out var existing))
            {
                previous = existing;
            }

            MappedAllocations[memory.Handle] =
                new MappedAllocationInfo(
                    mappedSize,
                    NormalizeLabel(label),
                    mappedAddress);
        }

        if (previous is { } old)
        {
            AdjustMappedMemory(old.Label, old.Size, countDelta: -1);
        }

        AdjustMappedMemory(label, mappedSize, countDelta: 1);
        MemoryDiagnostics.RecordEvent(
            "vulkan-host-memory-map",
            new
            {
                action = "map",
                address = unchecked((ulong)mappedAddress.ToInt64()),
                size = mappedSize,
                label = NormalizeLabel(label),
                memoryHandle = memory.Handle,
            });
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

        MappedAllocationInfo mapping = default;
        var found = false;
        lock (Gate)
        {
            found = MappedAllocations.Remove(memory.Handle, out mapping);
        }

        if (found)
        {
            AdjustMappedMemory(mapping.Label, mapping.Size, countDelta: -1);
            MemoryDiagnostics.RecordEvent(
                "vulkan-host-memory-map",
                new
                {
                    action = "unmap",
                    address = unchecked((ulong)mapping.Address.ToInt64()),
                    size = mapping.Size,
                    label = mapping.Label,
                    memoryHandle = memory.Handle,
                });
        }
    }

    public static ulong GetAllocationSize(DeviceMemory memory)
    {
        lock (Gate)
        {
            return DeviceAllocations.TryGetValue(memory.Handle, out var allocation)
                ? allocation.Size
                : 0;
        }
    }

    private static void AdjustDeviceMemory(string label, ulong size, long countDelta)
    {
        var bytes = checked((long)size);
        MemoryDiagnostics.Adjust("vulkan.device-memory", bytes * Math.Sign(countDelta), countDelta);
        MemoryDiagnostics.Adjust(
            $"vulkan.device-memory.{NormalizeLabel(label)}",
            bytes * Math.Sign(countDelta),
            countDelta);
    }

    private static void AdjustMappedMemory(string label, ulong size, long countDelta)
    {
        var bytes = checked((long)size);
        MemoryDiagnostics.Adjust(
            "vulkan.mapped-host-visible",
            bytes * Math.Sign(countDelta),
            countDelta);
        MemoryDiagnostics.Adjust(
            $"vulkan.mapped-host-visible.{NormalizeLabel(label)}",
            bytes * Math.Sign(countDelta),
            countDelta);
    }

    private static string NormalizeLabel(string label)
    {
        if (string.IsNullOrWhiteSpace(label))
        {
            return "unknown";
        }

        var builder = new System.Text.StringBuilder(label.Length);
        var needsSeparator = false;
        foreach (var character in label)
        {
            if (char.IsLetterOrDigit(character))
            {
                if (needsSeparator && builder.Length > 0)
                {
                    builder.Append('-');
                }

                builder.Append(char.ToLowerInvariant(character));
                needsSeparator = false;
            }
            else
            {
                needsSeparator = true;
            }
        }

        return builder.Length == 0 ? "unknown" : builder.ToString();
    }
}
