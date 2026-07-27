// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal static class WindowCapture
{
    private const uint PwClientOnly = 0x00000001;
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint BiRgb = 0;
    private const uint DibRgbColors = 0;

    public static bool TryCaptureClientArea(Process rootProcess, string frameDirectory, int sampleIndex, double elapsedSeconds, out string status)
    {
        status = "unavailable";
        if (!OperatingSystem.IsWindows() || rootProcess.HasExited) return false;
        var processIds = DescendantProcessIds(rootProcess.Id);
        nint selected = 0;
        _ = EnumWindows((window, parameter) =>
        {
            _ = GetWindowThreadProcessId(window, out var processId);
            if (!processIds.Contains(unchecked((int)processId)) || !IsWindowVisible(window) || IsIconic(window)) return true;
            if (!GetClientRect(window, out var rectangle) || rectangle.Right - rectangle.Left < 2 || rectangle.Bottom - rectangle.Top < 2) return true;
            selected = window;
            return false;
        }, 0);
        if (selected == 0)
        {
            status = "no-visible-nonminimized-process-window";
            return false;
        }

        if (!GetClientRect(selected, out var client)) return false;
        var width = client.Right - client.Left;
        var height = client.Bottom - client.Top;
        var windowDc = GetDC(selected);
        if (windowDc == 0) return false;
        var memoryDc = CreateCompatibleDC(windowDc);
        nint bitmap = 0;
        nint oldObject = 0;
        try
        {
            var info = new BitmapInfo
            {
                Header = new BitmapInfoHeader
                {
                    Size = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
                    Width = width,
                    Height = -height,
                    Planes = 1,
                    BitCount = 32,
                    Compression = BiRgb,
                },
            };
            bitmap = CreateDIBSection(windowDc, ref info, DibRgbColors, out var bits, 0, 0);
            if (bitmap == 0 || bits == 0) return false;
            oldObject = SelectObject(memoryDc, bitmap);
            if (!PrintWindow(selected, memoryDc, PwClientOnly))
            {
                status = "print-window-client-only-failed";
                return false;
            }
            var raw = new byte[checked(width * height * 4)];
            Marshal.Copy(bits, raw, 0, raw.Length);
            Directory.CreateDirectory(frameDirectory);
            var stem = $"window-{sampleIndex:D4}";
            var rawFile = stem + ".raw";
            File.WriteAllBytes(Path.Combine(frameDirectory, rawFile), raw);
            var descriptor = new RawFrameDescriptor(
                rawFile,
                width,
                height,
                width * 4,
                "B8G8R8A8_UNORM",
                "window-fallback",
                null,
                elapsedSeconds,
                DateTimeOffset.UtcNow,
                null,
                false,
                null);
            File.WriteAllText(Path.Combine(frameDirectory, stem + ".raw.json"), JsonSerializer.Serialize(descriptor, Program.JsonOptions));
            status = "captured-client-only-nondeterministic; occlusion-status=unknown";
            return true;
        }
        finally
        {
            if (oldObject != 0) _ = SelectObject(memoryDc, oldObject);
            if (bitmap != 0) _ = DeleteObject(bitmap);
            if (memoryDc != 0) _ = DeleteDC(memoryDc);
            _ = ReleaseDC(selected, windowDc);
        }
    }

    private static HashSet<int> DescendantProcessIds(int root)
    {
        var parents = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == new nint(-1)) return [root];
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (Process32First(snapshot, ref entry))
            {
                do
                {
                    parents[unchecked((int)entry.ProcessId)] = unchecked((int)entry.ParentProcessId);
                    entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
                }
                while (Process32Next(snapshot, ref entry));
            }
        }
        finally { _ = CloseHandle(snapshot); }
        var result = new HashSet<int> { root };
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var pair in parents)
            {
                if (!result.Contains(pair.Key) && result.Contains(pair.Value)) changed |= result.Add(pair.Key);
            }
        }
        return result;
    }

    private delegate bool EnumWindowsCallback(nint window, nint parameter);

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint Size;
        public int Width, Height;
        public ushort Planes, BitCount;
        public uint Compression, SizeImage;
        public int XPelsPerMeter, YPelsPerMeter;
        public uint ClrUsed, ClrImportant;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfo
    {
        public BitmapInfoHeader Header;
        public uint Colors;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size, Usage, ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId, Threads, ParentProcessId;
        public int BasePriority;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsCallback callback, nint parameter);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint window, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(nint window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(nint window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetClientRect(nint window, out Rect rectangle);

    [DllImport("user32.dll")]
    private static extern nint GetDC(nint window);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(nint window, nint dc);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PrintWindow(nint window, nint dc, uint flags);

    [DllImport("gdi32.dll")]
    private static extern nint CreateCompatibleDC(nint dc);

    [DllImport("gdi32.dll")]
    private static extern nint CreateDIBSection(nint dc, ref BitmapInfo info, uint usage, out nint bits, nint section, uint offset);

    [DllImport("gdi32.dll")]
    private static extern nint SelectObject(nint dc, nint value);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(nint value);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteDC(nint dc);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
