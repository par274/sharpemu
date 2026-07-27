// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.VideoOut;

using System.IO.MemoryMappedFiles;

/// <summary>
/// Publishes premultiplied BGRA overlay frames to the isolated emulator
/// process. The backing file is only a rendezvous point: both processes map
/// it and exchange pixels without per-frame filesystem I/O.
/// </summary>
public sealed unsafe class VulkanOverlayFrameWriter : IDisposable
{
    public const int MaxWidth = VulkanOverlayFrameProtocol.MaxWidth;
    public const int MaxHeight = VulkanOverlayFrameProtocol.MaxHeight;

    private readonly string _path;
    private readonly MemoryMappedFile _mapping;
    private readonly MemoryMappedViewAccessor _view;
    private byte* _memory;
    private long _sequence;
    private long _pixelSequence;
    private int _activeBuffer;
    private bool _disposed;

    public VulkanOverlayFrameWriter()
    {
        _path = Path.Combine(
            Path.GetTempPath(),
            $"SharpEmu-overlay-{Guid.NewGuid():N}.bin");

        using (var file = new FileStream(
                   _path,
                   FileMode.CreateNew,
                   FileAccess.ReadWrite,
                   FileShare.ReadWrite | FileShare.Delete))
        {
            file.SetLength(VulkanOverlayFrameProtocol.Capacity);
        }

        _mapping = MemoryMappedFile.CreateFromFile(
            _path,
            FileMode.Open,
            mapName: null,
            VulkanOverlayFrameProtocol.Capacity,
            MemoryMappedFileAccess.ReadWrite);
        _view = _mapping.CreateViewAccessor(
            0,
            VulkanOverlayFrameProtocol.Capacity,
            MemoryMappedFileAccess.ReadWrite);
        AcquirePointer();

        WriteInt32(VulkanOverlayFrameProtocol.MagicOffset, VulkanOverlayFrameProtocol.Magic);
        WriteInt32(VulkanOverlayFrameProtocol.VersionOffset, VulkanOverlayFrameProtocol.Version);
        WriteInt32(
            VulkanOverlayFrameProtocol.OpacityBitsOffset,
            BitConverter.SingleToInt32Bits(1));
        Volatile.Write(ref PixelSequence, 0);
        Volatile.Write(ref Sequence, 0);
    }

    /// <summary>Opaque descriptor passed to the child process.</summary>
    public string Descriptor => _path;

    public static (int Width, int Height) GetFrameSize(
        int surfaceWidth,
        int surfaceHeight) =>
        VulkanOverlayFrameProtocol.GetFrameSize(surfaceWidth, surfaceHeight);

    /// <summary>
    /// Copies a packed or padded premultiplied BGRA frame into the inactive
    /// shared buffer, then publishes it with one atomic sequence update.
    /// </summary>
    public void PublishFrame(
        nint pixels,
        int width,
        int height,
        int sourceStride,
        bool visible = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfLessThan(width, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(width, VulkanOverlayFrameProtocol.MaxWidth);
        ArgumentOutOfRangeException.ThrowIfLessThan(height, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(height, VulkanOverlayFrameProtocol.MaxHeight);

        var packedStride = checked(width * VulkanOverlayFrameProtocol.BytesPerPixel);
        ArgumentOutOfRangeException.ThrowIfLessThan(sourceStride, packedStride);
        if (pixels == 0)
        {
            throw new ArgumentNullException(nameof(pixels));
        }

        var nextBuffer = (_activeBuffer + 1) % VulkanOverlayFrameProtocol.BufferCount;
        var destination = _memory + VulkanOverlayFrameProtocol.BufferOffset(nextBuffer);
        var source = (byte*)pixels;
        for (var row = 0; row < height; row++)
        {
            Buffer.MemoryCopy(
                source + (row * sourceStride),
                destination + (row * packedStride),
                packedStride,
                packedStride);
        }

        WriteInt32(VulkanOverlayFrameProtocol.WidthOffset, width);
        WriteInt32(VulkanOverlayFrameProtocol.HeightOffset, height);
        WriteInt32(VulkanOverlayFrameProtocol.StrideOffset, packedStride);
        WriteInt32(VulkanOverlayFrameProtocol.BufferIndexOffset, nextBuffer);
        Volatile.Write(ref PixelSequence, ++_pixelSequence);
        WriteInt32(
            VulkanOverlayFrameProtocol.FlagsOffset,
            visible ? VulkanOverlayFrameProtocol.VisibleFlag : 0);
        _activeBuffer = nextBuffer;
        Volatile.Write(ref Sequence, ++_sequence);
    }

    /// <summary>
    /// Updates the compositor opacity without republishing the pixel buffer.
    /// This keeps presentation animations on the GPU side of the process
    /// boundary.
    /// </summary>
    public void SetOpacity(float opacity)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!float.IsFinite(opacity))
        {
            throw new ArgumentOutOfRangeException(nameof(opacity));
        }

        WriteInt32(
            VulkanOverlayFrameProtocol.OpacityBitsOffset,
            BitConverter.SingleToInt32Bits(Math.Clamp(opacity, 0, 1)));
        Volatile.Write(ref Sequence, ++_sequence);
    }

    public void SetVisible(bool visible)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        WriteInt32(
            VulkanOverlayFrameProtocol.FlagsOffset,
            visible ? VulkanOverlayFrameProtocol.VisibleFlag : 0);
        Volatile.Write(ref Sequence, ++_sequence);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_memory is not null)
        {
            _view.SafeMemoryMappedViewHandle.ReleasePointer();
            _memory = null;
        }

        _view.Dispose();
        _mapping.Dispose();
        try
        {
            File.Delete(_path);
        }
        catch (IOException exception)
        {
            // A child may still be unwinding its mapping. FILE_SHARE_DELETE
            // removes the file once that final handle closes on Windows.
            Console.Error.WriteLine(
                $"[VIDEOOUT][WARN] Overlay frame file cleanup was deferred: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            // Best-effort cleanup; the random file contains only UI pixels.
            Console.Error.WriteLine(
                $"[VIDEOOUT][WARN] Overlay frame file cleanup failed: {exception.Message}");
        }
    }

    private ref long Sequence =>
        ref *(long*)(_memory + VulkanOverlayFrameProtocol.SequenceOffset);

    private ref long PixelSequence =>
        ref *(long*)(_memory + VulkanOverlayFrameProtocol.PixelSequenceOffset);

    private void AcquirePointer()
    {
        byte* pointer = null;
        _view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
        _memory = pointer + _view.PointerOffset;
    }

    private void WriteInt32(int offset, int value) =>
        Volatile.Write(ref *(int*)(_memory + offset), value);
}

internal sealed unsafe class VulkanOverlayFrameReader : IDisposable
{
    private readonly MemoryMappedFile _mapping;
    private readonly MemoryMappedViewAccessor _view;
    private byte* _memory;
    private long _copiedPixelSequence = -1;
    private bool _disposed;

    private VulkanOverlayFrameReader(
        MemoryMappedFile mapping,
        MemoryMappedViewAccessor view)
    {
        _mapping = mapping;
        _view = view;
        byte* pointer = null;
        _view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
        _memory = pointer + _view.PointerOffset;
    }

    public static bool TryOpen(
        string descriptor,
        out VulkanOverlayFrameReader? reader,
        out string? error)
    {
        reader = null;
        error = null;
        try
        {
            if (string.IsNullOrWhiteSpace(descriptor))
            {
                error = "overlay descriptor is empty";
                return false;
            }

            var path = Path.GetFullPath(descriptor);
            var file = new FileInfo(path);
            if (!file.Exists || file.Length != VulkanOverlayFrameProtocol.Capacity)
            {
                error = "overlay shared frame file has an invalid size";
                return false;
            }

            using var fileStream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var mapping = MemoryMappedFile.CreateFromFile(
                fileStream,
                mapName: null,
                capacity: 0,
                MemoryMappedFileAccess.Read,
                HandleInheritability.None,
                leaveOpen: false);
            var view = mapping.CreateViewAccessor(
                0,
                VulkanOverlayFrameProtocol.Capacity,
                MemoryMappedFileAccess.Read);
            var candidate = new VulkanOverlayFrameReader(mapping, view);
            if (candidate.ReadInt32(VulkanOverlayFrameProtocol.MagicOffset) !=
                    VulkanOverlayFrameProtocol.Magic ||
                candidate.ReadInt32(VulkanOverlayFrameProtocol.VersionOffset) !=
                    VulkanOverlayFrameProtocol.Version)
            {
                candidate.Dispose();
                error = "overlay shared frame file has an unsupported header";
                return false;
            }

            reader = candidate;
            return true;
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            error = exception.Message;
            return false;
        }
    }

    /// <summary>
    /// Reads a coherent frame directly into a mapped Vulkan staging buffer.
    /// A double-buffer plus a sequence check avoids cross-process locks.
    /// </summary>
    public bool TryCopyLatest(
        Span<byte> destination,
        int expectedWidth,
        int expectedHeight,
        long previousSequence,
        out bool visible,
        out long sequence,
        out float opacity,
        out bool copied)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        visible = false;
        sequence = previousSequence;
        opacity = 1;
        copied = false;

        var requiredBytes = checked(
            expectedWidth *
            expectedHeight *
            VulkanOverlayFrameProtocol.BytesPerPixel);
        if (destination.Length < requiredBytes)
        {
            return false;
        }

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var before = Volatile.Read(ref Sequence);
            var flags = ReadInt32(VulkanOverlayFrameProtocol.FlagsOffset);
            var width = ReadInt32(VulkanOverlayFrameProtocol.WidthOffset);
            var height = ReadInt32(VulkanOverlayFrameProtocol.HeightOffset);
            var stride = ReadInt32(VulkanOverlayFrameProtocol.StrideOffset);
            var bufferIndex = ReadInt32(VulkanOverlayFrameProtocol.BufferIndexOffset);
            var pixelSequence = Volatile.Read(ref PixelSequence);
            opacity = BitConverter.Int32BitsToSingle(
                ReadInt32(VulkanOverlayFrameProtocol.OpacityBitsOffset));
            if (!float.IsFinite(opacity))
            {
                opacity = 1;
            }
            else
            {
                opacity = Math.Clamp(opacity, 0, 1);
            }

            visible = (flags & VulkanOverlayFrameProtocol.VisibleFlag) != 0;
            sequence = before;
            if (!visible)
            {
                return before == Volatile.Read(ref Sequence);
            }

            if (width != expectedWidth ||
                height != expectedHeight ||
                stride != expectedWidth * VulkanOverlayFrameProtocol.BytesPerPixel ||
                (uint)bufferIndex >= VulkanOverlayFrameProtocol.BufferCount)
            {
                return false;
            }

            if (before == previousSequence)
            {
                return true;
            }

            if (pixelSequence == _copiedPixelSequence)
            {
                return before == Volatile.Read(ref Sequence);
            }

            fixed (byte* destinationPointer = destination)
            {
                Buffer.MemoryCopy(
                    _memory + VulkanOverlayFrameProtocol.BufferOffset(bufferIndex),
                    destinationPointer,
                    requiredBytes,
                    requiredBytes);
            }

            if (before == Volatile.Read(ref Sequence))
            {
                _copiedPixelSequence = pixelSequence;
                copied = true;
                return true;
            }
        }

        visible = false;
        copied = false;
        return false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_memory is not null)
        {
            _view.SafeMemoryMappedViewHandle.ReleasePointer();
            _memory = null;
        }

        _view.Dispose();
        _mapping.Dispose();
    }

    private ref long Sequence =>
        ref *(long*)(_memory + VulkanOverlayFrameProtocol.SequenceOffset);

    private ref long PixelSequence =>
        ref *(long*)(_memory + VulkanOverlayFrameProtocol.PixelSequenceOffset);

    private int ReadInt32(int offset) =>
        Volatile.Read(ref *(int*)(_memory + offset));
}

internal static class VulkanOverlayFrameProtocol
{
    public const int Magic = 0x534F564C; // "LVOS", little-endian.
    public const int Version = 2;
    public const int BytesPerPixel = 4;
    public const int BufferCount = 2;
    public const int MaxWidth = 4096;
    public const int MaxHeight = 2160;
    public const int HeaderSize = 64;
    public const int MagicOffset = 0;
    public const int VersionOffset = 4;
    public const int SequenceOffset = 8;
    public const int FlagsOffset = 16;
    public const int WidthOffset = 20;
    public const int HeightOffset = 24;
    public const int StrideOffset = 28;
    public const int BufferIndexOffset = 32;
    public const int OpacityBitsOffset = 36;
    public const int PixelSequenceOffset = 40;
    public const int VisibleFlag = 1;
    public const long FrameBytes = (long)MaxWidth * MaxHeight * BytesPerPixel;
    public const long Capacity = HeaderSize + (FrameBytes * BufferCount);

    public static long BufferOffset(int index) => HeaderSize + (FrameBytes * index);

    public static (int Width, int Height) GetFrameSize(int surfaceWidth, int surfaceHeight)
    {
        var scale = Math.Min(
            1,
            Math.Min(
                MaxWidth / (double)Math.Max(surfaceWidth, 1),
                MaxHeight / (double)Math.Max(surfaceHeight, 1)));
        return (
            Math.Max(1, (int)Math.Round(surfaceWidth * scale)),
            Math.Max(1, (int)Math.Round(surfaceHeight * scale)));
    }
}
