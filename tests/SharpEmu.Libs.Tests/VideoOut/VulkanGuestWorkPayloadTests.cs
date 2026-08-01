// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using System.Text.Json;
using SharpEmu.Libs.Gpu;
using SharpEmu.Libs.VideoOut;
using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanGuestWorkPayloadTests
{
    [Fact]
    public void ComputePayloadIncludesBothTextureRepresentationsAndSharedArraysOnce()
    {
        var shader = new byte[11];
        var shared = new byte[13];
        var tiled = new byte[17];
        var otherGlobal = new byte[19];
        var texture = Texture(shared, tiled);
        var work = new VulkanComputeGuestDispatch(
            0,
            shader,
            [texture, Texture(shared, tiled)],
            [
                Buffer(shared),
                Buffer(otherGlobal),
                Buffer(otherGlobal),
            ],
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            false,
            false);

        Assert.Equal(
            (ulong)(shader.Length + shared.Length + tiled.Length + otherGlobal.Length),
            VulkanVideoPresenter.GetGuestWorkPayloadBytes(work));
    }

    [Fact]
    public void DrawPayloadIncludesShaderTextureBufferVertexAndIndexArraysOnce()
    {
        var sharedShader = new byte[5];
        var rgba = new byte[7];
        var tiled = new byte[11];
        var sharedBuffer = new byte[13];
        var vertexOnly = new byte[17];
        var indexOnly = new byte[19];
        var draw = new VulkanTranslatedGuestDraw(
            sharedShader,
            sharedShader,
            [Texture(rgba, tiled)],
            [Buffer(sharedBuffer), Buffer(sharedBuffer)],
            [
                Vertex(sharedBuffer),
                Vertex(vertexOnly),
            ],
            0,
            3,
            1,
            4,
            new GuestIndexBuffer(indexOnly, indexOnly.Length, false, false),
            GuestRenderState.Default);
        var work = new VulkanOffscreenGuestDraw(
            draw,
            [new GuestRenderTarget(1, 1, 1, 1, 0)],
            null,
            false,
            0);

        Assert.Equal(
            (ulong)(
                sharedShader.Length +
                rgba.Length +
                tiled.Length +
                sharedBuffer.Length +
                vertexOnly.Length +
                indexOnly.Length),
            VulkanVideoPresenter.GetGuestWorkPayloadBytes(work));
    }

    [Fact]
    public void ImageWritePayloadUsesItsPixelsAndNullFillHasNoPayload()
    {
        var pixels = new byte[23];

        Assert.Equal(
            (ulong)pixels.Length,
            VulkanVideoPresenter.GetGuestWorkPayloadBytes(
                new VulkanVideoPresenter.VulkanGuestImageWrite(1, pixels, 0)));
        Assert.Equal(
            0UL,
            VulkanVideoPresenter.GetGuestWorkPayloadBytes(
                new VulkanVideoPresenter.VulkanGuestImageWrite(1, null, 0)));
    }

    [Fact]
    public void OversizedItemIsAdmittedWhenQueueHasNoPayload()
    {
        Assert.False(
            VulkanVideoPresenter.WouldExceedGuestWorkByteBudget(
                pendingBytes: 0,
                incomingBytes: 9,
                budgetBytes: 8));
        Assert.True(
            VulkanVideoPresenter.WouldExceedGuestWorkByteBudget(
                pendingBytes: 1,
                incomingBytes: 8,
                budgetBytes: 8));
        Assert.False(
            VulkanVideoPresenter.WouldExceedGuestWorkByteBudget(
                pendingBytes: 8,
                incomingBytes: 0,
                budgetBytes: 8));
    }

    [Fact]
    public void EnqueueRequeueAndCompletionUseOneStoredPayloadTotal()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "sharpemu-guest-work-diagnostics",
            $"{Guid.NewGuid():N}.jsonl");
        var work = ComputeWork(new byte[31], new byte[37]);
        var expectedPayload = VulkanVideoPresenter.GetGuestWorkPayloadBytes(work);

        PrepareQueue();
        try
        {
            using (MemoryDiagnosticsSession.Start(path, TimeSpan.FromHours(1)))
            {
                var sequence = Enqueue(work);
                Assert.True(sequence > 0);
                Assert.Equal(expectedPayload, PendingBytes());

                var taken = Take(out var pending);
                Assert.True(taken);
                Assert.Equal(expectedPayload, PendingBytes());
                Assert.True(Requeue(pending));
                Assert.Equal(expectedPayload, PendingBytes());

                Assert.True(Take(out var requeued));
                Assert.Equal(expectedPayload, StoredPayload(requeued));
                Complete(requeued);
                Assert.Equal(0UL, PendingBytes());
                Assert.Equal(0, PendingCount());
                Assert.Equal(0, PendingQueueCount());
            }

            var categories = ReadFinalCategories(path);
            var retained = categories.GetProperty("managed.guest-queue-retained");
            Assert.Equal(0, retained.GetProperty("bytes").GetInt64());
            Assert.Equal(0, retained.GetProperty("count").GetInt64());

            var enqueued = categories.GetProperty("managed.guest-queue-enqueued");
            Assert.Equal((long)expectedPayload, enqueued.GetProperty("bytes").GetInt64());
            Assert.Equal(1, enqueued.GetProperty("count").GetInt64());
            Assert.False(categories.TryGetProperty(
                "managed.guest-queue-actual-retained",
                out _));
            Assert.False(categories.TryGetProperty(
                "managed.guest-queue-actual-enqueued",
                out _));

            // The same lifecycle with diagnostics disabled still uses the
            // production byte total and does not create another owner.
            var disabledWork = ComputeWork(new byte[41], new byte[43]);
            var disabledPayload = VulkanVideoPresenter.GetGuestWorkPayloadBytes(disabledWork);
            Assert.False(MemoryDiagnostics.IsEnabled);
            var disabledSequence = Enqueue(disabledWork);
            Assert.True(disabledSequence > 0);
            Assert.Equal(disabledPayload, PendingBytes());
            Assert.True(Take(out var disabledPending));
            Complete(disabledPending);
            Assert.Equal(0UL, PendingBytes());
        }
        finally
        {
            ResetQueue();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static GuestDrawTexture Texture(byte[] rgba, byte[] tiled) =>
        new(1, 1, 1, 1, 0, rgba, false, false, TiledSource: tiled);

    private static GuestMemoryBuffer Buffer(byte[] data) =>
        new(1, data, data.Length, false);

    private static GuestVertexBuffer Vertex(byte[] data) =>
        new(0, 4, 0, 0, 1, 16, 0, data, data.Length, false);

    private static VulkanComputeGuestDispatch ComputeWork(
        byte[] rgba,
        byte[] tiled) =>
        new(
            1,
            new byte[7],
            [Texture(rgba, tiled)],
            [Buffer(new byte[5])],
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            false,
            false);

    private static readonly Type PendingGuestWorkType =
        typeof(VulkanVideoPresenter).GetNestedType(
            "PendingGuestWork",
            BindingFlags.NonPublic)!;

    private static readonly object QueueGate =
        typeof(VulkanVideoPresenter)
            .GetField("_gate", BindingFlags.Static | BindingFlags.NonPublic)!
            .GetValue(null)!;

    private static readonly MethodInfo ResetHostSessionStateLockedMethod =
        typeof(VulkanVideoPresenter).GetMethod(
            "ResetHostSessionStateLocked",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo EnqueueGuestWorkLockedMethod =
        typeof(VulkanVideoPresenter).GetMethod(
            "EnqueueGuestWorkLocked",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo TryTakeGuestWorkMethod =
        typeof(VulkanVideoPresenter).GetMethod(
            "TryTakeGuestWork",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo RequeueGuestWorkFrontMethod =
        typeof(VulkanVideoPresenter).GetMethod(
            "RequeueGuestWorkFront",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo CompleteGuestWorkMethod =
        typeof(VulkanVideoPresenter).GetMethod(
            "CompleteGuestWork",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo ThreadField =
        typeof(VulkanVideoPresenter).GetField(
            "_thread",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo ClosedField =
        typeof(VulkanVideoPresenter).GetField(
            "_closed",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo PendingBytesField =
        typeof(VulkanVideoPresenter).GetField(
            "_pendingGuestWorkBytes",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo PendingCountField =
        typeof(VulkanVideoPresenter).GetField(
            "_pendingGuestWorkCount",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly FieldInfo PendingQueuesField =
        typeof(VulkanVideoPresenter).GetField(
            "_pendingGuestWorkByQueue",
            BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly PropertyInfo StoredPayloadProperty =
        PendingGuestWorkType.GetProperty("PayloadBytes")!;

    private static void PrepareQueue()
    {
        lock (QueueGate)
        {
            ResetHostSessionStateLockedMethod.Invoke(null, null);
            ClosedField.SetValue(null, false);
            ThreadField.SetValue(null, Thread.CurrentThread);
        }
    }

    private static void ResetQueue()
    {
        lock (QueueGate)
        {
            ResetHostSessionStateLockedMethod.Invoke(null, null);
            ClosedField.SetValue(null, false);
            ThreadField.SetValue(null, null);
            Monitor.PulseAll(QueueGate);
        }
    }

    private static long Enqueue(object work)
    {
        lock (QueueGate)
        {
            return (long)EnqueueGuestWorkLockedMethod.Invoke(null, [work])!;
        }
    }

    private static bool Take(out object pending)
    {
        var arguments = new object?[] { null, null, false };
        var taken = (bool)TryTakeGuestWorkMethod.Invoke(null, arguments)!;
        pending = arguments[0]!;
        return taken;
    }

    private static bool Requeue(object pending) =>
        (bool)RequeueGuestWorkFrontMethod.Invoke(null, [pending])!;

    private static void Complete(object pending) =>
        CompleteGuestWorkMethod.Invoke(null, [pending]);

    private static ulong StoredPayload(object pending) =>
        (ulong)StoredPayloadProperty.GetValue(pending)!;

    private static ulong PendingBytes() =>
        (ulong)PendingBytesField.GetValue(null)!;

    private static int PendingCount() =>
        (int)PendingCountField.GetValue(null)!;

    private static int PendingQueueCount() =>
        ((System.Collections.IDictionary)PendingQueuesField.GetValue(null)!).Count;

    private static JsonElement ReadFinalCategories(string path)
    {
        var records = File.ReadAllLines(path);
        using var document = JsonDocument.Parse(records[^1]);
        return document.RootElement.GetProperty("categories").Clone();
    }
}
