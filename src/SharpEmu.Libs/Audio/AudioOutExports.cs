// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.HLE.Host;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace SharpEmu.Libs.Audio;

public static class AudioOutExports
{
    private const int AudioOutOutputParamSize = 16;
    private const int AudioOutMaximumOutputCount = 25;

    internal const int AudioOutErrorInvalidPort = unchecked((int)0x80260003);
    internal const int AudioOutErrorInvalidPointer = unchecked((int)0x80260004);
    internal const int AudioOutErrorPortFull = unchecked((int)0x80260005);
    internal const int AudioOutErrorInvalidSize = unchecked((int)0x80260006);

    private static readonly ConcurrentDictionary<int, PortState> Ports = new();
    private static int _nextPortHandle;
    private static Func<uint, IHostAudioStream?>? _streamFactoryForTests;

    // Diagnostic: confirm sceAudioOutOutput is actually called and whether the
    // guest submits real samples or silence. Gated so it costs nothing when off.
    private static readonly bool _traceOutput = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_LOG_AUDIO_OUT"), "1", StringComparison.Ordinal);
    private static long _outputCount;

    private sealed class PortState : IDisposable
    {
        private readonly object _paceGate = new();
        private long _nextSilentOutput;

        public PortState(
            int handle,
            int userId,
            int type,
            uint bufferLength,
            uint frequency,
            int format,
            int channels,
            int bytesPerSample,
            bool isFloat,
            bool preservesGuestFormat,
            IHostAudioStream? backend,
            GuestAudioCallTrace? diagnostics,
            GuestAudioBufferTrace? bufferDiagnostics)
        {
            Handle = handle;
            UserId = userId;
            Type = type;
            BufferLength = bufferLength;
            Frequency = frequency;
            Format = format;
            Channels = channels;
            BytesPerSample = bytesPerSample;
            IsFloat = isFloat;
            PreservesGuestFormat = preservesGuestFormat;
            Backend = backend;
            Diagnostics = diagnostics;
            BufferDiagnostics = bufferDiagnostics;
        }

        public int UserId { get; }
        public int Handle { get; }
        public int Type { get; }
        public uint BufferLength { get; }
        public uint Frequency { get; }
        public int Format { get; }
        public int Channels { get; }
        public int BytesPerSample { get; }
        public bool IsFloat { get; }
        public bool PreservesGuestFormat { get; }
        public IHostAudioStream? Backend { get; }
        public GuestAudioCallTrace? Diagnostics { get; }
        public GuestAudioBufferTrace? BufferDiagnostics { get; }
        public object SubmissionGate { get; } = new();
        public volatile float Volume = 1.0f;
        public int BufferByteLength =>
            checked((int)BufferLength * Channels * BytesPerSample);

        public void PaceSilence()
        {
            long delay;
            lock (_paceGate)
            {
                var now = Stopwatch.GetTimestamp();
                if (_nextSilentOutput < now)
                {
                    _nextSilentOutput = now;
                }

                delay = _nextSilentOutput - now;
                _nextSilentOutput += checked(
                    (long)Math.Ceiling(
                        Stopwatch.Frequency * (double)BufferLength / Frequency));
            }

            if (delay > 0)
            {
                Thread.Sleep(TimeSpan.FromSeconds((double)delay / Stopwatch.Frequency));
            }
        }

        public void Dispose()
        {
            lock (SubmissionGate)
            {
                Backend?.Dispose();
            }
        }
    }

    private readonly record struct OutputDescriptor(int Handle, ulong SourceAddress);

    private struct ResolvedOutput
    {
        public int Handle;
        public ulong SourceAddress;
        public PortState Port;
        public byte[]? HostBuffer;
        public int HostBufferLength;
        public GuestAudioBufferObservation BufferObservation;
        public bool HasBufferObservation;
        public long CallSequence;
    }

    [SysAbiExport(
        Nid = "JfEPXVxhFqA",
        ExportName = "sceAudioOutInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutInit(CpuContext ctx) => ctx.SetReturn(0);

    [SysAbiExport(
        Nid = "ekNvsT22rsY",
        ExportName = "sceAudioOutOpen",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutOpen(CpuContext ctx)
    {
        var userId = unchecked((int)ctx[CpuRegister.Rdi]);
        var type = unchecked((int)ctx[CpuRegister.Rsi]);
        var bufferLength = unchecked((uint)ctx[CpuRegister.Rcx]);
        var frequency = unchecked((uint)ctx[CpuRegister.R8]);
        var format = unchecked((int)ctx[CpuRegister.R9]);
        if (bufferLength == 0 || frequency == 0 ||
            !TryGetFormat(format, out var channels, out var bytesPerSample, out var isFloat))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        IHostAudioStream? backend = null;
        var preservesGuestFormat = false;
        string backendName;
        try
        {
            var streamFactory = Volatile.Read(ref _streamFactoryForTests);
            if (streamFactory is not null)
            {
                backend = streamFactory(frequency);
                backendName = "test";
            }
            else
            {
                var audio = HostPlatform.Current.Audio;
                if (audio is IHostPcmAudioOutput pcmAudio)
                {
                    backend = pcmAudio.OpenPcmStream(
                        frequency,
                        channels,
                        isFloat ? HostPcmFormat.Float32 : HostPcmFormat.Signed16);
                    preservesGuestFormat = true;
                }
                else
                {
                    backend = audio.OpenStereoPcm16Stream(frequency);
                }
                backendName = audio.BackendName;
            }
        }
        catch (Exception exception)
        {
            backendName = "silent";
            HostAudioDiagnostics.RecordOpenFailure(
                owner: "audio-out",
                source: "guest-port",
                sampleRate: frequency,
                channels: channels,
                format: isFloat ? "F32" : "S16",
                maximumQueuedBytes: 0,
                exception: exception);
            Console.Error.WriteLine(
                $"[LOADER][WARN] AudioOut host backend unavailable: {exception.Message}");
        }

        var handle = Interlocked.Increment(ref _nextPortHandle);
        var diagnostics = GuestAudioDiagnostics.Enabled ? new GuestAudioCallTrace() : null;
        var bufferDiagnostics = GuestAudioDiagnostics.Enabled
            ? new GuestAudioBufferTrace()
            : null;
        Ports[handle] = new PortState(
            handle,
            userId,
            type,
            bufferLength,
            frequency,
            format,
            channels,
            bytesPerSample,
            isFloat,
            preservesGuestFormat,
            backend,
            diagnostics,
            bufferDiagnostics);
        if (HostAudioDiagnostics.Enabled &&
            backend is IHostAudioStreamDiagnostics streamDiagnostics)
        {
            streamDiagnostics.SetDiagnosticContext(
                owner: "audio-out",
                source: $"port-{handle}",
                movieInstanceId: 0,
                hostMovieGeneration: 0,
                guestStreamIdentity: $"port-{handle}");
        }
        Console.Error.WriteLine(
            $"[LOADER][INFO] AudioOut port {handle}: {frequency} Hz, " +
            $"{channels} ch, {(isFloat ? "float32" : "s16")}, " +
            $"{bufferLength} frames, backend={backendName}");
        if (diagnostics is not null && GuestAudioDiagnostics.Enabled)
        {
            GuestAudioDiagnostics.Record(
                "audioout.port-open",
                new
                {
                    portHandle = handle,
                    userId,
                    portType = type,
                    rawFormat = format,
                    sampleRate = frequency,
                    channels,
                    bytesPerSample,
                    sampleFormat = isFloat ? "F32" : "S16",
                    frameCount = bufferLength,
                    guestByteLength = checked((int)bufferLength * channels * bytesPerSample),
                    preservesGuestFormat,
                    hostInputChannels = preservesGuestFormat ? channels : 2,
                    hostInputFormat = preservesGuestFormat
                        ? (isFloat ? "F32" : "S16")
                        : "S16",
                    backend = backendName,
                });
        }

        return ctx.SetReturn(handle);
    }

    [SysAbiExport(
        Nid = "s1--uE9mBFw",
        ExportName = "sceAudioOutClose",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutClose(CpuContext ctx)
    {
        var handle = unchecked((int)ctx[CpuRegister.Rdi]);
        if (!Ports.TryRemove(handle, out var port))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        if (port.Diagnostics is not null && GuestAudioDiagnostics.Enabled)
        {
            GuestAudioDiagnostics.Record(
                "audioout.port-close",
                new
                {
                    portHandle = handle,
                    portType = port.Type,
                    sampleRate = port.Frequency,
                    channels = port.Channels,
                    frameCount = port.BufferLength,
                    rawFormat = port.Format,
                    preservesGuestFormat = port.PreservesGuestFormat,
                    callCount = port.Diagnostics.Sequence,
                });
        }

        port.Dispose();
        return ctx.SetReturn(0);
    }

    [SysAbiExport(
        Nid = "GrQ9s4IrNaQ",
        ExportName = "sceAudioOutGetPortState",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutGetPortState(CpuContext ctx)
    {
        var handle = unchecked((int)ctx[CpuRegister.Rdi]);
        var stateAddress = ctx[CpuRegister.Rsi];
        if (stateAddress == 0 || !Ports.TryGetValue(handle, out var port))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        // Same rule as AudioOut2 PortGetState: never bulk-write onto the caller
        // stack. Some titles place small locals next to the canary; a full
        // SceAudioOutPortState write smashes it.
        if (IsGuestStackAddress(stateAddress))
        {
            return ctx.SetReturn(0);
        }

        // SceAudioOutPortState: report a connected primary output at full volume
        // so pacing/mixing code sees a live port. We do no host rerouting, so
        // rerouteCounter and flag stay zero.
        Span<byte> state = stackalloc byte[16];
        state.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(state, 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(
            state[2..], (ushort)port.Channels);
        state[7] = 127;
        if (!ctx.Memory.TryWrite(stateAddress, state))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        return ctx.SetReturn(0);
    }

    private static bool IsGuestStackAddress(ulong value) =>
        value >= 0x0000_7FF0_0000_0000UL && value <= 0x0000_7FFF_FFFF_FFFFUL;

    [SysAbiExport(
        Nid = "w3PdaSTSwGE",
        ExportName = "sceAudioOutOutputs",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutOutputs(CpuContext ctx)
    {
        var parameterAddress = ctx[CpuRegister.Rdi];
        var outputCount = unchecked((uint)ctx[CpuRegister.Rsi]);
        if (outputCount == 0 || outputCount > AudioOutMaximumOutputCount)
        {
            return ctx.SetReturn(AudioOutErrorPortFull);
        }

        if (parameterAddress == 0)
        {
            return ctx.SetReturn(AudioOutErrorInvalidPointer);
        }

        var count = checked((int)outputCount);
        Span<byte> parameterBytes =
            stackalloc byte[AudioOutMaximumOutputCount * AudioOutOutputParamSize];
        parameterBytes = parameterBytes[..checked(count * AudioOutOutputParamSize)];
        if (!ctx.Memory.TryRead(parameterAddress, parameterBytes))
        {
            return ctx.SetReturn(AudioOutErrorInvalidPointer);
        }

        Span<OutputDescriptor> descriptors = stackalloc OutputDescriptor[count];
        for (var i = 0; i < count; i++)
        {
            var entry = parameterBytes.Slice(i * AudioOutOutputParamSize, AudioOutOutputParamSize);
            descriptors[i] = new OutputDescriptor(
                BinaryPrimitives.ReadInt32LittleEndian(entry),
                BinaryPrimitives.ReadUInt64LittleEndian(entry[8..]));
        }

        return ctx.SetReturn(SubmitOutputs(ctx, descriptors));
    }

    [SysAbiExport(
        Nid = "QOQtbeDqsT4",
        ExportName = "sceAudioOutOutput",
        Target = Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutOutput(CpuContext ctx)
    {
        var handle = unchecked((int)ctx[CpuRegister.Rdi]);
        var sourceAddress = ctx[CpuRegister.Rsi];
        if (!Ports.TryGetValue(handle, out var port))
        {
            // Host shutdown disposes the ports while guest audio threads are
            // still draining their last buffers; report success so the guest
            // winds down without a per-buffer error (and its WARN log flood).
            return ctx.SetReturn(_shutdown
                ? 0
                : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        var diagnosticsEnabled = port.Diagnostics is not null && GuestAudioDiagnostics.Enabled;
        var callSequence = diagnosticsEnabled ? port.Diagnostics!.Next() : 0;
        if (diagnosticsEnabled && GuestAudioDiagnostics.ShouldEmit(callSequence))
        {
            GuestAudioDiagnostics.Record(
                "audioout.output-call",
                new
                {
                    portHandle = handle,
                    operation = "output",
                    callSequence,
                    sourceAddress,
                    synchronizationOnly = sourceAddress == 0,
                });
        }

        if (sourceAddress == 0)
        {
            return ctx.SetReturn(0);
        }

        var buffer = ArrayPool<byte>.Shared.Rent(port.BufferByteLength);
        try
        {
            var source = buffer.AsSpan(0, port.BufferByteLength);
            if (!ctx.Memory.TryRead(sourceAddress, source))
            {
                return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
            }

            TraceOutput(handle, port, source);
            var observation = port.BufferDiagnostics is not null && diagnosticsEnabled
                ? port.BufferDiagnostics.Observe(
                    sourceAddress,
                    source,
                    checked((int)port.BufferLength),
                    port.Channels,
                    port.BytesPerSample,
                    port.IsFloat)
                : default;

            if (port.Backend is null)
            {
                if (diagnosticsEnabled && observation.Emit)
                {
                    GuestAudioDiagnostics.Record(
                        "audioout.host-submit",
                        new
                        {
                            portHandle = handle,
                            callSequence,
                            accepted = false,
                            reason = "backend-unavailable",
                            sourceAddress,
                            inputFingerprint = observation.Fingerprint,
                            input = new
                            {
                                leftPeak = observation.Metrics.LeftPeak,
                                rightPeak = observation.Metrics.RightPeak,
                                leftRms = observation.Metrics.LeftRms,
                                rightRms = observation.Metrics.RightRms,
                                otherPeak = observation.Metrics.OtherPeak,
                            },
                        });
                }

                port.PaceSilence();
                return ctx.SetReturn(0);
            }

            var outputLength = port.PreservesGuestFormat
                ? port.BufferByteLength
                : checked((int)port.BufferLength * AudioPcmConversion.OutputFrameSize);
            var output = ArrayPool<byte>.Shared.Rent(outputLength);
            try
            {
                ConvertForHost(port, source, output.AsSpan(0, outputLength));
                var outputSpan = output.AsSpan(0, outputLength);
                var submitStart = diagnosticsEnabled ? Stopwatch.GetTimestamp() : 0;
                var accepted = port.Backend.Submit(outputSpan);
                var submitTicks = diagnosticsEnabled
                    ? Stopwatch.GetTimestamp() - submitStart
                    : 0;
                if (diagnosticsEnabled && observation.Emit)
                {
                    RecordClassicSubmission(
                        port,
                        callSequence,
                        sourceAddress,
                        observation,
                        outputSpan,
                        accepted,
                        submitTicks,
                        conversionPath: port.PreservesGuestFormat
                            ? "preserved-guest-layout"
                            : "converted-stereo",
                        hostChannels: port.PreservesGuestFormat ? port.Channels : 2,
                        hostBytesPerSample: port.PreservesGuestFormat
                            ? port.BytesPerSample
                            : sizeof(short),
                        hostIsFloat: port.PreservesGuestFormat && port.IsFloat);
                }

                if (!accepted)
                {
                    port.PaceSilence();
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(output);
            }

            return ctx.SetReturn(0);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static int SubmitOutputs(CpuContext ctx, ReadOnlySpan<OutputDescriptor> descriptors)
    {
        var resolvedArray = ArrayPool<ResolvedOutput>.Shared.Rent(descriptors.Length);
        var resolved = resolvedArray.AsSpan(0, descriptors.Length);
        resolved.Clear();

        Span<int> lockOrder = stackalloc int[descriptors.Length];
        var acquiredLocks = 0;
        try
        {
            uint bufferLength = 0;
            for (var i = 0; i < descriptors.Length; i++)
            {
                var descriptor = descriptors[i];
                for (var previous = 0; previous < i; previous++)
                {
                    if (resolved[previous].Handle == descriptor.Handle)
                    {
                        return AudioOutErrorInvalidPort;
                    }
                }

                if (!Ports.TryGetValue(descriptor.Handle, out var port))
                {
                    return _shutdown ? 0 : AudioOutErrorInvalidPort;
                }

                if (i == 0)
                {
                    bufferLength = port.BufferLength;
                }
                else if (port.BufferLength != bufferLength)
                {
                    return AudioOutErrorInvalidSize;
                }

                resolved[i].Handle = descriptor.Handle;
                resolved[i].SourceAddress = descriptor.SourceAddress;
                resolved[i].Port = port;
                resolved[i].CallSequence = port.Diagnostics is not null && GuestAudioDiagnostics.Enabled
                    ? port.Diagnostics.Next()
                    : 0;
                lockOrder[i] = i;
            }

            var diagnosticsEnabled = GuestAudioDiagnostics.Enabled;
            var emitBatch = false;
            if (diagnosticsEnabled)
            {
                for (var i = 0; i < resolved.Length; i++)
                {
                    if (resolved[i].Port.Diagnostics is not null &&
                        GuestAudioDiagnostics.ShouldEmit(resolved[i].CallSequence))
                    {
                        emitBatch = true;
                        break;
                    }
                }
            }

            if (emitBatch)
            {
                var first = resolved[0];
                var last = resolved[^1];
                GuestAudioDiagnostics.Record(
                    "audioout.outputs-call",
                    new
                    {
                        operation = "outputs",
                        outputCount = resolved.Length,
                        firstPortHandle = first.Handle,
                        firstSourceAddress = first.SourceAddress,
                        firstCallSequence = first.CallSequence,
                        lastPortHandle = last.Handle,
                        lastSourceAddress = last.SourceAddress,
                        lastCallSequence = last.CallSequence,
                    });
            }

            // Every batch takes port locks in handle order. Two guest threads can
            // submit overlapping batches in a different descriptor order without
            // deadlocking each other.
            for (var i = 1; i < lockOrder.Length; i++)
            {
                var index = lockOrder[i];
                var position = i;
                while (position > 0 &&
                       resolved[lockOrder[position - 1]].Handle > resolved[index].Handle)
                {
                    lockOrder[position] = lockOrder[position - 1];
                    position--;
                }

                lockOrder[position] = index;
            }

            for (; acquiredLocks < lockOrder.Length; acquiredLocks++)
            {
                Monitor.Enter(resolved[lockOrder[acquiredLocks]].Port.SubmissionGate);
            }

            // AudioOutClose removes the handle before waiting for SubmissionGate.
            // Recheck after acquiring all gates so a close racing this batch cannot
            // turn a validated submission into a write to a disposed backend.
            for (var i = 0; i < resolved.Length; i++)
            {
                if (!Ports.TryGetValue(resolved[i].Handle, out var current) ||
                    !ReferenceEquals(current, resolved[i].Port))
                {
                    return _shutdown ? 0 : AudioOutErrorInvalidPort;
                }
            }

            // Stage every guest buffer before the first host submission. A bad
            // pointer in a later descriptor therefore cannot partially enqueue the
            // earlier ports.
            for (var i = 0; i < resolved.Length; i++)
            {
                ref var output = ref resolved[i];
                if (output.SourceAddress == 0)
                {
                    continue;
                }

                var sourceBuffer = ArrayPool<byte>.Shared.Rent(output.Port.BufferByteLength);
                try
                {
                    var source = sourceBuffer.AsSpan(0, output.Port.BufferByteLength);
                    if (!ctx.Memory.TryRead(output.SourceAddress, source))
                    {
                        return AudioOutErrorInvalidPointer;
                    }

                    TraceOutput(output.Handle, output.Port, source);
                    if (output.Port.BufferDiagnostics is not null && diagnosticsEnabled)
                    {
                        output.BufferObservation = output.Port.BufferDiagnostics.Observe(
                            output.SourceAddress,
                            source,
                            checked((int)output.Port.BufferLength),
                            output.Port.Channels,
                            output.Port.BytesPerSample,
                            output.Port.IsFloat);
                        output.HasBufferObservation = true;
                    }

                    output.HostBufferLength = output.Port.PreservesGuestFormat
                        ? output.Port.BufferByteLength
                        : checked((int)output.Port.BufferLength * AudioPcmConversion.OutputFrameSize);
                    output.HostBuffer = ArrayPool<byte>.Shared.Rent(output.HostBufferLength);
                    ConvertForHost(output.Port, source, output.HostBuffer.AsSpan(0, output.HostBufferLength));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(sourceBuffer);
                }
            }

            PortState? pacingPort = null;
            for (var i = 0; i < resolved.Length; i++)
            {
                ref var output = ref resolved[i];
                var accepted = false;
                var reason = string.Empty;
                var submitTicks = 0L;
                if (output.HostBuffer is null)
                {
                    reason = "null-buffer";
                }
                else if (output.Port.Backend is null)
                {
                    reason = "backend-unavailable";
                }
                else
                {
                    var outputSpan = output.HostBuffer.AsSpan(0, output.HostBufferLength);
                    var submitStart = diagnosticsEnabled &&
                                      output.HasBufferObservation &&
                                      output.BufferObservation.Emit
                        ? Stopwatch.GetTimestamp()
                        : 0;
                    accepted = output.Port.Backend.Submit(outputSpan);
                    if (submitStart != 0)
                    {
                        submitTicks = Stopwatch.GetTimestamp() - submitStart;
                    }

                    if (!accepted)
                    {
                        reason = "host-rejected";
                    }

                    if (diagnosticsEnabled &&
                        output.HasBufferObservation &&
                        output.BufferObservation.Emit)
                    {
                        RecordClassicSubmission(
                            output.Port,
                            output.CallSequence,
                            output.SourceAddress,
                            output.BufferObservation,
                            outputSpan,
                            accepted,
                            submitTicks,
                            conversionPath: output.Port.PreservesGuestFormat
                                ? "preserved-guest-layout"
                                : "converted-stereo",
                            hostChannels: output.Port.PreservesGuestFormat
                                ? output.Port.Channels
                                : 2,
                            hostBytesPerSample: output.Port.PreservesGuestFormat
                                ? output.Port.BytesPerSample
                                : sizeof(short),
                            hostIsFloat: output.Port.PreservesGuestFormat && output.Port.IsFloat,
                            reason: accepted ? string.Empty : reason);
                    }
                }

                if (!accepted)
                {
                    if (pacingPort is null ||
                        HasLongerBufferDuration(output.Port, pacingPort))
                    {
                        pacingPort = output.Port;
                    }
                }
            }

            // A batch is one guest scheduling point. When one or more ports have
            // no usable backend, pace once using the longest affected buffer rather
            // than sleeping once per port.
            pacingPort?.PaceSilence();
            return checked((int)resolved[0].Port.BufferLength);
        }
        finally
        {
            for (var i = acquiredLocks - 1; i >= 0; i--)
            {
                Monitor.Exit(resolved[lockOrder[i]].Port.SubmissionGate);
            }

            for (var i = 0; i < resolved.Length; i++)
            {
                if (resolved[i].HostBuffer is { } hostBuffer)
                {
                    ArrayPool<byte>.Shared.Return(hostBuffer);
                }
            }

            ArrayPool<ResolvedOutput>.Shared.Return(resolvedArray, clearArray: true);
        }
    }

    private static void RecordClassicSubmission(
        PortState port,
        long callSequence,
        ulong sourceAddress,
        GuestAudioBufferObservation observation,
        ReadOnlySpan<byte> hostBuffer,
        bool accepted,
        long submitTicks,
        string conversionPath,
        int hostChannels,
        int hostBytesPerSample,
        bool hostIsFloat,
        string reason = "")
    {
        if (!GuestAudioDiagnostics.Enabled || !observation.Emit)
        {
            return;
        }

        var afterConversion = GuestAudioDiagnostics.MeasureInterleaved(
            hostBuffer,
            checked((int)port.BufferLength),
            hostChannels,
            hostBytesPerSample,
            hostIsFloat);
        GuestAudioDiagnostics.Record(
            "audioout.host-submit",
            new
            {
                portHandle = port.Handle,
                callSequence,
                sourceAddress,
                sourceByteLength = observation.ByteLength,
                sourceFingerprint = observation.Fingerprint,
                sameAddressAsPrevious = observation.SameAddressAsPrevious,
                sameContentAsPrevious = observation.SameContentAsPrevious,
                sameAddressCount = observation.SameAddressCount,
                sameContentCount = observation.SameContentCount,
                declared = new
                {
                    sampleRate = port.Frequency,
                    channels = port.Channels,
                    bytesPerSample = port.BytesPerSample,
                    sampleFormat = port.IsFloat ? "F32" : "S16",
                    frameCount = port.BufferLength,
                    byteLength = port.BufferByteLength,
                    rawFormat = port.Format,
                },
                volume = port.Volume,
                conversionPath,
                hostInput = new
                {
                    channels = hostChannels,
                    bytesPerSample = hostBytesPerSample,
                    sampleFormat = hostIsFloat ? "F32" : "S16",
                    fingerprint = GuestAudioDiagnostics.Fingerprint(hostBuffer),
                    leftPeak = afterConversion.LeftPeak,
                    rightPeak = afterConversion.RightPeak,
                    leftRms = afterConversion.LeftRms,
                    rightRms = afterConversion.RightRms,
                    otherPeak = afterConversion.OtherPeak,
                },
                guestInput = new
                {
                    leftPeak = observation.Metrics.LeftPeak,
                    rightPeak = observation.Metrics.RightPeak,
                    leftRms = observation.Metrics.LeftRms,
                    rightRms = observation.Metrics.RightRms,
                    otherPeak = observation.Metrics.OtherPeak,
                },
                hostConversionBoundary = port.PreservesGuestFormat
                    ? "host-backend"
                    : "hle",
                accepted,
                reason,
                submitTicks,
                queuedPcmBytes = port.Backend?.QueuedPcmBytes ?? -1,
                queuedMilliseconds = port.Backend?.QueuedMilliseconds ?? -1,
            });
    }

    private static bool HasLongerBufferDuration(PortState candidate, PortState current) =>
        (ulong)candidate.BufferLength * current.Frequency >
        (ulong)current.BufferLength * candidate.Frequency;

    private static void ConvertForHost(PortState port, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (port.PreservesGuestFormat)
        {
            AudioPcmConversion.CopyWithVolume(source, destination, port.IsFloat, port.Volume);
            return;
        }

        AudioPcmConversion.ConvertToStereoPcm16(
            source,
            destination,
            checked((int)port.BufferLength),
            port.Channels,
            port.BytesPerSample,
            port.IsFloat,
            port.Volume);
    }

    private static void TraceOutput(int handle, PortState port, ReadOnlySpan<byte> source)
    {
        if (!_traceOutput)
        {
            return;
        }

        var n = Interlocked.Increment(ref _outputCount);
        if (n <= 8 || n % 200 == 0)
        {
            var peak = PeakAmplitude(source, port.IsFloat, port.BytesPerSample);
            Console.Error.WriteLine(
                $"[LOADER][TRACE] audioout.output#{n} handle={handle} bytes={source.Length} ch={port.Channels} float={port.IsFloat} vol={port.Volume:F2} peak={peak:F4} backend={(port.Backend is null ? "none" : "coreaudio")}");
        }
    }

    [SysAbiExport(
        Nid = "b+uAV89IlxE",
        ExportName = "sceAudioOutSetVolume",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceAudioOut")]
    public static int AudioOutSetVolume(CpuContext ctx)
    {
        var handle = unchecked((int)ctx[CpuRegister.Rdi]);
        var channelFlags = unchecked((uint)ctx[CpuRegister.Rsi]);
        var volumeArrayAddress = ctx[CpuRegister.Rdx];
        if (!Ports.TryGetValue(handle, out var port))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT);
        }

        var diagnosticsEnabled = port.Diagnostics is not null && GuestAudioDiagnostics.Enabled;
        var callSequence = diagnosticsEnabled ? port.Diagnostics!.Next() : 0;
        const int unityVolume = 32768;
        var maxVolume = 0;
        var found = false;
        if (volumeArrayAddress != 0)
        {
            Span<byte> raw = stackalloc byte[sizeof(int)];
            for (var channel = 0; channel < 8; channel++)
            {
                if ((channelFlags & (1u << channel)) == 0)
                {
                    continue;
                }

                if (!ctx.Memory.TryRead(volumeArrayAddress + (ulong)(channel * sizeof(int)), raw))
                {
                    return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
                }

                var value = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(raw);
                maxVolume = Math.Max(maxVolume, value);
                found = true;
            }
        }

        if (found)
        {
            port.Volume = Math.Clamp(maxVolume / (float)unityVolume, 0f, 1f);
        }

        if (diagnosticsEnabled && GuestAudioDiagnostics.ShouldEmit(callSequence))
        {
            GuestAudioDiagnostics.Record(
                "audioout.volume",
                new
                {
                    portHandle = handle,
                    callSequence,
                    channelFlags,
                    volumeArrayAddress,
                    found,
                    maximumGuestVolume = maxVolume,
                    normalizedVolume = port.Volume,
                });
        }

        return ctx.SetReturn(0);
    }

    // Peak normalized amplitude [0,1] of an interleaved PCM buffer, used only by
    // the SHARPEMU_LOG_AUDIO_OUT diagnostic to distinguish real audio from silence.
    private static float PeakAmplitude(ReadOnlySpan<byte> source, bool isFloat, int bytesPerSample)
    {
        var peak = 0f;
        if (isFloat && bytesPerSample == 4)
        {
            for (var i = 0; i + 4 <= source.Length; i += 4)
            {
                var v = Math.Abs(System.Buffers.Binary.BinaryPrimitives.ReadSingleLittleEndian(source.Slice(i, 4)));
                if (v > peak)
                {
                    peak = v;
                }
            }
        }
        else if (bytesPerSample == 2)
        {
            for (var i = 0; i + 2 <= source.Length; i += 2)
            {
                var v = Math.Abs(System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian(source.Slice(i, 2)) / 32768f);
                if (v > peak)
                {
                    peak = v;
                }
            }
        }

        return peak;
    }

    public static void ShutdownAllPorts()
    {
        Volatile.Write(ref _shutdown, true);
        foreach (var handle in Ports.Keys)
        {
            if (Ports.TryRemove(handle, out var port))
            {
                port.Dispose();
            }
        }
    }

    internal static void SetStreamFactoryForTests(Func<uint, IHostAudioStream?>? streamFactory) =>
        Volatile.Write(ref _streamFactoryForTests, streamFactory);

    internal static void ResetForTests()
    {
        foreach (var handle in Ports.Keys)
        {
            if (Ports.TryRemove(handle, out var port))
            {
                port.Dispose();
            }
        }

        _nextPortHandle = 0;
        _outputCount = 0;
        Volatile.Write(ref _shutdown, false);
        Volatile.Write(ref _streamFactoryForTests, null);
    }

    private static bool _shutdown;

    private static bool TryGetFormat(
        int rawFormat,
        out int channels,
        out int bytesPerSample,
        out bool isFloat)
    {
        var format = rawFormat & 0xFF;
        channels = format switch
        {
            0 or 3 => 1,
            1 or 4 => 2,
            2 or 5 or 6 or 7 => 8,
            _ => 0,
        };
        bytesPerSample = format is >= 3 and <= 5 or 7 ? 4 : 2;
        isFloat = bytesPerSample == 4;
        return channels != 0;
    }
}
