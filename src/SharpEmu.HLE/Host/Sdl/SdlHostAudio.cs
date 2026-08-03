// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;
using SDL;
using static SDL.SDL3;

namespace SharpEmu.HLE.Host.Sdl;

internal sealed unsafe class SdlHostAudio : IHostPcmAudioOutput
{
    /// <summary>
    /// Cap for streams this class paces itself (AudioOut). Blocking the guest
    /// here is that path's only pacing, so the device settles at this depth —
    /// it is the playback latency, and the floor under it is how much jitter the
    /// stream can absorb before it runs dry.
    /// </summary>
    private static readonly int TargetQueuedMilliseconds =
        int.TryParse(
            Environment.GetEnvironmentVariable("SHARPEMU_AUDIO_LATENCY_MS"),
            out var latencyMs) && latencyMs > 0
            ? latencyMs
            : 60;

    private const int MaximumWaitMilliseconds = 250;
    private static readonly object InitGate = new();
    private static bool _initialized;

    public string BackendName => "sdl3";

    /// <summary>
    /// Stereo PCM16 stream with a caller-chosen backpressure cap. Callers that
    /// pace the guest themselves pass a deeper cap so this class's backpressure
    /// does not fight their pacing.
    /// </summary>
    public IHostAudioStream OpenStereoPcm16Stream(uint sampleRate, int maxQueuedPcmBytes = 32 * 1024)
        => OpenStream(
            sampleRate,
            channels: 2,
            HostPcmFormat.Signed16,
            maxQueuedPcmBytes > 0 ? maxQueuedPcmBytes : 32 * 1024);

    /// <summary>
    /// Guest-format stream for AudioOut, which has no queue model of its own:
    /// blocking here is that path's only pacing, so the device settles at
    /// TargetQueuedMilliseconds and that depth is the playback latency.
    /// </summary>
    public IHostAudioStream OpenPcmStream(uint sampleRate, int channels, HostPcmFormat format)
    {
        var bytesPerSample = format == HostPcmFormat.Float32 ? sizeof(float) : sizeof(short);
        var cap = checked((int)((long)sampleRate * channels * bytesPerSample *
                                TargetQueuedMilliseconds / 1_000));
        return OpenStream(sampleRate, channels, format, cap);
    }

    private static IHostAudioStream OpenStream(
        uint sampleRate,
        int channels,
        HostPcmFormat format,
        int maximumQueuedBytes)
    {
        if (sampleRate is < 8_000 or > 384_000 || channels is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(
                sampleRate is < 8_000 or > 384_000 ? nameof(sampleRate) : nameof(channels));
        }

        EnsureInitialized();
        return new AudioStream(sampleRate, channels, format, maximumQueuedBytes);
    }

    private static void EnsureInitialized()
    {
        lock (InitGate)
        {
            if (_initialized)
            {
                return;
            }

            if ((SDL_WasInit(SDL_InitFlags.SDL_INIT_AUDIO) & SDL_InitFlags.SDL_INIT_AUDIO) == 0 &&
                !SDL_InitSubSystem(SDL_InitFlags.SDL_INIT_AUDIO))
            {
                throw new InvalidOperationException($"SDL audio initialization failed: {GetError()}");
            }

            _initialized = true;
        }
    }

    private static string GetError()
    {
        var error = Unsafe_SDL_GetError();
        return error is null ? "unknown SDL error" : Marshal.PtrToStringUTF8((nint)error) ?? "unknown SDL error";
    }

    private static readonly bool _traceQueue = string.Equals(
        Environment.GetEnvironmentVariable("SHARPEMU_LOG_AUDIO_QUEUE"),
        "1",
        StringComparison.Ordinal);

    private static int _nextStreamId;

    private sealed class AudioStream : IHostAudioStream, IHostAudioStreamDiagnostics
    {
        private readonly object _gate = new();
        private readonly int _maximumQueuedBytes;
        private readonly int _bytesPerFrame;
        private readonly uint _sampleRate;
        private readonly int _channels;
        private readonly SDL_AudioFormat _inputFormat;
        private readonly bool _diagnosticsEnabled;
        private readonly AudioSampleAccounting? _sampleAccounting;
        private readonly int _streamId = Interlocked.Increment(ref _nextStreamId);
        private SDL_AudioStream* _stream;
        private bool _disposed;
        private long _totalSubmittedInputBytes;
        private HostAudioProgressState _progressState = HostAudioProgressState.Starting;
        private double _lastEstimatedPlayedSeconds;
        private string _diagnosticOwner = string.Empty;
        private string _diagnosticSource = string.Empty;
        private string _diagnosticPhase = "open";
        private long _diagnosticMovieInstanceId;
        private long _diagnosticHostMovieGeneration;
        private bool _diagnosticOpenRecorded;
        private long _nextDiagnosticTimestamp;
        private long _failedSubmissionCount;
        private long _overTargetSubmissionCount;
        private long _queueQueryFailureCount;
        private long _diagnosticSubmissionCount;
        private long _underrunCount;
        private long _underrunTicks;
        private long _emptySinceTimestamp;
        private bool _queueIsEmpty;
        private long _clockReportAcceptedCount;
        private long _clockReportRejectedCount;
        private bool _hasDeviceState;
        private string _lastDeviceSignature = string.Empty;
        private long _deviceStateTransitionCount;

        // Queue diagnostics for the current report window.
        private long _windowStart = Stopwatch.GetTimestamp();
        private long _submissions;
        private long _submittedBytes;
        private long _blockedTicks;
        private long _overTargetSubmissions;
        private readonly AudioQueueObservationCounters? _queueObservationCounters;
        private int _minQueuedBytes = int.MaxValue;
        private int _maxQueuedBytes;
        private long _queuedByteSum;

        public AudioStream(
            uint sampleRate,
            int channels,
            HostPcmFormat format,
            int maximumQueuedBytes)
        {
            var bytesPerSample = format == HostPcmFormat.Float32 ? sizeof(float) : sizeof(short);
            _bytesPerFrame = channels * bytesPerSample;
            _sampleRate = sampleRate;
            _channels = channels;
            _inputFormat = format == HostPcmFormat.Float32
                ? SDL_AudioFormat.SDL_AUDIO_F32LE
                : SDL_AudioFormat.SDL_AUDIO_S16LE;
            _diagnosticsEnabled = HostAudioDiagnostics.Enabled;
            _sampleAccounting = _diagnosticsEnabled
                ? new AudioSampleAccounting(_bytesPerFrame)
                : null;
            _queueObservationCounters = _diagnosticsEnabled || _traceQueue
                ? new AudioQueueObservationCounters()
                : null;
            var spec = new SDL_AudioSpec
            {
                format = _inputFormat,
                channels = checked((byte)channels),
                freq = checked((int)sampleRate),
            };

            _stream = SDL_OpenAudioDeviceStream(
                SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK,
                &spec,
                null,
                IntPtr.Zero);
            if (_stream is null)
            {
                throw new InvalidOperationException($"SDL audio stream creation failed: {GetError()}");
            }

            if (!SDL_ResumeAudioStreamDevice(_stream))
            {
                SDL_DestroyAudioStream(_stream);
                _stream = null;
                throw new InvalidOperationException($"SDL audio stream start failed: {GetError()}");
            }

            _maximumQueuedBytes = maximumQueuedBytes;
        }

        public int QueuedMilliseconds
        {
            get
            {
                lock (_gate)
                {
                    if (_disposed || _stream is null)
                    {
                        return -1;
                    }

                    var bytesPerSecond = (double)_bytesPerFrame * _sampleRate;
                    var queuedBytes = ReadQueuedBytesLocked();
                    ObserveQueueLocked(queuedBytes, Stopwatch.GetTimestamp());
                    return bytesPerSecond <= 0
                        ? -1
                        : queuedBytes < 0
                            ? -1
                            : (int)(queuedBytes / bytesPerSecond * 1000.0);
                }
            }
        }

        public HostAudioProgress Progress
        {
            get
            {
                lock (_gate)
                {
                    return ReadProgressLocked();
                }
            }
        }

        public void MarkCompleted()
        {
            lock (_gate)
            {
                if (!_disposed && _progressState is not HostAudioProgressState.Failed)
                {
                    _progressState = HostAudioProgressState.Completed;
                }
            }
        }

        public void MarkFailed()
        {
            lock (_gate)
            {
                if (!_disposed)
                {
                    _progressState = HostAudioProgressState.Failed;
                }
            }
        }

        public bool Submit(ReadOnlySpan<byte> pcm)
        {
            if (pcm.IsEmpty)
            {
                return true;
            }

            HostAudioStreamDiagnosticSnapshot? diagnosticSnapshot = null;
            var submitted = false;
            lock (_gate)
            {
                if (_disposed || _stream is null)
                {
                    return false;
                }

                var blockStart = Stopwatch.GetTimestamp();
                var deadline = blockStart +
                               (Stopwatch.Frequency * MaximumWaitMilliseconds / 1_000);
                var queued = ReadQueuedBytesLocked();
                ObserveQueueLocked(queued, blockStart);
                var overrun = false;
                while (queued > _maximumQueuedBytes)
                {
                    if (Stopwatch.GetTimestamp() >= deadline)
                    {
                        // Enqueue anyway rather than discarding the buffer. A gap in
                        // the stream is an audible click; the extra latency of one
                        // over-deep submission is not, and the queue recovers as soon
                        // as the device drains back under the cap.
                        overrun = true;
                        break;
                    }

                    Thread.Sleep(1);
                    queued = ReadQueuedBytesLocked();
                    ObserveQueueLocked(queued, Stopwatch.GetTimestamp());
                }

                RecordSubmission(queued, blockStart, overTarget: overrun, bytes: pcm.Length);
                fixed (byte* data = pcm)
                {
                    submitted = SDL_PutAudioStreamData(_stream, (nint)data, pcm.Length);
                }

                if (!submitted)
                {
                    _progressState = HostAudioProgressState.Failed;
                }

                if (_sampleAccounting is not null)
                {
                    _sampleAccounting?.RecordSubmission(pcm.Length, submitted);
                    _diagnosticSubmissionCount++;
                    if (!submitted)
                    {
                        _failedSubmissionCount++;
                    }

                    if (overrun)
                    {
                        _overTargetSubmissionCount++;
                    }
                }

                if (submitted)
                {
                    // This is only an estimate of input no longer queued in SDL's
                    // input-format queue. SDL does not expose exact physical or
                    // audible device consumption here.
                    _totalSubmittedInputBytes += pcm.Length;
                    var bytesPerSecond = (double)_bytesPerFrame * _sampleRate;
                    if (bytesPerSecond > 0 && queued >= 0)
                    {
                        var estimatedPlayedSeconds = Math.Max(
                            0,
                            _totalSubmittedInputBytes - queued - pcm.Length) /
                            bytesPerSecond;
                        var reportAccepted = GuestAudioClock.Report(estimatedPlayedSeconds);
                        _lastEstimatedPlayedSeconds = Math.Max(
                            _lastEstimatedPlayedSeconds,
                            estimatedPlayedSeconds);
                        _progressState = HostAudioProgressState.Running;
                        if (_sampleAccounting is not null)
                        {
                            if (reportAccepted)
                            {
                                _clockReportAcceptedCount++;
                            }
                            else
                            {
                                _clockReportRejectedCount++;
                            }
                        }
                    }
                }

                if (ShouldCaptureDiagnosticLocked(Stopwatch.GetTimestamp()))
                {
                    diagnosticSnapshot = CaptureDiagnosticSnapshotLocked();
                }
            }

            if (diagnosticSnapshot is { } snapshot)
            {
                HostAudioDiagnostics.RecordStreamSummary(snapshot);
            }

            return submitted;
        }

        /// <summary>
        /// Samples the queue depth at the moment the guest was allowed to write.
        /// That depth is the playback latency the guest's audio is subject to, so
        /// it is the number to look at when the sound is late; an observed depth
        /// of zero is a genuine underrun, which is what a crackle sounds like.
        /// Caller holds <see cref="_gate"/>.
        /// </summary>
        private void RecordSubmission(int queuedBytes, long blockStart, bool overTarget, int bytes)
        {
            if (!_traceQueue)
            {
                return;
            }

            var now = Stopwatch.GetTimestamp();
            _submissions++;
            _submittedBytes += bytes;
            _blockedTicks += now - blockStart;
            _queuedByteSum += queuedBytes;
            _minQueuedBytes = Math.Min(_minQueuedBytes, queuedBytes);
            _maxQueuedBytes = Math.Max(_maxQueuedBytes, queuedBytes);
            if (overTarget)
            {
                _overTargetSubmissions++;
            }

            _queueObservationCounters!.RecordTraceSubmission(queuedBytes);

            var elapsedTicks = now - _windowStart;
            if (elapsedTicks < Stopwatch.Frequency)
            {
                return;
            }

            _windowStart = now;
            var seconds = elapsedTicks / (double)Stopwatch.Frequency;
            var bytesPerSecond = (double)_bytesPerFrame * _sampleRate;
            Console.Error.WriteLine(
                $"[PERF][AUDIO] stream#{_streamId} {seconds:F1}s " +
                $"queued_ms min={ToMilliseconds(_minQueuedBytes, bytesPerSecond):F0} " +
                $"avg={ToMilliseconds((int)(_queuedByteSum / Math.Max(1, _submissions)), bytesPerSecond):F0} " +
                $"max={ToMilliseconds(_maxQueuedBytes, bytesPerSecond):F0} " +
                $"cap={ToMilliseconds(_maximumQueuedBytes, bytesPerSecond):F0} " +
                $"submits/s={_submissions / seconds:F0} " +
                $"fill={_submittedBytes / seconds / bytesPerSecond * 100.0:F0}% " +
                $"blocked={_blockedTicks * 100.0 / elapsedTicks:F0}% " +
                $"empty={_queueObservationCounters!.TakeTraceWindowEmptyQueueObservations()} " +
                $"over_target={_overTargetSubmissions}");

            _submissions = 0;
            _submittedBytes = 0;
            _blockedTicks = 0;
            _overTargetSubmissions = 0;
            _minQueuedBytes = int.MaxValue;
            _maxQueuedBytes = 0;
            _queuedByteSum = 0;
        }

        public void SetDiagnosticContext(
            string owner,
            string source,
            long movieInstanceId,
            long hostMovieGeneration)
        {
            if (!_diagnosticsEnabled || !HostAudioDiagnostics.Enabled)
            {
                return;
            }

            HostAudioStreamDiagnosticSnapshot? snapshot = null;
            lock (_gate)
            {
                if (_disposed || _stream is null)
                {
                    return;
                }

                _diagnosticOwner = owner;
                _diagnosticSource = HostAudioDiagnostics.Identity(source);
                _diagnosticMovieInstanceId = movieInstanceId;
                _diagnosticHostMovieGeneration = hostMovieGeneration;
                if (!_diagnosticOpenRecorded)
                {
                    _diagnosticOpenRecorded = true;
                    snapshot = CaptureDiagnosticSnapshotLocked();
                }
            }

            if (snapshot is { } opened)
            {
                HostAudioDiagnostics.RecordStreamOpen(opened);
            }
        }

        public void SetDiagnosticPhase(string phase)
        {
            if (!_diagnosticsEnabled || !HostAudioDiagnostics.Enabled)
            {
                return;
            }

            HostAudioStreamDiagnosticSnapshot? snapshot = null;
            lock (_gate)
            {
                if (_disposed || _stream is null ||
                    string.Equals(_diagnosticPhase, phase, StringComparison.Ordinal))
                {
                    return;
                }

                _diagnosticPhase = phase;
                snapshot = CaptureDiagnosticSnapshotLocked();
            }

            if (snapshot is { } phaseSnapshot)
            {
                HostAudioDiagnostics.RecordStreamPhase(phaseSnapshot);
            }
        }

        public HostAudioStreamDiagnosticSnapshot GetDiagnosticSnapshot()
        {
            if (!_diagnosticsEnabled || !HostAudioDiagnostics.Enabled)
            {
                return default;
            }

            lock (_gate)
            {
                return _disposed || _stream is null
                    ? default
                    : CaptureDiagnosticSnapshotLocked();
            }
        }

        private int ReadQueuedBytesLocked()
        {
            var queuedBytes = SDL_GetAudioStreamQueued(_stream);
            if (queuedBytes < 0 && _sampleAccounting is not null)
            {
                _queueQueryFailureCount++;
            }

            return queuedBytes;
        }

        private HostAudioProgress ReadProgressLocked()
        {
            if (_disposed || _stream is null)
            {
                return new(HostAudioProgressState.Disposed, _lastEstimatedPlayedSeconds);
            }

            if (_progressState is HostAudioProgressState.Completed or
                HostAudioProgressState.Failed)
            {
                return new(_progressState, _lastEstimatedPlayedSeconds);
            }

            var queuedBytes = ReadQueuedBytesLocked();
            ObserveQueueLocked(queuedBytes, Stopwatch.GetTimestamp());
            if (queuedBytes < 0)
            {
                return new(HostAudioProgressState.Unavailable, _lastEstimatedPlayedSeconds);
            }

            var bytesPerSecond = (double)_bytesPerFrame * _sampleRate;
            if (bytesPerSecond <= 0)
            {
                return new(HostAudioProgressState.Unavailable, _lastEstimatedPlayedSeconds);
            }

            _lastEstimatedPlayedSeconds = Math.Max(
                _lastEstimatedPlayedSeconds,
                Math.Max(0, _totalSubmittedInputBytes - queuedBytes) / bytesPerSecond);
            _progressState = _totalSubmittedInputBytes == 0
                ? HostAudioProgressState.Starting
                : queuedBytes == 0
                    ? HostAudioProgressState.TemporaryUnderrun
                    : HostAudioProgressState.Running;
            return new(_progressState, _lastEstimatedPlayedSeconds);
        }

        private void ObserveQueueLocked(int queuedBytes, long timestamp)
        {
            if (_sampleAccounting is null)
            {
                return;
            }

            if (queuedBytes == 0)
            {
                _queueObservationCounters!.RecordDiagnosticObservation(queuedBytes);
                if (!_queueIsEmpty)
                {
                    _queueIsEmpty = true;
                    _underrunCount++;
                    _emptySinceTimestamp = timestamp;
                }
            }
            else if (queuedBytes > 0 && _queueIsEmpty)
            {
                _queueIsEmpty = false;
                _underrunTicks += Math.Max(0, timestamp - _emptySinceTimestamp);
                _emptySinceTimestamp = 0;
            }
        }

        private bool ShouldCaptureDiagnosticLocked(long timestamp)
        {
            if (!_diagnosticsEnabled || !HostAudioDiagnostics.Enabled)
            {
                return false;
            }

            if (_nextDiagnosticTimestamp != 0 &&
                timestamp < _nextDiagnosticTimestamp)
            {
                return false;
            }

            _nextDiagnosticTimestamp = timestamp + Stopwatch.Frequency;
            return true;
        }

        private HostAudioStreamDiagnosticSnapshot CaptureDiagnosticSnapshotLocked()
        {
            var queuedBytes = ReadQueuedBytesLocked();
            var availableBytes = SDL_GetAudioStreamAvailable(_stream);
            var deviceId = SDL_GetAudioStreamDevice(_stream);
            var deviceIdValue = unchecked((uint)deviceId);
            var deviceName = deviceIdValue == 0
                ? string.Empty
                : SDL_GetAudioDeviceName(deviceId) ?? string.Empty;
            var devicePaused = deviceIdValue != 0 && SDL_AudioDevicePaused(deviceId);
            var deviceSpec = default(SDL_AudioSpec);
            var deviceBufferFrames = 0;
            var hasDeviceFormat = deviceIdValue != 0 &&
                                  SDL_GetAudioDeviceFormat(
                                      deviceId,
                                      &deviceSpec,
                                      &deviceBufferFrames);
            var inputSpec = default(SDL_AudioSpec);
            var outputSpec = default(SDL_AudioSpec);
            var hasStreamFormat = SDL_GetAudioStreamFormat(
                _stream,
                &inputSpec,
                &outputSpec);
            var streamFrequencyRatio = SDL_GetAudioStreamFrequencyRatio(_stream);
            var accounting = _sampleAccounting?.Snapshot(queuedBytes);
            var accountingSnapshot = accounting ?? default;
            var now = Stopwatch.GetTimestamp();
            var deviceSignature = string.Concat(
                deviceIdValue,
                ":",
                deviceName,
                ":",
                devicePaused,
                ":",
                hasDeviceFormat ? deviceSpec.freq : 0,
                ":",
                hasDeviceFormat ? deviceSpec.channels : 0,
                ":",
                hasDeviceFormat ? deviceSpec.format.ToString() : string.Empty);
            if (!_hasDeviceState ||
                !string.Equals(_lastDeviceSignature, deviceSignature, StringComparison.Ordinal))
            {
                _hasDeviceState = true;
                _lastDeviceSignature = deviceSignature;
                _deviceStateTransitionCount++;
            }

            var underrunTicks = _underrunTicks;
            if (_queueIsEmpty && _emptySinceTimestamp != 0)
            {
                underrunTicks += Math.Max(0, now - _emptySinceTimestamp);
            }

            return new HostAudioStreamDiagnosticSnapshot
            {
                StreamId = _streamId,
                Owner = _diagnosticOwner,
                Source = _diagnosticSource,
                MovieInstanceId = _diagnosticMovieInstanceId,
                HostMovieGeneration = _diagnosticHostMovieGeneration,
                Phase = _diagnosticPhase,
                InputSampleRate = _sampleRate,
                InputChannels = _channels,
                InputBytesPerFrame = _bytesPerFrame,
                StreamInputFrequency = hasStreamFormat ? inputSpec.freq : 0,
                StreamInputChannels = hasStreamFormat ? inputSpec.channels : 0,
                StreamInputFormat = hasStreamFormat
                    ? inputSpec.format.ToString()
                    : _inputFormat.ToString(),
                StreamOutputFrequency = hasStreamFormat ? outputSpec.freq : 0,
                StreamOutputChannels = hasStreamFormat ? outputSpec.channels : 0,
                StreamOutputFormat = hasStreamFormat
                    ? outputSpec.format.ToString()
                    : string.Empty,
                MaximumQueuedBytes = _maximumQueuedBytes,
                MaximumQueuedFrames = _maximumQueuedBytes / _bytesPerFrame,
                MaximumQueuedMilliseconds = _maximumQueuedBytes /
                    ((double)_bytesPerFrame * _sampleRate) * 1000.0,
                QueuedInputBytes = queuedBytes,
                QueuedInputFrames = queuedBytes < 0
                    ? -1
                    : queuedBytes / _bytesPerFrame,
                QueuedInputMilliseconds = queuedBytes < 0
                    ? -1
                    : queuedBytes / ((double)_bytesPerFrame * _sampleRate) * 1000.0,
                ConvertedAvailableBytes = availableBytes,
                SubmittedInputBytes = accountingSnapshot.SubmittedInputBytes,
                SubmittedInputFrames = accountingSnapshot.SubmittedInputFrames,
                DequeuedInputBytes = accountingSnapshot.DequeuedInputBytes,
                DequeuedInputFrames = accountingSnapshot.DequeuedInputFrames,
                FailedSubmissionBytes = accountingSnapshot.FailedSubmissionBytes,
                FailedSubmissionFrames = accountingSnapshot.FailedSubmissionFrames,
                SubmissionCount = _diagnosticSubmissionCount,
                FailedSubmissionCount = _failedSubmissionCount,
                OverTargetSubmissionCount = _overTargetSubmissionCount,
                EmptyQueueObservations = _queueObservationCounters
                    ?.DiagnosticEmptyQueueObservations ?? 0,
                UnderrunCount = _underrunCount,
                UnderrunDurationMilliseconds = underrunTicks * 1000.0 / Stopwatch.Frequency,
                QueueQueryFailureCount = _queueQueryFailureCount,
                DeviceId = deviceIdValue,
                DeviceName = deviceName,
                DeviceState = deviceIdValue == 0
                    ? "unavailable"
                    : devicePaused
                        ? "paused"
                        : "running",
                DevicePaused = devicePaused,
                DeviceFrequency = hasDeviceFormat ? deviceSpec.freq : 0,
                DeviceChannels = hasDeviceFormat ? deviceSpec.channels : 0,
                DeviceFormat = hasDeviceFormat ? deviceSpec.format.ToString() : string.Empty,
                DeviceBufferFrames = hasDeviceFormat ? deviceBufferFrames : 0,
                DeviceStateTransitionCount = _deviceStateTransitionCount,
                StreamFrequencyRatio = streamFrequencyRatio,
                CallbackAvailable = false,
                CallbackRequestedFrames = 0,
                CallbackSuppliedFrames = 0,
                ClockReportAcceptedCount = _clockReportAcceptedCount,
                ClockReportRejectedCount = _clockReportRejectedCount,
                LastEstimatedPlayedSeconds = _lastEstimatedPlayedSeconds,
                GlobalGuestAudioClockSeconds = GuestAudioClock.PlayedSeconds,
            };
        }

        private static double ToMilliseconds(int bytes, double bytesPerSecond) =>
            bytesPerSecond <= 0 ? 0 : bytes / bytesPerSecond * 1000.0;

        public void Dispose()
        {
            HostAudioStreamDiagnosticSnapshot? diagnosticSnapshot = null;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                if (_diagnosticsEnabled && HostAudioDiagnostics.Enabled && _stream is not null)
                {
                    _diagnosticPhase = "disposed";
                    diagnosticSnapshot = CaptureDiagnosticSnapshotLocked();
                }

                _disposed = true;
                _progressState = HostAudioProgressState.Disposed;
                if (_stream is not null)
                {
                    SDL_ClearAudioStream(_stream);
                    SDL_DestroyAudioStream(_stream);
                    _stream = null;
                }
            }

            if (diagnosticSnapshot is { } snapshot)
            {
                HostAudioDiagnostics.RecordStreamSummary(snapshot);
            }
        }
    }
}
