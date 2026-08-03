// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using FFmpeg.AutoGen;
using SharpEmu.HLE.Host;

namespace SharpEmu.Libs.Media;

/// <summary>
/// Owns the audio side of one host movie. It deliberately opens its own input
/// context so video backpressure cannot stop audio packet progression. The
/// context owns one format input, codec, packet, frame, resampler, and host
/// stream; the conversion buffer and host queue are explicitly bounded.
/// </summary>
internal sealed unsafe class FfmpegMovieAudioDecoder :
    IMediaMovieAudio,
    IMediaAudioDiagnostics
{
    private const int OutputChannels = 2;
    private const int OutputBytesPerSample = sizeof(short);
    // Movie streams enable strict queue bounds on backends that otherwise
    // admit one final over-target submission while recovering from pressure.
    private const int MaximumQueuedPcmBytes = 32 * 1024;
    private const int MaximumSubmissionBytes = 16 * 1024;
    private const int MaximumSubmissionSamples =
        MaximumSubmissionBytes / (OutputChannels * OutputBytesPerSample);
    private const int MaximumInputChannels = 32;
    private const int MaximumInputSamplesPerConversion = 512;
    private const int MaximumAudioPacketBytes = 4 * 1024 * 1024;
    private const int MaximumDecodedAudioSamples = 1_048_576;

    private readonly object _stateGate = new();
    private readonly MovieAudioDrainLifecycle _drainLifecycle = new();
    private readonly double _declaredAudioDurationSeconds;
    private readonly int _audioStreamIndex;
    private readonly AVRational _audioTimeBase;
    private readonly long _formatStartTime;
    private readonly long _formatDuration;
    private readonly long _audioStreamStartTime;
    private readonly long _audioStreamDuration;
    private readonly int _audioInputSampleRate;
    private readonly int _audioInputChannels;
    private readonly AVSampleFormat _audioInputFormat;
    private readonly bool _diagnosticsEnabled;
    private readonly IHostAudioStreamDiagnostics? _audioStreamDiagnostics;
    private readonly bool _pauseSupported;
    private readonly AudioPcmStatistics? _pcmStatistics;
    private readonly byte[] _outputBuffer;
    private readonly CancellationTokenSource _stopSource = new();

    private AVFormatContext* _formatContext;
    private AVCodecContext* _codecContext;
    private AVFrame* _frame;
    private AVPacket* _packet;
    private SwrContext* _swrContext;
    private AVChannelLayout _swrInputLayout;
    private AVSampleFormat _swrInputFormat = AVSampleFormat.AV_SAMPLE_FMT_NONE;
    private int _swrInputSampleRate;
    private bool _swrInputLayoutValid;
    private MovieAudioSubmissionBoundary? _audioSubmission;
    private Thread? _pumpThread;
    private MovieAudioProgressState _state;
    private string _failureReason = string.Empty;
    private bool _started;
    private bool _paused;
    private long _decodedSourceFrames;
    private long _convertedOutputFrames;
    private long _submittedOutputFrames;
    private long _failedSubmissionFrames;
    private long _resamplerInputFrames;
    private long _resamplerOutputFrames;
    private double _lastEstimatedPlayedSeconds;
    private double _firstSourceTimestampSeconds = -1;
    private double _lastSourceTimestampSeconds = -1;
    private long _nextDiagnosticTimestamp;
    private string _diagnosticSource = string.Empty;
    private long _diagnosticMovieInstanceId;
    private long _diagnosticHostMovieGeneration;
    private int _disposed;

    private FfmpegMovieAudioDecoder(
        double declaredAudioDurationSeconds,
        int audioStreamIndex,
        AVRational audioTimeBase,
        int audioInputSampleRate,
        int audioInputChannels,
        AVSampleFormat audioInputFormat,
        AVFormatContext* formatContext,
        AVCodecContext* codecContext,
        AVFrame* frame,
        AVPacket* packet,
        SwrContext* swrContext,
        AVChannelLayout swrInputLayout,
        bool swrInputLayoutValid,
        MovieAudioSubmissionBoundary? audioSubmission,
        MovieAudioProgressState state,
        string failureReason,
        long formatStartTime,
        long formatDuration,
        long audioStreamStartTime,
        long audioStreamDuration)
    {
        _declaredAudioDurationSeconds = declaredAudioDurationSeconds;
        _audioStreamIndex = audioStreamIndex;
        _audioTimeBase = audioTimeBase;
        _formatStartTime = formatStartTime;
        _formatDuration = formatDuration;
        _audioStreamStartTime = audioStreamStartTime;
        _audioStreamDuration = audioStreamDuration;
        _audioInputSampleRate = audioInputSampleRate;
        _audioInputChannels = audioInputChannels;
        _audioInputFormat = audioInputFormat;
        _formatContext = formatContext;
        _codecContext = codecContext;
        _frame = frame;
        _packet = packet;
        _swrContext = swrContext;
        _swrInputLayout = swrInputLayout;
        _swrInputLayoutValid = swrInputLayoutValid;
        _audioSubmission = audioSubmission;
        _pauseSupported = audioSubmission?.SupportsPause == true;
        _state = state;
        _failureReason = failureReason;
        _diagnosticsEnabled = HostAudioDiagnostics.Enabled;
        _audioStreamDiagnostics = _diagnosticsEnabled
            ? audioSubmission?.Diagnostics
            : null;
        _pcmStatistics = _diagnosticsEnabled
            ? new AudioPcmStatistics(HostPcmFormat.Signed16, OutputChannels)
            : null;
        _outputBuffer = state == MovieAudioProgressState.Failed
            ? []
            : new byte[MaximumSubmissionBytes];
    }

    internal static FfmpegMovieAudioDecoder TryOpen(
        string path,
        long expectedFormatStartTime = long.MinValue,
        long expectedFormatDuration = long.MinValue)
    {
        FfmpegRuntime.EnsureInitialized();

        AVFormatContext* formatContext = null;
        AVCodecContext* codecContext = null;
        AVFrame* frame = null;
        AVPacket* packet = null;
        SwrContext* swrContext = null;
        AVChannelLayout swrInputLayout = default;
        var swrInputLayoutValid = false;
        IHostAudioStream? audioStream = null;
        MovieAudioSubmissionBoundary? audioSubmission = null;
        var declaredDurationSeconds = 0d;
        var audioTimeBase = default(AVRational);
        var formatStartTime = long.MinValue;
        var formatDuration = long.MinValue;
        var audioStreamStartTime = long.MinValue;
        var audioStreamDuration = long.MinValue;
        var audioInputSampleRate = 0;
        var audioInputChannels = 0;
        var audioInputFormat = AVSampleFormat.AV_SAMPLE_FMT_NONE;

        try
        {
            if (ffmpeg.avformat_open_input(&formatContext, path, null, null) < 0 ||
                formatContext is null)
            {
                return CreateFailed(path, "audio input open failed");
            }

            if (ffmpeg.avformat_find_stream_info(formatContext, null) < 0)
            {
                return CreateFailed(path, "audio stream information failed");
            }

            formatStartTime = formatContext->start_time;
            formatDuration = formatContext->duration;
            if ((expectedFormatStartTime != long.MinValue &&
                 formatStartTime != expectedFormatStartTime) ||
                (expectedFormatDuration != long.MinValue &&
                 formatDuration != expectedFormatDuration))
            {
                return CreateFailed(path, "independent audio origin mismatch");
            }

            AVCodec* decoder = null;
            var audioStreamIndex = ffmpeg.av_find_best_stream(
                formatContext,
                AVMediaType.AVMEDIA_TYPE_AUDIO,
                -1,
                -1,
                &decoder,
                0);
            if (audioStreamIndex < 0 || decoder is null)
            {
                return CreateFailed(path, "audio stream disappeared during independent open");
            }

            var stream = formatContext->streams[audioStreamIndex];
            audioTimeBase = stream->time_base;
            audioStreamStartTime = stream->start_time;
            audioStreamDuration = stream->duration;
            if (stream->duration > 0 && audioTimeBase.den > 0)
            {
                declaredDurationSeconds = stream->duration *
                    ((double)audioTimeBase.num / audioTimeBase.den);
            }

            codecContext = ffmpeg.avcodec_alloc_context3(decoder);
            if (codecContext is null ||
                ffmpeg.avcodec_parameters_to_context(
                    codecContext,
                    stream->codecpar) < 0 ||
                ffmpeg.avcodec_open2(codecContext, decoder, null) < 0)
            {
                return CreateFailed(path, "audio codec open failed", declaredDurationSeconds);
            }

            audioInputSampleRate = codecContext->sample_rate > 0
                ? codecContext->sample_rate
                : 48_000;
            audioInputChannels = codecContext->ch_layout.nb_channels;
            audioInputFormat = codecContext->sample_fmt;
            if (audioInputChannels <= 0 || audioInputChannels > MaximumInputChannels)
            {
                return CreateFailed(
                    path,
                    "audio channel count is outside the bounded conversion range",
                    declaredDurationSeconds,
                    audioTimeBase,
                    audioInputSampleRate,
                    audioInputChannels,
                    audioInputFormat);
            }

            if (!TryCreateResampler(
                    codecContext,
                    ref swrContext,
                    ref swrInputLayout,
                    ref swrInputLayoutValid))
            {
                return CreateFailed(
                    path,
                    "audio resampler open failed",
                    declaredDurationSeconds,
                    audioTimeBase,
                    audioInputSampleRate,
                    audioInputChannels,
                    audioInputFormat);
            }

            frame = ffmpeg.av_frame_alloc();
            packet = ffmpeg.av_packet_alloc();
            if (frame is null || packet is null)
            {
                return CreateFailed(
                    path,
                    "audio packet/frame allocation failed",
                    declaredDurationSeconds,
                    audioTimeBase,
                    audioInputSampleRate,
                    audioInputChannels,
                    audioInputFormat);
            }

            try
            {
                audioStream = HostPlatform.Current.Audio.OpenStereoPcm16Stream(
                    48_000,
                    MaximumQueuedPcmBytes);
            }
            catch (Exception exception) when (
                exception is InvalidOperationException or
                ArgumentOutOfRangeException or
                PlatformNotSupportedException or
                DllNotFoundException)
            {
                HostAudioDiagnostics.RecordOpenFailure(
                    owner: "movie",
                    source: path,
                    sampleRate: 48_000,
                    channels: OutputChannels,
                    format: "S16LE",
                    maximumQueuedBytes: MaximumQueuedPcmBytes,
                    exception);
                return CreateFailed(
                    path,
                    "host audio stream open failed",
                    declaredDurationSeconds,
                    audioTimeBase,
                    audioInputSampleRate,
                    audioInputChannels,
                    audioInputFormat);
            }

            if (audioStream is IHostAudioStreamControl controls)
            {
                controls.SetGuestClockReporting(false);
                controls.SetStrictQueueBound(true);
            }

            audioSubmission = new MovieAudioSubmissionBoundary(
                audioStream,
                OutputChannels * OutputBytesPerSample,
                48_000);
            audioStream = null;

            var result = new FfmpegMovieAudioDecoder(
                declaredDurationSeconds,
                audioStreamIndex,
                audioTimeBase,
                audioInputSampleRate,
                audioInputChannels,
                audioInputFormat,
                formatContext,
                codecContext,
                frame,
                packet,
                swrContext,
                swrInputLayout,
                swrInputLayoutValid,
                audioSubmission,
                MovieAudioProgressState.NotStarted,
                string.Empty,
                formatStartTime,
                formatDuration,
                audioStreamStartTime,
                audioStreamDuration);
            formatContext = null;
            codecContext = null;
            frame = null;
            packet = null;
            swrContext = null;
            swrInputLayout = default;
            swrInputLayoutValid = false;
            audioSubmission = null;
            return result;
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidOperationException or
            ArgumentOutOfRangeException or
            PlatformNotSupportedException or
            DllNotFoundException or
            OverflowException)
        {
            Console.Error.WriteLine(
                $"[LOADER][WARN] movie audio context failed for " +
                $"'{Path.GetFileName(path)}': {exception.Message}");
            return CreateFailed(
                path,
                "audio context setup failed",
                declaredDurationSeconds,
                audioTimeBase,
                audioInputSampleRate,
                audioInputChannels,
                audioInputFormat);
        }
        finally
        {
            audioSubmission?.Dispose();
            audioStream?.Dispose();
            if (swrContext is not null)
            {
                ffmpeg.swr_free(&swrContext);
            }

            if (swrInputLayoutValid)
            {
                ffmpeg.av_channel_layout_uninit(&swrInputLayout);
            }

            if (frame is not null)
            {
                ffmpeg.av_frame_free(&frame);
            }

            if (packet is not null)
            {
                ffmpeg.av_packet_free(&packet);
            }

            if (codecContext is not null)
            {
                ffmpeg.avcodec_free_context(&codecContext);
            }

            if (formatContext is not null)
            {
                ffmpeg.avformat_close_input(&formatContext);
            }
        }
    }

    private static FfmpegMovieAudioDecoder CreateFailed(
        string path,
        string reason,
        double declaredDurationSeconds = 0,
        AVRational audioTimeBase = default,
        int audioInputSampleRate = 0,
        int audioInputChannels = 0,
        AVSampleFormat audioInputFormat = AVSampleFormat.AV_SAMPLE_FMT_NONE) =>
        new(
            declaredDurationSeconds,
            -1,
            audioTimeBase,
            audioInputSampleRate,
            audioInputChannels,
            audioInputFormat,
            null,
            null,
            null,
            null,
            null,
            default,
            false,
            null,
            MovieAudioProgressState.Failed,
            reason,
            long.MinValue,
            long.MinValue,
            long.MinValue,
            long.MinValue);

    private static bool TryCreateResampler(
        AVCodecContext* codecContext,
        ref SwrContext* swrContext,
        ref AVChannelLayout inputLayout,
        ref bool inputLayoutValid)
    {
        var codecLayout = codecContext->ch_layout;
        var ownsCodecLayout = false;
        if (ffmpeg.av_channel_layout_check(&codecLayout) == 0)
        {
            ffmpeg.av_channel_layout_default(
                &codecLayout,
                Math.Max(1, codecContext->ch_layout.nb_channels));
            ownsCodecLayout = true;
        }

        try
        {
            AVChannelLayout copiedCodecLayout = default;
            if (ffmpeg.av_channel_layout_copy(&copiedCodecLayout, &codecLayout) < 0)
            {
                return false;
            }

            inputLayout = copiedCodecLayout;
            inputLayoutValid = true;
            AVChannelLayout outputLayout = default;
            ffmpeg.av_channel_layout_default(&outputLayout, OutputChannels);
            var sampleRate = codecContext->sample_rate > 0
                ? codecContext->sample_rate
                : 48_000;
            SwrContext* context = null;
            var configuredInputLayout = inputLayout;
            var result = ffmpeg.swr_alloc_set_opts2(
                &context,
                &outputLayout,
                AVSampleFormat.AV_SAMPLE_FMT_S16,
                48_000,
                &configuredInputLayout,
                codecContext->sample_fmt,
                sampleRate,
                0,
                null);
            ffmpeg.av_channel_layout_uninit(&outputLayout);
            if (result < 0 || context is null || ffmpeg.swr_init(context) < 0)
            {
                if (context is not null)
                {
                    ffmpeg.swr_free(&context);
                }

                return false;
            }

            swrContext = context;
            return true;
        }
        finally
        {
            if (ownsCodecLayout)
            {
                ffmpeg.av_channel_layout_uninit(&codecLayout);
            }
        }
    }

    public bool HasAudioTrack => true;

    public void Start()
    {
        lock (_stateGate)
        {
            if (_started || _state is
                    MovieAudioProgressState.Failed or
                    MovieAudioProgressState.Completed or
                    MovieAudioProgressState.Disposed)
            {
                return;
            }

            _started = true;
            _pumpThread = new Thread(PumpLoop)
            {
                IsBackground = true,
                Name = "SharpEmu Bink audio decoder",
            };
            _pumpThread.Start();
        }
    }

    public MovieAudioProgress GetMovieAudioProgress()
    {
        lock (_stateGate)
        {
            return new MovieAudioProgress(
                _state,
                _lastEstimatedPlayedSeconds,
                _drainLifecycle.HostDrainComplete,
                _failureReason,
                _pauseSupported);
        }
    }

    public void Pause()
    {
        lock (_stateGate)
        {
            if (_state is MovieAudioProgressState.Failed or
                MovieAudioProgressState.Completed or
                MovieAudioProgressState.Disposed)
            {
                return;
            }

            _paused = true;
            _state = MovieAudioProgressState.Paused;
            Monitor.PulseAll(_stateGate);
        }

        try
        {
            if (_pauseSupported)
            {
                _audioSubmission?.SetPaused(true);
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ObjectDisposedException)
        {
            Fail("host audio pause failed", exception);
        }
    }

    public void Resume()
    {
        try
        {
            if (_pauseSupported)
            {
                _audioSubmission?.SetPaused(false);
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ObjectDisposedException)
        {
            Fail("host audio resume failed", exception);
            return;
        }

        lock (_stateGate)
        {
            if (_state is not MovieAudioProgressState.Failed and
                not MovieAudioProgressState.Completed and
                not MovieAudioProgressState.Disposed)
            {
                _paused = false;
                if (_state == MovieAudioProgressState.Paused)
                {
                    _state = MovieAudioProgressState.Running;
                }
                Monitor.PulseAll(_stateGate);
            }
        }
    }

    public void SetMovieDiagnosticIdentity(
        string source,
        long movieInstanceId,
        long hostMovieGeneration)
    {
        if (!_diagnosticsEnabled)
        {
            return;
        }

        _diagnosticSource = source;
        _diagnosticMovieInstanceId = movieInstanceId;
        _diagnosticHostMovieGeneration = hostMovieGeneration;
        _audioStreamDiagnostics?.SetDiagnosticContext(
            owner: "movie",
            source,
            movieInstanceId,
            hostMovieGeneration);
        HostAudioDiagnostics.RecordMovieDecoderIdentity(
            source,
            movieInstanceId,
            hostMovieGeneration,
            _declaredAudioDurationSeconds,
            _audioInputSampleRate,
            _audioInputChannels,
            _audioInputFormat.ToString(),
            48_000,
            OutputChannels,
            AVSampleFormat.AV_SAMPLE_FMT_S16.ToString(),
            _formatStartTime,
            _formatDuration,
            _audioStreamIndex,
            _audioTimeBase.num,
            _audioTimeBase.den,
            _audioStreamStartTime,
            _audioStreamDuration);
    }

    public void SetDiagnosticPhase(string phase)
    {
        if (!_diagnosticsEnabled)
        {
            return;
        }

        _audioStreamDiagnostics?.SetDiagnosticPhase(phase);
    }

    private void PumpLoop()
    {
        try
        {
            var cancellationToken = _stopSource.Token;
            while (!cancellationToken.IsCancellationRequested)
            {
                if (IsPaused())
                {
                    SetDiagnosticPhase("paused");
                    lock (_stateGate)
                    {
                        Monitor.Wait(_stateGate, 10);
                    }

                    continue;
                }

                if (!_drainLifecycle.DemuxEof)
                {
                    SetDiagnosticPhase("audio-demux");
                    var readResult = ffmpeg.av_read_frame(_formatContext, _packet);
                    var readDisposition = MovieDemuxReadBoundary.Classify(
                        readResult,
                        ffmpeg.AVERROR_EOF);
                    if (readDisposition == MovieDemuxReadDisposition.EndOfInput)
                    {
                        _drainLifecycle.MarkDemuxEof();
                        if (!DrainCodecAtEof())
                        {
                            return;
                        }
                        continue;
                    }

                    if (readDisposition == MovieDemuxReadDisposition.Failure)
                    {
                        Fail($"audio demux failed ({readResult})");
                        return;
                    }

                    if (_packet->size < 0 || _packet->size > MaximumAudioPacketBytes)
                    {
                        ffmpeg.av_packet_unref(_packet);
                        Fail("audio packet exceeds the bounded input size");
                        return;
                    }

                    if (_packet->stream_index != _audioStreamIndex)
                    {
                        ffmpeg.av_packet_unref(_packet);
                        continue;
                    }

                    var decodeSucceeded = DecodeAudioPacket(_packet);
                    ffmpeg.av_packet_unref(_packet);
                    if (!decodeSucceeded)
                    {
                        return;
                    }

                    continue;
                }

                if (!_drainLifecycle.DecoderEof)
                {
                    if (!DrainCodecAtEof())
                    {
                        return;
                    }
                    continue;
                }

                if (!_drainLifecycle.ResamplerEof)
                {
                    SetDiagnosticPhase("audio-resampler-drain");
                    if (!DrainResampler())
                    {
                        return;
                    }

                    _drainLifecycle.MarkResamplerEof();
                    continue;
                }

                SetDiagnosticPhase("audio-host-drain");
                if (!WaitForHostDrain(cancellationToken))
                {
                    return;
                }

                return;
            }
        }
        catch (OperationCanceledException) when (_stopSource.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidOperationException or
            OverflowException or
            AccessViolationException)
        {
            Fail("audio pump failed", exception);
        }
    }

    private bool DecodeAudioPacket(AVPacket* packet)
    {
        var sendResult = ffmpeg.avcodec_send_packet(_codecContext, packet);
        if (sendResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
        {
            if (!DrainDecodedAudioFrames())
            {
                return false;
            }

            sendResult = ffmpeg.avcodec_send_packet(_codecContext, packet);
        }

        if (sendResult < 0)
        {
            Fail("audio packet decode failed");
            return false;
        }

        return DrainDecodedAudioFrames();
    }

    private bool DrainCodecAtEof()
    {
        if (_drainLifecycle.DecoderEof)
        {
            return true;
        }

        if (!_drainLifecycle.CodecDrainSent)
        {
            var sendResult = ffmpeg.avcodec_send_packet(_codecContext, null);
            if (sendResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                if (!DrainDecodedAudioFrames())
                {
                    return false;
                }

                return !_drainLifecycle.DecoderEof;
            }

            if (sendResult < 0)
            {
                Fail("audio decoder drain failed");
                return false;
            }

            _drainLifecycle.MarkCodecDrainSent();
        }

        return DrainDecodedAudioFrames();
    }

    private bool DrainDecodedAudioFrames()
    {
        while (true)
        {
            var receiveResult = ffmpeg.avcodec_receive_frame(_codecContext, _frame);
            if (receiveResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                return true;
            }

            if (receiveResult == ffmpeg.AVERROR_EOF)
            {
                _drainLifecycle.MarkDecoderEof();
                return true;
            }

            if (receiveResult < 0)
            {
                Fail("audio frame decode failed");
                return false;
            }

            var submitted = SubmitAudioFrame();
            ffmpeg.av_frame_unref(_frame);
            if (!submitted)
            {
                return false;
            }
        }
    }

    private bool SubmitAudioFrame()
    {
        if (_frame->nb_samples <= 0 || _frame->extended_data is null)
        {
            return true;
        }

        if (_frame->nb_samples > MaximumDecodedAudioSamples)
        {
            Fail("decoded audio frame exceeds the bounded sample count");
            return false;
        }

        if (_diagnosticsEnabled)
        {
            _decodedSourceFrames = checked(_decodedSourceFrames + _frame->nb_samples);
            if (_frame->pts != ffmpeg.AV_NOPTS_VALUE && _audioTimeBase.den > 0)
            {
                _lastSourceTimestampSeconds = _frame->pts *
                    ((double)_audioTimeBase.num / _audioTimeBase.den);
                if (_firstSourceTimestampSeconds < 0)
                {
                    _firstSourceTimestampSeconds = _lastSourceTimestampSeconds;
                }
            }
        }

        var sampleRate = _frame->sample_rate > 0
            ? _frame->sample_rate
            : _codecContext->sample_rate;
        if (sampleRate <= 0)
        {
            Fail("audio frame has no sample rate");
            return false;
        }

        var inputLayout = _frame->ch_layout;
        var ownsInputLayout = false;
        if (ffmpeg.av_channel_layout_check(&inputLayout) == 0)
        {
            inputLayout = _codecContext->ch_layout;
        }

        if (ffmpeg.av_channel_layout_check(&inputLayout) == 0)
        {
            ffmpeg.av_channel_layout_default(
                &inputLayout,
                Math.Max(1, _frame->ch_layout.nb_channels));
            ownsInputLayout = true;
        }

        try
        {
            if (!EnsureAudioResampler(
                    &inputLayout,
                    (AVSampleFormat)_frame->format,
                    sampleRate))
            {
                Fail("audio resampler reconfiguration failed");
                return false;
            }

            var channels = inputLayout.nb_channels;
            var bytesPerSample = ffmpeg.av_get_bytes_per_sample(
                (AVSampleFormat)_frame->format);
            if (channels <= 0 || channels > MaximumInputChannels || bytesPerSample <= 0)
            {
                Fail("audio frame format is outside the bounded conversion range");
                return false;
            }

            var planar = ffmpeg.av_sample_fmt_is_planar(
                (AVSampleFormat)_frame->format) != 0;
            var offset = 0;
            var inputPlanes = stackalloc byte*[MaximumInputChannels];
            while (offset < _frame->nb_samples)
            {
                var inputSamples = Math.Min(
                    MaximumInputSamplesPerConversion,
                    _frame->nb_samples - offset);
                if (planar)
                {
                    for (var channel = 0; channel < channels; channel++)
                    {
                        inputPlanes[channel] = _frame->extended_data[channel] +
                            (offset * bytesPerSample);
                    }
                }
                else
                {
                    inputPlanes[0] = _frame->extended_data[0] +
                        (offset * channels * bytesPerSample);
                }

                var converted = ConvertSamples(
                    inputPlanes,
                    inputSamples);
                if (converted < 0)
                {
                    return false;
                }

                offset += inputSamples;
            }

            return true;
        }
        finally
        {
            if (ownsInputLayout)
            {
                ffmpeg.av_channel_layout_uninit(&inputLayout);
            }
        }
    }

    private int ConvertSamples(
        byte** inputPlanes,
        int inputSamples)
    {
        fixed (byte* output = _outputBuffer)
        {
            var outputPlanes = stackalloc byte*[1];
            outputPlanes[0] = output;
            var converted = ffmpeg.swr_convert(
                _swrContext,
                outputPlanes,
                MaximumSubmissionSamples,
                inputPlanes,
                inputSamples);
            if (converted < 0)
            {
                Fail("audio resampling failed");
                return -1;
            }

            if (converted == 0)
            {
                RecordMovieDecoderSummaryIfDue();
                return 0;
            }

            var byteCount = checked(
                converted * OutputChannels * OutputBytesPerSample);
            _pcmStatistics?.Record(_outputBuffer.AsSpan(0, byteCount));
            var submissionResult = SubmitHostAudio(
                _outputBuffer.AsSpan(0, byteCount),
                converted,
                out var submissionProgress);
            if (submissionResult != MovieAudioSubmissionResult.Accepted)
            {
                if (submissionResult == MovieAudioSubmissionResult.HostFailure &&
                    !_stopSource.IsCancellationRequested)
                {
                    _failedSubmissionFrames = checked(
                        _failedSubmissionFrames + converted);
                    Fail("host audio submission failed");
                }

                if (submissionResult == MovieAudioSubmissionResult.ProgressUnavailable &&
                    !_stopSource.IsCancellationRequested)
                {
                    _failedSubmissionFrames = checked(
                        _failedSubmissionFrames + converted);
                    Fail("host audio progress source violated its exact contract");
                }

                return -1;
            }

            _convertedOutputFrames = checked(_convertedOutputFrames + converted);
            _resamplerInputFrames = checked(_resamplerInputFrames + inputSamples);
            _resamplerOutputFrames = checked(_resamplerOutputFrames + converted);
            _submittedOutputFrames = checked(_submittedOutputFrames + converted);
            if (!ApplyProgress(submissionProgress))
            {
                return -1;
            }
            RecordMovieDecoderSummaryIfDue();
            return converted;
        }
    }

    private bool DrainResampler()
    {
        while (ffmpeg.swr_get_out_samples(_swrContext, 0) > 0)
        {
            var converted = ConvertSamples(
                inputPlanes: null,
                inputSamples: 0);
            if (converted < 0)
            {
                return false;
            }

            if (converted == 0)
            {
                break;
            }
        }

        return true;
    }

    private MovieAudioSubmissionResult SubmitHostAudio(
        ReadOnlySpan<byte> samples,
        int outputFrames,
        out MovieAudioProgressSample progress)
    {
        var submission = _audioSubmission;
        if (submission is null)
        {
            progress = default;
            return MovieAudioSubmissionResult.HostFailure;
        }

        return submission.Submit(
            samples,
            outputFrames,
            _stopSource.Token,
            out progress);
    }

    private bool WaitForHostDrain(CancellationToken cancellationToken)
    {
        var submission = _audioSubmission;
        if (submission is null)
        {
            Fail("host audio submission boundary is unavailable");
            return false;
        }

        switch (submission.WaitForDrain(cancellationToken))
        {
            case MovieAudioDrainResult.Completed:
                ApplyProgress(submission.LastProgress);
                SetDiagnosticPhase("completed");
                lock (_stateGate)
                {
                    _drainLifecycle.MarkHostDrainComplete();
                    _state = MovieAudioProgressState.Completed;
                }

                RecordMovieDecoderSummaryIfDue(force: true);
                return true;
            case MovieAudioDrainResult.Cancelled:
                return false;
            case MovieAudioDrainResult.Unsupported:
                // An unavailable backend is an explicit capability state, not
                // a decoder failure. It cannot satisfy movie completion until
                // its owner supplies a drain boundary.
                SetDiagnosticPhase("audio-host-drain-unavailable");
                return false;
            default:
                Fail("host audio drain failed");
                return false;
        }
    }

    private bool IsPaused()
    {
        lock (_stateGate)
        {
            return _paused;
        }
    }

    private bool ApplyProgress(MovieAudioProgressSample progress)
    {
        if (!progress.HasProgress)
        {
            return true;
        }

        lock (_stateGate)
        {
            _lastEstimatedPlayedSeconds = Math.Max(
                _lastEstimatedPlayedSeconds,
                progress.Seconds);
            if (_state is MovieAudioProgressState.Failed or
                MovieAudioProgressState.Completed or
                MovieAudioProgressState.Disposed)
            {
                return true;
            }

            if (_paused)
            {
                _state = MovieAudioProgressState.Paused;
                return true;
            }

            _state = progress.TemporaryUnderrun
                ? MovieAudioProgressState.TemporaryUnderrun
                : MovieAudioProgressState.Running;
        }

        return true;
    }

    private void Fail(string reason, Exception? exception = null)
    {
        _drainLifecycle.MarkFailed();
        lock (_stateGate)
        {
            if (_state is MovieAudioProgressState.Failed or
                MovieAudioProgressState.Completed or
                MovieAudioProgressState.Disposed)
            {
                return;
            }

            _failureReason = reason;
            _state = MovieAudioProgressState.Failed;
        }

        if (exception is not null)
        {
            Console.Error.WriteLine(
                $"[LOADER][WARN] movie audio {reason}: {exception.Message}");
        }
        else
        {
            Console.Error.WriteLine($"[LOADER][WARN] movie audio {reason}.");
        }

        SetDiagnosticPhase("failed");
        RecordMovieDecoderSummaryIfDue(force: true);
        var submission = Interlocked.Exchange(ref _audioSubmission, null);
        submission?.Dispose();
    }

    private bool EnsureAudioResampler(
        AVChannelLayout* inputLayout,
        AVSampleFormat inputFormat,
        int inputSampleRate)
    {
        var storedInputLayout = _swrInputLayout;
        if (_swrContext is not null &&
            _swrInputFormat == inputFormat &&
            _swrInputSampleRate == inputSampleRate &&
            ffmpeg.av_channel_layout_compare(
                &storedInputLayout,
                inputLayout) == 0)
        {
            return true;
        }

        FreeAudioResampler();
        AVChannelLayout copiedInputLayout = default;
        if (ffmpeg.av_channel_layout_copy(&copiedInputLayout, inputLayout) < 0)
        {
            return false;
        }

        AVChannelLayout outputLayout = default;
        ffmpeg.av_channel_layout_default(&outputLayout, OutputChannels);
        SwrContext* context = null;
        var result = ffmpeg.swr_alloc_set_opts2(
            &context,
            &outputLayout,
            AVSampleFormat.AV_SAMPLE_FMT_S16,
            48_000,
            &copiedInputLayout,
            inputFormat,
            inputSampleRate,
            0,
            null);
        ffmpeg.av_channel_layout_uninit(&outputLayout);
        if (result < 0 || context is null || ffmpeg.swr_init(context) < 0)
        {
            if (context is not null)
            {
                ffmpeg.swr_free(&context);
            }

            ffmpeg.av_channel_layout_uninit(&copiedInputLayout);
            return false;
        }

        _swrContext = context;
        _swrInputLayout = copiedInputLayout;
        _swrInputLayoutValid = true;
        _swrInputFormat = inputFormat;
        _swrInputSampleRate = inputSampleRate;
        return true;
    }

    private void FreeAudioResampler()
    {
        if (_swrContext is not null)
        {
            var context = _swrContext;
            ffmpeg.swr_free(&context);
            _swrContext = null;
        }

        if (_swrInputLayoutValid)
        {
            var inputLayout = _swrInputLayout;
            ffmpeg.av_channel_layout_uninit(&inputLayout);
            _swrInputLayout = default;
            _swrInputLayoutValid = false;
        }

        _swrInputFormat = AVSampleFormat.AV_SAMPLE_FMT_NONE;
        _swrInputSampleRate = 0;
    }

    private void RecordMovieDecoderSummaryIfDue(bool force = false)
    {
        if (!_diagnosticsEnabled || _audioStreamDiagnostics is null)
        {
            return;
        }

        var now = Stopwatch.GetTimestamp();
        if (!force && _nextDiagnosticTimestamp != 0 &&
            now < _nextDiagnosticTimestamp)
        {
            return;
        }

        _nextDiagnosticTimestamp = now + Stopwatch.Frequency;
        var progress = GetMovieAudioProgress();
        HostAudioDiagnostics.RecordMovieDecoderSummary(
            _diagnosticSource,
            _diagnosticMovieInstanceId,
            _diagnosticHostMovieGeneration,
            _declaredAudioDurationSeconds,
            _decodedSourceFrames,
            _convertedOutputFrames,
            _submittedOutputFrames,
            _failedSubmissionFrames,
            _resamplerInputFrames,
            _resamplerOutputFrames,
            _firstSourceTimestampSeconds,
            _lastSourceTimestampSeconds,
            _audioStreamDiagnostics.GetDiagnosticSnapshot(),
            progress.State.ToString(),
            progress.Seconds,
            _drainLifecycle.DemuxEof,
            _drainLifecycle.DecoderEof,
            resamplerEof: _drainLifecycle.ResamplerEof,
            codecDrainSent: _drainLifecycle.CodecDrainSent,
            audioDrainComplete: progress.IsDrainComplete,
            hostDrainObserved: _drainLifecycle.HostDrainComplete,
            disposed: _drainLifecycle.Disposed,
            audioFailureReason: progress.FailureReason,
            pcmWindow: _pcmStatistics?.SnapshotAndReset() ?? default);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stopSource.Cancel();
        lock (_stateGate)
        {
            _paused = false;
            Monitor.PulseAll(_stateGate);
        }

        if (_pumpThread is not null &&
            Thread.CurrentThread != _pumpThread)
        {
            _pumpThread.Join();
        }

        lock (_stateGate)
        {
            _state = MovieAudioProgressState.Disposed;
            Monitor.PulseAll(_stateGate);
        }
        _drainLifecycle.MarkDisposed();
        RecordMovieDecoderSummaryIfDue(force: true);

        var submission = Interlocked.Exchange(ref _audioSubmission, null);
        submission?.Dispose();
        FreeAudioResampler();

        if (_frame is not null)
        {
            var frame = _frame;
            ffmpeg.av_frame_free(&frame);
            _frame = null;
        }

        if (_packet is not null)
        {
            var packet = _packet;
            ffmpeg.av_packet_free(&packet);
            _packet = null;
        }

        if (_codecContext is not null)
        {
            var codecContext = _codecContext;
            ffmpeg.avcodec_free_context(&codecContext);
            _codecContext = null;
        }

        if (_formatContext is not null)
        {
            var formatContext = _formatContext;
            ffmpeg.avformat_close_input(&formatContext);
            _formatContext = null;
        }

        _stopSource.Dispose();
        // The state was marked disposed before the stream boundary was
        // released so the final movie summary retains its generation and
        // lifecycle identity. The host stream emits its own disposed event.
    }
}
