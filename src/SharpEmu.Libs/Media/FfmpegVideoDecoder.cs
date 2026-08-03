// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers;
using System.Diagnostics;
using FFmpeg.AutoGen;
using SharpEmu.HLE.Host;

namespace SharpEmu.Libs.Media;

/// <summary>
/// Decodes a .bk2 (or any FFmpeg-readable movie) directly via FFmpeg's C API
/// through FFmpeg.AutoGen P/Invoke bindings against the dynamically linked
/// libraries published by github.com/sharpemu/ffmpeg-core -- no native C
/// bridge of our own to build. See docs/bink2-bridge.md.
/// </summary>
internal sealed unsafe class FfmpegVideoDecoder :
    IMediaFrameDecoder,
    IMediaAudioDiagnostics,
    IMovieAudioProgressSource,
    IMediaPumpDiagnostics
{
    private const int OutputAudioChannels = 2;
    private const int OutputAudioBytesPerSample = sizeof(short);

    private readonly object _decodeGate = new();
    private AVFormatContext* _formatContext;
    private AVCodecContext* _codecContext;
    private AVCodecContext* _audioCodecContext;
    private SwsContext* _swsContext;
    private SwrContext* _swrContext;
    private AVFrame* _frame;
    private AVFrame* _pendingFrame;
    private AVFrame* _audioFrame;
    private AVPacket* _packet;
    private IHostAudioStream? _audioStream;
    private readonly int _videoStreamIndex;
    private readonly AVRational _videoTimeBase;
    private readonly double _videoFrameDurationSeconds;
    private readonly int _audioStreamIndex;
    private readonly bool _hasAudioTrack;
    private readonly int _audioOutputSampleRate;
    private readonly AVRational _audioTimeBase;
    private readonly double _declaredAudioDurationSeconds;
    private readonly int _audioInputSampleRate;
    private readonly int _audioInputChannels;
    private readonly AVSampleFormat _audioInputFormat;
    private readonly IHostAudioStreamDiagnostics? _audioStreamDiagnostics;
    private long _decodedSourceFrames;
    private long _convertedOutputFrames;
    private long _failedSubmissionFrames;
    private long _resamplerInputFrames;
    private long _resamplerOutputFrames;
    private double _lastSourceTimestampSeconds = -1;
    private long _nextDiagnosticTimestamp;
    private string _diagnosticSource = string.Empty;
    private long _diagnosticMovieInstanceId;
    private long _diagnosticHostMovieGeneration;
    private AVChannelLayout _swrInputLayout;
    private AVSampleFormat _swrInputFormat = AVSampleFormat.AV_SAMPLE_FMT_NONE;
    private int _swrInputSampleRate;
    private bool _swrInputLayoutValid;
    private bool _draining;
    private bool _videoFlushSent;
    private bool _videoFailed;
    private bool _videoDecoderDrained;
    private bool _audioFlushSent;
    private bool _audioFailed;
    private bool _audioCompleted;
    private MovieAudioProgressState _audioProgressState;
    private double _lastMovieAudioSeconds;
    private double _pendingFrameTimestampSeconds = double.NaN;
    private double _pendingFrameDurationSeconds;
    private long _lateVideoFrameCount;
    private long _retainedNextFrameCount;
    private string _pumpState = "video-decode";
    private int _disposed;

    public uint Width { get; }

    public uint Height { get; }

    public uint FramesPerSecondNumerator { get; }

    public uint FramesPerSecondDenominator { get; }

    public bool HasAudioTrack => _hasAudioTrack;

    public long LateVideoFrameCount => Interlocked.Read(ref _lateVideoFrameCount);

    public long RetainedNextFrameCount => Interlocked.Read(ref _retainedNextFrameCount);

    public string PumpState => Volatile.Read(ref _pumpState);

    public long RetainedPacketCount => 0;

    public long RetainedPacketBytes => 0;

    private FfmpegVideoDecoder(
        AVFormatContext* formatContext,
        AVCodecContext* codecContext,
        int videoStreamIndex,
        AVRational videoTimeBase,
        double videoFrameDurationSeconds,
        AVCodecContext* audioCodecContext,
        int audioStreamIndex,
        bool hasAudioTrack,
        bool audioOpenFailed,
        IHostAudioStream? audioStream,
        int audioOutputSampleRate,
        AVRational audioTimeBase,
        double declaredAudioDurationSeconds,
        int audioInputSampleRate,
        int audioInputChannels,
        AVSampleFormat audioInputFormat,
        uint width,
        uint height,
        uint framesPerSecondNumerator,
        uint framesPerSecondDenominator)
    {
        _formatContext = formatContext;
        _codecContext = codecContext;
        _videoStreamIndex = videoStreamIndex;
        _videoTimeBase = videoTimeBase;
        _videoFrameDurationSeconds = videoFrameDurationSeconds;
        _audioCodecContext = audioCodecContext;
        _audioStreamIndex = audioStreamIndex;
        _hasAudioTrack = hasAudioTrack;
        _audioStream = audioStream;
        _audioOutputSampleRate = audioOutputSampleRate;
        _audioTimeBase = audioTimeBase;
        _declaredAudioDurationSeconds = declaredAudioDurationSeconds;
        _audioInputSampleRate = audioInputSampleRate;
        _audioInputChannels = audioInputChannels;
        _audioInputFormat = audioInputFormat;
        _audioFailed = hasAudioTrack &&
            (audioOpenFailed || audioCodecContext is null || audioStream is null);
        _audioProgressState = !hasAudioTrack
            ? MovieAudioProgressState.NoTrack
            : _audioFailed
                ? MovieAudioProgressState.Failed
                : MovieAudioProgressState.Starting;
        _audioStreamDiagnostics = HostAudioDiagnostics.Enabled
            ? audioStream as IHostAudioStreamDiagnostics
            : null;
        Width = width;
        Height = height;
        FramesPerSecondNumerator = framesPerSecondNumerator;
        FramesPerSecondDenominator = framesPerSecondDenominator;
        _frame = ffmpeg.av_frame_alloc();
        _pendingFrame = ffmpeg.av_frame_alloc();
        _audioFrame = audioCodecContext is null ? null : ffmpeg.av_frame_alloc();
        _packet = ffmpeg.av_packet_alloc();
    }

    private static void EnsureRootPathInitialized() =>
        SharpEmu.Libs.Media.FfmpegRuntime.EnsureInitialized();

    internal static bool TryOpen(
        string path,
        uint maximumWidth,
        uint maximumHeight,
        out FfmpegVideoDecoder? source)
    {
        source = null;
        EnsureRootPathInitialized();

        AVFormatContext* formatContext = null;
        AVCodecContext* codecContext = null;
        AVCodecContext* audioCodecContext = null;
        IHostAudioStream? audioStream = null;
        var audioOpenFailed = false;
        try
        {
            if (ffmpeg.avformat_open_input(&formatContext, path, null, null) < 0)
            {
                return false;
            }

            if (ffmpeg.avformat_find_stream_info(formatContext, null) < 0)
            {
                return false;
            }

            AVCodec* decoder = null;
            var videoStreamIndex = ffmpeg.av_find_best_stream(
                formatContext, AVMediaType.AVMEDIA_TYPE_VIDEO, -1, -1, &decoder, 0);
            if (videoStreamIndex < 0 || decoder is null)
            {
                return false;
            }

            var stream = formatContext->streams[videoStreamIndex];
            codecContext = ffmpeg.avcodec_alloc_context3(decoder);
            if (codecContext is null)
            {
                return false;
            }

            if (ffmpeg.avcodec_parameters_to_context(codecContext, stream->codecpar) < 0)
            {
                return false;
            }

            codecContext->thread_count = 0;
            codecContext->thread_type = ffmpeg.FF_THREAD_FRAME | ffmpeg.FF_THREAD_SLICE;
            if (ffmpeg.avcodec_open2(codecContext, decoder, null) < 0)
            {
                return false;
            }

            if (codecContext->width <= 0 || codecContext->height <= 0)
            {
                return false;
            }

            var frameRate = ffmpeg.av_guess_frame_rate(formatContext, stream, null);
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = stream->avg_frame_rate;
            }
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = stream->r_frame_rate;
            }
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = new AVRational { num = 30, den = 1 };
            }

            AVCodec* audioDecoder = null;
            var detectedAudioStreamIndex = ffmpeg.av_find_best_stream(
                formatContext,
                AVMediaType.AVMEDIA_TYPE_AUDIO,
                -1,
                -1,
                &audioDecoder,
                0);
            var hasAudioTrack = detectedAudioStreamIndex >= 0;
            var audioStreamIndex = TryOpenAudioDecoder(
                formatContext,
                out audioCodecContext,
                out var audioOutputSampleRate);
            if (hasAudioTrack && audioStreamIndex < 0)
            {
                audioOpenFailed = true;
                audioStreamIndex = detectedAudioStreamIndex;
            }
            var audioTimeBase = default(AVRational);
            var declaredAudioDurationSeconds = 0d;
            if (detectedAudioStreamIndex >= 0)
            {
                var audioMediaStream = formatContext->streams[detectedAudioStreamIndex];
                audioTimeBase = audioMediaStream->time_base;
                if (audioMediaStream->duration > 0 && audioTimeBase.den > 0)
                {
                    declaredAudioDurationSeconds = audioMediaStream->duration *
                        ((double)audioTimeBase.num / audioTimeBase.den);
                }
            }
            if (audioStreamIndex >= 0 && audioCodecContext is not null)
            {
                try
                {
                    audioStream = HostPlatform.Current.Audio.OpenStereoPcm16Stream(
                        checked((uint)audioOutputSampleRate));
                }
                catch (Exception exception) when (exception is InvalidOperationException or
                                                     ArgumentOutOfRangeException)
                {
                    HostAudioDiagnostics.RecordOpenFailure(
                        owner: "movie",
                        source: path,
                        sampleRate: checked((uint)Math.Max(0, audioOutputSampleRate)),
                        channels: OutputAudioChannels,
                        format: "S16LE",
                        maximumQueuedBytes: 32 * 1024,
                        exception);
                    Console.Error.WriteLine(
                        $"[LOADER][WARN] Bink audio output unavailable: {exception.Message}");
                    audioOpenFailed = true;
                    ffmpeg.avcodec_free_context(&audioCodecContext);
                    audioOutputSampleRate = 0;
                }
            }

            var outputWidth = (uint)codecContext->width;
            var outputHeight = (uint)codecContext->height;
            if (maximumWidth > 0 && maximumHeight > 0 &&
                (outputWidth > maximumWidth || outputHeight > maximumHeight))
            {
                if ((ulong)outputWidth * maximumHeight > (ulong)outputHeight * maximumWidth)
                {
                    outputHeight = (uint)((ulong)outputHeight * maximumWidth / outputWidth);
                    outputWidth = maximumWidth;
                }
                else
                {
                    outputWidth = (uint)((ulong)outputWidth * maximumHeight / outputHeight);
                    outputHeight = maximumHeight;
                }

                outputWidth = Math.Max(1, outputWidth);
                outputHeight = Math.Max(1, outputHeight);
            }

            source = new FfmpegVideoDecoder(
                formatContext,
                codecContext,
                videoStreamIndex,
                stream->time_base,
                (double)frameRate.den / frameRate.num,
                audioCodecContext,
                audioStreamIndex,
                hasAudioTrack,
                audioOpenFailed,
                audioStream,
                audioOutputSampleRate,
                audioTimeBase,
                declaredAudioDurationSeconds,
                audioCodecContext is null ? 0 : audioCodecContext->sample_rate,
                audioCodecContext is null ? 0 : audioCodecContext->ch_layout.nb_channels,
                audioCodecContext is null
                    ? AVSampleFormat.AV_SAMPLE_FMT_NONE
                    : audioCodecContext->sample_fmt,
                outputWidth,
                outputHeight,
                (uint)frameRate.num,
                (uint)frameRate.den);
            formatContext = null;
            codecContext = null;
            audioCodecContext = null;
            audioStream = null;
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        finally
        {
            if (codecContext is not null)
            {
                ffmpeg.avcodec_free_context(&codecContext);
            }

            if (audioCodecContext is not null)
            {
                ffmpeg.avcodec_free_context(&audioCodecContext);
            }

            audioStream?.Dispose();

            if (formatContext is not null)
            {
                ffmpeg.avformat_close_input(&formatContext);
            }
        }
    }

    private static int TryOpenAudioDecoder(
        AVFormatContext* formatContext,
        out AVCodecContext* codecContext,
        out int outputSampleRate)
    {
        codecContext = null;
        outputSampleRate = 0;

        AVCodec* decoder = null;
        var streamIndex = ffmpeg.av_find_best_stream(
            formatContext, AVMediaType.AVMEDIA_TYPE_AUDIO, -1, -1, &decoder, 0);
        if (streamIndex < 0 || decoder is null)
        {
            return -1;
        }

        var candidate = ffmpeg.avcodec_alloc_context3(decoder);
        if (candidate is null)
        {
            return -1;
        }

        var stream = formatContext->streams[streamIndex];
        if (ffmpeg.avcodec_parameters_to_context(candidate, stream->codecpar) < 0)
        {
            ffmpeg.avcodec_free_context(&candidate);
            return -1;
        }

        candidate->thread_count = 0;
        candidate->thread_type = ffmpeg.FF_THREAD_FRAME | ffmpeg.FF_THREAD_SLICE;
        if (ffmpeg.avcodec_open2(candidate, decoder, null) < 0)
        {
            ffmpeg.avcodec_free_context(&candidate);
            return -1;
        }

        outputSampleRate = candidate->sample_rate > 0 ? candidate->sample_rate : 48_000;
        codecContext = candidate;
        return streamIndex;
    }

    public void SetMovieDiagnosticIdentity(
        string source,
        long movieInstanceId,
        long hostMovieGeneration)
    {
        if (!HostAudioDiagnostics.Enabled)
        {
            return;
        }

        _diagnosticSource = source;
        _diagnosticMovieInstanceId = movieInstanceId;
        _diagnosticHostMovieGeneration = hostMovieGeneration;
        if (_audioStreamDiagnostics is not null)
        {
            _audioStreamDiagnostics.SetDiagnosticContext(
                owner: "movie",
                source,
                movieInstanceId,
                hostMovieGeneration);
        }

        HostAudioDiagnostics.RecordMovieDecoderIdentity(
            source,
            movieInstanceId,
            hostMovieGeneration,
            _declaredAudioDurationSeconds,
            _audioInputSampleRate,
            _audioInputChannels,
            _audioInputFormat.ToString(),
            _audioOutputSampleRate,
            OutputAudioChannels,
            AVSampleFormat.AV_SAMPLE_FMT_S16.ToString());
    }

    public void SetDiagnosticPhase(string phase)
    {
        if (!HostAudioDiagnostics.Enabled)
        {
            return;
        }

        if (_audioStreamDiagnostics is not null)
        {
            _audioStreamDiagnostics.SetDiagnosticPhase(phase);
        }
    }

    public MovieAudioProgress GetMovieAudioProgress()
    {
        lock (_decodeGate)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return new(MovieAudioProgressState.Disposed, _lastMovieAudioSeconds);
            }

            if (!_hasAudioTrack)
            {
                return new(MovieAudioProgressState.NoTrack, 0);
            }

            if (_audioFailed)
            {
                return new(MovieAudioProgressState.Failed, _lastMovieAudioSeconds);
            }

            if (_audioCompleted)
            {
                return new(MovieAudioProgressState.Completed, _lastMovieAudioSeconds);
            }

            if (_audioStream is null)
            {
                return new(MovieAudioProgressState.Failed, _lastMovieAudioSeconds);
            }

            var hostProgress = _audioStream.Progress;
            _lastMovieAudioSeconds = Math.Max(
                _lastMovieAudioSeconds,
                Math.Max(0, hostProgress.EstimatedPlayedSeconds));
            _audioProgressState = hostProgress.State switch
            {
                HostAudioProgressState.Starting => MovieAudioProgressState.Starting,
                HostAudioProgressState.Running => MovieAudioProgressState.Running,
                HostAudioProgressState.TemporaryUnderrun => MovieAudioProgressState.TemporaryUnderrun,
                HostAudioProgressState.Completed => MovieAudioProgressState.Completed,
                HostAudioProgressState.Failed => MovieAudioProgressState.Failed,
                HostAudioProgressState.Disposed => MovieAudioProgressState.Disposed,
                HostAudioProgressState.Unavailable => MovieAudioProgressState.Unavailable,
                _ => MovieAudioProgressState.Unavailable,
            };
            return new(_audioProgressState, _lastMovieAudioSeconds);
        }
    }

    public bool TryDecodeNextFrame(Span<byte> destination, double movieSeconds)
    {
        lock (_decodeGate)
        {
            Volatile.Write(ref _pumpState, "video-decode");
            if (Volatile.Read(ref _disposed) != 0)
            {
                return false;
            }

            if (_draining)
            {
                DrainAudioDecoder();
            }

            var stride = checked((int)(Width * 4));
            var required = (long)stride * Height;
            if (destination.Length < required)
            {
                return false;
            }

            while (true)
            {
                AVFrame* frameToConvert;
                var retained = false;
                if (HasPendingFrame)
                {
                    if (IsFrameLate(_pendingFrame, movieSeconds))
                    {
                        DiscardPendingFrame(late: true);
                        continue;
                    }

                    frameToConvert = _pendingFrame;
                    retained = true;
                }
                else
                {
                    if (!TryReceiveFrame())
                    {
                        RecordMovieDecoderSummaryIfDue();
                        return false;
                    }

                    if (IsFrameLate(_frame, movieSeconds))
                    {
                        ffmpeg.av_frame_unref(_frame);
                        Interlocked.Increment(ref _lateVideoFrameCount);
                        continue;
                    }

                    frameToConvert = _frame;
                }

                var converted = ConvertVideoFrame(frameToConvert, destination, stride);
                if (retained)
                {
                    DiscardPendingFrame(late: false);
                }
                else
                {
                    ffmpeg.av_frame_unref(_frame);
                }

                RecordMovieDecoderSummaryIfDue();
                return converted;
            }
        }
    }

    public MediaPumpResult PumpAudioWhileVideoBackpressured(double movieSeconds)
    {
        lock (_decodeGate)
        {
            Volatile.Write(ref _pumpState, "audio-pump");
            if (Volatile.Read(ref _disposed) != 0)
            {
                return MediaPumpResult.Disposed;
            }

            if (_videoFailed)
            {
                return MediaPumpResult.Failed;
            }

            if (!_hasAudioTrack || _audioFailed)
            {
                return MediaPumpResult.Backpressure;
            }

            if (HasPendingFrame && IsFrameLate(_pendingFrame, movieSeconds))
            {
                DiscardPendingFrame(late: true);
            }

            while (true)
            {
                var readResult = ffmpeg.av_read_frame(_formatContext, _packet);
                if (readResult < 0)
                {
                    Volatile.Write(ref _pumpState, "drain");
                    BeginDrain();
                    DrainVideoFramesForPump(movieSeconds);
                    if (_videoFailed)
                    {
                        Volatile.Write(ref _pumpState, "failed");
                        return MediaPumpResult.Failed;
                    }
                    return HasPendingFrame || !_videoDecoderDrained
                        ? MediaPumpResult.Backpressure
                        : MediaPumpResult.EndOfInput;
                }

                if (_packet->stream_index == _audioStreamIndex)
                {
                    DecodeAudioPacket(_packet);
                    ffmpeg.av_packet_unref(_packet);
                    return MediaPumpResult.Progress;
                }

                if (_packet->stream_index == _videoStreamIndex)
                {
                    var sendResult = SendVideoPacket(_packet, movieSeconds);
                    ffmpeg.av_packet_unref(_packet);
                    if (!sendResult)
                    {
                        Volatile.Write(ref _pumpState, "failed");
                        return MediaPumpResult.Failed;
                    }

                    DrainVideoFramesForPump(movieSeconds);
                    continue;
                }

                ffmpeg.av_packet_unref(_packet);
            }
        }
    }

    private bool SendVideoPacket(AVPacket* packet, double movieSeconds)
    {
        while (true)
        {
            var sendResult = ffmpeg.avcodec_send_packet(_codecContext, packet);
            if (sendResult >= 0)
            {
                return true;
            }

            if (sendResult != ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                _videoFailed = true;
                return false;
            }

            DrainVideoFramesForPump(movieSeconds);
            if (_videoFailed)
            {
                return false;
            }
        }
    }

    private bool ConvertVideoFrame(AVFrame* frame, Span<byte> destination, int stride)
    {
        _swsContext = ffmpeg.sws_getCachedContext(
            _swsContext,
            frame->width,
            frame->height,
            (AVPixelFormat)frame->format,
            (int)Width,
            (int)Height,
            AVPixelFormat.AV_PIX_FMT_BGRA,
            ffmpeg.SWS_FAST_BILINEAR,
            null,
            null,
            null);
        if (_swsContext is null)
        {
            return false;
        }

        fixed (byte* destinationPointer = destination)
        {
            var destinationPlanes = new byte*[4] { destinationPointer, null, null, null };
            var destinationStrides = new int[4] { stride, 0, 0, 0 };
            var convertedRows = ffmpeg.sws_scale(
                _swsContext,
                frame->data,
                frame->linesize,
                0,
                frame->height,
                destinationPlanes,
                destinationStrides);
            return convertedRows == (int)Height;
        }
    }

    private void DrainVideoFramesForPump(double movieSeconds)
    {
        if (_pendingFrame is null)
        {
            _videoFailed = true;
            return;
        }

        while (true)
        {
            var receiveResult = ffmpeg.avcodec_receive_frame(_codecContext, _frame);
            if (receiveResult == ffmpeg.AVERROR(ffmpeg.EAGAIN) ||
                receiveResult == ffmpeg.AVERROR_EOF)
            {
                if (receiveResult == ffmpeg.AVERROR_EOF)
                {
                    _videoDecoderDrained = true;
                }
                else if (_draining && !_videoFlushSent)
                {
                    TrySendVideoFlushPacket();
                }
                return;
            }

            if (receiveResult < 0)
            {
                _videoFailed = true;
                _videoDecoderDrained = true;
                return;
            }

            if (HasPendingFrame && IsFrameLate(_pendingFrame, movieSeconds))
            {
                DiscardPendingFrame(late: true);
            }

            if (IsFrameLate(_frame, movieSeconds))
            {
                ffmpeg.av_frame_unref(_frame);
                Interlocked.Increment(ref _lateVideoFrameCount);
                continue;
            }

            if (!HasPendingFrame)
            {
                if (ffmpeg.av_frame_ref(_pendingFrame, _frame) < 0)
                {
                    ffmpeg.av_frame_unref(_frame);
                    _videoDecoderDrained = true;
                    return;
                }

                _pendingFrameTimestampSeconds = GetFrameTimestamp(_frame) ?? double.NaN;
                _pendingFrameDurationSeconds = GetFrameDuration(_frame);
                Interlocked.Exchange(ref _retainedNextFrameCount, 1);
            }

            // Keep the earliest future frame. Later output is decoded to retain
            // codec reference state, then immediately released rather than
            // growing a second frame queue.
            ffmpeg.av_frame_unref(_frame);
        }
    }

    private bool HasPendingFrame =>
        _pendingFrame is not null && _pendingFrame->data[0] != null;

    private void DiscardPendingFrame(bool late)
    {
        if (!HasPendingFrame)
        {
            return;
        }

        ffmpeg.av_frame_unref(_pendingFrame);
        _pendingFrameTimestampSeconds = double.NaN;
        _pendingFrameDurationSeconds = 0;
        Interlocked.Exchange(ref _retainedNextFrameCount, 0);
        if (late)
        {
            Interlocked.Increment(ref _lateVideoFrameCount);
        }
    }

    private bool IsFrameLate(AVFrame* frame, double movieSeconds)
    {
        var timestamp = GetFrameTimestamp(frame);
        if (timestamp is not double actual)
        {
            return false;
        }

        return actual + GetFrameDuration(frame) <= movieSeconds;
    }

    private double? GetFrameTimestamp(AVFrame* frame)
    {
        var timestamp = frame->best_effort_timestamp != ffmpeg.AV_NOPTS_VALUE
            ? frame->best_effort_timestamp
            : frame->pts;
        return timestamp == ffmpeg.AV_NOPTS_VALUE
            ? null
            : timestamp * ((double)_videoTimeBase.num / _videoTimeBase.den);
    }

    private double GetFrameDuration(AVFrame* frame) =>
        frame->duration > 0
            ? frame->duration * ((double)_videoTimeBase.num / _videoTimeBase.den)
            : _videoFrameDurationSeconds;

    private void BeginDrain()
    {
        _draining = true;
        TrySendVideoFlushPacket();
        DrainAudioDecoder();
    }

    private bool TrySendVideoFlushPacket()
    {
        if (_videoFlushSent || _videoDecoderDrained || _videoFailed)
        {
            return !_videoFailed;
        }

        var sendResult = ffmpeg.avcodec_send_packet(_codecContext, null);
        if (sendResult >= 0)
        {
            _videoFlushSent = true;
            return true;
        }

        if (sendResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
        {
            return false;
        }

        _videoFailed = true;
        return false;
    }

    private void RecordMovieDecoderSummaryIfDue()
    {
        if (_audioStreamDiagnostics is null || !HostAudioDiagnostics.Enabled)
        {
            return;
        }

        var now = Stopwatch.GetTimestamp();
        if (_nextDiagnosticTimestamp != 0 && now < _nextDiagnosticTimestamp)
        {
            return;
        }

        _nextDiagnosticTimestamp = now + Stopwatch.Frequency;
        var streamSnapshot = _audioStreamDiagnostics.GetDiagnosticSnapshot();
        HostAudioDiagnostics.RecordMovieDecoderSummary(
            _diagnosticSource,
            _diagnosticMovieInstanceId,
            _diagnosticHostMovieGeneration,
            _declaredAudioDurationSeconds,
            _decodedSourceFrames,
            _convertedOutputFrames,
            streamSnapshot.SubmittedInputFrames,
            _failedSubmissionFrames,
            _resamplerInputFrames,
            _resamplerOutputFrames,
            _lastSourceTimestampSeconds,
            streamSnapshot);
    }

    private bool TryReceiveFrame()
    {
        while (true)
        {
            var receiveResult = ffmpeg.avcodec_receive_frame(_codecContext, _frame);
            if (receiveResult >= 0)
            {
                return true;
            }

            if (receiveResult == ffmpeg.AVERROR_EOF)
            {
                DrainAudioDecoder();
                _videoDecoderDrained = true;
                return false;
            }

            if (receiveResult != ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                _videoFailed = true;
                return false;
            }

            if (_draining)
            {
                if (!TrySendVideoFlushPacket())
                {
                    return false;
                }

                continue;
            }

            if (!TryFeedPacket())
            {
                return false;
            }
        }
    }

    private bool TryFeedPacket()
    {
        while (true)
        {
            var readResult = ffmpeg.av_read_frame(_formatContext, _packet);
            if (readResult < 0)
            {
                BeginDrain();
                return true;
            }

            if (_packet->stream_index == _audioStreamIndex)
            {
                DecodeAudioPacket(_packet);
                ffmpeg.av_packet_unref(_packet);
                continue;
            }

            if (_packet->stream_index != _videoStreamIndex)
            {
                ffmpeg.av_packet_unref(_packet);
                continue;
            }

            var sendResult = ffmpeg.avcodec_send_packet(_codecContext, _packet);
            if (sendResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                // TryReceiveFrame has just observed EAGAIN, so another EAGAIN
                // here would violate the send/receive contract. Fail visibly
                // rather than unref'ing and silently losing a dependent packet.
                _videoFailed = true;
            }
            ffmpeg.av_packet_unref(_packet);
            if (sendResult < 0)
            {
                _videoFailed = true;
                return false;
            }

            return true;
        }
    }

    private void DecodeAudioPacket(AVPacket* packet)
    {
        if (_audioCodecContext is null || _audioFrame is null || _audioFailed)
        {
            return;
        }

        var sendResult = ffmpeg.avcodec_send_packet(_audioCodecContext, packet);
        if (sendResult == ffmpeg.AVERROR(ffmpeg.EAGAIN))
        {
            DrainAvailableAudioFrames();
            sendResult = ffmpeg.avcodec_send_packet(_audioCodecContext, packet);
        }

        if (sendResult < 0)
        {
            DisableAudio("packet decode failed");
            return;
        }

        DrainAvailableAudioFrames();
    }

    private void DrainAudioDecoder()
    {
        if (_audioCodecContext is null || _audioFrame is null ||
            _audioCompleted || _audioFailed)
        {
            return;
        }

        if (!_audioFlushSent)
        {
            var sendResult = ffmpeg.avcodec_send_packet(_audioCodecContext, null);
            if (sendResult >= 0)
            {
                _audioFlushSent = true;
            }
            else if (sendResult != ffmpeg.AVERROR(ffmpeg.EAGAIN))
            {
                DisableAudio("audio flush failed");
                return;
            }
        }

        DrainAvailableAudioFrames();
    }

    private void DrainAvailableAudioFrames()
    {
        while (_audioCodecContext is not null && _audioFrame is not null)
        {
            var receiveResult = ffmpeg.avcodec_receive_frame(_audioCodecContext, _audioFrame);
            if (receiveResult == ffmpeg.AVERROR(ffmpeg.EAGAIN) ||
                receiveResult == ffmpeg.AVERROR_EOF)
            {
                if (receiveResult == ffmpeg.AVERROR_EOF)
                {
                    _audioCompleted = true;
                    _audioProgressState = MovieAudioProgressState.Completed;
                    _audioStream?.MarkCompleted();
                }
                return;
            }

            if (receiveResult < 0)
            {
                DisableAudio("frame decode failed");
                return;
            }

            if (!SubmitAudioFrame())
            {
                ffmpeg.av_frame_unref(_audioFrame);
                DisableAudio("host submission failed");
                return;
            }

            ffmpeg.av_frame_unref(_audioFrame);
        }
    }

    private bool SubmitAudioFrame()
    {
        if (_audioStream is null || _audioFrame is null ||
            _audioFrame->nb_samples <= 0 || _audioFrame->extended_data is null)
        {
            return true;
        }

        if (_audioStreamDiagnostics is not null)
        {
            _decodedSourceFrames = checked(_decodedSourceFrames + _audioFrame->nb_samples);
            if (_audioFrame->pts != ffmpeg.AV_NOPTS_VALUE &&
                _audioTimeBase.den > 0)
            {
                _lastSourceTimestampSeconds = _audioFrame->pts *
                    ((double)_audioTimeBase.num / _audioTimeBase.den);
            }
        }

        var sampleRate = _audioFrame->sample_rate > 0
            ? _audioFrame->sample_rate
            : _audioCodecContext->sample_rate;
        if (sampleRate <= 0)
        {
            return false;
        }

        var inputLayout = _audioFrame->ch_layout;
        var ownsInputLayout = false;
        if (ffmpeg.av_channel_layout_check(&inputLayout) == 0)
        {
            inputLayout = _audioCodecContext->ch_layout;
        }
        if (ffmpeg.av_channel_layout_check(&inputLayout) == 0)
        {
            ffmpeg.av_channel_layout_default(
                &inputLayout,
                Math.Max(1, _audioFrame->ch_layout.nb_channels));
            ownsInputLayout = true;
        }

        try
        {
            if (!EnsureAudioResampler(
                    &inputLayout,
                    (AVSampleFormat)_audioFrame->format,
                    sampleRate))
            {
                return false;
            }

            var maximumSamples = ffmpeg.swr_get_out_samples(
                _swrContext, _audioFrame->nb_samples);
            if (maximumSamples <= 0)
            {
                return true;
            }

            var outputBytes = checked(
                maximumSamples * OutputAudioChannels * OutputAudioBytesPerSample);
            var buffer = ArrayPool<byte>.Shared.Rent(outputBytes);
            try
            {
                fixed (byte* output = buffer)
                {
                    var outputPlanes = stackalloc byte*[1];
                    outputPlanes[0] = output;
                    var convertedSamples = ffmpeg.swr_convert(
                        _swrContext,
                        outputPlanes,
                        maximumSamples,
                        _audioFrame->extended_data,
                        _audioFrame->nb_samples);
                    if (convertedSamples < 0)
                    {
                        return false;
                    }

                    var convertedBytes = checked(
                        convertedSamples * OutputAudioChannels * OutputAudioBytesPerSample);
                    if (_audioStreamDiagnostics is not null)
                    {
                        _convertedOutputFrames = checked(
                            _convertedOutputFrames + convertedSamples);
                        _resamplerInputFrames = checked(
                            _resamplerInputFrames + _audioFrame->nb_samples);
                        _resamplerOutputFrames = checked(
                            _resamplerOutputFrames + convertedSamples);
                    }

                    var submitted = _audioStream.Submit(buffer.AsSpan(0, convertedBytes));
                    if (_audioStreamDiagnostics is not null && !submitted)
                    {
                        _failedSubmissionFrames = checked(
                            _failedSubmissionFrames + convertedSamples);
                    }

                    return submitted;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            if (ownsInputLayout)
            {
                ffmpeg.av_channel_layout_uninit(&inputLayout);
            }
        }
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
            ffmpeg.av_channel_layout_compare(&storedInputLayout, inputLayout) == 0)
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
        ffmpeg.av_channel_layout_default(&outputLayout, OutputAudioChannels);
        SwrContext* context = null;
        var allocateResult = ffmpeg.swr_alloc_set_opts2(
            &context,
            &outputLayout,
            AVSampleFormat.AV_SAMPLE_FMT_S16,
            _audioOutputSampleRate,
            &copiedInputLayout,
            inputFormat,
            inputSampleRate,
            0,
            null);
        ffmpeg.av_channel_layout_uninit(&outputLayout);
        if (allocateResult < 0 || context is null || ffmpeg.swr_init(context) < 0)
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

    private void DisableAudio(string reason)
    {
        if (_audioFailed)
        {
            return;
        }

        _audioFailed = true;
        _audioProgressState = MovieAudioProgressState.Failed;
        Volatile.Write(ref _pumpState, "failed");
        _audioStream?.MarkFailed();
        Console.Error.WriteLine($"[LOADER][WARN] Bink audio disabled: {reason}.");
        FreeAudioResampler();
        _audioStream?.Dispose();
        _audioStream = null;
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

    public void Dispose()
    {
        lock (_decodeGate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Volatile.Write(ref _pumpState, "disposed");
            _audioProgressState = MovieAudioProgressState.Disposed;
            FreeAudioResampler();
            _audioStream?.Dispose();
            _audioStream = null;

            if (_swsContext is not null)
            {
                ffmpeg.sws_freeContext(_swsContext);
                _swsContext = null;
            }

            if (_packet is not null)
            {
                var packet = _packet;
                ffmpeg.av_packet_free(&packet);
                _packet = null;
            }

            if (_frame is not null)
            {
                var frame = _frame;
                ffmpeg.av_frame_free(&frame);
                _frame = null;
            }

            if (_pendingFrame is not null)
            {
                var frame = _pendingFrame;
                ffmpeg.av_frame_free(&frame);
                _pendingFrame = null;
                _pendingFrameTimestampSeconds = double.NaN;
                _pendingFrameDurationSeconds = 0;
                Interlocked.Exchange(ref _retainedNextFrameCount, 0);
            }

            if (_audioFrame is not null)
            {
                var frame = _audioFrame;
                ffmpeg.av_frame_free(&frame);
                _audioFrame = null;
            }

            if (_codecContext is not null)
            {
                var codecContext = _codecContext;
                ffmpeg.avcodec_free_context(&codecContext);
                _codecContext = null;
            }

            if (_audioCodecContext is not null)
            {
                var codecContext = _audioCodecContext;
                ffmpeg.avcodec_free_context(&codecContext);
                _audioCodecContext = null;
            }

            if (_formatContext is not null)
            {
                var formatContext = _formatContext;
                ffmpeg.avformat_close_input(&formatContext);
                _formatContext = null;
            }
        }
    }
}
