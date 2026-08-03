// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using FFmpeg.AutoGen;

namespace SharpEmu.Libs.Media;

/// <summary>
/// Decodes the video side of a .bk2 (or any FFmpeg-readable movie). Movie
/// audio is owned by <see cref="FfmpegMovieAudioDecoder"/>, which has a
/// separate input context and therefore cannot be stopped by video
/// destination backpressure.
/// </summary>
internal sealed unsafe class FfmpegVideoDecoder :
    IMediaFrameDecoder,
    IMediaAudioDiagnostics,
    IMediaMovieAudio
{
    private readonly object _decodeGate = new();
    private AVFormatContext* _formatContext;
    private AVCodecContext* _codecContext;
    private SwsContext* _swsContext;
    private AVFrame* _frame;
    private AVPacket* _packet;
    private readonly FfmpegMovieAudioDecoder? _movieAudio;
    private readonly int _videoStreamIndex;
    private bool _draining;
    private int _disposed;

    public uint Width { get; }

    public uint Height { get; }

    public uint FramesPerSecondNumerator { get; }

    public uint FramesPerSecondDenominator { get; }

    private FfmpegVideoDecoder(
        AVFormatContext* formatContext,
        AVCodecContext* codecContext,
        int videoStreamIndex,
        FfmpegMovieAudioDecoder? movieAudio,
        uint width,
        uint height,
        uint framesPerSecondNumerator,
        uint framesPerSecondDenominator)
    {
        _formatContext = formatContext;
        _codecContext = codecContext;
        _videoStreamIndex = videoStreamIndex;
        _movieAudio = movieAudio;
        Width = width;
        Height = height;
        FramesPerSecondNumerator = framesPerSecondNumerator;
        FramesPerSecondDenominator = framesPerSecondDenominator;
        _frame = ffmpeg.av_frame_alloc();
        _packet = ffmpeg.av_packet_alloc();
        if (_frame is null || _packet is null)
        {
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

            throw new OutOfMemoryException("video packet/frame allocation failed");
        }
    }

    internal static bool TryOpen(
        string path,
        uint maximumWidth,
        uint maximumHeight,
        out FfmpegVideoDecoder? source)
    {
        source = null;
        FfmpegRuntime.EnsureInitialized();

        AVFormatContext* formatContext = null;
        AVCodecContext* codecContext = null;
        FfmpegMovieAudioDecoder? movieAudio = null;
        try
        {
            if (ffmpeg.avformat_open_input(&formatContext, path, null, null) < 0 ||
                formatContext is null)
            {
                return false;
            }

            if (ffmpeg.avformat_find_stream_info(formatContext, null) < 0)
            {
                return false;
            }

            AVCodec* decoder = null;
            var videoStreamIndex = ffmpeg.av_find_best_stream(
                formatContext,
                AVMediaType.AVMEDIA_TYPE_VIDEO,
                -1,
                -1,
                &decoder,
                0);
            if (videoStreamIndex < 0 || decoder is null)
            {
                return false;
            }

            var videoStream = formatContext->streams[videoStreamIndex];
            codecContext = ffmpeg.avcodec_alloc_context3(decoder);
            if (codecContext is null ||
                ffmpeg.avcodec_parameters_to_context(
                    codecContext,
                    videoStream->codecpar) < 0)
            {
                return false;
            }

            codecContext->thread_count = 0;
            codecContext->thread_type = ffmpeg.FF_THREAD_FRAME | ffmpeg.FF_THREAD_SLICE;
            if (ffmpeg.avcodec_open2(codecContext, decoder, null) < 0 ||
                codecContext->width <= 0 || codecContext->height <= 0)
            {
                return false;
            }

            var frameRate = ffmpeg.av_guess_frame_rate(
                formatContext,
                videoStream,
                null);
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = videoStream->avg_frame_rate;
            }
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = videoStream->r_frame_rate;
            }
            if (frameRate.num <= 0 || frameRate.den <= 0)
            {
                frameRate = new AVRational { num = 30, den = 1 };
            }

            // This query is against the already-open video context. It does
            // not create a second input for a no-audio movie.
            var audioStreamIndex = ffmpeg.av_find_best_stream(
                formatContext,
                AVMediaType.AVMEDIA_TYPE_AUDIO,
                -1,
                -1,
                null,
                0);
            if (audioStreamIndex >= 0)
            {
                movieAudio = FfmpegMovieAudioDecoder.TryOpen(
                    path,
                    formatContext->start_time,
                    formatContext->duration);
            }

            var outputWidth = (uint)codecContext->width;
            var outputHeight = (uint)codecContext->height;
            if (maximumWidth > 0 && maximumHeight > 0 &&
                (outputWidth > maximumWidth || outputHeight > maximumHeight))
            {
                if ((ulong)outputWidth * maximumHeight >
                    (ulong)outputHeight * maximumWidth)
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
                movieAudio,
                outputWidth,
                outputHeight,
                (uint)frameRate.num,
                (uint)frameRate.den);
            formatContext = null;
            codecContext = null;
            movieAudio = null;
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        finally
        {
            movieAudio?.Dispose();
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

    public bool HasAudioTrack => _movieAudio is not null && _movieAudio.HasAudioTrack;

    public void Start() => _movieAudio?.Start();

    public MovieAudioProgress GetMovieAudioProgress() =>
        _movieAudio?.GetMovieAudioProgress() ??
        new(MovieAudioProgressState.NoTrack, 0, true, string.Empty);

    public void Pause() => _movieAudio?.Pause();

    public void Resume() => _movieAudio?.Resume();

    public void SetMovieDiagnosticIdentity(
        string source,
        long movieInstanceId,
        long hostMovieGeneration) =>
        _movieAudio?.SetMovieDiagnosticIdentity(
            source,
            movieInstanceId,
            hostMovieGeneration);

    public void SetDiagnosticPhase(string phase) =>
        _movieAudio?.SetDiagnosticPhase(phase);

    public bool TryDecodeNextFrame(Span<byte> destination)
    {
        lock (_decodeGate)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return false;
            }

            var stride = checked((int)(Width * 4));
            var required = (long)stride * Height;
            if (destination.Length < required)
            {
                return false;
            }

            if (!TryReceiveFrame())
            {
                return false;
            }

            _swsContext = ffmpeg.sws_getCachedContext(
                _swsContext,
                _frame->width,
                _frame->height,
                (AVPixelFormat)_frame->format,
                (int)Width,
                (int)Height,
                AVPixelFormat.AV_PIX_FMT_BGRA,
                ffmpeg.SWS_FAST_BILINEAR,
                null,
                null,
                null);
            if (_swsContext is null)
            {
                ffmpeg.av_frame_unref(_frame);
                return false;
            }

            fixed (byte* destinationPointer = destination)
            {
                var destinationPlanes = new byte*[4] { destinationPointer, null, null, null };
                var destinationStrides = new int[4] { stride, 0, 0, 0 };
                var convertedRows = ffmpeg.sws_scale(
                    _swsContext,
                    _frame->data,
                    _frame->linesize,
                    0,
                    _frame->height,
                    destinationPlanes,
                    destinationStrides);
                ffmpeg.av_frame_unref(_frame);
                return convertedRows == (int)Height;
            }
        }
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

            if (receiveResult == ffmpeg.AVERROR_EOF ||
                receiveResult != ffmpeg.AVERROR(ffmpeg.EAGAIN) ||
                _draining)
            {
                return false;
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
            var readDisposition = MovieDemuxReadBoundary.Classify(
                readResult,
                ffmpeg.AVERROR_EOF);
            if (readDisposition == MovieDemuxReadDisposition.EndOfInput)
            {
                _draining = true;
                return ffmpeg.avcodec_send_packet(_codecContext, null) >= 0;
            }

            if (readDisposition == MovieDemuxReadDisposition.Failure)
            {
                Console.Error.WriteLine(
                    $"[LOADER][WARN] movie video demux failed ({readResult}).");
                return false;
            }

            if (_packet->stream_index != _videoStreamIndex)
            {
                ffmpeg.av_packet_unref(_packet);
                continue;
            }

            var sendResult = ffmpeg.avcodec_send_packet(_codecContext, _packet);
            ffmpeg.av_packet_unref(_packet);
            return sendResult >= 0;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _movieAudio?.Dispose();
        lock (_decodeGate)
        {
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
        }
    }
}
