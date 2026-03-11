// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Logging;

public readonly record struct LogEntry(
    DateTimeOffset Timestamp,
    LogLevel Level,
    string Category,
    string Message,
    string SourceFileName,
    int SourceLine,
    string SourceMemberName,
    Exception? Exception = null);
