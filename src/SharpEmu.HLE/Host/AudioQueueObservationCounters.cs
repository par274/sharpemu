// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// Separates the cumulative structured queue observations from the resettable
/// one-second legacy trace window. The caller serializes access.
/// </summary>
internal sealed class AudioQueueObservationCounters
{
    private long _diagnosticEmptyQueueObservations;
    private long _traceWindowEmptyQueueObservations;

    internal long DiagnosticEmptyQueueObservations =>
        _diagnosticEmptyQueueObservations;

    internal void RecordDiagnosticObservation(int queuedInputBytes)
    {
        if (queuedInputBytes == 0)
        {
            _diagnosticEmptyQueueObservations++;
        }
    }

    internal void RecordTraceSubmission(int queuedInputBytes)
    {
        if (queuedInputBytes == 0)
        {
            _traceWindowEmptyQueueObservations++;
        }
    }

    internal long TakeTraceWindowEmptyQueueObservations()
    {
        var observations = _traceWindowEmptyQueueObservations;
        _traceWindowEmptyQueueObservations = 0;
        return observations;
    }
}
