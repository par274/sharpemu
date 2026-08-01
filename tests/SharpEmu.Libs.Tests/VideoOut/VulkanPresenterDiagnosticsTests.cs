// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using System.Runtime.CompilerServices;
using SharpEmu.Libs.Tests.Diagnostics;
using SharpEmu.Libs.VideoOut;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

[Collection(MemoryDiagnosticsStateCollection.Name)]
public sealed class VulkanPresenterDiagnosticsTests
{
    private static readonly Type PresenterType =
        typeof(VulkanVideoPresenter).GetNestedType(
            "Presenter",
            BindingFlags.NonPublic)!;

    private static readonly Type PendingGuestWorkType =
        typeof(VulkanVideoPresenter).GetNestedType(
            "PendingGuestWork",
            BindingFlags.NonPublic)!;

    private static readonly Type TextureResourceType =
        PresenterType.GetNestedType(
            "TextureResource",
            BindingFlags.NonPublic)!;

    private static readonly MethodInfo SetDiagnosticWorkMethod =
        PresenterType.GetMethod(
            "SetDiagnosticWork",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo SetDiagnosticPhaseMethod =
        PresenterType.GetMethod(
            "SetDiagnosticPhase",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo ClearDiagnosticWorkMethod =
        PresenterType.GetMethod(
            "ClearDiagnosticWork",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo GetDiagnosticSnapshotMethod =
        PresenterType.GetMethod(
            "GetDiagnosticSnapshot",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo ReleaseTextureOwnershipMethod =
        PresenterType.GetMethod(
            "ReleaseTextureCacheDiagnosticOwnership",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo IncrementPendingSubmissionMethod =
        PresenterType.GetMethod(
            "IncrementDiagnosticPendingGuestSubmission",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo IncrementAbandonedSubmissionMethod =
        PresenterType.GetMethod(
            "IncrementDiagnosticAbandonedGuestSubmission",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo DecrementPendingSubmissionMethod =
        PresenterType.GetMethod(
            "DecrementDiagnosticPendingGuestSubmission",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo DecrementAbandonedSubmissionMethod =
        PresenterType.GetMethod(
            "DecrementDiagnosticAbandonedGuestSubmission",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

    [Fact]
    public void DisabledPresenterDiagnosticsLeaveDiagnosticStateUntouched()
    {
        var presenter = RuntimeHelpers.GetUninitializedObject(PresenterType);
        SetField(presenter, "_diagnosticsEnabled", false);
        SetField(presenter, "_diagnosticPhase", "sentinel-phase");
        SetField(presenter, "_diagnosticActiveWorkSummary", "sentinel-work");
        SetField(presenter, "_diagnosticActiveQueueName", "sentinel-queue");
        SetField(presenter, "_diagnosticLastProgress", "sentinel-progress");
        SetField(presenter, "_diagnosticActiveWorkSequence", 17L);
        SetField(presenter, "_diagnosticActiveSubmissionId", 23UL);
        SetField(presenter, "_diagnosticPhaseStartedTicks", 29L);
        SetField(presenter, "_diagnosticLastProgressTicks", 31L);
        SetField(presenter, "_diagnosticTraceActiveWork", true);

        SetDiagnosticPhaseMethod.Invoke(
            presenter,
            ["disabled-phase"]);
        SetDiagnosticWorkMethod.Invoke(
            presenter,
            [RuntimeHelpers.GetUninitializedObject(PendingGuestWorkType)]);
        ClearDiagnosticWorkMethod.Invoke(presenter, null);
        IncrementPendingSubmissionMethod.Invoke(presenter, null);
        IncrementAbandonedSubmissionMethod.Invoke(presenter, null);

        Assert.Null(GetDiagnosticSnapshotMethod.Invoke(presenter, null));
        Assert.Equal("sentinel-phase", GetField<string>(presenter, "_diagnosticPhase"));
        Assert.Equal(
            "sentinel-work",
            GetField<string>(presenter, "_diagnosticActiveWorkSummary"));
        Assert.Equal(
            "sentinel-queue",
            GetField<string>(presenter, "_diagnosticActiveQueueName"));
        Assert.Equal(
            "sentinel-progress",
            GetField<string>(presenter, "_diagnosticLastProgress"));
        Assert.Equal(17L, GetField<long>(presenter, "_diagnosticActiveWorkSequence"));
        Assert.Equal(23UL, GetField<ulong>(presenter, "_diagnosticActiveSubmissionId"));
        Assert.Equal(29L, GetField<long>(presenter, "_diagnosticPhaseStartedTicks"));
        Assert.Equal(31L, GetField<long>(presenter, "_diagnosticLastProgressTicks"));
        Assert.True(GetField<bool>(presenter, "_diagnosticTraceActiveWork"));
        Assert.Equal(
            0,
            GetField<int>(presenter, "_diagnosticPendingGuestSubmissionCount"));
        Assert.Equal(
            0,
            GetField<int>(presenter, "_diagnosticAbandonedGuestSubmissionCount"));
    }

    [Fact]
    public void TextureCacheOwnershipReleasesExactlyOnceAfterGateClears()
    {
        var presenter = RuntimeHelpers.GetUninitializedObject(PresenterType);
        var texture = RuntimeHelpers.GetUninitializedObject(TextureResourceType);
        SetField(presenter, "_diagnosticsEnabled", false);
        SetField(presenter, "_diagnosticTextureCacheCount", 1);
        SetField(presenter, "_diagnosticTextureCacheBytes", 4096L);
        SetField(texture, "DiagnosticCacheDeviceBytes", 4096L);
        SetField(texture, "DiagnosticCacheOwnership", 1);

        ReleaseTextureOwnershipMethod.Invoke(presenter, [texture]);
        ReleaseTextureOwnershipMethod.Invoke(presenter, [texture]);

        Assert.Equal(0, GetField<int>(presenter, "_diagnosticTextureCacheCount"));
        Assert.Equal(0L, GetField<long>(presenter, "_diagnosticTextureCacheBytes"));
        Assert.Equal(0L, GetField<long>(texture, "DiagnosticCacheDeviceBytes"));
        Assert.Equal(0, GetField<int>(texture, "DiagnosticCacheOwnership"));
    }

    [Fact]
    public void SubmissionCountersDrainWithoutGoingNegative()
    {
        var presenter = RuntimeHelpers.GetUninitializedObject(PresenterType);
        SetField(presenter, "_diagnosticsEnabled", true);

        IncrementPendingSubmissionMethod.Invoke(presenter, null);
        IncrementAbandonedSubmissionMethod.Invoke(presenter, null);
        SetField(presenter, "_diagnosticsEnabled", false);
        DecrementPendingSubmissionMethod.Invoke(presenter, null);
        DecrementPendingSubmissionMethod.Invoke(presenter, null);
        DecrementAbandonedSubmissionMethod.Invoke(presenter, null);
        DecrementAbandonedSubmissionMethod.Invoke(presenter, null);

        Assert.Equal(
            0,
            GetField<int>(presenter, "_diagnosticPendingGuestSubmissionCount"));
        Assert.Equal(
            0,
            GetField<int>(presenter, "_diagnosticAbandonedGuestSubmissionCount"));
    }

    private static void SetField(object target, string name, object value) =>
        GetField(target, name).SetValue(target, value);

    private static T GetField<T>(object target, string name) =>
        (T)GetField(target, name).GetValue(target)!;

    private static FieldInfo GetField(object target, string name) =>
        target.GetType().GetField(
            name,
            BindingFlags.Instance |
            BindingFlags.NonPublic |
            BindingFlags.Public) ??
        throw new MissingFieldException(target.GetType().FullName, name);
}
