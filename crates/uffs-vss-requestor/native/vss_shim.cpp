// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Implementation of the narrow VSS requestor shim declared in
// `vss_shim.h`. Compiled against the official Windows SDK's `vss.h` /
// `vswriter.h` / `vsbackup.h` (via `cargo-xwin`'s bundled SDK) and linked
// against `vssapi.lib` + `ole32.lib` — see this crate's `build.rs`.
//
// Sequence and context choice follow
// `docs/dev/architecture/uffs-vss-rust-cpp-shim-implementation-guide.md`:
// `VSS_CTX_FILE_SHARE_BACKUP` (ephemeral, auto-release, no writers) —
// this is a requestor for a filesystem point-in-time content scan, not
// an application-consistent backup, so no writer coordination
// (`GatherWriterMetadata`, `PrepareForBackup`, `BackupComplete`) is
// performed; the guide notes these are not valid in the no-writer flow.
//
// Deletion is release-only (`uffs_vss_session_release`), never
// `IVssBackupComponents::DeleteSnapshots`: an earlier version of this
// shim called `DeleteSnapshots` explicitly for deterministic
// normal-completion cleanup, but that call was observed to hang
// indefinitely on real Windows hardware when used on a
// `VSS_CTX_FILE_SHARE_BACKUP` snapshot set. Releasing the last
// `IVssBackupComponents` reference is this context's documented
// auto-release mechanism and is the only deletion path left.

#include "vss_shim.h"

#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

#include <new>

// One VSS requestor session: the live `IVssBackupComponents` plus enough
// state to delete its snapshot set later. Deliberately not reused across
// operations — `IVssBackupComponents` is documented as single-use per
// backup/restore/query operation.
struct UffsVssSession {
    IVssBackupComponents *backup_components = nullptr;
    bool com_initialized = false;
};

namespace {

wchar_t *duplicate_wide(const wchar_t *source) {
    if (source == nullptr) {
        return nullptr;
    }
    size_t length = 0;
    while (source[length] != L'\0') {
        ++length;
    }
    wchar_t *copy = new (std::nothrow) wchar_t[length + 1];
    if (copy == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index <= length; ++index) {
        copy[index] = source[index];
    }
    return copy;
}

void set_error(UffsVssError *out_error, HRESULT hr, UffsVssStage stage, const wchar_t *message) {
    if (out_error == nullptr) {
        return;
    }
    out_error->hresult = static_cast<int32_t>(hr);
    out_error->stage = stage;
    out_error->message = duplicate_wide(message != nullptr ? message : L"(no message)");
}

void zero_info(UffsVssSnapshotInfo *out_info) {
    if (out_info == nullptr) {
        return;
    }
    out_info->snapshot_set_id = GUID_NULL;
    out_info->snapshot_id = GUID_NULL;
    out_info->provider_id = GUID_NULL;
    out_info->original_volume_name = nullptr;
    out_info->snapshot_device_object = nullptr;
    out_info->creation_timestamp_unix_ms = 0;
}

// `VSS_TIMESTAMP` is a Windows `FILETIME`-shaped 64-bit value (100ns
// intervals since 1601-01-01). Convert to Unix milliseconds.
int64_t vss_timestamp_to_unix_ms(VSS_TIMESTAMP timestamp) {
    constexpr int64_t kFiletimeToUnixEpochOffsetIn100ns = 116444736000000000LL;
    int64_t hundred_ns_since_unix_epoch = static_cast<int64_t>(timestamp) - kFiletimeToUnixEpochOffsetIn100ns;
    return hundred_ns_since_unix_epoch / 10000;
}

void destroy_session(UffsVssSession *session) {
    if (session == nullptr) {
        return;
    }
    if (session->backup_components != nullptr) {
        // Releasing the last reference is what actually deletes the
        // snapshot for an auto-release context if it wasn't already
        // explicitly deleted — see this file's header-comment note.
        session->backup_components->Release();
        session->backup_components = nullptr;
    }
    if (session->com_initialized) {
        CoUninitialize();
        session->com_initialized = false;
    }
    delete session;
}

} // namespace

int32_t uffs_vss_create_file_share_snapshot(
    const wchar_t *volume_path,
    UffsVssSession **out_session,
    UffsVssSnapshotInfo *out_info,
    UffsVssError *out_error) {
    if (out_session != nullptr) {
        *out_session = nullptr;
    }
    zero_info(out_info);

    if (volume_path == nullptr || out_session == nullptr || out_info == nullptr) {
        set_error(out_error, E_INVALIDARG, UFFS_VSS_STAGE_INVALID_ARGUMENT, L"null argument");
        return E_INVALIDARG;
    }

    UffsVssSession *session = new (std::nothrow) UffsVssSession();
    if (session == nullptr) {
        set_error(out_error, E_OUTOFMEMORY, UFFS_VSS_STAGE_COM_INIT, L"allocation failure");
        return E_OUTOFMEMORY;
    }

    // A dedicated single-purpose helper process: this is the only COM
    // user in the whole process, so initializing the apartment here
    // (once, for this session's lifetime) and uninitializing on release
    // is the simplest correct pattern.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_COM_INIT, L"CoInitializeEx failed");
        delete session;
        return hr;
    }
    // S_FALSE means COM was already initialized on this thread; either
    // way we now hold a reference this session's release must balance.
    session->com_initialized = true;

    IVssBackupComponents *backup_components = nullptr;
    hr = CreateVssBackupComponents(&backup_components);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_CREATE_COMPONENTS, L"CreateVssBackupComponents failed");
        destroy_session(session);
        return hr;
    }
    session->backup_components = backup_components;

    hr = backup_components->InitializeForBackup();
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_INITIALIZE_BACKUP, L"InitializeForBackup failed");
        destroy_session(session);
        return hr;
    }

    hr = backup_components->SetContext(VSS_CTX_FILE_SHARE_BACKUP);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_SET_CONTEXT, L"SetContext(VSS_CTX_FILE_SHARE_BACKUP) failed");
        destroy_session(session);
        return hr;
    }

    hr = backup_components->SetBackupState(FALSE, FALSE, VSS_BT_COPY, FALSE);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_SET_BACKUP_STATE, L"SetBackupState failed");
        destroy_session(session);
        return hr;
    }

    VSS_ID snapshot_set_id = GUID_NULL;
    hr = backup_components->StartSnapshotSet(&snapshot_set_id);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_START_SET, L"StartSnapshotSet failed");
        destroy_session(session);
        return hr;
    }

    VSS_ID snapshot_id = GUID_NULL;
    hr = backup_components->AddToSnapshotSet(const_cast<wchar_t *>(volume_path), GUID_NULL, &snapshot_id);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_ADD_VOLUME, L"AddToSnapshotSet failed");
        destroy_session(session);
        return hr;
    }

    IVssAsync *async = nullptr;
    hr = backup_components->DoSnapshotSet(&async);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_DO_SET_SUBMIT, L"DoSnapshotSet failed to submit");
        destroy_session(session);
        return hr;
    }

    hr = async->Wait();
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_DO_SET_WAIT, L"IVssAsync::Wait failed");
        async->Release();
        destroy_session(session);
        return hr;
    }

    HRESULT async_result = S_OK;
    hr = async->QueryStatus(&async_result, nullptr);
    async->Release();
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_DO_SET_STATUS, L"IVssAsync::QueryStatus failed");
        destroy_session(session);
        return hr;
    }
    if (FAILED(async_result)) {
        set_error(out_error, async_result, UFFS_VSS_STAGE_DO_SET_STATUS, L"DoSnapshotSet completed with a failure result");
        destroy_session(session);
        return async_result;
    }

    VSS_SNAPSHOT_PROP properties;
    hr = backup_components->GetSnapshotProperties(snapshot_id, &properties);
    if (FAILED(hr)) {
        set_error(out_error, hr, UFFS_VSS_STAGE_GET_PROPERTIES, L"GetSnapshotProperties failed");
        destroy_session(session);
        return hr;
    }

    // Copy every field we need into shim-owned memory before freeing
    // VSS's own copy — never hand a pointer into `VSS_SNAPSHOT_PROP`
    // itself back across the ABI boundary.
    out_info->snapshot_set_id = properties.m_SnapshotSetId;
    out_info->snapshot_id = properties.m_SnapshotId;
    out_info->provider_id = properties.m_ProviderId;
    out_info->original_volume_name = duplicate_wide(properties.m_pwszOriginalVolumeName);
    out_info->snapshot_device_object = duplicate_wide(properties.m_pwszSnapshotDeviceObject);
    out_info->creation_timestamp_unix_ms = vss_timestamp_to_unix_ms(properties.m_tsCreationTimestamp);
    VssFreeSnapshotProperties(&properties);

    *out_session = session;
    return S_OK;
}

void uffs_vss_session_release(UffsVssSession *session) {
    destroy_session(session);
}

void uffs_vss_snapshot_info_free(UffsVssSnapshotInfo *info) {
    if (info == nullptr) {
        return;
    }
    delete[] info->original_volume_name;
    delete[] info->snapshot_device_object;
    zero_info(info);
}

void uffs_vss_error_free(UffsVssError *error) {
    if (error == nullptr) {
        return;
    }
    delete[] error->message;
    error->message = nullptr;
    error->hresult = S_OK;
}
