// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Narrow C ABI over the official `vsbackup.h` VSS requestor sequence.
// This is the entire native surface `uffs-vss-requestor`'s Rust side
// calls into — no raw IUnknown*, no vtable pointers, no caller-managed
// BSTR/VSS_SNAPSHOT_PROP ownership. Every out-pointer here is either a
// plain value type or a pointer this header's own `*_free` function
// releases; nothing SDK-owned crosses this boundary.

#pragma once

#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a live VSS requestor session (one `IVssBackupComponents`
// instance plus the snapshot-set/context state needed to delete it later).
// Only one snapshot set is ever created per session, matching
// `IVssBackupComponents`'s documented one-operation-per-instance contract.
typedef struct UffsVssSession UffsVssSession;

// Which step of the requestor sequence an error occurred at, for
// diagnostics (design doc: "Preserve stage and HRESULT").
typedef enum UffsVssStage {
    UFFS_VSS_STAGE_COM_INIT = 0,
    UFFS_VSS_STAGE_CREATE_COMPONENTS = 1,
    UFFS_VSS_STAGE_INITIALIZE_BACKUP = 2,
    UFFS_VSS_STAGE_SET_CONTEXT = 3,
    UFFS_VSS_STAGE_SET_BACKUP_STATE = 4,
    UFFS_VSS_STAGE_START_SET = 5,
    UFFS_VSS_STAGE_ADD_VOLUME = 6,
    UFFS_VSS_STAGE_DO_SET_SUBMIT = 7,
    UFFS_VSS_STAGE_DO_SET_WAIT = 8,
    UFFS_VSS_STAGE_DO_SET_STATUS = 9,
    UFFS_VSS_STAGE_GET_PROPERTIES = 10,
    UFFS_VSS_STAGE_INVALID_ARGUMENT = 11,
} UffsVssStage;

typedef struct UffsVssSnapshotInfo {
    GUID snapshot_set_id;
    GUID snapshot_id;
    GUID provider_id;
    // Both fields below are heap-allocated by this shim (a private copy,
    // never a pointer into VSS-owned VSS_SNAPSHOT_PROP memory) and must
    // be released via `uffs_vss_snapshot_info_free`.
    wchar_t *original_volume_name;
    wchar_t *snapshot_device_object;
    int64_t creation_timestamp_unix_ms;
} UffsVssSnapshotInfo;

typedef struct UffsVssError {
    int32_t hresult;
    UffsVssStage stage;
    // Heap-allocated by this shim; release via `uffs_vss_error_free`.
    wchar_t *message;
} UffsVssError;

// Create a `VSS_CTX_FILE_SHARE_BACKUP` (ephemeral, auto-release, no
// writer participation) snapshot of `volume_path` (a canonical
// `\\?\Volume{GUID}\`-style path).
//
// On success (return value `S_OK`): `*out_session` owns a live
// `IVssBackupComponents`, kept alive until `uffs_vss_session_release`;
// `*out_info` is populated and must be released via
// `uffs_vss_snapshot_info_free`. Because the context is auto-release,
// the underlying snapshot is deleted the moment `uffs_vss_session_release`
// drops the last reference to `IVssBackupComponents` — that is the
// *only* deletion path this shim exposes. There used to be a separate
// `uffs_vss_delete_snapshot_set` (calling `IVssBackupComponents::
// DeleteSnapshots`) for deterministic cleanup on normal completion, but
// that call was observed to hang indefinitely on real hardware when
// used on a `VSS_CTX_FILE_SHARE_BACKUP` snapshot set, so it was removed
// entirely rather than left as a landmine — `uffs_vss_session_release`
// is both the crash-safety net and the normal-completion path now.
//
// On failure: `*out_session` and `*out_info` are zeroed; `*out_error` is
// populated and must be released via `uffs_vss_error_free`.
int32_t uffs_vss_create_file_share_snapshot(
    const wchar_t *volume_path,
    UffsVssSession **out_session,
    UffsVssSnapshotInfo *out_info,
    UffsVssError *out_error);

// Release `session` (a no-op if `session` is `NULL`) — the only
// deletion path; see `uffs_vss_create_file_share_snapshot`'s doc
// comment above for why.
void uffs_vss_session_release(UffsVssSession *session);

void uffs_vss_snapshot_info_free(UffsVssSnapshotInfo *info);
void uffs_vss_error_free(UffsVssError *error);

#ifdef __cplusplus
}
#endif
