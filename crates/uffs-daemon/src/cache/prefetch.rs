// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Region kernel-prefetch hook (Phase 5 task 5.2).
//!
//! On Windows the records + names columns of a re-promoted shard
//! are mmap'd, so we want the kernel to start paging them in *before*
//! the search actually dereferences a record.  `PrefetchVirtualMemory`
//! is the Win32 API for that — single syscall, batched per region,
//! kernel does the I/O while the search-thread is still acquiring
//! the registry write-lock and swapping the Arc.
//!
//! On Mac / Linux the columns may be heap-resident (`ColumnStorage::Vec`)
//! or mmap'd (`ColumnStorage::Mmap`).  `posix_madvise(MADV_WILLNEED)`
//! is harmless on either: heap pages are already resident; mmap pages
//! get an async readahead nudge.  The trait stays the same; only the
//! impl differs.
//!
//! The trait is held by [`crate::index::IndexManager`] as
//! `Arc<dyn Prefetch>` so production wires the platform impl and
//! the Phase 5 unit tests inject a recording fake (see
//! `tests::RecordingPrefetch`) to assert the hook fires with the
//! right (records, names) regions on every promote.

use std::io;

/// One memory region for [`Prefetch::hint`].
///
/// Wraps a raw `*const u8` + length so the slice can travel through
/// the trait method's `Send + Sync` bounds.  Raw pointers are
/// always safe to pass between threads — the safety contract is
/// on **dereference**, which only happens inside the platform impl
/// under the kernel's own synchronisation (the mmap stays alive
/// for the lifetime of the body `Arc`).
///
/// `Copy + Clone` because the platform impls walk the slice into
/// the kernel's batched-prefetch struct (`WIN32_MEMORY_RANGE_ENTRY`
/// on Windows; per-region `posix_madvise` on Mac/Linux); shallow
/// copies are correct and cheap.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PrefetchRegion {
    /// First byte of the region.  Must be page-aligned for
    /// `PrefetchVirtualMemory`; the kernel rounds down on
    /// `posix_madvise` so alignment is best-effort.
    pub ptr: *const u8,
    /// Length in bytes.  `0` is a documented no-op on every
    /// platform we ship.
    pub len: usize,
}

#[expect(
    unsafe_code,
    reason = "raw pointer Send/Sync wrapper: transmission is safe; dereference is guarded by the body Arc kept alive across hint()"
)]
// SAFETY: A raw pointer carries no ownership; transmitting one
// between threads is sound.  The dereference inside the platform
// impls is guarded by the body `Arc` keeping the underlying
// allocation / mmap alive across the entire `hint()` call.
unsafe impl Send for PrefetchRegion {}
#[expect(
    unsafe_code,
    reason = "raw pointer Send/Sync wrapper: transmission is safe; dereference is guarded by the body Arc kept alive across hint()"
)]
// SAFETY: Sharing a raw pointer + length across threads has no
// aliasing implications until dereference, which (per `Send` impl
// above) is guarded by the body `Arc` kept alive across `hint()`.
unsafe impl Sync for PrefetchRegion {}

/// Region kernel-prefetch hook.
///
/// Implementations are held as `Arc<dyn Prefetch>` on
/// [`crate::index::IndexManager`].  Called from
/// [`crate::index::IndexManager::ensure_warm_for_dispatch`] inside
/// the per-letter `spawn_blocking` task, just after
/// `BodyLoader::load` returns the freshly-loaded body and before
/// the registry write-lock swap (Phase 5 task 5.5).
///
/// Implementors must be `Send + Sync + 'static` so the orchestrator
/// can `Arc::clone` the trait object into each blocking task.  The
/// function is `&self` so concurrent promotes (one per drive letter)
/// are safe.
pub(crate) trait Prefetch: Send + Sync + 'static {
    /// Hint to the kernel that the supplied virtual-address regions
    /// are about to be touched.  Best-effort; any I/O error is
    /// logged at the call site and the daemon continues.  An empty
    /// `regions` slice is a documented no-op on every platform.
    fn hint(&self, regions: &[PrefetchRegion]) -> io::Result<()>;
}

/// Production prefetch implementation.
///
/// On Windows: single `PrefetchVirtualMemory` syscall with a stack-
/// allocated `WIN32_MEMORY_RANGE_ENTRY[]` built from `regions`.  On
/// Mac/Linux: per-region `posix_madvise(_, _, MADV_WILLNEED)` —
/// errors collapse into the first nonzero return.
///
/// Phase 5 task 5.2 — paired with the Phase-5 dogfood gate
/// "promote-on-search latency drops on the next-after-promote query".
pub(crate) struct PlatformPrefetch;

impl Prefetch for PlatformPrefetch {
    #[cfg(target_os = "windows")]
    fn hint(&self, regions: &[PrefetchRegion]) -> io::Result<()> {
        use windows::Win32::System::Memory::{PrefetchVirtualMemory, WIN32_MEMORY_RANGE_ENTRY};
        use windows::Win32::System::Threading::GetCurrentProcess;

        if regions.is_empty() {
            return Ok(());
        }

        // Translate our wrapper to the Win32 struct.  Layouts are
        // independent so we can't `transmute` the slice — explicit
        // map+collect is the only sound option.
        let entries: Vec<WIN32_MEMORY_RANGE_ENTRY> = regions
            .iter()
            .map(|region| WIN32_MEMORY_RANGE_ENTRY {
                VirtualAddress: region.ptr.cast::<core::ffi::c_void>().cast_mut(),
                NumberOfBytes: region.len,
            })
            .collect();

        #[expect(
            unsafe_code,
            reason = "GetCurrentProcess Win32 FFI returning a process pseudo-handle"
        )]
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid
        // for the process lifetime; the pseudo-handle does not need
        // closing.
        let process = unsafe { GetCurrentProcess() };
        #[expect(
            unsafe_code,
            reason = "PrefetchVirtualMemory Win32 FFI; safety preconditions satisfied by the orchestrator holding the body Arc across the call"
        )]
        // SAFETY: `process` was just obtained from `GetCurrentProcess`
        // above and is valid for the process lifetime.
        // `entries.as_ptr()` is non-null and aligned (Vec invariant),
        // valid for `entries.len()` contiguous reads of
        // `WIN32_MEMORY_RANGE_ENTRY`.  The caller (orchestrator)
        // keeps the body `Arc` alive across this call so each
        // `region.ptr` remains a live mapping.  `flags = 0` is the
        // documented "no special behaviour" value per Win32 docs
        // (`PrefetchVirtualMemory` accepts only
        // `PREFETCH_PROCESS_FOR_RECEIVE` or 0; we want 0).
        let result = unsafe { PrefetchVirtualMemory(process, &entries, 0) };
        result.map_err(|err| io::Error::other(err.to_string()))
    }

    #[cfg(not(target_os = "windows"))]
    fn hint(&self, regions: &[PrefetchRegion]) -> io::Result<()> {
        if regions.is_empty() {
            return Ok(());
        }

        // Per-region `posix_madvise(MADV_WILLNEED)`.  Heap regions
        // are already resident, so the kernel collapses the call
        // to a no-op; mmap'd regions get an async readahead nudge.
        // We bail at the first error — the demote controller logs
        // the failure and keeps going.
        for region in regions {
            #[expect(
                unsafe_code,
                reason = "posix_madvise requires unsafe FFI; safety preconditions are satisfied by the orchestrator holding the body Arc across the call"
            )]
            // SAFETY: `region.ptr` is the start of a live byte
            // range owned by the body `Arc` the orchestrator
            // keeps alive across this call.  `posix_madvise`
            // takes a `*mut c_void` but is documented as not
            // mutating the bytes; the cast is per-platform safe
            // because the kernel only touches page-table state.
            let result = unsafe {
                libc::posix_madvise(
                    region.ptr.cast::<core::ffi::c_void>().cast_mut(),
                    region.len,
                    libc::POSIX_MADV_WILLNEED,
                )
            };
            if result != 0_i32 {
                return Err(io::Error::from_raw_os_error(result));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::{Prefetch, PrefetchRegion};

    /// Phase 5 task 5.9 fake.  Records every `hint()` call with
    /// the (ptr, len) pairs as plain integers so the assertion
    /// can match against the body's records / names regions
    /// without juggling raw pointers.
    pub(crate) struct RecordingPrefetch {
        // `(usize, usize)` not `PrefetchRegion` because the
        // assertion side wants to compare against integers
        // captured by the test, not raw pointers that need
        // re-derivation.  The cast ptr → usize is identity;
        // the payload semantics are preserved.
        calls: Mutex<Vec<Vec<(usize, usize)>>>,
    }

    impl RecordingPrefetch {
        pub(crate) const fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        /// Snapshot of every recorded `hint()` invocation, in
        /// call-order.  Each entry is the full `regions` slice
        /// of that call (so a 2-region promote shows as a
        /// `[Vec<(_,_)>; 1]` with a 2-element inner vec).
        pub(crate) fn calls(&self) -> Vec<Vec<(usize, usize)>> {
            self.calls
                .lock()
                .expect("RecordingPrefetch mutex never poisoned in tests")
                .clone()
        }
    }

    impl Prefetch for RecordingPrefetch {
        fn hint(&self, regions: &[PrefetchRegion]) -> std::io::Result<()> {
            let snapshot: Vec<(usize, usize)> = regions
                .iter()
                .map(|region| (region.ptr as usize, region.len))
                .collect();
            // Mutex poisoning would only happen if a previous
            // `hint()` panicked while holding the lock.  In tests
            // we treat that as an outright failure rather than
            // hide it behind an `Ok(())` — surface the panic so
            // the suite tells us the fake is misbehaving.
            //
            // Guard scope tightened to the push so clippy's
            // `significant_drop_tightening` is satisfied; the
            // mutex is released the moment the snapshot lands.
            {
                let mut guard = self.calls.lock().map_err(|err| {
                    std::io::Error::other(format!("RecordingPrefetch mutex poisoned: {err}"))
                })?;
                guard.push(snapshot);
            };
            Ok(())
        }
    }

    /// Smoke-test the production stub on every platform: empty
    /// regions are a no-op; non-empty regions complete without
    /// panic.  Uses a heap allocation we own so the pointer is
    /// guaranteed live for the call.
    #[test]
    fn platform_prefetch_handles_empty_and_heap_regions() {
        use super::PlatformPrefetch;

        let prefetch = PlatformPrefetch;

        // Empty slice: documented no-op.
        prefetch
            .hint(&[])
            .expect("empty hint() never errors on any platform");

        // Heap region: kernel sees a live virtual-address range
        // backed by anonymous private pages.  `MADV_WILLNEED` /
        // `PrefetchVirtualMemory` may collapse to a no-op for
        // already-resident pages but must not panic or error.
        let buffer = vec![0_u8; 4096];
        let region = PrefetchRegion {
            ptr: buffer.as_ptr(),
            len: buffer.len(),
        };
        // On Windows, `PrefetchVirtualMemory` rejects ranges that
        // aren't part of a memory-mapped file with `ERROR_INVALID_
        // PARAMETER`.  That's an error, not a panic — accept either
        // outcome to keep the smoke-test cross-platform: the real
        // contract is "no panic, no crash".
        drop(prefetch.hint(&[region]));
        // Buffer must outlive the call, which it does syntactically.
        drop(buffer);
    }

    /// Recording fake captures every region as (ptr-as-usize,
    /// len) so tests can assert without juggling raw pointers.
    #[test]
    fn recording_prefetch_captures_every_region_in_order() {
        let prefetch = RecordingPrefetch::new();
        assert_eq!(prefetch.calls(), Vec::<Vec<(usize, usize)>>::new());

        let buf_a = [0_u8; 16];
        let buf_b = [0_u8; 32];
        let regions_first = [PrefetchRegion {
            ptr: buf_a.as_ptr(),
            len: buf_a.len(),
        }];
        let regions_second = [
            PrefetchRegion {
                ptr: buf_a.as_ptr(),
                len: buf_a.len(),
            },
            PrefetchRegion {
                ptr: buf_b.as_ptr(),
                len: buf_b.len(),
            },
        ];

        prefetch.hint(&regions_first).unwrap();
        prefetch.hint(&regions_second).unwrap();

        let captured = prefetch.calls();
        assert_eq!(captured.len(), 2, "two hint() calls recorded");
        let first = captured.first().expect("two recorded calls");
        assert_eq!(first.len(), 1);
        assert_eq!(
            *first.first().expect("first call recorded one region"),
            (buf_a.as_ptr() as usize, 16_usize),
        );
        let second = captured.get(1).expect("two recorded calls");
        assert_eq!(second.len(), 2);
        assert_eq!(
            *second.first().expect("second call recorded two regions"),
            (buf_a.as_ptr() as usize, 16_usize),
        );
        assert_eq!(
            *second.get(1).expect("second call recorded two regions"),
            (buf_b.as_ptr() as usize, 32_usize),
        );
    }
}
