// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-only command handlers for the `uffs-mft` binary.

mod bench;
mod benchmark_index;
mod benchmark_mft;
mod bitmap_diag;
mod capture;
mod drives;
mod incremental;
mod info;
mod read;
mod save;
mod shared;
mod usn;

pub(crate) use self::bench::{cmd_bench, cmd_bench_all};
pub(crate) use self::benchmark_index::{
    BenchmarkIndexLeanOptions, cmd_benchmark_index, cmd_benchmark_index_lean,
    cmd_benchmark_multi_volume, cmd_benchmark_tree,
};
pub(crate) use self::benchmark_mft::cmd_benchmark_mft;
pub(crate) use self::bitmap_diag::cmd_bitmap_diag;
pub(crate) use self::capture::cmd_capture;
pub(crate) use self::drives::cmd_drives;
pub(crate) use self::incremental::{
    cmd_cache_clear, cmd_cache_get, cmd_cache_status, cmd_index_all, cmd_index_load,
    cmd_index_save, cmd_index_update,
};
pub(crate) use self::info::cmd_info;
pub(crate) use self::read::cmd_read;
pub(crate) use self::save::{cmd_metafile, cmd_save};
pub(crate) use self::usn::{cmd_usn_info, cmd_usn_read};
