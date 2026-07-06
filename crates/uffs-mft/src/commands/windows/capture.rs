// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `capture` command — bundle a drive's `$MFT` + NTFS metafiles into one
//! hashed, manifested directory (`docs/architecture/mft-full-capture.md` §5–6).
//!
//! Writes the compressed `$MFT` and each metafile (via
//! [`uffs_mft::platform::metafile`]) into `out/drive_<x>/`, plus a
//! `manifest.json` (volume facts + per-artifact SHA-256) and a `SHA256SUMS`
//! file for transfer verification. Best-effort: an artifact that cannot be read
//! is skipped and noted, not fatal.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI capture progress output"
)]

use std::path::Path;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use uffs_mft::platform::metafile::{self, MetafileHeader, MetafileKind};
use uffs_mft::platform::{DriveLetter, VolumeHandle};
use uffs_mft::usize_to_u64;

/// One captured artifact, recorded in the manifest.
#[derive(serde::Serialize)]
struct ArtifactRecord {
    /// File name within the capture directory.
    file: String,
    /// NTFS metafile name (e.g. `$Boot`).
    kind: String,
    /// Source MFT FRS number.
    frs: u8,
    /// File size in bytes (header + payload).
    bytes: u64,
    /// SHA-256 of the file, lowercase hex.
    sha256: String,
}

/// Source-volume facts recorded in the manifest.
#[derive(serde::Serialize)]
struct VolumeInfo {
    /// Volume serial number, hex.
    serial: String,
    /// NTFS version (e.g. `3.1`).
    ntfs_version: String,
    /// Cluster size in bytes.
    bytes_per_cluster: u32,
    /// MFT record size in bytes.
    mft_record_size: u32,
}

/// The capture bundle manifest (`manifest.json`).
#[derive(serde::Serialize)]
struct Manifest {
    /// Manifest schema version.
    schema: u32,
    /// Captured drive letter.
    drive: String,
    /// Capture timestamp (RFC 3339, UTC).
    captured_at: String,
    /// `uffs-mft` version.
    tool_version: String,
    /// Source-volume facts.
    volume: VolumeInfo,
    /// Captured artifacts.
    artifacts: Vec<ArtifactRecord>,
}

/// SHA-256 of a byte slice, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Capture one metafile: read → save (with header) → hash. Returns its record.
fn capture_metafile(
    drive: DriveLetter,
    kind: MetafileKind,
    dir: &Path,
    drive_lower: &str,
    serial: u64,
    timestamp: u64,
) -> Result<ArtifactRecord> {
    let stem = kind.name().trim_start_matches('$').to_lowercase();
    let file = format!("{drive_lower}_{stem}.bin");
    let path = dir.join(&file);

    let data =
        metafile::read_metafile(drive, kind).with_context(|| format!("reading {}", kind.name()))?;
    let header = MetafileHeader {
        kind,
        drive,
        volume_serial: serial,
        timestamp,
        data_size: usize_to_u64(data.len()),
    };
    metafile::save_metafile_to_file(&path, &header, &data)
        .with_context(|| format!("saving {}", kind.name()))?;
    let bytes = std::fs::read(&path).with_context(|| format!("re-reading {}", path.display()))?;
    Ok(ArtifactRecord {
        file,
        kind: kind.name().to_owned(),
        frs: kind.frs(),
        bytes: usize_to_u64(bytes.len()),
        sha256: sha256_hex(&bytes),
    })
}

/// Assemble the capture manifest from volume facts and collected artifacts.
fn build_manifest(
    drive: DriveLetter,
    vol: &uffs_mft::platform::NtfsVolumeData,
    artifacts: Vec<ArtifactRecord>,
) -> Manifest {
    Manifest {
        schema: 1,
        drive: drive.to_string(),
        captured_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        volume: VolumeInfo {
            serial: format!("0x{:016X}", vol.volume_serial_number),
            ntfs_version: format!("{}.{}", vol.ntfs_major_version, vol.ntfs_minor_version),
            bytes_per_cluster: vol.bytes_per_cluster,
            mft_record_size: vol.bytes_per_file_record_segment,
        },
        artifacts,
    }
}

/// Write `manifest.json` + `SHA256SUMS` into the capture directory.
fn write_bundle(dir: &Path, manifest: &Manifest) -> Result<()> {
    let manifest_json =
        serde_json::to_string_pretty(manifest).context("serialising manifest.json")?;
    std::fs::write(dir.join("manifest.json"), &manifest_json).context("writing manifest.json")?;

    let mut sums = String::new();
    for artifact in &manifest.artifacts {
        sums.push_str(&artifact.sha256);
        sums.push_str("  ");
        sums.push_str(&artifact.file);
        sums.push('\n');
    }
    std::fs::write(dir.join("SHA256SUMS"), sums).context("writing SHA256SUMS")?;
    Ok(())
}

/// The NTFS metafiles the `capture` command bundles alongside the `$MFT`.
const METAFILE_KINDS: [MetafileKind; 9] = [
    MetafileKind::Boot,
    MetafileKind::Bitmap,
    MetafileKind::Secure,
    MetafileKind::AttrDef,
    MetafileKind::MftMirr,
    MetafileKind::Volume,
    MetafileKind::BadClus,
    MetafileKind::LogFile,
    MetafileKind::UsnJrnl,
];

/// Capture the compressed `$MFT` (LZ4) into the bundle.
fn capture_mft(drive: DriveLetter, dir: &Path, drive_lower: &str) -> Result<ArtifactRecord> {
    use uffs_mft::{MftReader, SaveRawOptions};

    let file = format!("{drive_lower}_mft.compressed.bin");
    let path = dir.join(&file);
    let reader = MftReader::open(drive).with_context(|| format!("opening $MFT on {drive}:"))?;
    let options = SaveRawOptions {
        compress: true,
        compression_level: 3,
        volume_letter: drive,
        raw_compat: false,
    };
    reader
        .save_raw_to_file(&path, &options)
        .with_context(|| format!("saving $MFT to {}", path.display()))?;
    let bytes = std::fs::read(&path).with_context(|| format!("re-reading {}", path.display()))?;
    Ok(ArtifactRecord {
        file,
        kind: "$MFT".to_owned(),
        frs: 0,
        bytes: usize_to_u64(bytes.len()),
        sha256: sha256_hex(&bytes),
    })
}

/// Capture the `$MFT` + every metafile into `dir`, printing progress and
/// returning their manifest records (best-effort: failures are skipped/noted).
fn collect_artifacts(
    drive: DriveLetter,
    dir: &Path,
    drive_lower: &str,
    serial: u64,
    timestamp: u64,
) -> Vec<ArtifactRecord> {
    let mut artifacts = Vec::new();

    match capture_mft(drive, dir, drive_lower) {
        Ok(record) => {
            println!(
                "  ✅ {:<9} {:>12} bytes  {}",
                "$MFT", record.bytes, record.file
            );
            artifacts.push(record);
        }
        Err(err) => println!("  ⚠️  {:<9} skipped — {err:#}", "$MFT"),
    }

    for kind in METAFILE_KINDS {
        match capture_metafile(drive, kind, dir, drive_lower, serial, timestamp) {
            Ok(record) => {
                println!(
                    "  ✅ {:<9} {:>12} bytes  {}",
                    kind.name(),
                    record.bytes,
                    record.file
                );
                artifacts.push(record);
            }
            Err(err) => println!("  ⚠️  {:<9} skipped — {err:#}", kind.name()),
        }
    }

    artifacts
}

/// Capture one drive's `$MFT` + all metafiles + `manifest.json` + `SHA256SUMS`
/// into `out/drive_<x>/`.
fn capture_one_drive(drive: DriveLetter, out: &Path) -> Result<()> {
    let drive_lower = drive.to_string().to_lowercase();
    let dir = out.join(format!("drive_{drive_lower}"));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating capture dir {}", dir.display()))?;

    let handle = VolumeHandle::open(drive).with_context(|| format!("Failed to open {drive}:"))?;
    let vol = handle.volume_data();
    let serial = vol.volume_serial_number;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());

    println!("═══════════════════════════════════════════════════════════════");
    println!("  UFFS capture — drive {drive}: → {}", dir.display());
    println!("═══════════════════════════════════════════════════════════════");

    let artifacts = collect_artifacts(drive, &dir, &drive_lower, serial, timestamp);
    let manifest = build_manifest(drive, vol, artifacts);
    write_bundle(&dir, &manifest)?;

    println!();
    println!("  Manifest: {}", dir.join("manifest.json").display());
    println!("  Hashes:   {}", dir.join("SHA256SUMS").display());
    println!("  {} artifact(s) captured.", manifest.artifacts.len());
    Ok(())
}

/// `capture` command — bundle one drive (`--drive C`) or every eligible NTFS
/// volume (`--all-drives`) into `out/drive_<x>/`.
///
/// With `--all-drives`, a per-drive failure is reported and skipped so the run
/// continues; the command still errors at the end if any drive failed.
pub(crate) async fn cmd_capture(
    drive: Option<DriveLetter>,
    out: &Path,
    all_drives: bool,
) -> Result<()> {
    if !all_drives {
        let only =
            drive.context("`--drive <LETTER>` is required unless `--all-drives` is given")?;
        return capture_one_drive(only, out);
    }

    let drives = uffs_mft::platform::detect_ntfs_drives();
    if drives.is_empty() {
        anyhow::bail!("no NTFS drives detected to capture");
    }
    println!("Capturing {} NTFS drive(s)…", drives.len());

    let mut failures: Vec<DriveLetter> = Vec::new();
    for letter in drives {
        if let Err(err) = capture_one_drive(letter, out) {
            println!("  ⚠️  drive {letter}: capture failed — {err:#}");
            failures.push(letter);
        }
    }
    if !failures.is_empty() {
        let list = failures
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!("{} drive(s) failed to capture: {list}", failures.len());
    }
    Ok(())
}
