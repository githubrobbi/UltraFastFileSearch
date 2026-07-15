// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

use uffs_mft::index::{
    IndexNameRef, IndexStreamInfo, LinkInfo, MftIndex, NO_ENTRY, ROOT_FRS, SizeInfo, StandardInfo,
};

use super::*;

// WI-4.4 malformed-name tests live in a sibling file (shared fixtures via
// `super`) to keep this file under the 800-LOC policy. Explicit `#[path]`
// because this module is itself `#[path]`-loaded (`compact.rs` → `tests`),
// so plain `mod malformed;` would resolve against `src/`, not here.
#[path = "compact_tests/malformed.rs"]
mod malformed;

// ── helpers ──────────────────────────────────────────────────────

/// Push a name into the index and return its `IndexNameRef`.
fn push_name(index: &mut MftIndex, name: &str) -> IndexNameRef {
    let offset = index.add_name(name);
    let ext_id = index.intern_extension(name);
    IndexNameRef::new(
        offset,
        u16::try_from(name.len()).expect("test name too long"),
        name.is_ascii(),
        ext_id,
    )
}

/// Build a small fixture: root, one dir ("Docs"), a few files.
fn fixture_index() -> MftIndex {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::C);

    // Root (FRS 5)
    let root_name = push_name(&mut idx, ".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = root_name;
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // Docs directory (FRS 100)
    let docs_name = push_name(&mut idx, "Docs");
    let docs = idx.get_or_create(100.into());
    docs.stdinfo.set_directory(true);
    docs.first_name.name = docs_name;
    docs.first_name.parent_frs = Into::into(ROOT_FRS);
    docs.descendants = 3;
    docs.treesize = 500;

    // file.txt (FRS 200) — simple single-name, single-stream
    let file_name = push_name(&mut idx, "file.txt");
    let file = idx.get_or_create(200.into());
    file.first_name.name = file_name;
    file.first_name.parent_frs = Into::into(100);
    file.first_stream.size = SizeInfo {
        length: 120,
        allocated: 128,
    };
    file.stdinfo.created = 1_000_000;
    file.stdinfo.modified = 2_000_000;
    file.stdinfo.accessed = 3_000_000;
    file.stdinfo.flags = 0x20; // ARCHIVE

    // hardlink.txt (FRS 201) — 2 names (hardlink)
    let hl_primary = push_name(&mut idx, "hardlink.txt");
    let hl_alt_name = push_name(&mut idx, "hardlink_alt.txt");

    let link_idx = u32::try_from(idx.links.len()).expect("link overflow");
    idx.links.push(LinkInfo {
        next_entry: NO_ENTRY,
        name: hl_alt_name,
        _pad0: [0; 4],
        parent_frs: Into::into(ROOT_FRS),
    });

    let hl = idx.get_or_create(201.into());
    hl.first_name.name = hl_primary;
    hl.first_name.parent_frs = Into::into(100);
    hl.first_name.next_entry = link_idx;
    hl.name_count = 2;
    hl.first_stream.size = SizeInfo {
        length: 50,
        allocated: 64,
    };

    // ads_file.dat (FRS 202) — 2 streams (ADS)
    let ads_name = push_name(&mut idx, "ads_file.dat");
    let stream_name = push_name(&mut idx, "Zone.Identifier");

    let stream_idx = u32::try_from(idx.streams.len()).expect("stream overflow");
    idx.streams.push(IndexStreamInfo {
        size: SizeInfo {
            length: 26,
            allocated: 32,
        },
        next_entry: NO_ENTRY,
        name: stream_name,
        flags: 0,
        _pad0: [0; 3],
    });

    let ads = idx.get_or_create(202.into());
    ads.first_name.name = ads_name;
    ads.first_name.parent_frs = Into::into(100);
    ads.first_stream.size = SizeInfo {
        length: 300,
        allocated: 512,
    };
    ads.first_stream.next_entry = stream_idx;
    ads.stream_count = 2;

    // $MFT system metafile (FRS 0) — should be filterable
    let mft_name = push_name(&mut idx, "$MFT");
    let mft_rec = idx.get_or_create(0.into());
    mft_rec.first_name.name = mft_name;
    mft_rec.first_name.parent_frs = Into::into(ROOT_FRS);
    mft_rec.first_stream.size = SizeInfo {
        length: 500_000,
        allocated: 512_000,
    };

    idx
}

// ── Test 1: All critical fields transfer to CompactRecord ──────

#[test]
fn compact_preserves_all_critical_fields() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    // Find file.txt by scanning names
    let file_rec = drive
        .records
        .iter()
        .find(|rec| rec.name(&drive.names) == "file.txt")
        .expect("file.txt not found in compact index");

    assert_eq!(file_rec.size, 120, "size must transfer");
    assert_eq!(file_rec.allocated, 128, "allocated must transfer");
    assert_eq!(file_rec.created, 1_000_000, "created must transfer");
    assert_eq!(file_rec.modified, 2_000_000, "modified must transfer");
    assert_eq!(file_rec.accessed, 3_000_000, "accessed must transfer");
    assert_eq!(file_rec.flags, 0x20, "flags must transfer");
    assert!(!file_rec.is_directory(), "file must not be a directory");
}

// ── Test 2: Directory tree metrics transfer ────────────────────

#[test]
fn compact_preserves_directory_tree_metrics() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    let docs_rec = drive
        .records
        .iter()
        .find(|rec| rec.name(&drive.names) == "Docs")
        .expect("Docs not found");

    assert_eq!(docs_rec.descendants, 3, "descendants must transfer");
    assert_eq!(docs_rec.treesize, 500, "treesize must transfer");
    assert!(docs_rec.is_directory(), "Docs must be a directory");
}

// ── Test 3: Hardlink records only keep first_name ──────────────
// Regression: streaming pipeline iterated name_count × stream_count;
// compact stores only first_name. Refactor MUST account for this gap.

#[test]
fn compact_expands_hardlink_names() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    // Both primary and alternate hardlink names must appear as separate
    // CompactRecords so the unified pipeline matches the legacy pipeline.
    let hl_names: Vec<&str> = drive
        .records
        .iter()
        .filter(|rec| {
            let nm = rec.name(&drive.names);
            nm.contains("hardlink")
        })
        .map(|rec| rec.name(&drive.names))
        .collect();

    assert!(
        hl_names.contains(&"hardlink.txt"),
        "primary name must appear"
    );
    assert!(
        hl_names.contains(&"hardlink_alt.txt"),
        "alternate hardlink name must appear (expanded at build time)"
    );
}

// ── Test 4: ADS records only keep first_stream size ────────────
// Regression: streaming iterated stream_count; compact stores first_stream
// only. The ADS size (26 bytes) is invisible in compact.

#[test]
fn compact_stores_only_primary_stream_size() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    let ads_rec = drive
        .records
        .iter()
        .find(|rec| rec.name(&drive.names) == "ads_file.dat")
        .expect("ads_file.dat not found");

    // Compact stores the primary stream's size (300), NOT the ADS (26).
    assert_eq!(ads_rec.size, 300, "compact must store first_stream size");
    assert_eq!(
        ads_rec.allocated, 512,
        "compact must store first_stream allocated"
    );
    // The ADS size=26 is not visible here — it can only be resolved
    // by going back to the MftIndex. Any refactored output that shows
    // ADS rows must look up the original MftIndex stream data.
}

// ── Test 5: System metafile ($MFT) is present and filterable ───
// Regression: streaming used PathResolver.is_valid_idx which skips FRS 0–15;
// compact uses name.starts_with('$'). Different semantics.

#[test]
fn compact_filters_system_metafiles() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    // $MFT (FRS 0) must be filtered at build time — its CompactRecord should
    // have name_len=0 (default/zeroed), matching the legacy pipeline which
    // filters system metafiles via PathResolver.
    let has_mft = drive
        .records
        .iter()
        .any(|rec| rec.name(&drive.names) == "$MFT");

    assert!(
        !has_mft,
        "$MFT must NOT appear in compact index (filtered at build time)"
    );
}

// ── Test 6: parent_idx and children index ──────────────────────
// Regression: tree traversal relies on correct parent_idx wiring.

#[test]
fn compact_parent_idx_and_children_correct() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    // Find Docs' compact index
    let docs_pos = drive
        .records
        .iter()
        .position(|rec| rec.name(&drive.names) == "Docs")
        .expect("Docs not found");

    // Find file.txt's compact index
    let file_pos = drive
        .records
        .iter()
        .position(|rec| rec.name(&drive.names) == "file.txt")
        .expect("file.txt not found");

    // file.txt's parent_idx should point to Docs
    let file_rec = drive.records.get(file_pos).expect("file_pos out of bounds");
    let docs_pos_u32 = u32::try_from(docs_pos).expect("docs_pos overflow");
    assert_eq!(
        file_rec.parent_idx, docs_pos_u32,
        "file.txt parent_idx must point to Docs"
    );

    // Docs' children should include file.txt
    let file_pos_u32 = u32::try_from(file_pos).expect("file_pos overflow");
    let docs_children = drive.children.get(docs_pos);
    assert!(
        docs_children.contains(&file_pos_u32),
        "Docs children must include file.txt (idx {file_pos}), got: {docs_children:?}"
    );
}

// ── Test 7: names_lower for case-insensitive search ────────────

#[test]
fn compact_names_lower_is_correct() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    let docs_rec = drive
        .records
        .iter()
        .find(|rec| rec.name(&drive.names) == "Docs")
        .expect("Docs not found");

    let lower_name = docs_rec.name(&drive.names).to_ascii_lowercase();
    assert_eq!(
        lower_name, "docs",
        "on-the-fly lowering must produce lowercase"
    );
}

// ── Test 8: Verify record count matches ────────────────────────

#[test]
fn compact_record_count_includes_hardlinks() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);
    // Compact index has base records (same count as MftIndex) plus extra
    // records for expanded hardlink alternate names.
    assert!(
        drive.records.len() >= idx.records.len(),
        "compact must have at least as many records as MftIndex (base + hardlinks)"
    );
    // The fixture has exactly 1 hardlink alternate name (hardlink_alt.txt)
    // and 1 ADS stream (ads_file.dat:Zone.Identifier), so compact should
    // have exactly 2 extra records beyond MftIndex base records.
    assert_eq!(
        drive.records.len(),
        idx.records.len() + 2,
        "fixture: 1 hardlink expansion + 1 ADS expansion expected"
    );
}

// ── Regression test: parity between compact and legacy pipeline ──
// Catches three specific regressions:
//   (A) System metafiles ($MFT, $Extend, etc.) must be filtered at build time
//   (B) Root directory ("." name) must be present and searchable
//   (C) Hardlinked files must have all names expanded as separate records

#[test]
fn compact_parity_root_present_sysfiles_absent_hardlinks_expanded() {
    let idx = fixture_index();
    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);

    // (A) System metafiles must NOT appear.
    let system_names: Vec<&str> = drive
        .records
        .iter()
        .map(|rec| rec.name(&drive.names))
        .filter(|nm| nm.starts_with('$'))
        .collect();
    assert!(
        system_names.is_empty(),
        "no $-prefixed system metafiles in compact index, found: {system_names:?}"
    );

    // (B) Root directory must be present (name = ".").
    let root_present = drive
        .records
        .iter()
        .any(|rec| rec.name(&drive.names) == "." && rec.is_directory());
    assert!(root_present, "root directory '.' must be in compact index");

    // (C) Both hardlink names must be present.
    let all_names: Vec<&str> = drive
        .records
        .iter()
        .map(|rec| rec.name(&drive.names))
        .filter(|nm| !nm.is_empty())
        .collect();
    assert!(
        all_names.contains(&"hardlink.txt"),
        "primary hardlink name must be present"
    );
    assert!(
        all_names.contains(&"hardlink_alt.txt"),
        "alternate hardlink name must be present (expanded at build time)"
    );
}

// ── ADS (Alternate Data Stream) expansion ──────────────────────────

/// Build a fixture with a file that has an ADS (Zone.Identifier).
fn fixture_index_with_ads() -> MftIndex {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::M);

    // Root (FRS 5)
    let root_name = push_name(&mut idx, ".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = root_name;
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // file.pdf (FRS 100) — has a Zone.Identifier ADS
    let file_name = push_name(&mut idx, "file.pdf");
    let file = idx.get_or_create(100.into());
    file.first_name.name = file_name;
    file.first_name.parent_frs = Into::into(ROOT_FRS);
    file.first_stream.size = SizeInfo {
        length: 50_000,
        allocated: 51_200,
    };
    file.stdinfo.created = 1_000_000;
    file.stdinfo.modified = 2_000_000;
    file.stdinfo.accessed = 3_000_000;
    file.stdinfo.flags = 32; // Archive
    file.set_has_default_data();

    // Add ADS: Zone.Identifier
    let ads_name_offset = idx.add_name("Zone.Identifier");
    let ads_name_ref = IndexNameRef::new(ads_name_offset, 15, true, 0); // "Zone.Identifier" = 15 chars
    let ads_si = uffs_mft::len_to_u32(idx.streams.len());
    idx.streams.push(IndexStreamInfo {
        size: SizeInfo {
            length: 228,
            allocated: 0,
        },
        next_entry: NO_ENTRY,
        name: ads_name_ref,
        flags: 8 << 2, // type_name_id=8 for $DATA
        _pad0: [0; 3],
    });

    // Chain ADS to the record's stream list
    let file_idx = idx.frs_to_idx_opt(100.into()).unwrap();
    let file_mut = idx.records.get_mut(file_idx).expect("record must exist");
    file_mut.first_stream.next_entry = ads_si;
    file_mut.stream_count = 2;
    file_mut.total_stream_count = 2;

    idx
}

#[test]
fn ads_expanded_into_compact_records() {
    let idx = fixture_index_with_ads();
    let (compact, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::M, &idx);

    // Collect all non-empty names.
    let all_names: Vec<&str> = compact
        .records
        .iter()
        .map(|rec| rec.name(&compact.names))
        .filter(|n| !n.is_empty() && *n != ".")
        .collect();

    assert!(
        all_names.contains(&"file.pdf"),
        "primary file name must be present, got: {all_names:?}"
    );
    assert!(
        all_names.contains(&"file.pdf:Zone.Identifier"),
        "ADS entry must be expanded into a separate CompactRecord, got: {all_names:?}"
    );
}

#[test]
fn ads_compact_record_has_stream_size() {
    let idx = fixture_index_with_ads();
    let (compact, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::M, &idx);

    let ads_rec = compact
        .records
        .iter()
        .find(|rec| rec.name(&compact.names) == "file.pdf:Zone.Identifier")
        .expect("ADS CompactRecord must exist");

    assert_eq!(ads_rec.size, 228, "ADS size must be the stream's size");
    assert_eq!(
        ads_rec.allocated, 0,
        "ADS allocated must be the stream's allocated"
    );
    assert_eq!(ads_rec.descendants, 0, "ADS must have no tree descendants");
    assert_eq!(ads_rec.treesize, 0, "ADS must have no treesize");
}

#[test]
fn ads_compact_record_inherits_timestamps() {
    let idx = fixture_index_with_ads();
    let (compact, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::M, &idx);

    let base_rec = compact
        .records
        .iter()
        .find(|rec| rec.name(&compact.names) == "file.pdf")
        .expect("base file must exist");
    let ads_rec = compact
        .records
        .iter()
        .find(|rec| rec.name(&compact.names) == "file.pdf:Zone.Identifier")
        .expect("ADS must exist");

    assert_eq!(
        ads_rec.created, base_rec.created,
        "ADS inherits created timestamp"
    );
    assert_eq!(
        ads_rec.modified, base_rec.modified,
        "ADS inherits modified timestamp"
    );
    assert_eq!(
        ads_rec.accessed, base_rec.accessed,
        "ADS inherits accessed timestamp"
    );
    assert_eq!(
        ads_rec.flags, base_rec.flags,
        "ADS inherits flags from non-directory base record"
    );
}

#[test]
fn ads_on_directory_strips_directory_flag() {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::M);

    // Create root (FRS 5)
    let root_name = push_name(&mut idx, ".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = root_name;
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // Create a directory (FRS 200) with DIRECTORY | ARCHIVE flags
    let dir_name = push_name(&mut idx, "Airlink 430W");
    let dir_rec = idx.get_or_create(200.into());
    dir_rec.first_name.name = dir_name;
    dir_rec.first_name.parent_frs = Into::into(ROOT_FRS);
    dir_rec.stdinfo.set_directory(true);
    dir_rec.stdinfo.flags |= StandardInfo::IS_ARCHIVE;

    // Add ADS: Win32App_1
    let ads_name_offset = idx.add_name("Win32App_1");
    let ads_name_ref = IndexNameRef::new(ads_name_offset, 10, true, 0); // "Win32App_1" = 10 chars
    let ads_si = uffs_mft::len_to_u32(idx.streams.len());
    idx.streams.push(IndexStreamInfo {
        size: SizeInfo {
            length: 0,
            allocated: 0,
        },
        next_entry: NO_ENTRY,
        name: ads_name_ref,
        flags: 8 << 2, // type_name_id=8 for $DATA
        _pad0: [0; 3],
    });

    let dir_idx = idx.frs_to_idx_opt(200.into()).unwrap();
    let dir_mut = idx.records.get_mut(dir_idx).expect("record must exist");
    dir_mut.first_stream.next_entry = ads_si;
    dir_mut.stream_count = 2;
    dir_mut.total_stream_count = 2;

    let (compact, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::M, &idx);

    // The directory itself should have DIRECTORY flag.
    let dir_compact = compact
        .records
        .iter()
        .find(|rec| rec.name(&compact.names) == "Airlink 430W")
        .expect("directory must exist");
    assert!(
        dir_compact.is_directory(),
        "directory must have DIRECTORY flag"
    );

    // The ADS CompactRecord preserves raw NTFS flags (ground truth).
    // DIRECTORY bit remains set because the parent IS a directory.
    // The display layer (make_display_row) handles ADS-on-directory
    // separately by checking for ':' in the name.
    let ads_compact = compact
        .records
        .iter()
        .find(|rec| rec.name(&compact.names) == "Airlink 430W:Win32App_1")
        .expect("directory ADS must be expanded");
    assert!(
        ads_compact.is_directory(),
        "ADS on directory preserves DIRECTORY flag (NTFS ground truth)"
    );
    assert_ne!(
        ads_compact.flags & StandardInfo::IS_ARCHIVE,
        0,
        "ADS preserves ARCHIVE flag from parent record"
    );
    // Verify the combined flags match the parent's flags exactly.
    assert_eq!(
        ads_compact.flags, dir_compact.flags,
        "ADS flags must match parent directory flags (raw NTFS parity)"
    );
}

// ── is_ntfs_metafile_name: exact-allowlist classifier ──────────────
//
// 2026-06-11: `--hide-system` used to hide every name starting with `$`,
// which wrongly suppressed ordinary `$`-prefixed files that Everything (and
// every file manager) displays — `$Recycle.Bin`, `$PatchCache`, and the
// WinSxS `$$_*.cdf-ms` filemaps.  The classifier now matches only the fixed
// set of reserved NTFS metafiles.

#[test]
fn metafile_name_matches_reserved_set_case_insensitively() {
    for name in [
        "$MFT",
        "$MFTMirr",
        "$LogFile",
        "$Volume",
        "$AttrDef",
        "$Bitmap",
        "$Boot",
        "$BadClus",
        "$Secure",
        "$UpCase",
        "$Extend",
        "$ObjId",
        "$Quota",
        "$Reparse",
        "$UsnJrnl",
        "$RmMetadata",
        "$Repair",
        "$Txf",
    ] {
        assert!(
            is_ntfs_metafile_name(name),
            "{name} is a reserved NTFS metafile and must classify as one"
        );
    }
    // NTFS is case-insensitive; canonical casing varies in the wild.
    assert!(is_ntfs_metafile_name("$mft"));
    assert!(is_ntfs_metafile_name("$BADCLUS"));
}

#[test]
fn metafile_name_rejects_ordinary_dollar_files() {
    for name in [
        "$Recycle.Bin",
        "$PatchCache",
        "$WinREAgent",
        "$secret.dbt",
        // WinSxS filemaps — the concrete files the old filter wrongly hid.
        "$$_diagnostics_system_windowsmediaplayerconfiguration_537e287f.cdf-ms",
        "$MFTfoo", // prefix of a metafile name, but not an exact match
        "normal.txt",
        "config",
        "",
    ] {
        assert!(
            !is_ntfs_metafile_name(name),
            "{name:?} is an ordinary file and must NOT classify as a metafile"
        );
    }
}

/// Build a `DriveCompactIndex` whose `ext_names` table is at its
/// legitimate maximum size (`u16::MAX` entries — see
/// `DriveCompactIndex::intern_extension`'s own ceiling check).
fn drive_with_full_ext_names_table() -> DriveCompactIndex {
    let names: Vec<u8> = Vec::new();
    let records: Vec<CompactRecord> = Vec::new();
    let fold = uffs_text::case_fold::CaseFold::default_table();
    let trigram = TrigramIndex::build(&records, &names, fold);
    let children = ChildrenIndex::build(&records);
    let ext_index = ExtensionIndex::build(&records);

    // ids 0..u16::MAX-1 → exactly u16::MAX entries, the largest table
    // `intern_extension` will ever produce (it refuses to assign
    // id == u16::MAX).  Slot 0 keeps the reserved "no extension" string.
    let mut ext_names: Vec<Box<str>> = (0..u16::MAX)
        .map(|i| Box::from(format!("ext{i}")))
        .collect();
    if let Some(slot) = ext_names.get_mut(0) {
        *slot = Box::from("");
    }

    DriveCompactIndex {
        letter: uffs_mft::platform::DriveLetter::C,
        records: ColumnStorage::from_vec(records),
        names: ColumnStorage::from_vec(names),
        trigram: Arc::new(trigram),
        children: Arc::new(children),
        ext_index: Arc::new(ext_index),
        fold,
        ext_names,
        source: IndexSource::MftFile(std::path::PathBuf::from("C:")),
        source_epoch: 0,
        bloom: None,
        path_trie: None,
        frs_to_compact: Vec::new(),
        delta: None,
    }
}

/// Regression (uffsd crash on `--ext <list>` with several misses):
/// `resolve_ext_ids` used to zip an unbounded `0_u16..` range against
/// `ext_names.iter()`. `RangeFrom<u16>::next()` computes its *next*
/// state before yielding, so once `ext_names` reached its legitimate
/// `u16::MAX`-entry ceiling, looking up an extension absent from the
/// table drove the range one step past `u16::MAX` and panicked with
/// "attempt to add with overflow" — even though every id the table
/// could ever hold fit comfortably in a `u16`. Queries that missed on
/// even one requested extension (common with a multi-extension
/// `--ext` filter) crashed the whole daemon.
#[test]
fn resolve_ext_ids_handles_full_table_miss_without_overflow() {
    let drive = drive_with_full_ext_names_table();
    assert_eq!(drive.ext_names.len(), usize::from(u16::MAX));

    // Absent extension: must scan the entire (full) table and return
    // no matches instead of panicking.
    let ids = drive.resolve_ext_ids(&["nonexistent".to_owned()]);
    assert!(ids.is_empty());
}

/// Companion to the miss-case regression above: a real extension at
/// the very last valid slot still resolves to the correct id.
#[test]
fn resolve_ext_ids_finds_last_slot_of_full_table() {
    let drive = drive_with_full_ext_names_table();
    let last_id = u16::MAX - 1;
    let last_ext = format!("ext{last_id}");

    let ids = drive.resolve_ext_ids(&[last_ext]);
    assert_eq!(ids, vec![last_id]);
}
