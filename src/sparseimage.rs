// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Sparse images (`.sparseimage`): one file holding a header with a band
//! table, then the bands the disk has written to.
//!
//! # Layout
//!
//! Source: the libyal libmodi format notes, section "Sparse disk image
//! (.sparseimage) format" in
//! <https://github.com/libyal/libmodi/blob/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc>,
//! cross-checked against the Keramics description at
//! <https://keramics.github.io/sparseimage.html>. Both describe the same
//! layout and both mark several header fields as unknown; the Keramics page
//! is a later write-up of the same analysis, not an independent
//! implementation, and no third implementation was found.
//!
//! All integers are big-endian. The header is 4096 bytes:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | signature `sprs` |
//! | 4 | 4 | version (only 3 has been seen) |
//! | 8 | 4 | sectors per band (sectors are always 512 bytes) |
//! | 12 | 4 | unknown (seen as 1), ignored |
//! | 16 | 4 | disk size in sectors |
//! | 20 | 12 | unknown, ignored |
//! | 32 | 4 | unknown, ignored |
//! | 36 | 28 | unknown, ignored |
//! | 64 | 4096 - 64 | band table: 1008 entries of 4 bytes |
//!
//! Table entry `i` describes the `i`th band slot in the file. A non-zero
//! entry `n` says slot `i` holds disk band `n`, counted from 1; zero means
//! the entry is unused. Slot `i` starts at file offset
//! `4096 + i * sectors_per_band * 512`; disk band `n` covers disk bytes from
//! `(n - 1) * sectors_per_band * 512`. Disk bands with no table entry read as
//! zeros. Slots may hold bands in any order. The references give no limit on
//! the table, so the reader takes it as the 1008 entries that fit in the
//! 4096-byte header they describe.
//!
//! # Choices where the references are silent
//!
//! - Only version 3 opens; any other version is `Unsupported`, naming it.
//! - A mapped slot that starts at or past the end of the file is corrupt.
//! - A mapped slot that starts inside the file but is cut short by its end
//!   reads the missing part as zeros, so an interrupted copy still opens.
//! - Two table entries naming the same disk band are corrupt.
//! - A file with bytes past the end of the last slot its table maps is
//!   `Unsupported`. 1008 slots of the common 1 MiB band hold about 1 GiB;
//!   how bigger images extend the table is undocumented (the unknown field
//!   at byte 32 is a candidate), and refusing beats reading the wrong band.
//!   To be settled against a large real image in the conformance pass.
//! - The reader holds one `(disk band, slot)` pair per used table entry (at
//!   most 1008), sorted by disk band. Nothing is sized by the claimed disk.

use std::path::Path;
use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;

/// The structure name used in errors.
const WHAT: &str = "sparse image header";
/// Size of the header, which is also the file offset of slot 0.
const HEADER_LEN: usize = 4096;
/// Byte offset of the band table in the header.
const TABLE_OFFSET: usize = 64;
/// Entries in the band table.
const TABLE_ENTRIES: usize = (HEADER_LEN - TABLE_OFFSET) / 4;
/// `sprs` read as a big-endian number.
const SIGNATURE: u32 = 0x7370_7273;
/// The only version seen in the wild.
const VERSION: u32 = 3;
/// Bytes per sector.
const SECTOR: u64 = 512;

/// Opens the image at `path` read-only.
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    Ok(Arc::new(SparseImageSource::new(file)?))
}

/// One used table entry.
#[derive(Debug, Clone, Copy)]
struct Mapped {
    /// Disk band number, counted from 1.
    band: u32,
    /// File offset of the slot holding the band.
    file_offset: u64,
    /// Table index of the slot, for error reports.
    slot: u32,
}

/// The disk a sparse image presents.
pub struct SparseImageSource {
    file: Arc<dyn BlockSource>,
    /// Bytes per band.
    band_bytes: u64,
    /// Size of the disk in bytes.
    len: u64,
    /// Used table entries, sorted by disk band, without duplicates.
    mapped: Vec<Mapped>,
}

fn corrupt(offset: usize, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(WHAT, Location::Byte(offset as u64), kind))
}

/// Header offset of table entry `slot`, for error locations.
fn entry_offset(slot: usize) -> usize {
    TABLE_OFFSET.saturating_add(slot.saturating_mul(4))
}

fn be32(header: &[u8], offset: usize) -> Result<u32> {
    offset
        .checked_add(4)
        .and_then(|end| header.get(offset..end))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| {
            corrupt(
                offset,
                CorruptKind::Truncated {
                    needed: 4,
                    available: 0,
                },
            )
        })
}

impl SparseImageSource {
    /// Parses the header of the sparse image stored in `file`.
    ///
    /// Fails with [`Error::Corrupt`] when the header is damaged and with
    /// [`Error::Unsupported`] for a version other than 3.
    pub fn new(file: Arc<dyn BlockSource>) -> Result<Self> {
        let file_len = file.len();
        if file_len < HEADER_LEN as u64 {
            return Err(corrupt(
                0,
                CorruptKind::Truncated {
                    needed: HEADER_LEN as u64,
                    available: file_len,
                },
            ));
        }
        let mut header = vec![0u8; HEADER_LEN];
        file.read_at(0, &mut header)?;

        let signature = be32(&header, 0)?;
        if signature != SIGNATURE {
            return Err(corrupt(
                0,
                CorruptKind::BadSignature {
                    expected: u64::from(SIGNATURE),
                    found: u64::from(signature),
                },
            ));
        }
        let version = be32(&header, 4)?;
        if version != VERSION {
            return Err(Error::unsupported(format!(
                "sparse image version {version}"
            )));
        }
        let sectors_per_band = be32(&header, 8)?;
        if sectors_per_band == 0 {
            return Err(corrupt(
                8,
                CorruptKind::InvalidValue {
                    field: "sectors per band",
                    value: 0,
                },
            ));
        }
        let total_sectors = be32(&header, 16)?;
        // Both fit: a u32 times 512 is below 2^41.
        let band_bytes = u64::from(sectors_per_band) * SECTOR;
        let len = u64::from(total_sectors) * SECTOR;
        let band_count = len.div_ceil(band_bytes);

        let table = header.get(TABLE_OFFSET..).unwrap_or_default();
        let mut mapped = Vec::new();
        for (slot, entry) in table
            .as_chunks::<4>()
            .0
            .iter()
            .take(TABLE_ENTRIES)
            .enumerate()
        {
            let entry_offset = entry_offset(slot);
            let band = u32::from_be_bytes(*entry);
            if band == 0 {
                continue;
            }
            if u64::from(band) > band_count {
                return Err(corrupt(
                    entry_offset,
                    CorruptKind::OutOfRange {
                        field: "band number",
                        value: u64::from(band),
                        limit_name: "band count",
                        limit: band_count,
                    },
                ));
            }
            let slot = u32::try_from(slot).unwrap_or(u32::MAX);
            let file_offset = u64::from(slot)
                .checked_mul(band_bytes)
                .and_then(|n| n.checked_add(HEADER_LEN as u64))
                .ok_or_else(|| {
                    corrupt(
                        entry_offset,
                        CorruptKind::Overflow {
                            field: "band offset",
                        },
                    )
                })?;
            if file_offset >= file_len {
                return Err(corrupt(
                    entry_offset,
                    CorruptKind::OutOfRange {
                        field: "band offset",
                        value: file_offset,
                        limit_name: "file size",
                        limit: file_len,
                    },
                ));
            }
            mapped.push(Mapped {
                band,
                file_offset,
                slot,
            });
        }
        mapped.sort_unstable_by_key(|m| (m.band, m.slot));
        if let Some((_, second)) = mapped
            .iter()
            .zip(mapped.iter().skip(1))
            .find(|(a, b)| a.band == b.band)
        {
            return Err(corrupt(
                entry_offset(second.slot as usize),
                CorruptKind::InvalidValue {
                    field: "duplicate band number",
                    value: u64::from(second.band),
                },
            ));
        }
        // The references describe one header with room for 1008 bands, which
        // at the common 1 MiB band size maps only about 1 GiB. How larger
        // images are laid out is not documented (the field at byte 32 may
        // point to more table space). A file holding data past the last slot
        // its table maps is such an image: refuse it rather than misread it.
        let mapped_end = mapped
            .iter()
            .map(|m| m.file_offset.saturating_add(band_bytes))
            .max()
            .unwrap_or(HEADER_LEN as u64);
        if file_len > mapped_end {
            return Err(Error::unsupported(
                "sparse images with data past their band table",
            ));
        }
        Ok(Self {
            file,
            band_bytes,
            len,
            mapped,
        })
    }

    /// The disk band (counted from 1) holding disk byte `pos`, and the
    /// offset of `pos` inside it.
    fn locate(&self, pos: u64) -> Option<(u64, u64)> {
        let band = pos.checked_div(self.band_bytes)?.checked_add(1)?;
        Some((band, pos.checked_rem(self.band_bytes)?))
    }

    fn read_with(&self, offset: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let file_len = self.file.len();
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size: file_len,
        };
        let mut pos = offset;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < band_bytes` and `rest`
        // is not empty, so the loop ends after at most `buf.len()` passes.
        while !rest.is_empty() {
            let left = rest.len();
            let (band, within) = self.locate(pos).ok_or_else(|| oob(pos, left))?;
            let in_band = self
                .band_bytes
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_band).map_or(left, |in_band| in_band.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            let found = u32::try_from(band)
                .ok()
                .and_then(|b| self.mapped.binary_search_by_key(&b, |m| m.band).ok())
                .and_then(|i| self.mapped.get(i));
            match found {
                None => chunk.fill(0),
                Some(m) => {
                    let start = m
                        .file_offset
                        .checked_add(within)
                        .ok_or_else(|| oob(m.file_offset, chunk.len()))?;
                    // A band cut short by the end of the file reads as zeros.
                    let avail = usize::try_from(file_len.saturating_sub(start))
                        .map_or(n, |avail| avail.min(n));
                    let (data, zeros) = chunk
                        .split_at_mut_checked(avail)
                        .ok_or_else(|| oob(start, n))?;
                    if !data.is_empty() {
                        if bulk {
                            self.file.read_bulk(start, data)?;
                        } else {
                            self.file.read_at(start, data)?;
                        }
                    }
                    zeros.fill(0);
                }
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

impl BlockSource for SparseImageSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, false)
    }

    fn read_bulk(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    /// Sectors per band in the test images: 1024-byte bands.
    const SPB: u32 = 2;
    const BAND: usize = 1024;

    /// The byte a stored band holds at `offset`, for disk band `band`.
    fn pattern(band: u32, offset: usize) -> u8 {
        (band as usize * 31 + offset * 7 + 1) as u8
    }

    /// Builds an image. `slots[i]` is the disk band stored in slot `i`
    /// (0 leaves the slot's table entry unused but still stores bytes).
    fn build(spb: u32, total_sectors: u32, slots: &[u32]) -> Vec<u8> {
        let band_bytes = spb as usize * 512;
        let mut out = vec![0u8; HEADER_LEN];
        out[..4].copy_from_slice(b"sprs");
        out[4..8].copy_from_slice(&3u32.to_be_bytes());
        out[8..12].copy_from_slice(&spb.to_be_bytes());
        out[12..16].copy_from_slice(&1u32.to_be_bytes());
        out[16..20].copy_from_slice(&total_sectors.to_be_bytes());
        for (i, band) in slots.iter().enumerate() {
            let at = TABLE_OFFSET + i * 4;
            out[at..at + 4].copy_from_slice(&band.to_be_bytes());
            out.extend((0..band_bytes).map(|o| pattern(*band, o)));
        }
        out
    }

    fn open_bytes(bytes: Vec<u8>) -> Result<SparseImageSource> {
        SparseImageSource::new(Arc::new(MemSource::new(bytes)))
    }

    /// What the disk should hold: stored bands in place, zeros elsewhere.
    fn expected(total_sectors: u32, slots: &[u32]) -> Vec<u8> {
        let len = total_sectors as usize * 512;
        let mut disk = vec![0u8; len];
        for band in slots.iter().filter(|b| **b != 0) {
            let start = (*band as usize - 1) * BAND;
            for o in 0..BAND {
                if let Some(b) = disk.get_mut(start + o) {
                    *b = pattern(*band, o);
                }
            }
        }
        disk
    }

    fn read_all(src: &SparseImageSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    fn set32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn is_corrupt(r: Result<SparseImageSource>) -> Corruption {
        match r {
            Err(Error::Corrupt(c)) => c,
            Err(other) => panic!("expected Corrupt, got {other:?}"),
            Ok(_) => panic!("expected Corrupt, got Ok"),
        }
    }

    #[test]
    fn round_trip_out_of_order_with_holes() {
        // 9 sectors: bands 1..=4 full, band 5 half. Bands 2 and 4 unmapped.
        let slots = [5, 1, 3];
        let src = open_bytes(build(SPB, 9, &slots)).unwrap();
        assert_eq!(src.len(), 9 * 512);
        assert_eq!(src.sector_size(), 512);
        assert_eq!(read_all(&src), expected(9, &slots));
    }

    #[test]
    fn unmapped_bands_read_as_zero() {
        let src = open_bytes(build(SPB, 6, &[])).unwrap();
        assert_eq!(read_all(&src), vec![0u8; 6 * 512]);
    }

    #[test]
    fn zero_entries_between_used_ones_are_skipped() {
        // Slot 1 is unused but present in the file.
        let slots = [2, 0, 1];
        let src = open_bytes(build(SPB, 4, &slots)).unwrap();
        assert_eq!(read_all(&src), expected(4, &slots));
    }

    #[test]
    fn reads_straddle_bands() {
        let slots = [3, 1, 2];
        let src = open_bytes(build(SPB, 6, &slots)).unwrap();
        let want = expected(6, &slots);
        for (offset, len) in [(1000, 100), (1020, 2000), (0, 3072), (2047, 2), (5, 3067)] {
            let mut buf = vec![0u8; len];
            src.read_at(offset as u64, &mut buf).unwrap();
            assert_eq!(buf, want[offset..offset + len], "at {offset} len {len}");
            let mut bulk = vec![0u8; len];
            src.read_bulk(offset as u64, &mut bulk).unwrap();
            assert_eq!(bulk, buf);
        }
    }

    #[test]
    fn mapped_then_unmapped_straddle() {
        let slots = [1];
        let src = open_bytes(build(SPB, 4, &slots)).unwrap();
        let want = expected(4, &slots);
        let mut buf = vec![0u8; 600];
        src.read_at(800, &mut buf).unwrap();
        assert_eq!(buf, want[800..1400]);
    }

    #[test]
    fn last_byte_and_end_of_disk() {
        let slots = [2];
        let src = open_bytes(build(SPB, 3, &slots)).unwrap();
        let want = expected(3, &slots);
        let mut one = [0u8; 1];
        src.read_at(src.len() - 1, &mut one).unwrap();
        assert_eq!(one[0], want[want.len() - 1]);
        // An empty read at the end succeeds.
        src.read_at(src.len(), &mut []).unwrap();
    }

    #[test]
    fn reads_past_the_end_fail() {
        let src = open_bytes(build(SPB, 3, &[1])).unwrap();
        let len = src.len();
        let mut buf = [0u8; 2];
        assert!(matches!(
            src.read_at(len - 1, &mut buf),
            Err(Error::OutOfBounds { .. })
        ));
        assert!(matches!(
            src.read_bulk(len, &mut buf),
            Err(Error::OutOfBounds { .. })
        ));
        assert!(matches!(
            src.read_at(u64::MAX, &mut buf),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn band_cut_short_reads_zeros_for_the_missing_part() {
        let slots = [1, 2];
        let mut bytes = build(SPB, 4, &slots);
        bytes.truncate(bytes.len() - 300);
        let src = open_bytes(bytes).unwrap();
        let mut want = expected(4, &slots);
        for b in &mut want[2048 - 300..2048] {
            *b = 0;
        }
        assert_eq!(read_all(&src), want);
    }

    #[test]
    fn band_slot_past_the_end_is_corrupt() {
        let mut bytes = build(SPB, 4, &[1, 2]);
        bytes.truncate(HEADER_LEN + BAND);
        let c = is_corrupt(open_bytes(bytes));
        assert_eq!(c.location, Location::Byte(TABLE_OFFSET as u64 + 4));
        assert!(matches!(
            c.kind,
            CorruptKind::OutOfRange {
                field: "band offset",
                ..
            }
        ));
    }

    #[test]
    fn short_file_is_truncated() {
        let c = is_corrupt(open_bytes(vec![0u8; 100]));
        assert!(matches!(c.kind, CorruptKind::Truncated { .. }));
        let c = is_corrupt(open_bytes(Vec::new()));
        assert!(matches!(c.kind, CorruptKind::Truncated { .. }));
        let mut bytes = build(SPB, 4, &[1]);
        bytes.truncate(HEADER_LEN - 1);
        assert!(matches!(
            is_corrupt(open_bytes(bytes)).kind,
            CorruptKind::Truncated { .. }
        ));
    }

    #[test]
    fn bad_signature() {
        let mut bytes = build(SPB, 4, &[1]);
        bytes[0] = b'x';
        let c = is_corrupt(open_bytes(bytes));
        assert_eq!(c.location, Location::Byte(0));
        assert!(matches!(c.kind, CorruptKind::BadSignature { .. }));
    }

    #[test]
    fn unknown_versions_are_unsupported() {
        for version in [0u32, 1, 2, 4, u32::MAX] {
            let mut bytes = build(SPB, 4, &[1]);
            set32(&mut bytes, 4, version);
            match open_bytes(bytes) {
                Err(Error::Unsupported(text)) => {
                    assert!(text.contains(&version.to_string()), "{text}");
                }
                other => panic!("expected Unsupported, got {:?}", other.err()),
            }
        }
    }

    #[test]
    fn zero_sectors_per_band_is_corrupt() {
        let mut bytes = build(SPB, 4, &[]);
        set32(&mut bytes, 8, 0);
        let c = is_corrupt(open_bytes(bytes));
        assert_eq!(c.location, Location::Byte(8));
        assert!(matches!(
            c.kind,
            CorruptKind::InvalidValue {
                field: "sectors per band",
                ..
            }
        ));
    }

    #[test]
    fn band_number_past_the_disk_is_corrupt() {
        // 4 sectors is 2 bands; band 3 does not exist.
        let c = is_corrupt(open_bytes(build(SPB, 4, &[1, 3])));
        assert_eq!(c.location, Location::Byte(TABLE_OFFSET as u64 + 4));
        assert!(matches!(
            c.kind,
            CorruptKind::OutOfRange {
                field: "band number",
                value: 3,
                limit: 2,
                ..
            }
        ));
        // An empty disk has no bands at all.
        assert!(matches!(
            is_corrupt(open_bytes(build(SPB, 0, &[1]))).kind,
            CorruptKind::OutOfRange { .. }
        ));
        // A band count of 3 allows band 3 but not u32::MAX.
        assert!(open_bytes(build(SPB, 5, &[3])).is_ok());
        let mut bytes = build(SPB, 5, &[1]);
        set32(&mut bytes, TABLE_OFFSET, u32::MAX);
        assert!(matches!(
            is_corrupt(open_bytes(bytes)).kind,
            CorruptKind::OutOfRange { .. }
        ));
    }

    #[test]
    fn duplicate_band_is_corrupt() {
        let c = is_corrupt(open_bytes(build(SPB, 6, &[2, 1, 2])));
        assert_eq!(c.location, Location::Byte(TABLE_OFFSET as u64 + 8));
        assert!(matches!(
            c.kind,
            CorruptKind::InvalidValue {
                field: "duplicate band number",
                value: 2
            }
        ));
    }

    #[test]
    fn huge_band_size_does_not_overflow_or_allocate() {
        // A band of 2 TiB on a 2 TiB disk with an empty table opens and reads zeros.
        let mut bytes = build(SPB, 4, &[]);
        set32(&mut bytes, 8, u32::MAX);
        set32(&mut bytes, 16, u32::MAX);
        let src = open_bytes(bytes).unwrap();
        assert_eq!(src.len(), u64::from(u32::MAX) * 512);
        let mut buf = [1u8; 64];
        src.read_at(src.len() - 64, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 64]);

        // The same band size with slot 1 mapped puts it far past the file.
        let mut bytes = build(SPB, 4, &[1, 1]);
        bytes.truncate(HEADER_LEN + BAND);
        set32(&mut bytes, 8, u32::MAX);
        set32(&mut bytes, 16, u32::MAX);
        set32(&mut bytes, TABLE_OFFSET, 0);
        set32(&mut bytes, TABLE_OFFSET + 4, 1);
        assert!(matches!(
            is_corrupt(open_bytes(bytes)).kind,
            CorruptKind::OutOfRange {
                field: "band offset",
                ..
            }
        ));
    }

    #[test]
    fn full_table_is_accepted() {
        let slots: Vec<u32> = (1..=TABLE_ENTRIES as u32).rev().collect();
        let total = TABLE_ENTRIES as u32 * SPB;
        let src = open_bytes(build(SPB, total, &slots)).unwrap();
        let want = expected(total, &slots);
        let mut buf = vec![0u8; 3000];
        src.read_at(500_000, &mut buf).unwrap();
        assert_eq!(buf, want[500_000..503_000]);
    }

    #[test]
    fn data_past_the_band_table_is_unsupported() {
        // A full table with one more band's worth of bytes after its last
        // slot: the layout of such images is undocumented.
        let slots: Vec<u32> = (1..=TABLE_ENTRIES as u32).collect();
        let mut bytes = build(SPB, (TABLE_ENTRIES as u32 + 1) * SPB, &slots);
        bytes.extend(std::iter::repeat_n(0xA5, BAND));
        match open_bytes(bytes) {
            Err(Error::Unsupported(what)) => assert!(what.contains("band table"), "{what}"),
            Err(other) => panic!("expected Unsupported, got {other:?}"),
            Ok(_) => panic!("expected Unsupported, got Ok"),
        }
        // A trailing slot whose table entry is unused counts the same way.
        let bytes = build(SPB, 4, &[1, 0]);
        assert!(matches!(open_bytes(bytes), Err(Error::Unsupported(_))));
        // A last band cut short is still fine.
        let mut bytes = build(SPB, 4, &[2, 1]);
        bytes.truncate(bytes.len() - 100);
        assert!(open_bytes(bytes).is_ok());
    }

    #[test]
    fn open_reads_a_file_from_disk() {
        let slots = [2, 1];
        let dir = std::env::temp_dir().join(format!("disk-atlas-sprs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.sparseimage");
        std::fs::write(&path, build(SPB, 4, &slots)).unwrap();
        let src = open(&path).unwrap();
        let mut buf = vec![0u8; 4 * 512];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, expected(4, &slots));
        drop(src);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Writes seed inputs for the `sparseimage` fuzz target into the
    /// directory named by `ATLAS_FUZZ_SEEDS`, in a `sparseimage`
    /// subfolder. Does nothing when the variable is unset. Run it with
    /// `cargo test --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes files; run by the fuzz CI job"]
    fn write_fuzz_seeds() {
        let Some(root) = std::env::var_os("ATLAS_FUZZ_SEEDS") else {
            return;
        };
        let dir = Path::new(&root).join("sparseimage");
        std::fs::create_dir_all(&dir).expect("create seed directory");
        let mut cut = build(SPB, 4, &[1, 2]);
        cut.truncate(cut.len() - 300);
        let mut bad_band = build(SPB, 4, &[1]);
        set32(&mut bad_band, TABLE_OFFSET, 9);
        let mut dup = build(SPB, 6, &[2, 1]);
        set32(&mut dup, TABLE_OFFSET + 4, 2);
        let mut huge = build(SPB, 4, &[1]);
        set32(&mut huge, 8, u32::MAX);
        set32(&mut huge, 16, u32::MAX);
        let full: Vec<u32> = (1..=TABLE_ENTRIES as u32).rev().collect();
        let seeds: Vec<(&str, Vec<u8>)> = vec![
            ("empty_table", build(SPB, 6, &[])),
            ("out_of_order", build(SPB, 9, &[5, 1, 3])),
            ("hole_in_table", build(SPB, 4, &[2, 0, 1])),
            ("cut_short", cut),
            ("band_past_disk", bad_band),
            ("duplicate_band", dup),
            ("huge_band", huge),
            ("full_table", build(SPB, TABLE_ENTRIES as u32 * SPB, &full)),
            ("header_only", build(SPB, 4, &[])[..HEADER_LEN].to_vec()),
        ];
        for (name, bytes) in seeds {
            std::fs::write(dir.join(name), bytes).expect("write sparseimage seed");
        }
    }
}
