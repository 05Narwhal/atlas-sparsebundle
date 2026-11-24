// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Sparse bundles (`.sparsebundle` folders).
//!
//! # Layout
//!
//! A bundle is a folder holding `Info.plist` (with a copy in `Info.bckup`),
//! a `bands` folder and, when the image is encrypted, a `token` file. The
//! property list names the disk and band sizes:
//!
//! | Key | Meaning |
//! |---|---|
//! | `diskimage-bundle-type` | `com.apple.diskimage.sparsebundle` |
//! | `bundle-backingstore-version` | 1 is the only layout read here |
//! | `band-size` | bytes per band: a multiple of 512, 4096 to 1 GiB |
//! | `size` | the disk's length in bytes |
//!
//! Band `i` covers disk bytes `i * band_size ..` and is stored in
//! `bands/<i in lowercase hex>`, with no leading zeros. The format is
//! described in the libyal libmodi notes, "Sparse bundle disk image
//! (.sparsebundle) format".
//!
//! # Choices where the format notes are silent
//!
//! - A missing band file reads as zeros. So does the tail of a band file
//!   shorter than `band_size`. Bytes past `band_size` in a band file are
//!   ignored.
//! - Any other failure to open or read a band file fails the read: a band
//!   that cannot be read never reads as zeros.
//! - Version 2 of the backing store exists on newer macOS and its layout is
//!   not known here, so it is `Unsupported`.
//! - `Info.bckup` is tried only when `Info.plist` cannot be read or parsed.
//! - Open band files are kept in a 64-entry LRU, which also remembers bands
//!   that are absent. Nothing is allocated per band of the disk.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use atlas_dmg::plist::{self, Value};
use atlas_fs_core::error::{CorruptKind, Corruption, Error, IoContext, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;

/// The structure name used in errors.
const WHAT: &str = "sparse bundle Info.plist";
/// The most bytes read from a property list.
const MAX_PLIST: u64 = 1 << 20;
/// Band files kept open (or known to be absent).
const BAND_CACHE: usize = 64;
/// Smallest and largest band size accepted.
const MIN_BAND_SIZE: u64 = 4096;
const MAX_BAND_SIZE: u64 = 1 << 30;
/// Bytes per sector.
const SECTOR: u64 = 512;
/// The value of `diskimage-bundle-type`.
const BUNDLE_TYPE: &str = "com.apple.diskimage.sparsebundle";

/// Opens the bundle folder at `path` read-only.
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    Ok(Arc::new(SparseBundleSource::new(path)?))
}

/// The cache entry for one band: its open file, or `None` when it is absent.
type Band = Option<Arc<FileSource>>;

/// The disk a sparse bundle presents.
pub struct SparseBundleSource {
    bands_dir: PathBuf,
    band_size: u64,
    len: u64,
    /// Most recently used last.
    cache: Mutex<Vec<(u64, Band)>>,
}

fn corrupt(kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(WHAT, Location::Byte(0), kind))
}

fn invalid(field: &'static str, value: u64) -> Error {
    corrupt(CorruptKind::InvalidValue { field, value })
}

/// Reads `path` whole, refusing more than [`MAX_PLIST`] bytes.
fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let context = |op| IoContext::Path {
        op,
        path: path.to_path_buf(),
    };
    let file = File::open(path).map_err(|e| Error::io(context("opening"), e))?;
    let mut bytes = Vec::new();
    file.take(MAX_PLIST.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(context("reading"), e))?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_PLIST) {
        return Err(corrupt(CorruptKind::LimitExceeded {
            what: "property list size",
            limit: MAX_PLIST,
        }));
    }
    Ok(bytes)
}

/// The property list of the bundle: `Info.plist`, or `Info.bckup` when that
/// one cannot be read. Fails with the `Info.plist` error when both fail.
fn read_info(bundle: &Path) -> Result<Value> {
    let load = |name: &str| read_limited(&bundle.join(name)).and_then(|b| plist::parse(&b));
    load("Info.plist").or_else(|first| load("Info.bckup").map_err(|_| first))
}

/// An integer key as `u64`, with errors that name the key.
fn integer(
    info: &Value,
    key: &'static str,
    missing: &'static str,
    bad: &'static str,
) -> Result<u64> {
    let value = info
        .get(key)
        .ok_or_else(|| corrupt(CorruptKind::Other(missing)))?;
    let n = value
        .as_integer()
        .ok_or_else(|| corrupt(CorruptKind::Other(bad)))?;
    u64::try_from(n).map_err(|_| invalid(key, u64::try_from(n.unsigned_abs()).unwrap_or(u64::MAX)))
}

impl SparseBundleSource {
    /// Opens the bundle folder `bundle`.
    ///
    /// Fails with [`Error::Unsupported`] for an encrypted bundle (it has a
    /// `token` file), another bundle type or another backing store version,
    /// and with [`Error::Corrupt`] when a key is missing or out of range.
    pub fn new(bundle: &Path) -> Result<Self> {
        let token = bundle.join("token");
        match fs::symlink_metadata(&token) {
            Ok(_) => return Err(Error::unsupported("encrypted disk images")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::io(
                    IoContext::Path {
                        op: "opening",
                        path: token,
                    },
                    e,
                ));
            }
        }

        let info = read_info(bundle)?;

        let kind = info
            .get("diskimage-bundle-type")
            .ok_or_else(|| corrupt(CorruptKind::Other("diskimage-bundle-type is missing")))?
            .as_str()
            .ok_or_else(|| corrupt(CorruptKind::Other("diskimage-bundle-type is not a string")))?;
        if kind != BUNDLE_TYPE {
            return Err(Error::unsupported(format!("disk image bundle type {kind}")));
        }

        let version = info
            .get("bundle-backingstore-version")
            .ok_or_else(|| corrupt(CorruptKind::Other("bundle-backingstore-version is missing")))?
            .as_integer()
            .ok_or_else(|| {
                corrupt(CorruptKind::Other(
                    "bundle-backingstore-version is not an integer",
                ))
            })?;
        if version != 1 {
            return Err(Error::unsupported(format!(
                "sparse bundle backing store version {version}"
            )));
        }

        let band_size = integer(
            &info,
            "band-size",
            "band-size is missing",
            "band-size is not an integer",
        )?;
        if band_size < MIN_BAND_SIZE {
            return Err(corrupt(CorruptKind::OutOfRange {
                field: "band-size",
                value: band_size,
                limit_name: "minimum band size",
                limit: MIN_BAND_SIZE,
            }));
        }
        if band_size > MAX_BAND_SIZE {
            return Err(corrupt(CorruptKind::OutOfRange {
                field: "band-size",
                value: band_size,
                limit_name: "maximum band size",
                limit: MAX_BAND_SIZE,
            }));
        }
        if band_size.checked_rem(SECTOR) != Some(0) {
            return Err(invalid("band-size", band_size));
        }

        let len = integer(&info, "size", "size is missing", "size is not an integer")?;
        if len == 0 {
            return Err(invalid("size", 0));
        }

        let bands_dir = bundle.join("bands");
        let meta = fs::metadata(&bands_dir).map_err(|e| {
            Error::io(
                IoContext::Path {
                    op: "opening",
                    path: bands_dir.clone(),
                },
                e,
            )
        })?;
        if !meta.is_dir() {
            return Err(Error::io(
                IoContext::Path {
                    op: "opening",
                    path: bands_dir,
                },
                io::Error::from(io::ErrorKind::NotADirectory),
            ));
        }
        Ok(Self {
            bands_dir,
            band_size,
            len,
            cache: Mutex::new(Vec::new()),
        })
    }

    /// Bytes per band, from `band-size`.
    pub fn band_size(&self) -> u64 {
        self.band_size
    }

    fn cached(&self, index: u64) -> Option<Band> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let at = cache.iter().position(|(i, _)| *i == index)?;
        let entry = cache.remove(at);
        let band = entry.1.clone();
        cache.push(entry);
        Some(band)
    }

    fn remember(&self, index: u64, band: &Band) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.iter().any(|(i, _)| *i == index) {
            // Another thread opened it while this one did.
            return;
        }
        if cache.len() >= BAND_CACHE {
            cache.remove(0);
        }
        cache.push((index, band.clone()));
    }

    /// The file of band `index`, or `None` when the bundle has none.
    fn band(&self, index: u64) -> Result<Band> {
        if let Some(band) = self.cached(index) {
            return Ok(band);
        }
        let path = self.bands_dir.join(format!("{index:x}"));
        let band = match FileSource::open(&path) {
            Ok(file) => Some(Arc::new(file)),
            Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        self.remember(index, &band);
        Ok(band)
    }

    fn read_with(&self, offset: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size: self.len,
        };
        let mut pos = offset;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < band_size` and `rest`
        // is not empty, so the loop ends after at most `buf.len()` passes.
        while !rest.is_empty() {
            let left = rest.len();
            let index = pos
                .checked_div(self.band_size)
                .ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_rem(self.band_size)
                .ok_or_else(|| oob(pos, left))?;
            let in_band = self
                .band_size
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_band).map_or(left, |in_band| in_band.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            match self.band(index)? {
                None => chunk.fill(0),
                Some(file) => {
                    // A band file shorter than the band reads zeros after its end.
                    let avail = usize::try_from(file.len().saturating_sub(within))
                        .map_or(n, |avail| avail.min(n));
                    let (data, zeros) = chunk
                        .split_at_mut_checked(avail)
                        .ok_or_else(|| oob(pos, n))?;
                    if !data.is_empty() {
                        if bulk {
                            file.read_bulk(within, data)?;
                        } else {
                            file.read_at(within, data)?;
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

impl BlockSource for SparseBundleSource {
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

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(dead_code, unused_imports, missing_docs)]
pub mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// The smallest band size, so a few kilobytes make several bands.
    const BAND: usize = 4096;

    /// A unique folder under the system temp directory, removed on drop.
    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "disk-atlas-sparsebundle-test-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(path.join("bands")).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            fs::write(self.0.join(name), bytes).unwrap();
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The byte band `band` holds at `offset`.
    fn pattern(band: u64, offset: usize) -> u8 {
        (band as usize * 29 + offset * 3 + 1) as u8
    }

    fn band_bytes(band: u64, len: usize) -> Vec<u8> {
        (0..len).map(|o| pattern(band, o)).collect()
    }

    /// A property list with the given entries; each value is raw XML.
    pub fn plist_xml(entries: &[(&str, &str)]) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>",
        );
        for (key, value) in entries {
            xml.push_str(&format!("<key>{key}</key>{value}"));
        }
        xml.push_str("</dict></plist>");
        xml
    }

    fn good(size: u64) -> Vec<(&'static str, String)> {
        vec![
            (
                "diskimage-bundle-type",
                format!("<string>{BUNDLE_TYPE}</string>"),
            ),
            (
                "bundle-backingstore-version",
                "<integer>1</integer>".to_string(),
            ),
            ("band-size", format!("<integer>{BAND}</integer>")),
            ("size", format!("<integer>{size}</integer>")),
        ]
    }

    fn xml_of(entries: &[(&'static str, String)]) -> String {
        let borrowed: Vec<(&str, &str)> = entries.iter().map(|(k, v)| (*k, v.as_str())).collect();
        plist_xml(&borrowed)
    }

    /// A bundle with `Info.plist` for `size` bytes and the given band files
    /// (band number, file contents).
    fn bundle(size: u64, bands: &[(u64, Vec<u8>)]) -> Temp {
        let temp = Temp::new();
        temp.write("Info.plist", xml_of(&good(size)).as_bytes());
        for (band, bytes) in bands {
            temp.write(&format!("bands/{band:x}"), bytes);
        }
        temp
    }

    /// What the disk should hold, from the band files.
    fn expected(size: u64, bands: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut disk = vec![0u8; size as usize];
        for (band, bytes) in bands {
            let start = *band as usize * BAND;
            for (o, b) in bytes.iter().take(BAND).enumerate() {
                if let Some(slot) = disk.get_mut(start + o) {
                    *slot = *b;
                }
            }
        }
        disk
    }

    fn read_all(src: &SparseBundleSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    fn err_of(temp: &Temp) -> Error {
        match SparseBundleSource::new(&temp.0) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    fn corrupt_of(temp: &Temp) -> Corruption {
        match err_of(temp) {
            Error::Corrupt(c) => c,
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    fn unsupported_of(temp: &Temp, needle: &str) {
        match err_of(temp) {
            Error::Unsupported(text) => assert!(text.contains(needle), "{text}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    fn is_send_sync<T: Send + Sync>() {}

    #[test]
    fn is_send_and_sync() {
        is_send_sync::<SparseBundleSource>();
    }

    #[test]
    fn round_trip_with_missing_short_and_long_bands() {
        let size = 5 * BAND as u64 + 700;
        let bands = vec![
            (0, band_bytes(0, BAND)),
            // Band 1 is missing. Band 2 is short, band 3 is longer than a band.
            (2, band_bytes(2, 1000)),
            (3, band_bytes(3, BAND + 500)),
            (5, band_bytes(5, 700)),
        ];
        let temp = bundle(size, &bands);
        let src = SparseBundleSource::new(&temp.0).unwrap();
        assert_eq!(src.len(), size);
        assert_eq!(src.band_size(), BAND as u64);
        assert_eq!(src.sector_size(), 512);
        let want = expected(size, &bands);
        assert_eq!(read_all(&src), want);
        // Band 4 is missing too; the bytes past band 3's end were ignored.
        assert!(want[4 * BAND..5 * BAND].iter().all(|b| *b == 0));
        assert!(want[3 * BAND..4 * BAND] == band_bytes(3, BAND)[..]);
    }

    #[test]
    fn reads_straddle_three_bands() {
        let size = 4 * BAND as u64;
        let bands = vec![
            (0, band_bytes(0, BAND)),
            (2, band_bytes(2, BAND)),
            (3, band_bytes(3, BAND)),
        ];
        let temp = bundle(size, &bands);
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let want = expected(size, &bands);
        for (offset, len) in [
            (BAND - 10, BAND + 20),
            (BAND - 1, 2 * BAND + 2),
            (5, 4 * BAND - 5),
        ] {
            let mut buf = vec![0u8; len];
            src.read_at(offset as u64, &mut buf).unwrap();
            assert_eq!(buf, want[offset..offset + len], "at {offset} len {len}");
            let mut bulk = vec![0u8; len];
            src.read_bulk(offset as u64, &mut bulk).unwrap();
            assert_eq!(bulk, buf);
        }
    }

    #[test]
    fn last_byte_of_a_size_that_is_not_a_band_multiple() {
        let size = 2 * BAND as u64 + 1;
        let bands = vec![(2, band_bytes(2, 1))];
        let temp = bundle(size, &bands);
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let mut one = [0u8; 1];
        src.read_at(size - 1, &mut one).unwrap();
        assert_eq!(one[0], pattern(2, 0));
        src.read_at(size, &mut []).unwrap();
    }

    #[test]
    fn reads_past_the_end_fail() {
        let temp = bundle(3 * BAND as u64, &[(0, band_bytes(0, BAND))]);
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let len = src.len();
        let mut buf = [0u8; 2];
        for result in [
            src.read_at(len - 1, &mut buf),
            src.read_bulk(len, &mut buf),
            src.read_at(u64::MAX, &mut buf),
        ] {
            assert!(matches!(result, Err(Error::OutOfBounds { .. })));
        }
    }

    #[test]
    fn band_names_are_lowercase_hex() {
        let size = 27 * BAND as u64;
        let bands = vec![
            (9, band_bytes(9, BAND)),
            (10, band_bytes(10, BAND)),
            (26, band_bytes(26, BAND)),
        ];
        let temp = bundle(size, &bands);
        assert!(temp.0.join("bands/a").is_file());
        assert!(temp.0.join("bands/1a").is_file());
        let src = SparseBundleSource::new(&temp.0).unwrap();
        assert_eq!(read_all(&src), expected(size, &bands));
    }

    #[test]
    fn more_bands_than_the_cache_holds() {
        let count = BAND_CACHE as u64 + 6;
        let size = count * BAND as u64;
        // Every other band is present.
        let bands: Vec<(u64, Vec<u8>)> = (0..count)
            .filter(|b| b % 2 == 0)
            .map(|b| (b, band_bytes(b, BAND)))
            .collect();
        let temp = bundle(size, &bands);
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let want = expected(size, &bands);
        assert_eq!(read_all(&src), want);
        assert_eq!(read_all(&src), want);
        let mut buf = vec![0u8; 100];
        src.read_at(3, &mut buf).unwrap();
        assert_eq!(buf, want[3..103]);
    }

    #[test]
    fn a_band_that_cannot_be_read_fails_the_read() {
        let temp = bundle(2 * BAND as u64, &[]);
        // A folder where a band file belongs.
        fs::create_dir_all(temp.0.join("bands/1")).unwrap();
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let mut buf = [0u8; 8];
        src.read_at(0, &mut buf).unwrap();
        assert!(src.read_at(BAND as u64, &mut buf).is_err());
    }

    #[test]
    fn open_returns_the_same_disk() {
        let bands = vec![(1, band_bytes(1, BAND))];
        let temp = bundle(2 * BAND as u64, &bands);
        let src = open(&temp.0).unwrap();
        let mut buf = vec![0u8; 2 * BAND];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, expected(2 * BAND as u64, &bands));
    }

    #[test]
    fn info_bckup_is_used_when_info_plist_is_missing_or_bad() {
        let good_xml = xml_of(&good(2 * BAND as u64));
        let temp = Temp::new();
        temp.write("Info.bckup", good_xml.as_bytes());
        assert_eq!(
            SparseBundleSource::new(&temp.0).unwrap().len(),
            2 * BAND as u64
        );
        temp.write("Info.plist", b"this is not a plist <<<");
        assert_eq!(
            SparseBundleSource::new(&temp.0).unwrap().len(),
            2 * BAND as u64
        );
        // An oversize Info.plist falls back too.
        temp.write("Info.plist", &vec![b' '; MAX_PLIST as usize + 1]);
        assert!(SparseBundleSource::new(&temp.0).is_ok());
    }

    #[test]
    fn both_property_lists_bad_reports_the_info_plist_error() {
        let temp = Temp::new();
        assert!(matches!(err_of(&temp), Error::Io { .. }));
        temp.write("Info.plist", b"<plist><dict><key>a</key></dict></plist>");
        temp.write("Info.bckup", b"nothing");
        let c = corrupt_of(&temp);
        assert_eq!(c.structure, "property list");
        // The key-level errors do not fall back to the backup.
        temp.write("Info.plist", plist_xml(&[]).as_bytes());
        temp.write("Info.bckup", xml_of(&good(BAND as u64)).as_bytes());
        assert!(matches!(corrupt_of(&temp).kind, CorruptKind::Other(_)));
    }

    #[test]
    fn oversize_info_plist_is_limit_exceeded() {
        let temp = Temp::new();
        temp.write("Info.plist", &vec![b' '; MAX_PLIST as usize + 1]);
        let c = corrupt_of(&temp);
        assert_eq!(c.structure, WHAT);
        assert!(matches!(
            c.kind,
            CorruptKind::LimitExceeded {
                limit: MAX_PLIST,
                ..
            }
        ));
    }

    #[test]
    fn token_file_means_encrypted() {
        let temp = bundle(BAND as u64, &[]);
        temp.write("token", b"");
        unsupported_of(&temp, "encrypted disk images");
        // Checked before the property list is read.
        fs::remove_file(temp.0.join("Info.plist")).unwrap();
        unsupported_of(&temp, "encrypted disk images");
    }

    #[test]
    fn missing_keys_are_corrupt() {
        for key in [
            "diskimage-bundle-type",
            "bundle-backingstore-version",
            "band-size",
            "size",
        ] {
            let mut entries = good(BAND as u64);
            entries.retain(|(k, _)| *k != key);
            let temp = Temp::new();
            temp.write("Info.plist", xml_of(&entries).as_bytes());
            let c = corrupt_of(&temp);
            assert_eq!(c.structure, WHAT);
            match c.kind {
                CorruptKind::Other(text) => assert!(text.contains(key), "{key}: {text}"),
                other => panic!("{key}: unexpected {other:?}"),
            }
        }
    }

    /// Replaces one key's value in an otherwise good list.
    fn with(key: &'static str, value: &str) -> Temp {
        let mut entries = good(10 * BAND as u64);
        for entry in &mut entries {
            if entry.0 == key {
                entry.1 = value.to_string();
            }
        }
        let temp = Temp::new();
        temp.write("Info.plist", xml_of(&entries).as_bytes());
        temp
    }

    #[test]
    fn bundle_type_and_version_mismatches_are_unsupported() {
        unsupported_of(
            &with(
                "diskimage-bundle-type",
                "<string>com.example.other</string>",
            ),
            "com.example.other",
        );
        for version in ["2", "0", "-1"] {
            unsupported_of(
                &with(
                    "bundle-backingstore-version",
                    &format!("<integer>{version}</integer>"),
                ),
                &format!("version {version}"),
            );
        }
    }

    #[test]
    fn wrong_value_types_are_corrupt() {
        for (key, value) in [
            ("diskimage-bundle-type", "<integer>1</integer>"),
            ("bundle-backingstore-version", "<string>1</string>"),
            ("band-size", "<string>4096</string>"),
            ("band-size", "<real>4096.0</real>"),
            ("band-size", "<true/>"),
            ("size", "<string>4096</string>"),
            ("size", "<real>4096.0</real>"),
        ] {
            let c = corrupt_of(&with(key, value));
            assert!(matches!(c.kind, CorruptKind::Other(_)), "{key} {value}");
        }
    }

    #[test]
    fn band_size_limits() {
        for (value, field_ok) in [
            ("4095", false),
            ("0", false),
            ("2048", false),
            ("4097", false),
            ("4608", true),
            ("1073741824", true),
            ("1073742336", false),
            ("-4096", false),
            ("99999999999999999999999", false),
        ] {
            let temp = with("band-size", &format!("<integer>{value}</integer>"));
            let result = SparseBundleSource::new(&temp.0);
            assert_eq!(result.is_ok(), field_ok, "band-size {value}");
            if let Err(Error::Corrupt(c)) = result {
                assert!(
                    matches!(
                        c.kind,
                        CorruptKind::OutOfRange {
                            field: "band-size",
                            ..
                        } | CorruptKind::InvalidValue {
                            field: "band-size",
                            ..
                        }
                    ),
                    "band-size {value}: {c}"
                );
            }
        }
        let c = corrupt_of(&with("band-size", "<integer>4097</integer>"));
        assert!(matches!(
            c.kind,
            CorruptKind::InvalidValue {
                field: "band-size",
                value: 4097
            }
        ));
    }

    #[test]
    fn size_must_be_positive_and_is_kept_exact() {
        for value in ["0", "-5"] {
            let c = corrupt_of(&with("size", &format!("<integer>{value}</integer>")));
            assert!(matches!(
                c.kind,
                CorruptKind::InvalidValue { field: "size", .. }
            ));
        }
        let temp = with("size", "<integer>1000003</integer>");
        let src = SparseBundleSource::new(&temp.0).unwrap();
        assert_eq!(src.len(), 1_000_003);
        // A huge disk with no band files costs nothing to open and reads zeros.
        let temp = with("size", "<integer>17592186044416</integer>");
        let src = SparseBundleSource::new(&temp.0).unwrap();
        let mut buf = [1u8; 16];
        src.read_at(src.len() - 16, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn missing_bands_folder_is_an_error() {
        let temp = bundle(BAND as u64, &[]);
        fs::remove_dir_all(temp.0.join("bands")).unwrap();
        assert!(matches!(err_of(&temp), Error::Io { .. }));
    }

    #[test]
    fn empty_plist_names_no_band_size() {
        let temp = Temp::new();
        temp.write("Info.plist", b"<plist/>");
        assert!(SparseBundleSource::new(&temp.0).is_err());
    }
}
