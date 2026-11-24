// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Apple sparse disk images.
//!
//! [`sparsebundle`] opens a `.sparsebundle` folder (an `Info.plist` and a
//! `bands` folder) and [`sparseimage`] opens a single-file `.sparseimage`.
//! Both present the disk as a `BlockSource`; bands that were never written
//! read as zeros.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::block::BlockSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let bundle = atlas_sparsebundle::sparsebundle::open(Path::new("Backup.sparsebundle"))?;
//! let image = atlas_sparsebundle::sparseimage::open(Path::new("Backup.sparseimage"))?;
//! println!("{} and {} bytes of disk", bundle.len(), image.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

pub mod sparsebundle;
pub mod sparseimage;
