# atlas-sparsebundle

Opens Apple sparse bundles (a folder of band files with an `Info.plist`) and single-file `.sparseimage` images as a `BlockSource`. Bands that were never written read as zeros.

- Band maps and sizes from `Info.plist` and the sparse image header are validated before use.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
