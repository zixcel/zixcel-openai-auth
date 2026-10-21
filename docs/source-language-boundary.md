# Source language boundary

The library implementation and tests remain Rust. There are no first-party
JavaScript runtime or verification entrypoints in this owner.

The former `verify-msrv.mjs` and `verify-source-size.mjs` were not called by
workflows, documented commands or library consumers. The MSRV script also
required the obsolete private registry, contradicting the current crates.io
manifest. They are retired rather than promoted into a second policy authority.

The current Cargo manifest and owner Rust CI define the MSRV; the release
admission checks the actual package version and crates.io publication target.
Existing source/security policy tests now reject first-party `.js`/`.mjs`/`.cjs`
under `src` and `scripts`, while allowing typed helpers and third-party references.
Generated or third-party JavaScript is not automatically classified as a defect.

No Rust API, dependency, version, authentication route or publication permission
is changed. Verify the ordinary owner CI and the actual Cargo file list; source
retirement does not assert a new registry release.
