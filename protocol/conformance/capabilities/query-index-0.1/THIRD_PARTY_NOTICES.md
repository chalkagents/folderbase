# Third-party notices

`unicode-casefold-v9-data.mjs` is derived from `unicode-casefold` 0.2.0 by
Chris Wong and contributors. That crate publishes the Unicode 9.0.0 full
default case-fold table and is distributed under either the MIT License or the
Apache License 2.0, at the recipient's option. Folderbase uses the Apache-2.0
option; the repository's root `LICENSE` contains its complete text.

Immutable 0.2.0 source artifact:
<https://docs.rs/crate/unicode-casefold/0.2.0/source/>. The crates.io artifact
checksum is `b7f66b1c8f8caa2ab31dc6d3f35386f16efdab89668f93411e565ac368908e8f`.

The generated module records the SHA-256 digest of the exact upstream
`src/tables.rs` input. It is checked in and self-contained; independent
Folderbase implementers do not need Cargo or a Cargo registry checkout to run
the conformance suite. The adjacent generator is an optional maintainer tool.

`unicode-nfc-v17-data.mjs` is modified/derived from
`unicode-normalization` 0.1.25 by the Rust Project Developers and contributors,
distributed under Apache-2.0 OR MIT. Folderbase uses the Apache-2.0 option. The
crates.io checksum is
`5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8`;
the exact generated `src/tables.rs` input has SHA-256
`177d5f08019cc8e335444fcab61aabb7f6309f158f6ebbd7525c73c0e532ec44`.

The Unicode 9 source data is covered by Unicode-DFS-2016:

> Copyright © 1991-2016 Unicode, Inc. All rights reserved. Distributed under
> the Terms of Use in <https://www.unicode.org/copyright.html>.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of the Unicode data files and any associated documentation (the “Data
> Files”) or Unicode software and any associated documentation (the
> “Software”) to deal in the Data Files or Software without restriction,
> including without limitation the rights to use, copy, modify, merge,
> publish, distribute, and/or sell copies of the Data Files or Software, and to
> permit persons to whom the Data Files or Software are furnished to do so,
> provided that either (a) this copyright and permission notice appear with all
> copies of the Data Files or Software, or (b) this copyright and permission
> notice appear in associated Documentation.
>
> THE DATA FILES AND SOFTWARE ARE PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY
> KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
> THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS
> INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR
> CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
> DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
> TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
> OF THE DATA FILES OR SOFTWARE.
>
> Except as contained in this notice, the name of a copyright holder shall not
> be used in advertising or otherwise to promote the sale, use or other
> dealings in these Data Files or Software without prior written authorization
> of the copyright holder.

The normalization tables derive from Unicode 17.0.0 data under the Unicode
Terms of Use linked above. Both checked-in modules are independently runnable;
their generators are maintainer-only reproducibility tools.
