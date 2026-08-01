# `@folderbase/cli`

`@folderbase/cli` installs and runs the exact native
[Folderbase Core](https://github.com/chalkagents/folderbase) command-line
release for the current machine.

```sh
npx @folderbase/cli init .
```

The npm package is a dependency-free distribution adapter. Folderbase remains
an open-source Rust engine and ordinary native executable; it is not
reimplemented in JavaScript and is not installed into the folder being
initialized.

## Supported hosts

- macOS on Apple silicon
- macOS on Intel
- Linux on ARM64
- Linux on x64

Node.js 22.14 or newer is required for the launcher. The downloaded native CLI
does not require Node.js after a separate persistent installation.

## Integrity and caching

The launcher downloads the native executable and `SHA256SUMS` from the exact
matching GitHub release over HTTPS. It refuses missing, duplicate, malformed,
or mismatched checksum records. A verified executable is cached by release
version and re-hashed before execution.

The default cache is:

- `~/Library/Caches/folderbase/cli` on macOS
- `$XDG_CACHE_HOME/folderbase/cli` or `~/.cache/folderbase/cli` on Linux

Linux honors `XDG_CACHE_HOME` only when it is an absolute path, as required by
the XDG base-directory contract. A relative value falls back to `~/.cache` so
the launcher never writes its cache into the current project.

No npm installation lifecycle script runs and no shell evaluates CLI
arguments. Standard input, output, error, arguments, and exit status are
forwarded directly to the native executable.

## Development

From the repository root:

```sh
npm test --prefix packages/npm-cli
node scripts/test-npm-cli-package.mjs
node --test scripts/tests/npm-publication-policy.test.mjs scripts/tests/ci-policy.test.mjs
```

The tests use local fixture binaries and never execute a downloaded production
artifact.
