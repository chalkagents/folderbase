# Safe Project 2 unmanaged fixture

This is a deliberately small, invented folder tree for deterministic
`folderbase inspect`, transform-planning, and migration tests. It approximates
the approved ChalkAgents → Prosperna engagement → Project 2 account shape without
including any live Project 2, Prosperna, ChalkAgents, or personal data.

Every payload is invented. Files with document, database, archive, image, or
video extensions are tiny labeled placeholders rather than real customer
artifacts. Any credential-like value is explicitly fake and unusable. This
folder is intentionally **not** a folderbase: it has no `FOLDERBASE.md` or
`.folderbase/manifest.json`.

The labels above describe provenance and navigation only. They do not imply
permission inheritance. A later migration should propose independently
governed folderbases and a workspace rather than turning this whole tree into one
shareable folderbase.

## Intended topology

The fixture should eventually produce a reviewable proposal shaped like:

```text
Project 2 Account Workspace
├── Project 2 Account Folderbase
├── ChalkAgents–Prosperna Engagement Folderbase
├── Security Remediation Project Folderbase
├── Loyalty Revamp Project Folderbase
├── Support and Maintenance Project Folderbase
├── Commercial Folderbase — restricted
└── Client-shared View — explicit approved objects only
```

This is an expected proposal, not an on-disk permission model. The current
folders remain unmanaged source material until an approved migration creates
real folderbase boundaries.

## Expected inspection signals

- Existing context: `AGENTS.md`, `Account/README.md`,
  `Engagement-Provenance/README.md`, `Evidence/Curated/README.md`,
  `emails/README.md`,
  `Reference/Client Company 2-dev/README.md`, and
  `Reference/Client Company 2-dev/.chalk/README.md`.
- Git context: `.gitmodules` markers beneath the development reference,
  security tooling, and Loyalty reference app represent nested repositories
  without embedding live `.git` directories.
- Generated/reconstructable:
  `dashboard/node_modules/example-package/package.json`,
  `dashboard/.next/build-manifest.json`, and
  `Reference/Client Company 2-dev/mobile/.dart_tool/package_config.json`,
  `Loyalty-Revamp/Reference-App/dist/bundle.js`, and
  `Security-Remediation/Tooling/target/debug/tool-output.bin`.
- Secret-shaped:
  `Reference/Client Company 2-dev/config/api_key.txt` and
  `Reference/Client Company 2-dev/config/.env.synthetic`. Their contents are
  labeled fakes.
- Temporary: `tmp/render-preview.tmp`.
- Version families: `Commercial-Restricted/Agreement_Draft_v2.md`,
  `Commercial-Restricted/Agreement_Revised_v3.md`, and
  `Commercial-Restricted/Agreement_Final_v4.md`; and the three synthetic
  Loyalty proposal revisions.
- Raw versus curated evidence:
  `Evidence/Raw/Emails/thread-001.eml` remains source evidence while
  `Evidence/Curated/README.md` records a derived understanding and its limits.
- Format and storage-policy placeholders: tiny `.pdf`, `.sqlite`, `.zip`, and
  `.mp4` files exercise preservation policy without inflating the repository.
- Likely permission/lifecycle boundaries: `Client-Shared/`,
  `Commercial-Restricted/`, `Security-Remediation/`, `Evidence/Raw/`,
  `emails/`, and the nested development repositories.

An inspector may report additional conservative hints. It must perform no
writes, expose no secret contents, and avoid treating generated paths as
deletion instructions. Exact deterministic expectations for later end-to-end
tests live in the sibling
`fixtures/client-company-2-shaped-unmanaged.expected.json` file so the
expectation artifact is not itself part of the inspected source tree.

## Golden-journey normalization

The CLI golden test accepts only this exact committed fixture. It copies the
tree to an isolated temporary `Project-2-Account` folder, then gives three existing
semantic scopes analyzer-visible boundary names:

- `Engagement-Provenance` becomes
  `ChalkAgents-Prosperna-Client-Engagement`.
- `Loyalty-Revamp` becomes `Loyalty-Revamp-Project`.
- `Support-and-Maintenance` becomes
  `Support-and-Maintenance-Project`.

This normalization changes no source bytes and does not touch this committed
fixture. It makes the intended account, engagement, project, commercial,
security, and client-shared decisions explicit through the current public CLI
heuristic. The test harness lexically rejects every external fixture path before
canonicalizing or reading it.
