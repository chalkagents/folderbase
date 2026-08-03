# Folderbase documentation

This Next.js/Fumadocs application is the canonical source for
[docs.folderbase.ai](https://docs.folderbase.ai). It documents released Core
behavior; proposed or unreleased behavior must be labeled explicitly.

## Local validation

```bash
npm ci
npm test
```

`npm test` lints, type-checks, and builds every route. To run the development
server:

```bash
npm run dev
```

Open http://localhost:3000.

## Source and deployment contract

- Documentation content lives in `content/docs/`.
- CI selects the dedicated docs lane for `apps/docs/**` changes and requires
  lint, type generation, and a production build before merge.
- Vercel Git deployment is enabled only for `main` in `vercel.json`. Pull
  request branches are validated by CI but do not consume preview deployments.
- A successful merge to `main` triggers the production deployment connected to
  `docs.folderbase.ai`.

Canonical protocol schemas and conformance fixtures remain under the
repository-level `protocol/` directory. Site prose must agree with those files,
the stable CLI inventory in `docs/cli-json-v1.md`, and the released executable.
