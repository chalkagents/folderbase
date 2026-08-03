const gitRef = process.env.VERCEL_GIT_COMMIT_REF;

// Vercel continues a build on exit 1 and ignores it on exit 0. Git previews
// always provide a ref. An absent ref is a deliberate CLI/manual deployment.
process.exit(gitRef === undefined || gitRef === "main" ? 1 : 0);
