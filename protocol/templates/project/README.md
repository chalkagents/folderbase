# Project Folderbase template

This directory is a source template, not an initialized folderbase.

1. Substitute every `${...}` token in
   `.folderbase/manifest.template.json`.
2. Save the substituted file as `.folderbase/manifest.json`.
3. Never overwrite an existing `AGENTS.md` or `CLAUDE.md`; propose adding only
   the managed block.
4. Create protocol state additively. Do not move or rewrite existing project
   content during initialization.

Each initialized folderbase must receive its own UUID-backed `folderbase_` identity and
RFC 3339 creation time.
