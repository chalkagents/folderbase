# Folderbase Core README Banner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a branded system-diagram banner and compact project badges to the top of the Folderbase Core README.

**Architecture:** Generate one repository-owned PNG using the established Folderbase visual system, then reference it from the README through accessible, linked HTML. Validate the image properties, README links, and repository checks without changing technical documentation below the introduction.

**Tech Stack:** Markdown/HTML, PNG, built-in image generation, shell-based asset and link validation, Cargo workspace checks.

---

### Task 0: Keep brainstorming artifacts local

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add the visual-companion directory to repository ignores**

Append this exact entry once:

```gitignore
.superpowers/
```

- [ ] **Step 2: Verify companion files are ignored**

Run:

```sh
git check-ignore .superpowers/brainstorm/*/content/banner-directions.html
```

Expected: the companion mockup path is printed and no `.superpowers/` files appear in `git status --short`.

### Task 1: Produce the repository banner

**Files:**
- Create: `docs/assets/folderbase-readme-banner.png`

- [ ] **Step 1: Record the precondition**

Run:

```sh
test ! -e docs/assets/folderbase-readme-banner.png
```

Expected: exit 0, confirming the new asset will not overwrite an existing repository file.

- [ ] **Step 2: Generate the banner with the built-in image tool**

Use this production prompt:

```text
Use case: infographic-diagram
Asset type: GitHub README repository banner, final production asset
Primary request: Create a wide Folderbase banner that positions the project as the open folder database for AI agents and explains its basic system model.
Scene/backdrop: near-black technical drafting board with restrained warm-paper grid lines, measurement ticks, and subtle printed texture.
Composition/framing: 1600×640 landscape. Left 58% contains brand and message. Right 42% contains a compact left-to-right technical diagram. Keep a generous safe area on every edge.
Left subject: acid-lime square FB mark, Folderbase wordmark, small category line, and large two-line headline.
Right subject: ordinary mixed-file folder → additive .folderbase/ layer → explicitly granted AI agent. Show small technical labels for identity, versions, policy, queries, and Change Sets.
Style/medium: flat editorial technical infographic, crisp linework, high contrast, GitHub-readable at reduced width.
Color palette: near-black #17120e, warm paper #f5efe4, acid lime #d7ff3f only.
Text (verbatim): "FOLDERBASE"; "THE OPEN FOLDER DATABASE FOR AI AGENTS"; "Turn any folder into a database."; "ORDINARY FOLDER"; ".folderbase/"; "AGENT GRANT"; "IDENTITY"; "VERSIONS"; "POLICY"; "QUERIES"; "CHANGE SETS".
Typography: bold geometric sans for the main statement; the word "database" in black editorial serif italic on an acid-lime rectangular highlight; compact uppercase monospace for technical labels.
Constraints: exact spelling and punctuation; no extra marketing copy; essential text must remain legible at README width; no gradients; no blue or purple; no emoji; no generic robot, brain, cloud, sparkle, 3D object, or watermark.
```

Copy the selected built-in output into `docs/assets/folderbase-readme-banner-source.png` and preserve the generated original under the built-in image directory.

- [ ] **Step 3: Normalize the final canvas without distortion**

Run:

```sh
banner_tmp_dir=$(mktemp -d)
sips --resampleWidth 1600 docs/assets/folderbase-readme-banner-source.png \
  --out "$banner_tmp_dir/banner-wide.png"
sips --cropToHeightWidth 640 1600 "$banner_tmp_dir/banner-wide.png" \
  --out docs/assets/folderbase-readme-banner.png
```

Expected: the image is scaled proportionally to 1600 pixels wide, then center-cropped vertically to 1600 × 640 without stretching. Delete `docs/assets/folderbase-readme-banner-source.png` after the final asset passes inspection; the built-in generated original remains preserved.

- [ ] **Step 4: Inspect the generated asset**

Use the local image viewer and confirm:

- exact category and headline copy;
- clear ordinary folder → `.folderbase/` → agent flow;
- no clipped labels or invented text;
- visual match to Folderbase black, warm-paper, and acid-lime branding.

Expected: all four checks pass. If exact text is unusable, make one targeted image-edit retry that changes only the incorrect text.

- [ ] **Step 5: Validate file properties**

Run:

```sh
file docs/assets/folderbase-readme-banner.png
sips -g pixelWidth -g pixelHeight docs/assets/folderbase-readme-banner.png
```

Expected: PNG image data in RGB/RGBA color with `pixelWidth: 1600` and `pixelHeight: 640`.

### Task 2: Integrate the banner and badges

**Files:**
- Modify: `README.md:1-7`

- [ ] **Step 1: Capture the current README body boundary**

Run:

```sh
sed -n '1,16p' README.md
```

Expected: the existing heading, tagline, and introduction are visible before editing.

- [ ] **Step 2: Replace the redundant heading and tagline**

Replace the current `# Folderbase` heading and bold tagline with this exact block:

```html
<p align="center">
  <a href="https://folderbase.ai">
    <img src="docs/assets/folderbase-readme-banner.png" alt="Folderbase — the open folder database for AI agents" width="100%">
  </a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-d7ff3f" alt="Apache-2.0 license"></a>
  <img src="https://img.shields.io/badge/rust-1.96%2B-17120e?logo=rust&amp;logoColor=f5efe4" alt="Rust 1.96 or newer">
  <a href="https://github.com/chalkagents/folderbase/actions/workflows/ci.yml"><img src="https://github.com/chalkagents/folderbase/actions/workflows/ci.yml/badge.svg" alt="Continuous integration status"></a>
</p>
```

Keep the paragraph beginning `Folderbase turns an ordinary folder` immediately after the badge row. Do not change later README content.

- [ ] **Step 3: Validate README references**

Run:

```sh
test -f docs/assets/folderbase-readme-banner.png
rg -n 'folderbase-readme-banner|folderbase\.ai|Apache--2\.0|rust-1\.96|actions/workflows/ci\.yml' README.md
```

Expected: the asset exists and every banner/badge reference appears in the README.

- [ ] **Step 4: Verify the body did not drift**

Run:

```sh
git diff --word-diff=porcelain -- README.md
```

Expected: only the former heading/tagline block is replaced; the explanatory introduction and technical sections remain unchanged.

### Task 3: Verify and publish the implementation

**Files:**
- Verify: `README.md`
- Verify: `docs/assets/folderbase-readme-banner.png`

- [ ] **Step 1: Run repository formatting and tests**

Run:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
```

Expected: both commands exit 0.

- [ ] **Step 2: Check the final diff**

Run:

```sh
git diff --check
git status --short
```

Expected: no whitespace errors; only the approved README, banner asset, plan, and intentional local companion ignore rule are present.

- [ ] **Step 3: Commit the implementation**

Run:

```sh
git add README.md docs/assets/folderbase-readme-banner.png .gitignore docs/superpowers/plans/2026-08-01-readme-banner.md
git commit -m "docs: add branded Folderbase README banner"
```

Expected: one implementation commit on `codex/readme-banner`.

- [ ] **Step 4: Push the branch**

Run:

```sh
git push -u origin codex/readme-banner
```

Expected: the branch is available at `chalkagents/folderbase` for review or merging.
