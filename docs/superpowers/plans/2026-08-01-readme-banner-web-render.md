# Folderbase README Web-Rendered Banner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the image-model-generated README banner with a polished, deterministic light-theme rendering of the approved Direction C system diagram.

**Architecture:** A self-contained HTML file owns the fixed 1600 × 640 composition, typography, grid, and inline SVG linework. A small Python Playwright script opens that file with local Chromium, waits for fonts/layout, asserts the viewport geometry, and captures the final PNG. The README continues to reference the same PNG path, so no integration copy changes are required.

**Tech Stack:** HTML5, CSS, inline SVG, Python 3, Playwright/Chromium, PNG, GitHub Markdown.

---

### Task 1: Build the deterministic Direction C composition

**Files:**
- Create: `docs/assets/banner-source/folderbase-readme-banner.html`

- [ ] **Step 1: Create the fixed canvas and visual tokens**

Create one self-contained document with no remote imports. Define a `1600px × 640px` canvas and these exact tokens:

```css
:root {
  --paper: #f4efe6;
  --ink: #17120e;
  --muted: #6c675f;
  --line: rgba(23, 18, 14, 0.18);
  --line-strong: rgba(23, 18, 14, 0.34);
  --lime: #d7ff3f;
}

* { box-sizing: border-box; }
html, body { width: 1600px; height: 640px; margin: 0; overflow: hidden; }
body { background: var(--paper); color: var(--ink); }
.banner { position: relative; width: 1600px; height: 640px; }
```

Use an inline SVG behind the content for a 48-pixel drafting grid, a 32-pixel outer frame, and restrained registration marks. This avoids generated texture and ensures crisp repeatable geometry.

- [ ] **Step 2: Build the left editorial panel**

Use real text nodes and CSS, not SVG paths or raster text. Include these exact elements:

```html
<div class="brand-row">
  <div class="mark">FB</div>
  <div class="wordmark">FOLDERBASE</div>
</div>
<div class="category">THE OPEN FOLDER DATABASE FOR AI AGENTS</div>
<h1>Turn any folder<br>into a <em>database.</em></h1>
```

Use `Helvetica Neue, Arial, sans-serif` for brand/headline, `SFMono-Regular, Menlo, monospace` for technical labels, and `Georgia, Times New Roman, serif` for the italic emphasis. The main statement is the largest text. `database.` uses black italic text on a rectangular acid-lime highlight with no rotation or synthetic texture.

- [ ] **Step 3: Build the right system diagram**

Construct the approved three-stage Direction C flow as real HTML and inline SVG:

```html
<section class="system" aria-label="Ordinary folder becomes a folder database and receives an agent grant">
  <article class="stage stage-files">...</article>
  <div class="flow-arrow" aria-hidden="true">...</div>
  <article class="stage stage-layer">...</article>
  <div class="flow-arrow" aria-hidden="true">...</div>
  <article class="stage stage-agent">...</article>
</section>
```

The three stage labels are exactly `ORDINARY FOLDER`, `.folderbase/`, and `AGENT GRANT`. The first stage shows six mixed-file tiles labeled `DOC`, `IMG`, `CODE`, `CSV`, `PDF`, and `MD`. The middle stage is a bordered list with exactly `IDENTITY`, `VERSIONS`, `POLICY`, `QUERIES`, and `CHANGE SETS`. The last stage is a permission card with one geometric keyhole/grant symbol. A thin return line labeled `CHANGE SETS` connects the agent stage back to the ordinary-folder stage.

- [ ] **Step 4: Verify source semantics and exact copy**

Run:

```sh
rg -n 'FOLDERBASE|THE OPEN FOLDER DATABASE FOR AI AGENTS|Turn any folder|database\.|ORDINARY FOLDER|\.folderbase/|AGENT GRANT|IDENTITY|VERSIONS|POLICY|QUERIES|CHANGE SETS' docs/assets/banner-source/folderbase-readme-banner.html
rg -n 'https?://|<img|emoji|gradient' docs/assets/banner-source/folderbase-readme-banner.html
```

Expected: every required phrase is present; the second command returns no matches.

- [ ] **Step 5: Commit the source composition**

```sh
git add docs/assets/banner-source/folderbase-readme-banner.html
git commit -m "docs: build reproducible Folderbase banner source"
```

### Task 2: Add the reproducible browser capture

**Files:**
- Create: `docs/assets/banner-source/render.py`
- Modify: `docs/assets/folderbase-readme-banner.png`

- [ ] **Step 1: Add the capture script**

Create this exact capture contract:

```python
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "folderbase-readme-banner.html"
OUTPUT = HERE.parent / "folderbase-readme-banner.png"

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(
        viewport={"width": 1600, "height": 640},
        device_scale_factor=1,
    )
    page.goto(SOURCE.as_uri(), wait_until="load")
    page.evaluate("document.fonts.ready")
    dimensions = page.evaluate(
        "({ width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight })"
    )
    assert dimensions == {"width": 1600, "height": 640}, dimensions
    page.screenshot(path=str(OUTPUT), full_page=False, animations="disabled")
    browser.close()
```

- [ ] **Step 2: Render the PNG**

Run:

```sh
python3 docs/assets/banner-source/render.py
```

Expected: `docs/assets/folderbase-readme-banner.png` is replaced by the browser-rendered light Direction C banner.

- [ ] **Step 3: Validate the capture**

Run:

```sh
file docs/assets/folderbase-readme-banner.png
sips -g pixelWidth -g pixelHeight docs/assets/folderbase-readme-banner.png
```

Expected: an RGB/RGBA PNG with `pixelWidth: 1600` and `pixelHeight: 640`.

- [ ] **Step 4: Inspect the PNG visually**

Open the final PNG at original detail and confirm:

- the light warm-paper Direction C composition is preserved;
- every text string is exact and crisp;
- the folder → `.folderbase/` → agent flow reads left to right;
- no elements collide, clip, or resemble generative imagery.

- [ ] **Step 5: Commit the renderer and replacement asset**

```sh
git add docs/assets/banner-source/render.py docs/assets/folderbase-readme-banner.png
git commit -m "docs: render polished Folderbase README banner"
```

### Task 3: Verify and update the existing pull request

**Files:**
- Verify: `README.md`
- Verify: `docs/assets/folderbase-readme-banner.png`
- Verify: `docs/assets/banner-source/folderbase-readme-banner.html`
- Verify: `docs/assets/banner-source/render.py`

- [ ] **Step 1: Re-run the renderer and prove determinism**

Run:

```sh
first_digest=$(shasum -a 256 docs/assets/folderbase-readme-banner.png | cut -d' ' -f1)
python3 docs/assets/banner-source/render.py
second_digest=$(shasum -a 256 docs/assets/folderbase-readme-banner.png | cut -d' ' -f1)
test "$first_digest" = "$second_digest"
```

Expected: exit 0 and identical PNG digests.

- [ ] **Step 2: Run repository checks**

Run:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 3: Confirm README integration remains intact**

Run:

```sh
rg -n 'docs/assets/folderbase-readme-banner.png|Folderbase — the open folder database for AI agents' README.md
git status --short
```

Expected: the README still references the same accessible asset path; only the intended source, renderer, and replacement PNG changes remain.

- [ ] **Step 4: Push the updated branch**

Run:

```sh
git push origin codex/readme-banner
```

Expected: pull request #39 updates with the reproducible web-rendered banner.
