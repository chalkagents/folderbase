# Folderbase Core README Banner Design

## Purpose

Give the `chalkagents/folderbase` repository an immediate, branded explanation of the category before a visitor reads the README. The banner should make Folderbase recognizable as the open folder database for AI agents while preserving the technical, evidence-led character of the project.

## Approved Direction

Use the selected **System Diagram / Direction C** composition: a bold category statement on the left and a compact product model on the right. Preserve that approved hierarchy and flow; the refinement is in execution quality rather than a new layout.

### Exact copy

- Category line: `THE OPEN FOLDER DATABASE FOR AI AGENTS`
- Main statement: `Turn any folder into a database.`
- Diagram labels: `ORDINARY FOLDER`, `.folderbase/`, `AGENT GRANT`, `IDENTITY`, `VERSIONS`, `POLICY`, `QUERIES`, and `CHANGE SETS`

The word `database` is the visual emphasis: black editorial italic on an acid-lime highlight.

## Visual Design

- Canvas: 1600 × 640 PNG.
- Background: light warm-paper field with a restrained near-black drafting grid and measurement details, matching the editorial character of folderbase.ai.
- Palette: warm paper, Folderbase near-black, and acid lime. No gradients, blue, or purple.
- Left panel: Folderbase mark, category line, and large two-line statement.
- Right panel: a concise left-to-right system diagram showing an ordinary mixed-file folder, the additive `.folderbase/` layer, and a bounded agent connection.
- Diagram style: deterministic geometric SVG/CSS linework and interface-like labels. No emoji, robots, brains, clouds, sparkles, 3D renders, generic AI imagery, or image-model artifacts.
- Texture: no generated texture. Use only subtle CSS color and line variation where it improves depth without reducing small-text legibility.
- Safe area: all essential copy and diagram labels remain comfortably inside the canvas for GitHub responsive scaling.

## Production Method

- Build the banner as a fixed 1600 × 640 HTML/CSS composition.
- Use real web typography, SVG/CSS primitives, and exact text rather than generative imagery.
- Keep the reproducible source under `docs/assets/banner-source/`.
- Capture the layout at exactly 1600 × 640 through a headless browser and write the final PNG to `docs/assets/folderbase-readme-banner.png`.
- The capture must be deterministic and must not depend on network-loaded fonts or images.

## README Integration

- Store the asset at `docs/assets/folderbase-readme-banner.png`.
- Place it at the top of `README.md` using an HTML image element with `width="100%"` for predictable GitHub rendering.
- Link the banner to `https://folderbase.ai`.
- Use descriptive alt text: `Folderbase — the open folder database for AI agents`.
- Add a compact centered badge row beneath the banner for Apache-2.0, Rust, and the repository CI workflow.
- Remove the existing `# Folderbase` heading and bold tagline because the banner replaces both. Preserve the explanatory introduction beginning “Folderbase turns an ordinary folder…” directly below the badges.

## Accessibility and Repository Constraints

- The banner must remain understandable through its alt text when images are disabled.
- Important information such as installation, license, and project status remains ordinary README text; the image is not the only source.
- Badge destinations must point to the repository license, Rust project information, and the existing CI workflow.
- The PNG should be compressed enough for fast README loading without visible degradation.

## Acceptance Criteria

1. The exact category and main-statement copy are spelled correctly and legible at GitHub README width.
2. The right-side diagram clearly communicates ordinary folder → additive `.folderbase/` layer → permissioned agent work.
3. The image follows the established Folderbase visual system used on folderbase.ai.
4. The banner links to folderbase.ai and has meaningful alt text.
5. License, Rust, and CI badges render and link correctly.
6. Existing README technical content is unchanged except for the redundant heading and tagline at the top.
7. Markdown and repository checks remain clean.

## Out of Scope

- Rewriting the README body.
- Changing product terminology or protocol claims.
- Adding screenshots, animated media, or per-section illustrations.
- Changing CI, packaging, or release behavior.
