import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="docs-home">
      <section className="docs-hero">
        <div className="docs-hero-copy">
          <p className="docs-eyebrow"><span /> FOLDERBASE CORE · v0.5.0</p>
          <h1>
            Keep the folder.
            <br />
            Add the <em>database.</em>
          </h1>
          <p className="docs-lede">
            Install the open Folderbase Core, add a durable <code>.folderbase</code>{' '}
            layer, and give humans and agents a safe interface to ordinary files.
          </p>
          <div className="docs-actions">
            <Link className="docs-button docs-button-primary" href="/docs/getting-started/quickstart">
              Start the quickstart <span aria-hidden="true">→</span>
            </Link>
            <a className="docs-button" href="https://github.com/chalkagents/folderbase" target="_blank" rel="noreferrer">
              View source <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
        <div className="docs-terminal" aria-label="Folderbase installation example">
          <div className="terminal-head">
            <span>QUICKSTART / LOCAL CORE</span>
            <strong>OPEN</strong>
          </div>
          <div className="terminal-body">
            <p><span>$</span> npx @folderbase/cli inspect . --json</p>
            <p className="terminal-response">✓ ordinary folder inspected</p>
            <p><span>$</span> npx @folderbase/cli init . --dry-run --json</p>
            <p className="terminal-response">✓ additive plan ready for review</p>
            <p><span>$</span> npx @folderbase/cli init . --expected-plan-digest … --json</p>
            <div className="terminal-tree">
              <strong>.folderbase/</strong>
              <span>└── manifest.json</span>
              <span>…your existing files</span>
            </div>
          </div>
          <div className="terminal-foot">
            <span>FILES STAY FILES</span>
            <span>APACHE-2.0</span>
          </div>
        </div>
      </section>

      <section className="release-strip">
        <span>AVAILABLE NOW</span>
        <strong>CORE 0.5</strong>
        <span>STABLE SURFACE</span>
        <strong>CLI JSON v1</strong>
        <span>COMPATIBILITY</span>
        <strong>CONTRACT v1</strong>
      </section>

      <section className="docs-paths">
        <div className="section-heading">
          <p>CHOOSE A PATH</p>
          <h2>From folder to working system.</h2>
        </div>
        <div className="path-grid">
          <Link href="/docs/getting-started/install" className="path-card">
            <span>01 / INSTALL</span>
            <h3>Run Folderbase locally</h3>
            <p>Use the verified native CLI through npx, a downloaded binary, or Cargo.</p>
            <strong>Install Core →</strong>
          </Link>
          <Link href="/docs/getting-started/quickstart" className="path-card path-card-accent">
            <span>02 / INITIALIZE</span>
            <h3>Turn a folder into a Folderbase</h3>
            <p>Inspect first, preview every addition, then initialize without moving your files.</p>
            <strong>Five-minute quickstart →</strong>
          </Link>
          <Link href="/docs/guides/agents" className="path-card">
            <span>03 / OPERATE</span>
            <h3>Give agents a safe workspace</h3>
            <p>List, read, and save ordinary files with scoped context and stale-write protection.</p>
            <strong>Agent workflow →</strong>
          </Link>
        </div>
      </section>

      <section className="docs-principles">
        <div>
          <p className="docs-eyebrow"><span /> THE OPEN PRIMITIVE</p>
          <h2>Built for work that must remain understandable.</h2>
        </div>
        <div className="principle-list">
          <article><span>01</span><h3>Files stay files</h3><p>No proprietary container. Native tools keep working.</p></article>
          <article><span>02</span><h3>Inspect before changing</h3><p>Plans are reviewable before Folderbase mutates a folder.</p></article>
          <article><span>03</span><h3>Agents get contracts</h3><p>Stable JSON, expected hashes, explicit scopes, durable provenance.</p></article>
          <article><span>04</span><h3>Core stays local</h3><p>The open engine works without a Folderbase account or cloud service.</p></article>
        </div>
      </section>
    </main>
  );
}
