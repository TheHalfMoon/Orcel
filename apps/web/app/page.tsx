const github = "https://github.com/TheHalfMoon/Orcel";
const releases = `${github}/releases`;
const security = `${github}/blob/main/docs/security/THREAT_MODEL.md`;
const docs = `${github}/tree/main/docs`;
const brandUrl = (process.env.ORCEL_WEB_BASE_PATH ?? "") + "/brand.html";
const brandWordmarkUrl = (process.env.ORCEL_WEB_BASE_PATH ?? "") + "/brand/orcel-lockup-white.svg";

const Arrow = () => (
  <svg aria-hidden="true" viewBox="0 0 16 16" width="16" height="16">
    <path d="M3 8h9M8.5 3.5 13 8l-4.5 4.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const Cross = () => (
  <svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14">
    <path d="m4 4 8 8M12 4l-8 8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

const Fingerprint = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" width="18" height="18">
    <path d="M12 11v3M8.5 6.5A6 6 0 0 1 18 11v2M6 11a6 6 0 0 0 .5 2.5M9 11a3 3 0 0 1 6 0v3a6 6 0 0 1-1 3.3M9 15a9 9 0 0 0 1.2 4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
  </svg>
);

const ApprovalPreview = () => (
  <figure className="approval" aria-label="Example Orcel approval dialog for a single file write">
    <div className="approval-head">
      <span className="approval-title"><span className="brand-mark brand-mark-white" aria-hidden="true" /> Approval required</span>
      <span className="approval-meta"><span className="pill pill-soft">SOFT</span><span className="mono">0:42</span></span>
    </div>
    <div className="approval-body">
      <p className="approval-who">ChatGPT wants to</p>
      <p className="approval-what">Write 1 file in myproject</p>
      <dl className="approval-facts">
        <dt>tool</dt><dd>fs_write</dd>
        <dt>path</dt><dd>src/routes/session.ts</dd>
        <dt>sha256</dt><dd>9f2c…a71e → 41bd…07c3</dd>
      </dl>
      <pre className="approval-diff" aria-label="Proposed change"><code><span className="diff-ctx">  export async function refresh(req) {"{"}</span>
<span className="diff-del">− const token = req.cookies.t;</span>
<span className="diff-add">+ const token = readSessionToken(req);</span>
<span className="diff-add">+ if (!token) return deny(401);</span>
<span className="diff-ctx">  {"}"}</span></code></pre>
      <div className="approval-actions" aria-hidden="true">
        <span className="fake-button fake-button-ghost">Deny</span>
        <span className="fake-button fake-button-primary">Approve once</span>
      </div>
    </div>
    <figcaption>Bound to this exact content and file hash. Used once, then it expires.</figcaption>
  </figure>
);

const CodePanel = () => (
  <div className="code-shell" aria-label="MCP configuration example">
    <div className="window-bar">
      <span className="window-dots" aria-hidden="true"><i /><i /><i /></span>
      <span>mcp.json</span>
      <span className="window-state">local</span>
    </div>
    <pre><code>{`{
  "mcpServers": {
    "orcel": {
      "command": "orcel",
      "args": ["mcp", "stdio"]
    }
  }
}`}</code></pre>
    <div className="compat-note">
      <span>Identity note</span>
      <p><code>orcel</code> is the current CLI identifier. Prior installations and trusted state are not silently migrated.</p>
    </div>
  </div>
);

const MobileNav = () => (
  <details className="mobile-nav">
    <summary aria-label="Toggle primary navigation">
      <span>Menu</span>
      <span className="mobile-nav-toggle" aria-hidden="true"><i /><i /></span>
    </summary>
    <nav className="mobile-nav-panel" aria-label="Mobile primary navigation">
      <a href="#product">Product</a>
      <a href="#security">Security</a>
      <a href="#developers">Developers</a>
      <a href={brandUrl}>Brand</a>
      <a href={releases}>Releases</a>
      <a href={github}>GitHub</a>
    </nav>
  </details>
);

export default function Home() {
  return (
    <main>
      <a className="skip-link" href="#content">Skip to content</a>

      <header className="site-header">
        <div className="header-inner">
          <a className="brand" href="#" aria-label="Orcel home">
            <img className="brand-wordmark" src={brandWordmarkUrl} width="138" height="32" alt="Orcel" />
          </a>
          <nav className="desktop-nav" aria-label="Primary navigation">
            <a href="#product">Product</a>
            <a href="#security">Security</a>
            <a href="#developers">Developers</a>
            <a href={brandUrl}>Brand</a>
            <a href={releases}>Releases</a>
            <a href={github}>GitHub</a>
          </nav>
          <MobileNav />
          <a className="header-cta" href={releases}>
            View releases <Arrow />
          </a>
        </div>
      </header>

      <div id="content" tabIndex={-1}>
        <section className="hero section-shell">
          <div className="hero-copy-col">
            <div className="eyebrow"><span className="status-dot" /> Local-first computer access for AI agents</div>
            <h1>Your computer.<br /><span className="muted-line">Your terms.</span></h1>
            <p className="hero-copy">
              Orcel gives MCP-compatible agents a governed path to your own computer.
              Reads stay inside folders you trust. Every change waits for your yes.
            </p>
            <div className="hero-actions">
              <a className="button button-primary" href={github}>View on GitHub <Arrow /></a>
              <a className="button button-secondary" href={security}>Read the security model</a>
            </div>
            <p className="hero-footnote">Open source · Apache-2.0 · Windows 10/11 · No mandatory Orcel cloud</p>
          </div>
          <div className="hero-visual">
            <ApprovalPreview />
          </div>
        </section>

        <section className="stats" aria-label="Orcel at a glance">
          <div className="section-shell stats-inner">
            <div><strong>31</strong><span>tools for local MCP clients</span></div>
            <div><strong>26</strong><span>in the smaller remote core profile</span></div>
            <div><strong>0</strong><span>inbound ports for the ChatGPT tunnel</span></div>
            <div><strong className="accent">1:1</strong><span>one approval, one exact action</span></div>
          </div>
        </section>

        <section className="section-shell" id="product">
          <div className="section-heading">
            <span className="section-index">01 / Product</span>
            <h2>The assistant asks.<br /><span className="muted-line">You decide.</span></h2>
            <p>Use the AI client you prefer without handing it an unrestricted shell, filesystem, or desktop.</p>
          </div>
          <div className="card-row">
            <article className="card">
              <span className="card-index">01</span>
              <h3>Standard MCP interface</h3>
              <p>Connect ChatGPT through the Secure MCP Tunnel, or Claude Desktop and any local client over stdio.</p>
              <code className="card-code">orcel mcp stdio</code>
            </article>
            <article className="card">
              <span className="card-index">02</span>
              <h3>Local-first authority</h3>
              <p>Add the folders an assistant may use. Local policy stays decisive, even over optional remote transport.</p>
              <code className="card-code">orcel workspace add myproject C:\code\app</code>
            </article>
            <article className="card card-accent">
              <span className="card-index">03</span>
              <h3>Fail closed</h3>
              <p>Missing trust, stale identity, expired authority, or an unsupported capability returns a bounded failure.</p>
            </article>
          </div>
        </section>

        <section className="section-shell" id="security">
          <div className="section-heading">
            <span className="section-index">02 / Security first</span>
            <h2>Two kinds of yes.</h2>
            <p>The computer stays authoritative. The agent can request; it cannot approve itself or silently promote itself.</p>
          </div>
          <div className="yes-row">
            <article className="yes-card">
              <div className="yes-top"><span className="pill pill-soft">SOFT</span><span>Writes · commits · clipboard · fetch</span></div>
              <h3>A dialog that shows exactly what will happen.</h3>
              <p>The file, the content hash, the workspace. Each approval is used once, expires quickly, and is bound to that action and policy.</p>
            </article>
            <article className="yes-card">
              <div className="yes-top"><span className="pill pill-strong">STRONG</span><span>Trust changes · deletes · revoke</span></div>
              <h3>Windows Hello for the moves that matter.</h3>
              <p>PIN, fingerprint or face. <code>orcel emergency-revoke</code> invalidates every pending approval at once.</p>
              <span className="hello"><Fingerprint /> Confirm with Windows Hello</span>
            </article>
          </div>
          <ul className="not-list" aria-label="What Orcel is not">
            <li><Cross /> Not an unrestricted remote shell</li>
            <li><Cross /> Not a general-purpose remote desktop</li>
            <li><Cross /> No UI actuation over MCP</li>
          </ul>
        </section>

        <section className="section-shell boundary-section">
          <div className="boundary-copy">
            <span className="section-index">03 / Computer use</span>
            <h2>Powerful capabilities.<br /><span className="muted-line">Clear boundaries.</span></h2>
            <p>Computer use is not a shortcut around policy. Observation, proposals, approvals, execution, and postconditions remain separate steps.</p>
            <a className="text-link" href={security}>Explore the threat model <Arrow /></a>
          </div>
          <ol className="step-list">
            <li><span>01</span><div><strong>Observe</strong><p>Read only through qualified, bounded surfaces.</p></div></li>
            <li><span>02</span><div><strong>Propose</strong><p>Agent output is untrusted proposal data, not authority.</p></div></li>
            <li><span>03</span><div><strong>Validate</strong><p>Targets, policy, trust, freshness, and risk are checked locally.</p></div></li>
            <li><span>04</span><div><strong>Approve &amp; act</strong><p>Mutations run only through the governed local path.</p></div></li>
            <li><span>05</span><div><strong>Record</strong><p>Outcomes are reported without inventing success or rollback.</p></div></li>
          </ol>
        </section>

        <section className="section-shell developer-section" id="developers">
          <div className="developer-copy">
            <span className="section-index">04 / For developers</span>
            <h2>Integrate once.<br /><span className="muted-line">Keep the boundary.</span></h2>
            <p>Orcel exposes the qualified local surface through MCP, so clients can change without changing who owns authority.</p>
            <div className="hero-actions">
              <a className="button button-primary" href={docs}>Read the docs <Arrow /></a>
              <a className="button button-secondary" href={github}>Browse the repository</a>
            </div>
          </div>
          <CodePanel />
        </section>

        <section className="section-shell">
          <div className="final-cta">
            <span className="brand-mark final-mark" aria-hidden="true" />
            <div className="final-copy">
              <h2>Keep the keys.</h2>
              <p>Open source, local-first, and built around explicit authority.</p>
            </div>
            <div className="hero-actions final-actions">
              <a className="button button-dark" href={releases}>View verified releases <Arrow /></a>
              <a className="button button-outline-dark" href={github}>Browse the source</a>
            </div>
            <p className="release-note">Published artifacts stay on the canonical GitHub Releases surface. Verify checksums and provenance before install.</p>
          </div>
        </section>
      </div>

      <footer className="site-footer">
        <div className="section-shell footer-inner">
          <div className="footer-brand">
            <span className="brand"><img className="brand-wordmark" src={brandWordmarkUrl} width="138" height="32" alt="Orcel" /></span>
            <p>Your computer, on your terms.</p>
          </div>
          <div className="footer-links">
            <a href="#product">Product</a>
            <a href="#security">Security</a>
            <a href="#developers">Developers</a>
            <a href={docs}>Docs</a>
            <a href={brandUrl}>Brand identity</a>
            <a href={releases}>Releases</a>
            <a href={github}>GitHub</a>
          </div>
          <p className="footer-meta">Apache-2.0 · Local-first by design</p>
        </div>
      </footer>
    </main>
  );
}
