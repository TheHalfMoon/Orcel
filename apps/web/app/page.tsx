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

const Shield = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22">
    <path d="M12 3 20 6v5.5c0 4.7-3.1 7.8-8 9.5-4.9-1.7-8-4.8-8-9.5V6l8-3Z" fill="none" stroke="currentColor" strokeWidth="1.5" />
    <path d="m8.4 12.1 2.2 2.2 5-5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const Lock = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22">
    <rect x="5" y="10" width="14" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" strokeWidth="1.5" />
  </svg>
);

const Layers = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22">
    <path d="m12 3 9 5-9 5-9-5 9-5Z" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    <path d="m4 12 8 4.5 8-4.5M4 16l8 4.5 8-4.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

const Eye = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22">
    <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" fill="none" stroke="currentColor" strokeWidth="1.5" />
    <circle cx="12" cy="12" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
  </svg>
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
        <a className="brand" href="#" aria-label="Orcel home">
          <img className="brand-wordmark" src={brandWordmarkUrl} width="130" height="37" alt="Orcel" />
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
      </header>

      <div id="content" tabIndex={-1}>
        <section className="hero section-shell">
          <div className="hero-aura" aria-hidden="true" />
          <div className="eyebrow"><span className="status-dot" /> Local-first computer access for AI agents</div>
          <h1>Your computer.<br />Your terms.</h1>
          <p className="hero-copy">
            Orcel gives MCP-compatible agents a governed path to your own computer.
            Work stays bounded by local trust, approvals, policy, and audit.
          </p>
          <div className="hero-actions">
            <a className="button button-primary" href={github}>View on GitHub <Arrow /></a>
            <a className="button button-secondary" href={security}>Read the security model</a>
          </div>
          <p className="hero-footnote">Open source · Apache-2.0 · No mandatory Orcel cloud</p>

          <div className="hero-console" aria-label="Orcel authority boundary illustration">
            <div className="console-topbar">
              <div className="console-brand">
                <span className="brand-mark brand-mark-color" aria-hidden="true" />
                <img className="brand-wordmark brand-wordmark-console" src={brandWordmarkUrl} width="98" height="28" alt="Orcel" />
              </div>
              <div className="console-status"><span className="status-dot" /> Local boundary active</div>
            </div>
            <div className="console-grid">
              <article className="flow-card">
                <span className="flow-kicker">01 · AGENT</span>
                <h3>Request</h3>
                <p>An MCP client proposes a bounded action.</p>
                <div className="agent-row">
                  <span>ChatGPT</span><span>Claude</span><span>Codex</span><span>MCP</span>
                </div>
              </article>
              <div className="flow-arrow" aria-hidden="true">→</div>
              <article className="flow-card boundary-card">
                <span className="flow-kicker">02 · ORCEL</span>
                <h3>Decide locally</h3>
                <p>Trust, policy, approval, leases, and target identity stay authoritative.</p>
                <div className="boundary-list">
                  <span><i /> Trust checked</span>
                  <span><i /> Policy bounded</span>
                  <span><i /> Approval local</span>
                </div>
              </article>
              <div className="flow-arrow" aria-hidden="true">→</div>
              <article className="flow-card">
                <span className="flow-kicker">03 · COMPUTER</span>
                <h3>Act, then record</h3>
                <p>Qualified local providers perform only the permitted operation.</p>
                <div className="capability-row">
                  <span>Files</span><span>Git</span><span>Browser</span><span>Desktop</span>
                </div>
              </article>
            </div>
          </div>
        </section>

        <section className="proof-strip" aria-label="Product principles">
          <span>LOCAL-FIRST</span><i />
          <span>STANDARD MCP</span><i />
          <span>EXPLICIT APPROVALS</span><i />
          <span>BOUNDED AUTHORITY</span><i />
          <span>AUDITABLE ACTIONS</span>
        </section>

        <section className="section-shell feature-section" id="product">
          <div className="section-heading">
            <span className="section-index">01 / PRODUCT</span>
            <h2>One boundary.<br />Every agent.</h2>
            <p>Use the AI client you prefer without handing it an unrestricted shell, filesystem, or desktop.</p>
          </div>
          <div className="feature-grid">
            <article className="feature-card feature-card-wide">
              <span className="feature-number">01</span>
              <h3>Standard MCP interface</h3>
              <p>Connect through the Model Context Protocol instead of a private agent runtime.</p>
              <div className="protocol-line">
                <span>CLIENT</span><i /> <span>MCP</span><i /> <strong>ORCEL</strong><i /> <span>LOCAL PROVIDER</span>
              </div>
            </article>
            <article className="feature-card">
              <span className="feature-number">02</span>
              <h3>Local-first authority</h3>
              <p>Local policy remains decisive even when optional remote transport is in use.</p>
            </article>
            <article className="feature-card">
              <span className="feature-number">03</span>
              <h3>Fail closed</h3>
              <p>Missing trust, stale identity, expired authority, or unsupported capability returns a bounded failure.</p>
            </article>
          </div>
        </section>

        <section className="section-shell security-section" id="security">
          <div className="section-heading compact">
            <span className="section-index">02 / SECURITY FIRST</span>
            <h2>Permission lives here.</h2>
            <p>The computer stays authoritative. The agent can request; it cannot silently promote itself.</p>
          </div>
          <div className="security-grid">
            <article><span className="icon-box"><Shield /></span><h3>Approvals stay local</h3><p>Approval flows are decided on the computer that owns the authority.</p></article>
            <article><span className="icon-box"><Lock /></span><h3>No silent elevation</h3><p>Agent input cannot mint trust, approval, leases, or privileged authority.</p></article>
            <article><span className="icon-box"><Layers /></span><h3>Bounded capabilities</h3><p>Files, Git, browser, desktop, and registered tools stay behind explicit contracts.</p></article>
            <article><span className="icon-box"><Eye /></span><h3>Auditable actions</h3><p>Security decisions and qualified execution paths produce inspectable evidence.</p></article>
          </div>
        </section>

        <section className="boundary-section">
          <div className="section-shell boundary-inner">
            <div>
              <span className="section-index">03 / COMPUTER USE</span>
              <h2>Powerful capabilities.<br />Clear boundaries.</h2>
              <p>Computer use is not a shortcut around policy. Observation, proposals, approvals, execution, and postconditions remain separate steps.</p>
              <a className="text-link" href={security}>Explore the threat model <Arrow /></a>
            </div>
            <ol className="step-list">
              <li><span>01</span><div><strong>Observe</strong><p>Read only through qualified, bounded surfaces.</p></div></li>
              <li><span>02</span><div><strong>Propose</strong><p>Agent output is untrusted proposal data, not authority.</p></div></li>
              <li><span>03</span><div><strong>Validate</strong><p>Targets, policy, trust, freshness, and risk are checked locally.</p></div></li>
              <li><span>04</span><div><strong>Approve & act</strong><p>Mutations run only through the governed local path.</p></div></li>
              <li><span>05</span><div><strong>Record</strong><p>Outcomes are reported without inventing success or rollback.</p></div></li>
            </ol>
          </div>
        </section>

        <section className="section-shell developer-section" id="developers">
          <div className="developer-copy">
            <span className="section-index">04 / FOR DEVELOPERS</span>
            <h2>Integrate once.<br />Keep the boundary.</h2>
            <p>Orcel exposes the qualified local surface through MCP, so clients can change without changing who owns authority.</p>
            <div className="developer-actions">
              <a className="button button-primary" href={docs}>Read the docs <Arrow /></a>
              <a className="button button-secondary" href={github}>Browse the repository</a>
            </div>
          </div>
          <CodePanel />
        </section>

        <section className="section-shell final-cta">
          <span className="brand-mark brand-mark-color final-logo" aria-hidden="true" />
          <span className="section-index">ORCEL</span>
          <h2>A more capable agent.<br />On your computer.</h2>
          <p>Open source, local-first, and built around explicit authority.</p>
          <div className="hero-actions final-actions">
            <a className="button button-primary" href={releases}>View verified releases <Arrow /></a>
            <a className="button button-secondary" href={github}>Browse the source</a>
          </div>
          <p className="release-note">Published artifacts stay on the canonical GitHub Releases surface. Verify checksums and provenance before install.</p>
        </section>
      </div>

      <footer className="site-footer">
        <div className="footer-brand">
          <span className="brand"><img className="brand-wordmark" src={brandWordmarkUrl} width="130" height="37" alt="Orcel" /></span>
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
      </footer>
    </main>
  );
}
