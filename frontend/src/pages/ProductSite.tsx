import { useEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import '../styles/product.css';

const views = [
  { name: 'Overview', image: '/product/console-overview.png', alt: 'Actual Sentinel-NET overview showing 65 events produced from a synthetic PCAP by the real detection pipeline.' },
  { name: 'Investigation', image: '/product/console-investigation.png', alt: 'Actual detection investigation with separate classifier and anomaly scores, flow context and statistical evidence from synthetic traffic.' },
];

function ProductPreview() {
  const [selected, setSelected] = useState(0);
  const dialog = useRef<HTMLDialogElement>(null);
  const view = views[selected]!;
  return <figure className="product-preview" id="workspace">
    <div className="product-preview__bar">
      <div className="product-tabs" role="tablist" aria-label="Console views">
        {views.map((item, index) => <button key={item.name} type="button" role="tab"
          id={`view-tab-${index}`} aria-selected={selected === index} aria-controls="console-preview"
          tabIndex={selected === index ? 0 : -1}
          onClick={() => setSelected(index)} onKeyDown={event => {
            if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
              event.preventDefault();
              const next = event.key === 'Home' ? 0 : event.key === 'End' ? views.length - 1 : (selected + 1) % views.length;
              setSelected(next);
              document.getElementById(`view-tab-${next}`)?.focus();
            }
          }}>{item.name}</button>)}
      </div>
      <span className="product-preview__label">THE SOC COMMAND CENTER</span>
    </div>
    <div id="console-preview" role="tabpanel" aria-labelledby={`view-tab-${selected}`} className="product-preview__image" tabIndex={0}>
      <img src={view.image} alt={view.alt} width="1440" height="1000" fetchPriority="high" />
    </div>
    <figcaption>
      <span>Actual application. Synthetic traffic, real model inference.<small className="product-mobile-hint">Scroll the image horizontally to inspect the workspace.</small></span>
      <button type="button" className="product-text-button" onClick={() => dialog.current?.showModal()}>Expand view <span aria-hidden="true">↗</span></button>
    </figcaption>
    <dialog ref={dialog} className="product-image-dialog" aria-label={`${view.name} screenshot`} onClick={event => { if (event.target === dialog.current) dialog.current.close(); }}>
      <div className="product-dialog-bar"><span>{view.name} · Synthetic PCAP replay</span><button type="button" onClick={() => dialog.current?.close()}>Close view</button></div>
      <div className="product-dialog-image" tabIndex={0} aria-label="Scrollable application screenshot"><img src={view.image} alt={view.alt} width="1440" height="1000" /></div>
    </dialog>
  </figure>;
}

function ProductStory() {
  return <>
    <section className="product-workflow product-container product-section" id="workflow" aria-labelledby="workflow-title">
      <p className="product-section-label">01 / FROM CAPTURE TO CONTEXT</p>
      <div className="product-section-intro"><h2 id="workflow-title">Follow the traffic.<br /><em>Keep the context.</em></h2><p>Start with a recorded PCAP. Trace observed packets into flows, then into scored events you can inspect in one workspace.</p></div>
      <ol className="product-steps">
        <li><span className="product-step-number">01</span><h3>Read the capture</h3><p>Replay packets from a local PCAP file without sending traffic back onto the network.</p><span className="product-step-detail">PASSIVE INPUT</span></li>
        <li><span className="product-step-number">02</span><h3>Build the flow</h3><p>Group observed conversations and extract timing, volume, direction, and protocol features.</p><span className="product-step-detail">52 CANONICAL FEATURES</span></li>
        <li><span className="product-step-number">03</span><h3>Examine the signal</h3><p>Read classifier output alongside anomaly scores and available supporting evidence.</p><span className="product-step-detail">DISTINCT SCORE SEMANTICS</span></li>
        <li><span className="product-step-number">04</span><h3>Investigate the record</h3><p>Follow the same event from SQLite storage to the API and SOC Command Center.</p><span className="product-step-detail">CONSISTENT EVENT IDENTITY</span></li>
      </ol>
    </section>
    <section className="product-evidence product-section" aria-labelledby="evidence-title">
      <div className="product-container product-evidence__layout">
        <div><p className="product-section-label">02 / EVIDENCE WITH CONTEXT</p><h2 id="evidence-title">A score deserves<br /><em>an explanation.</em></h2><p className="product-lead">A model classification starts an investigation. It does not confirm an attack.</p><p className="product-copy">Inspect the source and destination, follow the flow, and see which model produced the result. Available explanations distinguish model contributions from statistical deviations.</p><a href="#workspace" className="product-inline-link">Explore the workspace <span aria-hidden="true">↗</span></a></div>
        <dl className="product-score-definitions">
          <div><dt><span>01</span> Classification score</dt><dd>The classifier’s output for a class. An uncalibrated score, not a confirmed probability of attack.</dd></div>
          <div><dt><span>02</span> Anomaly score</dt><dd>How unusual a flow appears to the anomaly detector. Unusual traffic can also be legitimate.</dd></div>
          <div><dt><span>03</span> Supporting evidence</dt><dd>Model or statistical context with its source and version. Unavailable explanations are identified explicitly.</dd></div>
        </dl>
      </div>
    </section>
    <section className="product-boundary product-container product-section" aria-labelledby="boundary-title">
      <p className="product-section-label">03 / A DELIBERATE BOUNDARY</p>
      <div className="product-section-intro"><h2 id="boundary-title">Observe.<br /><em>Without intervening.</em></h2><div><p>Sentinel-NET inspects observed traffic. It does not actively probe hosts, inject packets, block connections, or decrypt payloads.</p><p className="product-small-copy">Software read-only behavior is distinct from physical one-way isolation. A network TAP or data diode requires its own deployment verification.</p></div></div>
      <div className="product-boundary-line"><span>Read-only inspection</span><span>No active probing</span><span>No payload decryption</span></div>
    </section>
    <section className="product-readiness product-container product-section" id="project-status" aria-labelledby="readiness-title">
      <div><p className="product-section-label">PROJECT STATUS</p><h2 id="readiness-title">Clear about<br /><em>where we stand.</em></h2><p className="product-copy">A research prototype with tested replay, event persistence, and a CLI-owned continuous passive sensor. Real-interface deployment and sustained performance still require validation.</p></div>
      <div className="product-faq">
        <details open><summary>What can I use today?</summary><p>Process recorded PCAP traffic through feature extraction and real model inference. Browse stored flows and events, inspect available explanations, and receive events over an authenticated WebSocket connection.</p></details>
        <details><summary>Is the continuous sensor service ready?</summary><p>The continuous service supports local interface selection, operational health, and graceful shutdown. Live capture and replay require the same explicitly approved frozen model bundle. Capture also requires local permissions. Real-interface validation and sustained throughput validation remain ahead. No production-readiness or near-real-time performance claim is made.</p></details>
        <details><summary>What do the screenshots show?</summary><p>The actual SOC interface connected to an isolated local backend. The records came from synthetic PCAP traffic processed by real XGBoost and Isolation Forest models in an isolated local verification run. They are not live customer traffic or measured detection-performance results.</p></details>
        <details><summary>What do I need to open the console?</summary><p>A running Sentinel-NET backend, its endpoint URL, and an API key. The console opens its existing connection workflow. There is no hosted account or public sensor connection provided by this page.</p></details>
      </div>
    </section>
    <section className="product-closing product-section" aria-labelledby="closing-title"><div className="product-container"><p className="product-section-label">YOUR NEXT INVESTIGATION</p><h2 id="closing-title">Bring your traffic<br /><em>into focus.</em></h2><Link className="product-button" to="/">Open the console <span aria-hidden="true">↗</span></Link><p>Use your own backend. Keep the evidence in context.</p></div></section>
  </>;
}

function LegalPage({ kind }: { kind: 'privacy' | 'terms' }) {
  return <article className="product-legal product-container">
    <p className="product-section-label">DRAFT FOR REVIEW</p>
    <h1>{kind === 'privacy' ? 'Privacy Policy' : 'Terms of Service'}</h1>
    <p className="product-lead">This draft describes the repository’s current behavior. It is not a finalized policy for a hosted service.</p>
    {kind === 'privacy' ? <>
      <h2>The product page</h2><p>This page serves product information and static screenshots. It adds no analytics, advertising trackers, contact forms, or externally hosted fonts. Hosting infrastructure and any server access logs depend on the deployment.</p>
      <h2>The SOC console</h2><p>When you configure the console, it saves the backend URL and API key in this browser tab’s sessionStorage and uses them to connect to that backend. The backend stores flow and event records in SQLite, including network addresses, ports, timestamps, model scores, and available evidence. The product page does not upload a capture file.</p>
      <h2>Screenshot data</h2><p>The screenshots use synthetic traffic processed by the actual detection pipeline. They do not depict customer traffic.</p>
      <h2>Information still required</h2><p>The deployment operator, contact details, hosting provider, access controls, retention and deletion procedures, and any additional data recipients must be confirmed before this draft becomes a published privacy policy. No retention period or compliance certification is asserted here.</p>
    </> : <>
      <h2>Current scope</h2><p>Sentinel-NET is a research prototype for passive network analysis. The public page does not provide a hosted service, a customer account, or an uptime commitment. The console connects to a backend configured by its user.</p>
      <h2>Software license</h2><p>The repository is distributed under the MIT License. Its permission notice, conditions, and warranty disclaimer are available in the <a href="/product/LICENSE.txt">software license</a>. This page does not replace that license.</p>
      <h2>Interpreting results</h2><p>Model scores and supporting evidence require investigation. They do not establish a confirmed attack, attribution, or a guarantee that traffic is safe. The project has not established production readiness or sustained throughput guarantees.</p>
      <h2>Information still required</h2><p>Any operator identity, service-specific terms, support commitments, governing jurisdiction, and contractual obligations must be supplied and reviewed before offering a hosted service. None are invented in this draft.</p>
    </>}
    <Link className="product-inline-link" to="/product">Return to Sentinel-NET</Link>
  </article>;
}

export function ProductSite() {
  const location = useLocation();
  const mobileMenu = useRef<HTMLDetailsElement>(null);
  const legal = location.pathname === '/product/privacy' ? 'privacy' : location.pathname === '/product/terms' ? 'terms' : null;
  const home = location.pathname === '/product' || location.pathname === '/product/';
  useEffect(() => {
    const previous = document.title;
    document.title = legal ? `${legal === 'privacy' ? 'Privacy Policy' : 'Terms of Service'} | Sentinel-NET` : 'Sentinel-NET | Network evidence, in clear view';
    return () => { document.title = previous; };
  }, [legal]);
  useEffect(() => {
    mobileMenu.current?.removeAttribute('open');
    if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
    else window.scrollTo(0, 0);
  }, [location.pathname, location.hash]);
  return <div className="product-site">
    <a className="product-skip" href="#product-main">Skip to content</a>
    <header className="product-header product-container">
      <Link className="product-brand" to="/product" aria-label="Eidolon Sentinel-NET home"><strong>EIDOLON</strong><span>SENTINEL-NET</span></Link>
      <nav aria-label="Product navigation"><Link to="/product#workspace">Workspace</Link><Link to="/product#workflow">How it works</Link><Link to="/" className="product-nav-cta">Open console <span aria-hidden="true">↗</span></Link></nav>
      <details ref={mobileMenu} className="product-mobile-menu" onKeyDown={event => { if (event.key === 'Escape') { mobileMenu.current?.removeAttribute('open'); mobileMenu.current?.querySelector('summary')?.focus(); } }}><summary>Menu</summary><nav aria-label="Mobile product navigation" onClick={() => mobileMenu.current?.removeAttribute('open')}><Link to="/product#workspace">Workspace</Link><Link to="/product#workflow">How it works</Link><Link to="/product#project-status">Project status</Link></nav></details>
    </header>
    <main id="product-main">
      {home ? <>
        <section className="product-hero product-container" aria-labelledby="product-title">
          <div className="product-eyebrow"><span>PASSIVE NETWORK ANALYSIS</span><span>RESEARCH PROTOTYPE</span></div>
          <h1 id="product-title">Network evidence.<br /><em>In clear view.</em></h1>
          <div className="product-hero__intro"><p>Follow the traffic. Understand the signal.<br />A focused workspace for examining network flows, model scores, and the evidence behind each detection.</p>
            <div className="product-hero__actions"><Link className="product-button" to="/">Explore the console <span aria-hidden="true">↗</span></Link><span>Connect your own Sentinel-NET backend.</span></div>
          </div>
          <ProductPreview />
        </section>
        <ProductStory />
      </> : legal ? <LegalPage kind={legal} /> : <section className="product-legal product-container"><h1>Page not found.</h1><p>This product page does not exist.</p><Link className="product-inline-link" to="/product">Return to Sentinel-NET</Link></section>}
    </main>
    <footer className="product-footer product-container"><div><Link className="product-brand" to="/product"><strong>EIDOLON</strong></Link><p>Sentinel-NET. Evidence for the investigation.</p><small>Research prototype · SIH26145</small></div><nav aria-label="Footer navigation"><Link to="/product/privacy">Privacy Policy <small>Draft</small></Link><Link to="/product/terms">Terms of Service <small>Draft</small></Link><a href="/product/LICENSE.txt">MIT License</a></nav></footer>
  </div>;
}
