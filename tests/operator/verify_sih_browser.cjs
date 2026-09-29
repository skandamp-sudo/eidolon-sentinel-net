/* Optional real-browser verification. Uses an already installed Playwright/Chrome. */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const root = path.resolve(__dirname, '../..');
const liveInterface = process.argv[2];
let stage = 'browser launch';
(async () => {
  const key = fs.readFileSync(path.join(root, '.sentinel-demo.local'), 'utf8').trim().split('=')[1];
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    const urls = [], messages = [], htmls = [];
    let wsAuth = false;
    page.on('request', r => urls.push(r.url()));
    page.on('console', m => messages.push(m.text()));
    page.on('websocket', ws => ws.on('framereceived', f => {
      try { if (JSON.parse(f.payload).type === 'auth_ok') wsAuth = true; } catch {}
    }));
    page.on('response', async r => {
      if (r.request().resourceType() === 'document') htmls.push(await r.text());
    });
    stage = 'navigation';
    await page.goto('http://127.0.0.1:5174');
    await page.waitForURL('**/sensor');
    stage = 'WebSocket UI';
    await page.waitForFunction(() => /WS\s+CONNECTED/.test(document.body.innerText), null, { timeout: 15000 });
    stage = 'sessionStorage';
    const state = await page.evaluate(() => ({
      url: sessionStorage.getItem('sentinel_api_url'),
      key: sessionStorage.getItem('sentinel_api_key'),
      configured: sessionStorage.getItem('sentinel_configured'),
    }));
    assert.equal(state.url, 'http://127.0.0.1:8010');
    assert.equal(state.key, key);
    assert.equal(state.configured, 'true');
    assert(wsAuth);
    let liveProof = {};
    if (liveInterface) {
      stage = 'sustained live sensor';
      const initialText = await page.locator('.sensor-metric').filter({hasText:'Packets Observed'}).innerText();
      const start = Date.now();
      const samples = [];
      while (Date.now() - start < 65000) {
        const sample = await page.evaluate(async () => {
          const response = await fetch('http://127.0.0.1:8010/api/v1/status', {headers:{'X-API-Key':sessionStorage.getItem('sentinel_api_key')}});
          if (!response.ok) throw new Error('Status failed');
          const s = await response.json();
          return {state:s.sensor_state, mode:s.sensor_mode, interface:s.capture_interface, metrics:s.metrics, subscribers:s.websocket_subscribers};
        });
        assert.equal(sample.state, 'running');
        assert.equal(sample.mode, 'live_passive_sensor');
        assert.equal(sample.interface, liveInterface);
        assert(sample.subscribers > 0);
        samples.push(sample);
        await page.waitForTimeout(1000);
      }
      const m = samples.at(-1).metrics;
      for (const name of ['packets_observed','packets_parsed','packets_processed','flows_created','features_generated','detections_generated','events_persisted']) assert(m[name] > 0, name);
      const finalText = await page.locator('.sensor-metric').filter({hasText:'Packets Observed'}).innerText();
      assert.notEqual(finalText, initialText);
      assert(/WS\s+CONNECTED/.test(await page.locator('body').innerText()));
      liveProof = {runningSeconds:(Date.now()-start)/1000, statusSamples:samples.length, socUpdatesLive:true,
        parsed:m.packets_parsed, processed:m.packets_processed, flowsCreated:m.flows_created,
        features:m.features_generated, detections:m.detections_generated, persisted:m.events_persisted,
        nonIpSkipped:m.packets_non_ip_skipped, malformed:m.packets_malformed,
        captureErrors:m.capture_errors, processingErrors:m.processing_errors, persistenceErrors:m.persistence_errors};
    }
    stage = 'API and bootstrap';
    const result = await page.evaluate(async () => {
      const headers = { 'X-API-Key': sessionStorage.getItem('sentinel_api_key') };
      const status = await (await fetch('http://127.0.0.1:8010/api/v1/status', { headers })).json();
      const events = await (await fetch('http://127.0.0.1:8010/api/v1/events?limit=1', { headers })).json();
      const repeat = await fetch('/__eidolon_demo_bootstrap', { method: 'POST' });
      return { packets: status.metrics.packets_observed, flows: status.metrics.flows_completed, events: events.total,
        subscribers: status.websocket_subscribers, repeat: repeat.status };
    });
    result.unauth = (await page.request.get('http://127.0.0.1:8010/api/v1/events')).status();
    stage = 'result assertions';
    if (!liveInterface) { assert.equal(result.packets, 191); assert.equal(result.flows, 72); assert.equal(result.events, 72); }
    assert.equal(result.unauth, 401); assert.equal(result.repeat, 410);
    stage = 'credential leakage checks';
    assert(!urls.some(x => x.includes(key)));
    assert(!messages.some(x => x.includes(key)));
    assert(!htmls.some(x => x.includes(key)));
    // Keep the real subscriber alive long enough for launcher readiness observation.
    await page.waitForTimeout(1000);
    console.log(JSON.stringify({ autoAuth: true, websocketAuthenticated: wsAuth, ...result, ...liveProof,
      noKeyInURLsConsoleHTML: true }));
  } finally { await browser.close(); }
})().catch(() => {
  console.error('Browser verification failed at ' + stage + ' (credential-bearing details withheld)');
  process.exit(1);
});
