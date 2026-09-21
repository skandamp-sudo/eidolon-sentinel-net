/**
 * Root application component.
 *
 * Manages:
 * - API client lifecycle (created when credentials are configured)
 * - WebSocket connection for live events
 * - Bounded live event buffer (max 100, deduped by ID)
 * - Navigation and routing
 *
 * SECURITY:
 * - API key held in ref/closure, never in rendered state
 * - sessionStorage for current-tab persistence only
 * - No credentials in URL, DOM, or error messages
 */

import { useState, useCallback, useRef, useEffect, lazy, Suspense } from 'react';
import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom';
import { createApiClient, type ApiClient } from '@/api/client';
import { WebSocketManager } from '@/api/websocket';
import { AppContext } from '@/hooks/useAppContext';
import type { DetectionEvent, WebSocketConnectionState } from '@/api/types';

// Lazy-loaded pages
import { Overview } from '@/pages/Overview';
import { Detections } from '@/pages/Detections';
import { DetectionDetail } from '@/pages/DetectionDetail';
import { Flows } from '@/pages/Flows';
import { FlowDetail } from '@/pages/FlowDetail';
import { Sensor } from '@/pages/Sensor';
import { Intelligence } from '@/pages/Intelligence';
import { Settings } from '@/pages/Settings';

const MAX_LIVE_EVENTS = 100;
const SESSION_KEY_URL = 'sentinel_api_url';
// Note: API key stored in sessionStorage, never localStorage
const SESSION_KEY_AUTH = 'sentinel_configured';

const ProductSite = lazy(() => import('@/pages/ProductSite').then(module => ({ default: module.ProductSite })));

export function App() {
  return <Routes>
    <Route path="/product/*" element={<Suspense fallback={<p role="status">Loading product page…</p>}><ProductSite /></Suspense>} />
    <Route path="*" element={<ConsoleApp />} />
  </Routes>;
}

function ConsoleApp() {
  const [navOpen, setNavOpen] = useState(false);
  const [api, setApi] = useState<ApiClient | null>(null);
  const [isConfigured, setIsConfigured] = useState(false);
  const [liveEvents, setLiveEvents] = useState<DetectionEvent[]>([]);
  const [wsState, setWsState] = useState<WebSocketConnectionState>('disconnected');
  const [healthStatus, setHealthStatus] = useState<'ok' | 'error' | 'unknown'>('unknown');
  const [currentTime, setCurrentTime] = useState(new Date());

  const wsManagerRef = useRef<WebSocketManager | null>(null);
  const seenIdsRef = useRef(new Set<string>());
  const location = useLocation();
  useEffect(() => { setNavOpen(false); }, [location.pathname]);

  useEffect(() => () => wsManagerRef.current?.disconnect(), []);

  // Clock tick
  useEffect(() => {
    const interval = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Auto-configure from sessionStorage on mount
  useEffect(() => {
    const savedUrl = sessionStorage.getItem(SESSION_KEY_URL);
    const configured = sessionStorage.getItem(SESSION_KEY_AUTH);
    if (savedUrl && configured) {
      // Re-read key from sessionStorage (it's per-tab)
      const key = sessionStorage.getItem('sentinel_api_key');
      if (key) {
        handleConfigure(savedUrl, key);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Health check polling
  useEffect(() => {
    if (!api) return;
    const check = async () => {
      try {
        await api.getHealth();
        setHealthStatus('ok');
      } catch {
        setHealthStatus('error');
      }
    };
    check();
    const interval = setInterval(check, 30_000);
    return () => clearInterval(interval);
  }, [api]);

  const handleLiveEvent = useCallback((event: DetectionEvent) => {
    if (seenIdsRef.current.has(event.id)) return;

    if (seenIdsRef.current.size >= MAX_LIVE_EVENTS) {
      const first = seenIdsRef.current.values().next().value;
      if (first) seenIdsRef.current.delete(first);
    }
    seenIdsRef.current.add(event.id);

    setLiveEvents(prev => {
      const next = [event, ...prev];
      return next.slice(0, MAX_LIVE_EVENTS);
    });
  }, []);

  const handleConfigure = useCallback((baseUrl: string, apiKey: string) => {
    // Tear down old WS
    wsManagerRef.current?.disconnect();

    const client = createApiClient(baseUrl, apiKey);
    setApi(client);
    setIsConfigured(true);

    // Persist (session only)
    sessionStorage.setItem(SESSION_KEY_URL, baseUrl);
    sessionStorage.setItem(SESSION_KEY_AUTH, 'true');
    sessionStorage.setItem('sentinel_api_key', apiKey);

    // Connect WebSocket
    const wsUrl = baseUrl.replace(/^http/, 'ws') + '/api/v1/ws/events';
    const manager = new WebSocketManager({
      url: wsUrl,
      apiKey,
      onEvent: handleLiveEvent,
      onStateChange: setWsState,
    });
    wsManagerRef.current = manager;
    manager.connect();
  }, [handleLiveEvent]);

  const handleDisconnect = useCallback(() => {
    wsManagerRef.current?.disconnect();
    setApi(null);
    setIsConfigured(false);
    setWsState('disconnected');
    setLiveEvents([]);
    seenIdsRef.current.clear();
    sessionStorage.removeItem(SESSION_KEY_URL);
    sessionStorage.removeItem(SESSION_KEY_AUTH);
    sessionStorage.removeItem('sentinel_api_key');
  }, []);

  const opsLinks = [
    { to: '/', label: 'Overview' },
    { to: '/detections', label: 'Detections' },
    { to: '/flows', label: 'Flows' },
    { to: '/sensor', label: 'Sensor' },
  ];

  const analysisLinks = [
    { to: '/intelligence', label: 'Intelligence' },
  ];

  const wsStateLabel: Record<WebSocketConnectionState, string> = {
    connecting: 'CONNECTING',
    authenticating: 'AUTHENTICATING',
    connected: 'CONNECTED',
    disconnected: 'DISCONNECTED',
    reconnecting: 'RECONNECTING',
  };

  const wsStateDot: Record<WebSocketConnectionState, string> = {
    connecting: 'status-dot--warn',
    authenticating: 'status-dot--warn',
    connected: 'status-dot--ok',
    disconnected: 'status-dot--error',
    reconnecting: 'status-dot--warn',
  };

  const padZero = (n: number) => n.toString().padStart(2, '0');
  const formattedTime = `${padZero(currentTime.getHours())}:${padZero(currentTime.getMinutes())}:${padZero(currentTime.getSeconds())}`;

  return (
    <AppContext.Provider value={{ api, isConfigured, liveEvents, wsState }}>
      <div className="app-layout">
        <a className="skip-link" href="#main-content">Skip to content</a>
        {/* ─── Status Bar ────────────────────────────────────── */}
        <header className="status-bar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 1rem' }}>
          <div className="status-bar__identity">
            <button className="btn btn--secondary menu-toggle" aria-expanded={navOpen} aria-controls="soc-navigation" onClick={() => setNavOpen(!navOpen)}>Menu</button>
            <span className="status-bar__brand" style={{ fontWeight: 'bold' }}>EIDOLON // SENTINEL-NET</span>
            <span style={{ color: 'var(--text-muted, #888)', fontSize: '0.85em', letterSpacing: '0.05em' }}>SOC COMMAND CENTER</span>
          </div>

          <div className="status-bar__indicators" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="status-indicator" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <span className={`status-dot ${healthStatus === 'ok' ? 'status-dot--ok' : healthStatus === 'error' ? 'status-dot--error' : 'status-dot--unknown'}`} />
              <span style={{ fontSize: '0.85em' }}>API</span>
              <span style={{ fontSize: '0.85em', color: 'var(--text-muted, #888)' }}>{healthStatus === 'ok' ? 'REACHABLE' : healthStatus === 'error' ? 'DOWN' : '...'}</span>
            </div>
            
            <span style={{ color: 'var(--border-color, #333)' }}>|</span>

            <div className="status-indicator" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <span className={`status-dot ${wsStateDot[wsState]}`} />
              <span style={{ fontSize: '0.85em' }}>WS</span>
              <span style={{ fontSize: '0.85em', color: 'var(--text-muted, #888)' }}>{wsStateLabel[wsState]}</span>
            </div>
            
            {liveEvents.length > 0 && (
              <>
                <span style={{ color: 'var(--border-color, #333)' }}>|</span>
                <div className="status-indicator" style={{ display: 'flex', alignItems: 'center', padding: '0.1rem 0.4rem', background: 'var(--bg-card, rgba(0,0,0,0.2))', border: '1px solid var(--border-color, #333)', borderRadius: '4px', fontSize: '0.8em', fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--color-primary, #4a90e2)' }}>{liveEvents.length}</span>
                  <span style={{ marginLeft: '4px', color: 'var(--text-muted, #888)' }}>EVENTS</span>
                </div>
              </>
            )}

            <span style={{ color: 'var(--border-color, #333)' }}>|</span>

            <div className="status-indicator" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9em', letterSpacing: '0.05em' }}>
              {formattedTime}
            </div>
          </div>
        </header>

        {/* ─── Sidebar ───────────────────────────────────────── */}
        <nav id="soc-navigation" className={`sidebar ${navOpen ? "sidebar--open" : ""}`} role="navigation" aria-label="Main navigation" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '1.1rem', fontWeight: 'bold', borderBottom: '1px solid var(--border-color, #333)', marginBottom: '1rem' }}>
            <span style={{ color: 'var(--color-primary, #4a90e2)' }}></span>
            <span>EIDOLON</span>
          </div>

          <div className="nav-section" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted, #888)', padding: '0 1rem', marginBottom: '0.5rem', letterSpacing: '0.05em' }}>Operations</div>
          {opsLinks.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === '/'}
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}
            >
              {link.label}
            </NavLink>
          ))}

          <div className="nav-section" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted, #888)', padding: '0 1rem', marginTop: '1.5rem', marginBottom: '0.5rem', letterSpacing: '0.05em' }}>Analysis</div>
          {analysisLinks.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}
            >
              {link.label}
            </NavLink>
          ))}

          <div style={{ flexGrow: 1 }} />

          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: '0.5rem', paddingBottom: '0.5rem' }}>
            <NavLink
              to="/settings"
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}
            >
              Settings
            </NavLink>
            <div style={{ textAlign: 'center', padding: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted, #888)' }}>
              v0.6.0
            </div>
          </div>
        </nav>

        {/* ─── Main Content ──────────────────────────────────── */}
        <main id="main-content" tabIndex={-1} className="page-content" role="main" style={{ display: 'flex', flexDirection: 'column' }}>
          {!isConfigured && location.pathname !== '/settings' ? (
            <div style={{ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
              <div className="card" style={{ maxWidth: '440px', width: '100%', padding: '2.5rem 2rem', textAlign: 'center', background: 'var(--bg-card, #1a1a1a)', border: '1px solid var(--border-color, #333)', borderRadius: '8px', boxShadow: 'none' }}>
                
                <h2 style={{ margin: '0 0 1rem 0', fontFamily: 'var(--font-mono)', fontSize: '1.25rem', letterSpacing: '0.05em' }}>SECURE ACCESS REQUIRED</h2>
                <p style={{ color: 'var(--text-muted, #888)', marginBottom: '2.5rem', lineHeight: '1.6' }}>
                  Node connection to Sentinel-NET is not established. Please configure your endpoint and authorization credentials to proceed.
                </p>
                <NavLink 
                  to="/settings" 
                  style={{ 
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                    padding: '0.75rem 2rem', 
                    background: 'var(--color-primary, #4a90e2)', 
                    color: 'var(--bg-primary)', 
                    textDecoration: 'none', 
                    fontFamily: 'var(--font-mono)', 
                    fontWeight: 'bold', 
                    borderRadius: '4px',
                    transition: 'opacity 0.2s'
                  }}
                  onMouseOver={(e) => e.currentTarget.style.opacity = '0.9'}
                  onMouseOut={(e) => e.currentTarget.style.opacity = '1'}
                >
                  CONNECTION SETTINGS
                </NavLink>
              </div>
            </div>
          ) : (
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/detections/:eventId" element={<DetectionDetail />} />
              <Route path="/flows" element={<Flows />} />
              <Route path="/flows/:flowId" element={<FlowDetail />} />
              <Route path="/sensor" element={<Sensor />} />
              <Route path="/intelligence" element={<Intelligence />} />
              <Route path="/settings" element={<Settings onConfigure={handleConfigure} onDisconnect={handleDisconnect} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          )}
        </main>
      </div>
    </AppContext.Provider>
  );
}
