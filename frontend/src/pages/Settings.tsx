/**
 * Settings page — API endpoint and credential configuration.
 *
 * SECURITY:
 * - API key input uses type="password"
 * - Credentials stored in sessionStorage only (cleared when tab closes)
 * - Never logged, rendered as visible text, or included in error messages
 * - No eval(), no dangerouslySetInnerHTML
 */

import { useState } from 'react';
import { createApiClient } from '@/api/client';
import { useAppContext } from '@/hooks/useAppContext';

interface SettingsProps {
  onConfigure: (baseUrl: string, apiKey: string) => void;
  onDisconnect: () => void;
}

export function Settings({ onConfigure, onDisconnect }: SettingsProps) {
  const { isConfigured, wsState } = useAppContext();

  const [apiUrl, setApiUrl] = useState(
    sessionStorage.getItem('sentinel_api_url') || 'http://127.0.0.1:8000',
  );
  const [apiKey, setApiKey] = useState('');
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState('');

  const handleTestConnection = async () => {
    if (!apiUrl || !apiKey) {
      setTestStatus('error');
      setErrorMsg('API URL and key are required.');
      return;
    }

    setTestStatus('testing');
    setErrorMsg('');

    try {
      const testClient = createApiClient(apiUrl, apiKey);
      const ok = await testClient.testConnection();
      setTestStatus(ok ? 'success' : 'error');
      if (!ok) setErrorMsg('Could not reach the API. Check the endpoint URL.');
    } catch {
      setTestStatus('error');
      setErrorMsg('Connection failed. Check your endpoint and network.');
    }
  };

  const handleSave = () => {
    if (!apiUrl || !apiKey) return;
    onConfigure(apiUrl, apiKey);
    setApiKey(''); // Clear from local state after configuring
    setTestStatus('idle');
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
      <div className="page-header">
        <h1 className="page-title">SETTINGS</h1>
        <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)', marginTop: 'var(--space-2)' }}>
          Connection & Configuration
        </div>
      </div>

      {isConfigured && (
        <div className="card" style={{ border: '1px solid var(--accent-success)', background: 'rgba(39, 174, 96, 0.05)' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-4)', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="status-indicator" style={{ marginBottom: 'var(--space-2)' }}>
                <span className={`status-dot ${wsState === 'connected' ? 'status-dot--ok' : 'status-dot--warn'}`} />
                <span style={{ color: 'var(--text-primary)', fontWeight: 600, letterSpacing: '0.05em' }}>
                  BACKEND CONFIGURED
                </span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-sm)', color: 'var(--text-muted)' }}>
                {sessionStorage.getItem('sentinel_api_url') || 'Unknown URL'}
              </div>
              <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-1)' }}>
                WebSocket State: <span style={{ color: wsState === 'connected' ? 'var(--accent-success)' : 'var(--accent-warn)' }}>{wsState}</span>
              </div>
            </div>
            <button 
              className="btn" 
              style={{ background: 'var(--accent-danger)', color: 'var(--bg-primary)', borderColor: 'var(--accent-danger)' }} 
              onClick={onDisconnect}
            >
              Disconnect
            </button>
          </div>
        </div>
      )}

      <div className="card settings-form">
        <div className="card__title">Configuration</div>

        <div className="form-group" style={{ marginBottom: 'var(--space-4)' }}>
          <label htmlFor="api-url" className="form-label" style={{ display: 'block', marginBottom: 'var(--space-2)' }}>
            API Endpoint
          </label>
          <input
            id="api-url"
            type="text"
            className="form-input"
            style={{ fontFamily: 'var(--font-mono)', width: '100%', padding: 'var(--space-2)', background: 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '4px' }}
            value={apiUrl}
            onChange={e => setApiUrl(e.target.value)}
            placeholder="http://127.0.0.1:8000"
            autoComplete="off"
          />
        </div>

        <div className="form-group" style={{ marginBottom: 'var(--space-4)' }}>
          <label htmlFor="api-key" className="form-label" style={{ display: 'block', marginBottom: 'var(--space-2)' }}>
            API Key
          </label>
          <input
            id="api-key"
            type="password"
            className="form-input"
            style={{ width: '100%', padding: 'var(--space-2)', background: 'var(--bg-elevated)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: '4px' }}
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="Enter API key"
            autoComplete="off"
          />
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)', marginTop: 'var(--space-6)' }}>
          <button
            className="btn btn--secondary"
            onClick={handleTestConnection}
            disabled={testStatus === 'testing' || !apiUrl || !apiKey}
          >
            {testStatus === 'testing' ? 'Testing…' : 'Test Connection'}
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSave}
            disabled={!apiUrl || !apiKey}
          >
            Connect
          </button>
        </div>

        {testStatus === 'success' && (
          <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-3)', background: 'rgba(39, 174, 96, 0.1)', border: '1px solid var(--accent-success)', color: 'var(--accent-success)', fontSize: 'var(--font-size-sm)', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>✓</span> Connection successful
          </div>
        )}

        {testStatus === 'error' && errorMsg && (
          <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-3)', background: 'rgba(231, 76, 60, 0.1)', border: '1px solid var(--accent-danger)', color: 'var(--accent-danger)', fontSize: 'var(--font-size-sm)', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>✗</span> {errorMsg}
          </div>
        )}
      </div>

      <div style={{ 
        padding: 'var(--space-4)', 
        background: 'var(--bg-elevated)', 
        border: '1px solid var(--border-color)', 
        borderRadius: '4px',
        borderLeft: '4px solid var(--accent-info)'
      }}>
        <div style={{ color: 'var(--accent-info)', fontWeight: 600, marginBottom: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          Credential storage
        </div>
        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', lineHeight: '1.5' }}>
          API key is stored in sessionStorage for this browser tab only. It is cleared when the tab is closed. Credentials are never logged or transmitted outside of authenticated API requests.
        </div>
      </div>
    </div>
  );
}
