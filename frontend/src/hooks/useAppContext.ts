/**
 * Application context providing API client, live events, and WebSocket state
 * to all components.
 *
 * SECURITY:
 * - API key stored in closure via createApiClient, never in React state
 * - sessionStorage used only for the current tab
 * - Credentials never logged or rendered in DOM
 */

import { createContext, useContext } from 'react';
import type { ApiClient } from '@/api/client';
import type { DetectionEvent, WebSocketConnectionState } from '@/api/types';

export interface AppContextValue {
  api: ApiClient | null;
  isConfigured: boolean;
  liveEvents: DetectionEvent[];
  wsState: WebSocketConnectionState;
}

export const AppContext = createContext<AppContextValue>({
  api: null,
  isConfigured: false,
  liveEvents: [],
  wsState: 'disconnected',
});

export function useAppContext(): AppContextValue {
  return useContext(AppContext);
}
