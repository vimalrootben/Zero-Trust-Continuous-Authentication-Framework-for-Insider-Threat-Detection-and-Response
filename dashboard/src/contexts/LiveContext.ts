import { createContext, useContext } from 'react';
import type { LiveMessage } from '../hooks/useLiveUpdates';
import type { Alert } from '../services/api';

export interface LiveContextValue {
  alerts: Alert[];
  liveLogs: LiveMessage[];
  connected: boolean;
  onLogout: () => void;
}

export const LiveContext = createContext<LiveContextValue>({
  alerts: [],
  liveLogs: [],
  connected: false,
  onLogout: () => {},
});

export const useLive = () => useContext(LiveContext);
