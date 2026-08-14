import { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Alert } from '../services/api';

export interface LiveMessage {
  timestamp: string;
  type: string;
  payload: any;
}

export function useLiveUpdates() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [liveLogs, setLiveLogs] = useState<LiveMessage[]>([]);
  const [connected, setConnected] = useState<boolean>(false);

  useEffect(() => {
    const token = api.getToken();
    if (!token) {
      setConnected(false);
      return;
    }

    const wsUrl = `ws://localhost:8000/dashboard/ws?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      loggerLog('System', 'Dashboard WebSocket connected');
      setConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        loggerLog(data.type || 'unknown', data.payload || data);

        if (data.type === 'alert') {
          const alert = data.payload as Alert;
          setAlerts(prev => [alert, ...prev]);
        }

        // Dispatch window event for specific component reactive listeners
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('edr-ws-message', { detail: data }));
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message', err);
      }
    };

    ws.onclose = () => {
      loggerLog('System', 'Dashboard WebSocket disconnected');
      setConnected(false);
    };

    ws.onerror = (err) => {
      loggerLog('Error', 'Dashboard WebSocket error occurred');
      console.error('WebSocket error', err);
    };

    function loggerLog(type: string, payload: any) {
      const msg: LiveMessage = {
        timestamp: new Date().toLocaleTimeString(),
        type,
        payload
      };
      setLiveLogs(prev => [msg, ...prev].slice(0, 200)); // Keep last 200 messages
    }

    return () => {
      ws.close();
    };
  }, []);

  return { alerts, liveLogs, connected };
}
