import React, {
  createContext,
  useContext,
  useState,
  useRef,
  useEffect,
  useCallback,
} from 'react';

const TerminalContext = createContext(null);
const TERMINAL_SESSION_STORAGE_KEY = 'jrts-terminal-session-id';

function resolveTerminalSessionId() {
  if (typeof window === 'undefined') {
    return 'terminal-default-session';
  }

  const existing = window.sessionStorage.getItem(TERMINAL_SESSION_STORAGE_KEY);
  if (existing && existing.trim()) {
    return existing.trim();
  }

  const generated =
    typeof window.crypto !== 'undefined' && typeof window.crypto.randomUUID === 'function'
      ? window.crypto.randomUUID()
      : `terminal-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  window.sessionStorage.setItem(TERMINAL_SESSION_STORAGE_KEY, generated);
  return generated;
}

export const TerminalProvider = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionState, setConnectionState] = useState('connecting');
  const [lastError, setLastError] = useState(null);
  const [sessionMeta, setSessionMeta] = useState({
    workingDirectory: '',
    historyCount: 0,
    processRunning: false,
    lastExportPath: '',
  });

  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const subscribersRef = useRef(new Set());
  const mountedRef = useRef(true);
  const outputBufferRef = useRef('');
  const sessionIdRef = useRef(resolveTerminalSessionId());

  const withSessionPath = useCallback((basePath) => {
    const separator = basePath.includes('?') ? '&' : '?';
    return `${basePath}${separator}sessionId=${encodeURIComponent(sessionIdRef.current)}`;
  }, []);

  const appendOutputBuffer = useCallback((chunk) => {
    outputBufferRef.current += chunk;
    if (outputBufferRef.current.length > 1000000) {
      outputBufferRef.current = outputBufferRef.current.slice(-750000);
    }
  }, []);

  const notifySubscribers = useCallback((chunk) => {
    appendOutputBuffer(chunk);
    subscribersRef.current.forEach((callback) => {
      try {
        callback(chunk);
      } catch (error) {
        console.error('Terminal subscriber callback failed:', error);
      }
    });
  }, [appendOutputBuffer]);

  const scheduleReconnect = useCallback((delayMs = 1500) => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
    }

    reconnectTimerRef.current = setTimeout(() => {
      if (!mountedRef.current) {
        return;
      }

      setConnectionState('connecting');
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsPath = withSessionPath('/api/terminal/ws');
      const ws = new WebSocket(`${protocol}//${window.location.host}${wsPath}`);

      ws.onopen = () => {
        if (!mountedRef.current) {
          return;
        }
        setIsConnected(true);
        setConnectionState('connected');
        setLastError(null);
      };

      ws.onmessage = (event) => {
        if (typeof event.data === 'string') {
          notifySubscribers(event.data);
          return;
        }

        if (event.data instanceof Blob) {
          event.data
            .text()
            .then((text) => notifySubscribers(text))
            .catch((error) => console.error('Failed to decode terminal blob payload:', error));
          return;
        }

        if (event.data instanceof ArrayBuffer) {
          notifySubscribers(new TextDecoder().decode(event.data));
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) {
          return;
        }
        setIsConnected(false);
        setConnectionState('offline');
        scheduleReconnect(1500);
      };

      ws.onerror = (event) => {
        console.error('Terminal WS Error', event);
        setConnectionState('offline');
        setLastError('Terminal websocket connection error');
      };

      wsRef.current = ws;
    }, delayMs);
  }, [notifySubscribers, withSessionPath]);

  const refreshSessionState = useCallback(async () => {
    try {
      const response = await fetch(withSessionPath('/api/terminal/state'));
      if (!response.ok) {
        return;
      }

      const data = await response.json();
      setSessionMeta((previous) => ({
        ...previous,
        workingDirectory: data.workingDirectory || previous.workingDirectory,
        historyCount: Number.isFinite(data.historyCount) ? data.historyCount : previous.historyCount,
        processRunning: !!data.processRunning,
      }));
    } catch {
      // State endpoint is best-effort metadata and should never break terminal UX.
    }
  }, [withSessionPath]);

  const openTerminal = useCallback(() => {
    setIsOpen(true);
    setIsMinimized(false);
  }, []);

  const closeTerminal = useCallback(() => {
    setIsOpen(false);
    setIsMinimized(false);
  }, []);

  const minimizeTerminal = useCallback(() => {
    setIsOpen(true);
    setIsMinimized(true);
  }, []);

  const restoreTerminal = useCallback(() => {
    setIsOpen(true);
    setIsMinimized(false);
  }, []);

  const toggleTerminal = useCallback(() => {
    if (!isOpen) {
      openTerminal();
      return;
    }

    if (isMinimized) {
      restoreTerminal();
      return;
    }

    minimizeTerminal();
  }, [isOpen, isMinimized, openTerminal, restoreTerminal, minimizeTerminal]);

  const subscribeToOutput = useCallback((callback, options = {}) => {
    const replayBufferedOutput = options.replay !== false;
    subscribersRef.current.add(callback);

    if (replayBufferedOutput && outputBufferRef.current) {
      callback(outputBufferRef.current);
    }

    return () => {
      subscribersRef.current.delete(callback);
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    // Connect immediately on mount (0ms delay = immediate)
    setConnectionState('connecting');
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsPath = withSessionPath('/api/terminal/ws');
    const ws = new WebSocket(`${protocol}//${window.location.host}${wsPath}`);

    ws.onopen = () => {
      if (!mountedRef.current) return;
      setIsConnected(true);
      setConnectionState('connected');
      setLastError(null);
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        notifySubscribers(event.data);
        return;
      }
      if (event.data instanceof Blob) {
        event.data
          .text()
          .then((text) => notifySubscribers(text))
          .catch((error) => console.error('Failed to decode terminal blob payload:', error));
        return;
      }
      if (event.data instanceof ArrayBuffer) {
        notifySubscribers(new TextDecoder().decode(event.data));
      }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setIsConnected(false);
      setConnectionState('offline');
      scheduleReconnect(3000);
    };

    ws.onerror = (event) => {
      console.error('Terminal WS Error', event);
      setConnectionState('offline');
      setLastError('Terminal websocket connection error');
    };

    wsRef.current = ws;
    refreshSessionState();

    return () => {
      mountedRef.current = false;

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      subscribersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (isOpen) {
      refreshSessionState();
    }
  }, [isOpen, refreshSessionState]);

  const sendRawInput = useCallback((payload) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(payload);
      return true;
    }

    if (connectionState !== 'connecting') {
      scheduleReconnect(120);
    }
    setLastError('Terminal is offline. Unable to send input.');
    return false;
  }, [connectionState, scheduleReconnect]);

  const executeCommand = useCallback((commandText) => {
    const command = String(commandText || '').trim();
    if (!command) {
      return { sent: false, reason: 'Command is empty' };
    }

    const sent = sendRawInput(`${command}\r`);
    if (sent) {
      setSessionMeta((previous) => ({
        ...previous,
        historyCount: previous.historyCount + 1,
      }));
      refreshSessionState();
    }

    return sent
      ? { sent: true }
      : { sent: false, reason: 'Terminal is disconnected' };
  }, [sendRawInput, refreshSessionState]);

  const resizeTerminal = useCallback((cols, rows) => {
    if (Number.isFinite(cols) && Number.isFinite(rows)) {
      sendRawInput(JSON.stringify({ type: 'resize', cols, rows }));
    }
  }, [sendRawInput]);

  const interruptTerminal = useCallback(() => {
    const sent = sendRawInput('\u0003');
    if (!sent) {
      return { success: false, error: 'Terminal is disconnected' };
    }
    return { success: true };
  }, [sendRawInput]);

  const clearTerminal = useCallback(async () => {
    try {
      const response = await fetch(withSessionPath('/api/terminal/clear'), { method: 'POST' });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unable to clear terminal session' }));
        throw new Error(errorData.error || 'Unable to clear terminal session');
      }

      outputBufferRef.current = '';
      notifySubscribers('\u001b[2J\u001b[H');
      await refreshSessionState();
      return { success: true };
    } catch (error) {
      setLastError(error.message);
      return { success: false, error: error.message };
    }
  }, [notifySubscribers, refreshSessionState, withSessionPath]);

  const exportSession = useCallback(async () => {
    try {
      const response = await fetch(withSessionPath('/api/terminal/export'), { method: 'POST' });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Terminal export failed');
      }

      setSessionMeta((previous) => ({
        ...previous,
        lastExportPath: data.file || previous.lastExportPath,
      }));

      return { success: true, ...data };
    } catch (error) {
      setLastError(error.message);
      return { success: false, error: error.message };
    }
  }, [withSessionPath]);

  const killTerminalSession = useCallback(async () => {
    try {
      const response = await fetch(withSessionPath('/api/terminal/kill'), { method: 'POST' });
      const data = await response.json().catch(() => ({ status: 'destroyed' }));

      if (!response.ok) {
        throw new Error(data.error || 'Unable to terminate terminal session');
      }

      notifySubscribers('\r\n\u001b[31m[Terminal Session Terminated]\u001b[0m\r\n');
      await refreshSessionState();
      return { success: true, ...data };
    } catch (error) {
      setLastError(error.message);
      return { success: false, error: error.message };
    }
  }, [notifySubscribers, refreshSessionState, withSessionPath]);

  return (
    <TerminalContext.Provider value={{
      isOpen,
      isMinimized,
      toggleTerminal,
      openTerminal,
      closeTerminal,
      minimizeTerminal,
      restoreTerminal,
      isConnected,
      connectionState,
      lastError,
      sessionMeta,
      sessionId: sessionIdRef.current,
      wsRef,
      subscribeToOutput,
      sendRawInput,
      executeCommand,
      resizeTerminal,
      interruptTerminal,
      clearTerminal,
      exportSession,
      killTerminalSession,
      refreshSessionState,
    }}>
      {children}
    </TerminalContext.Provider>
  );
};

export const useTerminal = () => useContext(TerminalContext);
