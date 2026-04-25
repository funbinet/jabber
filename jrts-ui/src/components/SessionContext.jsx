import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';

/**
 * Session persistence context for JRTS module execution.
 * Preserves module state (inputs, task, logs, progress, output) across navigation.
 * Uses sessionStorage — clears when browser/app closes.
 */

const SESSION_KEY = 'jrts_module_sessions';

const SessionContext = createContext(null);

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used within SessionProvider');
  return ctx;
}

export function SessionProvider({ children }) {
  const [sessions, setSessions] = useState(() => {
    try {
      const stored = sessionStorage.getItem(SESSION_KEY);
      return stored ? JSON.parse(stored) : {};
    } catch {
      return {};
    }
  });

  // Persist to sessionStorage whenever sessions change
  useEffect(() => {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
    } catch (e) {
      console.warn('Failed to persist session state:', e);
    }
  }, [sessions]);

  const saveSession = useCallback((moduleId, state) => {
    setSessions(prev => ({
      ...prev,
      [moduleId]: {
        ...state,
        _savedAt: Date.now(),
      },
    }));
  }, []);

  const restoreSession = useCallback((moduleId) => {
    return sessions[moduleId] || null;
  }, [sessions]);

  const clearSession = useCallback((moduleId) => {
    setSessions(prev => {
      const next = { ...prev };
      delete next[moduleId];
      return next;
    });
  }, []);

  const clearAllSessions = useCallback(() => {
    setSessions({});
    try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  }, []);

  const getActiveSessions = useCallback(() => {
    return Object.entries(sessions)
      .filter(([, s]) => s.status === 'RUNNING')
      .map(([moduleId, s]) => ({ moduleId, ...s }));
  }, [sessions]);

  return (
    <SessionContext.Provider value={{
      saveSession,
      restoreSession,
      clearSession,
      clearAllSessions,
      getActiveSessions,
      sessions,
    }}>
      {children}
    </SessionContext.Provider>
  );
}
