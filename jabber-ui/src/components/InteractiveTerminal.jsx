import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { X, Minimize2, Maximize2, TerminalSquare, Save, Trash2, XOctagon } from 'lucide-react';
import { useTerminal } from '../context/TerminalProvider';
import '@xterm/xterm/css/xterm.css';

const InteractiveTerminal = () => {
  const {
    isOpen,
    isMinimized,
    closeTerminal,
    minimizeTerminal,
    restoreTerminal,
    isConnected,
    connectionState,
    lastError,
    sessionMeta,
    subscribeToOutput,
    sendRawInput,
    interruptTerminal,
    resizeTerminal,
    clearTerminal,
    exportSession,
  } = useTerminal();

  const terminalRef = useRef(null);
  const panelRef = useRef(null);
  const xtermRef = useRef(null);
  const fitAddonRef = useRef(null);
  const resizeObserverRef = useRef(null);
  const isVisibleRef = useRef(false);

  const [mountNode, setMountNode] = useState(null);
  const [feedback, setFeedback] = useState('');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    const node = document.querySelector('.app-body') || document.getElementById('jabber-workspace') || document.body;
    setMountNode(node);
  }, []);

  useEffect(() => {
    isVisibleRef.current = isOpen && !isMinimized;
  }, [isOpen, isMinimized]);

  useEffect(() => {
    if (!mountNode || !terminalRef.current || xtermRef.current) {
      return;
    }

    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      allowTransparency: true,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
      fontSize: 13,
      lineHeight: 1.28,
      scrollback: 8000,
      theme: {
        background: '#0b1119',
        foreground: '#d7e2f0',
        cursor: '#67d6ff',
        cursorAccent: '#0b1119',
        selectionBackground: 'rgba(103, 214, 255, 0.24)',
        black: '#101820',
        red: '#ff6f6f',
        green: '#63d697',
        yellow: '#e9c46a',
        blue: '#8bb4ff',
        magenta: '#d8a6ff',
        cyan: '#66d9ef',
        white: '#e7edf5',
        brightBlack: '#47576d',
        brightRed: '#ff9a9a',
        brightGreen: '#97f2b6',
        brightYellow: '#f7d794',
        brightBlue: '#b4cdff',
        brightMagenta: '#e4c4ff',
        brightCyan: '#9ee9ff',
        brightWhite: '#f5f9ff',
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalRef.current);

    const subscriptionCleanup = subscribeToOutput((chunk) => {
      term.write(chunk);
    }, { replay: true });

    const onData = term.onData((data) => {
      sendRawInput(data);
    });

    const onResize = term.onResize(({ cols, rows }) => {
      resizeTerminal(cols, rows);
    });

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    const fitTerminalToPanel = () => {
      if (!isVisibleRef.current || !fitAddonRef.current || !xtermRef.current) {
        return;
      }

      try {
        fitAddonRef.current.fit();
        resizeTerminal(xtermRef.current.cols, xtermRef.current.rows);
      } catch {
        // Ignore fit races while panel transitions.
      }
    };

    requestAnimationFrame(fitTerminalToPanel);

    const handleWindowResize = () => {
      fitTerminalToPanel();
    };
    window.addEventListener('resize', handleWindowResize);

    if (window.ResizeObserver && panelRef.current) {
      const observer = new ResizeObserver(() => {
        fitTerminalToPanel();
      });
      observer.observe(panelRef.current);
      resizeObserverRef.current = observer;
    }

    return () => {
      window.removeEventListener('resize', handleWindowResize);

      if (resizeObserverRef.current) {
        resizeObserverRef.current.disconnect();
        resizeObserverRef.current = null;
      }

      subscriptionCleanup();
      onData.dispose();
      onResize.dispose();

      term.dispose();
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [mountNode, subscribeToOutput, sendRawInput, resizeTerminal]);

  useEffect(() => {
    if (!isOpen || isMinimized) {
      return;
    }

    const timer = setTimeout(() => {
      xtermRef.current?.focus();

      if (fitAddonRef.current && xtermRef.current) {
        try {
          fitAddonRef.current.fit();
          resizeTerminal(xtermRef.current.cols, xtermRef.current.rows);
        } catch {
          // Ignore fit races while opening.
        }
      }
    }, 80);

    return () => clearTimeout(timer);
  }, [isOpen, isMinimized, resizeTerminal]);

  const handleInterrupt = () => {
    const result = interruptTerminal();
    if (result.success) {
      setFeedback('Interrupt signal sent (Ctrl+C).');
      xtermRef.current?.focus();
      return;
    }

    setFeedback(`Interrupt failed: ${result.error}`);
  };

  const handleClear = async () => {
    const result = await clearTerminal();
    setFeedback(result.success ? 'Terminal output cleared.' : `Clear failed: ${result.error}`);
    xtermRef.current?.focus();
  };

  const handleExport = async () => {
    setIsSaving(true);
    const result = await exportSession();
    setIsSaving(false);

    if (result.success) {
      setFeedback(`Session exported: ${result.file}`);
      return;
    }

    setFeedback(`Export failed: ${result.error}`);
  };

  if (!mountNode) {
    return null;
  }

  const effectiveFeedback = feedback || lastError;
  const connectionClass =
    connectionState === 'connected'
      ? 'is-connected'
      : connectionState === 'connecting'
        ? 'is-connecting'
        : 'is-offline';
  const connectionLabel =
    connectionState === 'connected'
      ? 'Connected'
      : connectionState === 'connecting'
        ? 'Connecting'
        : 'Offline';

  return createPortal(
    <div
      className={`jabber-terminal-overlay ${isOpen ? 'is-open' : ''} ${isMinimized ? 'is-minimized' : ''}`}
      aria-hidden={!isOpen}
    >
      <section
        className={`jabber-terminal-panel ${isMinimized ? 'is-minimized' : ''}`}
        role="dialog"
        aria-modal="false"
        aria-label="Terminal"
        ref={panelRef}
        onMouseDown={() => {
          if (isMinimized) {
            restoreTerminal();
            return;
          }
          xtermRef.current?.focus();
        }}
      >
        <header className="jabber-terminal-header">
          <div className="jabber-terminal-title-wrap">
            <TerminalSquare className="jabber-terminal-title-icon" size={16} />
            <span className="jabber-terminal-title">Terminal</span>
            <span className={`jabber-terminal-connection ${connectionClass}`}>
              {connectionLabel}
            </span>
          </div>

          <div className="jabber-terminal-meta">
            <span className="jabber-terminal-meta-item" title={sessionMeta.workingDirectory || 'Unknown path'}>
              {sessionMeta.workingDirectory || 'Directory unavailable'}
            </span>
            <span className="jabber-terminal-meta-item">History: {sessionMeta.historyCount}</span>
          </div>

          <div className="jabber-terminal-actions">
            <button type="button" className="jabber-terminal-action-btn" onClick={handleExport} disabled={isSaving} title="Save Session">
              <Save size={14} />
            </button>
            <button
              type="button"
              className="jabber-terminal-action-btn"
              onClick={handleInterrupt}
              title="Interrupt (Ctrl+C)"
              disabled={!isConnected}
            >
              <XOctagon size={14} />
            </button>
            <button type="button" className="jabber-terminal-action-btn" onClick={handleClear} title="Clear Terminal">
              <Trash2 size={14} />
            </button>
            <button
              type="button"
              className="jabber-terminal-action-btn"
              onClick={isMinimized ? restoreTerminal : minimizeTerminal}
              title={isMinimized ? 'Restore Terminal' : 'Minimize Terminal'}
            >
              {isMinimized ? <Maximize2 size={14} /> : <Minimize2 size={14} />}
            </button>
            <button type="button" className="jabber-terminal-action-btn danger" onClick={closeTerminal} title="Close Terminal">
              <X size={14} />
            </button>
          </div>
        </header>

        <div className="jabber-terminal-content">
          <div
            className="jabber-terminal-scrollback"
            ref={terminalRef}
            id="jabber-terminal-output"
            onMouseDown={() => xtermRef.current?.focus()}
          />

          <div className="jabber-terminal-footnote">
            <span>Interactive shell ready: type directly in terminal</span>
            <span>Ctrl+C to interrupt</span>
          </div>

          {effectiveFeedback && (
            <div className="jabber-terminal-feedback">
              {effectiveFeedback}
            </div>
          )}
        </div>
      </section>
    </div>,
    mountNode
  );
};

export default InteractiveTerminal;
