import React from 'react';
import { Globe, Mail, TerminalSquare } from 'lucide-react';
import { useTerminal } from '../context/TerminalProvider.jsx';

/* Inline SVG icons for platforms lucide doesn't cover */
const GitHubIcon = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
  </svg>
);

const CodebergIcon = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
    <path d="M11.955.49A12 12 0 0 0 0 12.49a12 12 0 0 0 1.832 6.373L11.838 5.928a.187.187 0 0 1 .324 0l10.006 12.935A12 12 0 0 0 24 12.49a12 12 0 0 0-12-12 12 12 0 0 0-.045 0zm.375 6.467l4.416 5.302a.187.187 0 0 1-.135.304H7.389a.187.187 0 0 1-.134-.304z" />
  </svg>
);

export default function StatusBar({ isConnected, moduleCount, categoryCount }) {
  const { toggleTerminal, isOpen, isMinimized } = useTerminal();

  return (
    <footer className="statusbar" id="jabber-statusbar">
      <div className="statusbar__left">
        <span className="statusbar__creator desktop-only">funbinet</span>
        <div className="statusbar__links">
          <a href="https://dancan.tech" target="_blank" rel="noopener noreferrer"
            className="statusbar__link" title="Website">
            <Globe size={13} />
          </a>
          <a href="https://github.com/funbinet" target="_blank" rel="noopener noreferrer"
            className="statusbar__link" title="GitHub">
            <GitHubIcon />
          </a>
          <a href="https://codeberg.org/funbinet" target="_blank" rel="noopener noreferrer"
            className="statusbar__link" title="Codeberg">
            <CodebergIcon />
          </a>
          <a href="mailto:funbinet@gmail.com"
            className="statusbar__link" title="Email">
            <Mail size={13} />
          </a>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, justifyContent: 'center' }}>
        <button
          onClick={toggleTerminal}
          className={`statusbar__terminal-btn ${isOpen && !isMinimized ? 'is-active' : ''} ${isOpen && isMinimized ? 'is-minimized' : ''}`}
          title={isOpen ? (isMinimized ? 'Restore Terminal (minimized)' : 'Toggle Terminal') : 'Open Terminal'}
        >
          <TerminalSquare size={14} />
          <span className="desktop-only">{isOpen ? (isMinimized ? 'TERMINAL (MIN)' : 'TERMINAL') : 'TERMINAL'}</span>
        </button>
      </div>

      <div className="statusbar__right">
        <span className="desktop-only">{moduleCount} modules</span>
        <span className="desktop-only">|</span>
        <span className="desktop-only">{categoryCount} categories</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <span className="statusbar__live-dot" />
          <span style={{ color: isConnected ? 'var(--emerald)' : 'var(--risk-critical)', fontSize: '10px' }}>
            {isConnected ? 'Online' : 'Offline'}
          </span>
        </span>
      </div>
    </footer>
  );
}
