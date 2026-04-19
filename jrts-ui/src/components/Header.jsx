import React from 'react';

export default function Header({ isConnected, systemInfo }) {
  return (
    <header className="app-header" id="jrts-header">
      <div className="app-header__logo">
        <div className="app-header__logo-icon">
          <img src="/jabber.png" alt="JRTS" />
        </div>
        <div>
          <div className="app-header__title">JABBER RED TEAMING SUITE</div>
        </div>
      </div>
      <div className="app-header__spacer" />
      <div className="app-header__status">
        <div className={`app-header__status-dot`}
          style={{ background: isConnected ? 'var(--emerald)' : 'var(--risk-critical)' }} />
        <span>{isConnected ? 'Engine Online' : 'Connecting...'}</span>
        {systemInfo && (
          <span style={{ color: 'var(--steel)', fontSize: '11px', borderLeft: '1px solid var(--border)', paddingLeft: '0.75rem', marginLeft: '0.25rem' }}>
            {systemInfo.version} · {systemInfo.modules_loaded} modules
          </span>
        )}
      </div>
    </header>
  );
}
