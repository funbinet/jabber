import React from 'react';
import { Menu, X, Maximize2, Minimize2 } from 'lucide-react';

export default function Header({
  isConnected, systemInfo, isScrolled, isFullscreen,
  onToggleFullscreen, onToggleMobileNav, mobileNavOpen
}) {
  return (
    <header className={`app-header ${isScrolled ? 'app-header--scrolled' : ''}`} id="jabber-header">
      {/* Hamburger (mobile/tablet) */}
      <button
        className="app-header__action-btn app-header__hamburger"
        onClick={onToggleMobileNav}
        aria-label={mobileNavOpen ? 'Close menu' : 'Open menu'}
      >
        {mobileNavOpen ? <X size={18} /> : <Menu size={18} />}
      </button>

      {/* Logo */}
      <div className="app-header__logo">
        <div className="app-header__logo-icon">
          <img alt="JABBER" src="https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png" />
        </div>
        <div>
          <div className="app-header__title">
            <span className="app-header__title-short">JABBER</span>
            <span className="app-header__title-full">JABBER</span>
          </div>
        </div>
      </div>

      <div className="app-header__spacer" />

      {/* Status */}
      <div className="app-header__status">
        <div
          className="app-header__status-dot"
          style={{ background: isConnected ? 'var(--emerald)' : 'var(--risk-critical)' }}
        />
        <span className="app-header__status-text">
          {isConnected ? 'Engine Online' : 'Connecting...'}
        </span>
        {systemInfo && (
          <span className="app-header__status-details">
            {systemInfo.version} · {systemInfo.modules_loaded} modules
          </span>
        )}
      </div>

      {/* Actions */}
      <div className="app-header__actions">
        <button
          className="app-header__action-btn"
          onClick={onToggleFullscreen}
          aria-label={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
          title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        >
          {isFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
        </button>
      </div>
    </header>
  );
}
