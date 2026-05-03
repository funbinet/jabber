import React, { useState } from 'react';
import { Settings, Monitor, Palette, Bell, Info, ExternalLink, Sun, Moon, MoonStar, Terminal, FileText, Zap } from 'lucide-react';

export default function SettingsView({ systemInfo, isConnected, settings, onSettingsChange }) {
  const [notifications, setNotifications] = useState(true);

  if (!settings || !onSettingsChange) {
    return null; // Safeguard while props are loading
  }

  const { theme, fontScale, animationsEnabled, terminalAutoScroll, rawOutputDefault } = settings;
  const { setTheme, setFontScale, setAnimationsEnabled, setTerminalAutoScroll, setRawOutputDefault } = onSettingsChange;

  return (
    <div className="settings-view animate-fade-in">
      <div className="workspace__header">
        <h1 className="workspace__title">Settings</h1>
        <p className="workspace__description">Configure your JABBER workspace preferences</p>
      </div>

      {/* System Info */}
      <div className="settings-section">
        <div className="settings-section__title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Info size={16} /> System Information
        </div>
        <div className="settings-item">
          <div>
            <div className="settings-item__label">Connection Status</div>
            <div className="settings-item__desc">Backend engine connectivity</div>
          </div>
          <span style={{
            color: isConnected ? 'var(--emerald)' : 'var(--risk-critical)',
            fontSize: '12px', fontWeight: 600
          }}>
            {isConnected ? '● Connected' : '● Offline'}
          </span>
        </div>
        {systemInfo && (
          <>
            <div className="settings-item">
              <div>
                <div className="settings-item__label">Engine Version</div>
                <div className="settings-item__desc">JABBER backend version</div>
              </div>
              <span style={{ color: 'var(--ice-blue)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                {systemInfo.version}
              </span>
            </div>
            <div className="settings-item">
              <div>
                <div className="settings-item__label">Modules Loaded</div>
                <div className="settings-item__desc">Total modules in memory</div>
              </div>
              <span style={{ color: 'var(--crimson)', fontSize: '14px', fontWeight: 700 }}>
                {systemInfo.modules_loaded}
              </span>
            </div>
          </>
        )}
        <div className="settings-item">
          <div>
            <div className="settings-item__label">UI Version</div>
            <div className="settings-item__desc">Frontend build</div>
          </div>
          <span style={{ color: 'var(--steel-light)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
            V 5.5
          </span>
        </div>
      </div>

      {/* Appearance */}
      <div className="settings-section">
        <div className="settings-section__title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Palette size={16} /> Appearance & Layout
        </div>
        <div className="settings-item" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="settings-item__label">Theme</div>
            <div className="settings-item__desc">Color scheme for the interface</div>
          </div>
          <div className="mode-segmented" style={{ width: 'auto' }}>
            <button
              className={`mode-segmented__segment ${theme === 'light' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setTheme('light')}
              title="Light Mode"
              style={{ padding: '0.5rem 1rem' }}
            >
              <Sun size={18} />
            </button>
            <button
              className={`mode-segmented__segment ${theme === 'dark' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setTheme('dark')}
              title="Dark Mode"
              style={{ padding: '0.5rem 1rem' }}
            >
              <Moon size={18} />
            </button>
            <button
              className={`mode-segmented__segment ${theme === 'midnight' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setTheme('midnight')}
              title="Midnight Mode"
              style={{ padding: '0.5rem 1rem' }}
            >
              <MoonStar size={18} />
            </button>
          </div>
        </div>
        
        <div className="settings-item">
          <div>
            <div className="settings-item__label">Font Scale</div>
            <div className="settings-item__desc">Adjust global text size</div>
          </div>
          <div className="mode-segmented" style={{ width: 'auto' }}>
            <button
              className={`mode-segmented__segment ${fontScale === 'small' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setFontScale('small')}
            >
              Small
            </button>
            <button
              className={`mode-segmented__segment ${fontScale === 'default' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setFontScale('default')}
            >
              Default
            </button>
            <button
              className={`mode-segmented__segment ${fontScale === 'large' ? 'mode-segmented__segment--active' : ''}`}
              onClick={() => setFontScale('large')}
            >
              Large
            </button>
          </div>
        </div>

        <div className="settings-item">
          <div>
            <div className="settings-item__label">UI Animations</div>
            <div className="settings-item__desc">Enable layout transitions and hover effects</div>
          </div>
          <label className="form-group__checkbox">
            <input
              type="checkbox"
              checked={animationsEnabled}
              onChange={e => setAnimationsEnabled(e.target.checked)}
            />
          </label>
        </div>
      </div>

      {/* Terminal & Output */}
      <div className="settings-section">
        <div className="settings-section__title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Terminal size={16} /> Execution & Output
        </div>
        <div className="settings-item">
          <div>
            <div className="settings-item__label">Terminal Auto-Scroll</div>
            <div className="settings-item__desc">Automatically scroll to bottom on new output</div>
          </div>
          <label className="form-group__checkbox">
            <input
              type="checkbox"
              checked={terminalAutoScroll}
              onChange={e => setTerminalAutoScroll(e.target.checked)}
            />
          </label>
        </div>
        <div className="settings-item">
          <div>
            <div className="settings-item__label">Raw Output Default</div>
            <div className="settings-item__desc">Always show raw JSON/text before formatted view</div>
          </div>
          <label className="form-group__checkbox">
            <input
              type="checkbox"
              checked={rawOutputDefault}
              onChange={e => setRawOutputDefault(e.target.checked)}
            />
          </label>
        </div>
        <div className="settings-item">
          <div>
            <div className="settings-item__label">Execution Alerts</div>
            <div className="settings-item__desc">Show notifications when module completes</div>
          </div>
          <label className="form-group__checkbox">
            <input
              type="checkbox"
              checked={notifications}
              onChange={e => setNotifications(e.target.checked)}
            />
          </label>
        </div>
      </div>

      {/* Links */}
      <div className="settings-section">
        <div className="settings-section__title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ExternalLink size={16} /> Links
        </div>
        <div className="settings-item">
          <a href="https://dancan.tech" target="_blank" rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--ice-blue)', fontSize: '13px' }}>
            <ExternalLink size={14} /> dancan.tech
          </a>
        </div>
        <div className="settings-item">
          <a href="https://github.com/funbinet" target="_blank" rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--ice-blue)', fontSize: '13px' }}>
            <ExternalLink size={14} /> GitHub — funbinet
          </a>
        </div>
      </div>
    </div>
  );
}
