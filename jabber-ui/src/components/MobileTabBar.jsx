import React from 'react';
import { Home, Package, FileText, TerminalSquare, Settings } from 'lucide-react';

const TAB_ITEMS = [
  { id: 'dashboard', icon: Home, label: 'Home' },
  { id: 'modules', icon: Package, label: 'Modules' },
  { id: 'artifacts', icon: FileText, label: 'Artifacts' },
  { id: 'search', icon: TerminalSquare, label: 'Search' },
  { id: 'settings', icon: Settings, label: 'Settings' },
];

export default function MobileTabBar({ activeView, onSelect }) {
  // Map views to tab highlighting
  const activeTab = ['dashboard'].includes(activeView) ? 'dashboard'
    : ['category', 'executor', 'modules'].includes(activeView) ? 'modules'
    : ['reports', 'profiler'].includes(activeView) ? 'reports'
    : activeView;

  return (
    <nav className="mobile-tab-bar" id="jabber-mobile-tabs">
      {TAB_ITEMS.map(item => {
        const Icon = item.icon;
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            className={`mobile-tab-bar__item ${isActive ? 'mobile-tab-bar__item--active' : ''}`}
            onClick={() => onSelect(item.id)}
            aria-label={item.label}
          >
            <span className="mobile-tab-bar__icon">
              <Icon size={20} />
            </span>
            <span className="mobile-tab-bar__label">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
