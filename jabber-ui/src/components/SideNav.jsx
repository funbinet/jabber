import React from 'react';
import {
  Search, Package, Lock, Shield, Zap, ArrowUp, Key, Globe,
  Wifi, Network, Users, FileSearch, Radio, GitBranch, Unlock,
  Server, Wrench, Home, Database, FileText, X, Settings, Smartphone
} from 'lucide-react';

const ICON_COMPONENTS = {
  Search, Package, Lock, Shield, Zap, ArrowUp, Key, Globe,
  Wifi, Network, Users, FileSearch, Radio, GitBranch, Unlock,
  Server, Wrench, Home, Database, FileText, Smartphone
};

const GROUP_ORDER = [
  'Intelligence & Planning',
  'Access & Penetration',
  'Privilege & Identity',
  'Operations & Assets',
  'Data & Utilities',
];

export default function SideNav({ categories, activeCategory, onCategorySelect, onHomeClick, iconMap, isOpen, onClose, view }) {
  function getIcon(catId) {
    const iconName = iconMap?.[catId] || 'Wrench';
    const IconComp = ICON_COMPONENTS[iconName] || Wrench;
    return <IconComp size={16} className="sidebar__item-icon" />;
  }

  // Group categories by their group field
  const grouped = {};
  categories.forEach(cat => {
    const g = cat.group || 'Other';
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(cat);
  });

  return (
    <nav className={`sidebar ${isOpen ? 'sidebar--open' : ''}`} id="jabber-sidenav">
      {/* Mobile close button */}
      <button className="sidebar__close-btn" onClick={onClose} aria-label="Close navigation">
        <X size={20} />
      </button>

      <div className="sidebar__section">
        <div
          className={`sidebar__item ${!activeCategory && view === 'dashboard' ? 'sidebar__item--active' : ''}`}
          onClick={onHomeClick}
          id="nav-home"
        >
          <Home size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Dashboard</span>
        </div>
        <div
          className={`sidebar__item ${view === 'search' ? 'sidebar__item--active' : ''}`}
          onClick={() => {
            if (typeof onCategorySelect === 'function') onCategorySelect('SEARCH');
            // We need to pass a way to set view to search. Let's assume the parent can handle 'SEARCH' category as view='search'
            // Wait, App.jsx handleCategorySelect doesn't handle 'SEARCH'. I'll need to update App.jsx too, or pass a new prop.
          }}
          id="nav-search"
        >
          <Search size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Search</span>
        </div>
        <div
          className={`sidebar__item ${view === 'reports' ? 'sidebar__item--active' : ''}`}
          onClick={() => onCategorySelect('ARTIFACTS')}
          id="nav-artifacts"
        >
          <FileText size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Artifacts</span>
        </div>
        <div
          className={`sidebar__item ${view === 'settings' ? 'sidebar__item--active' : ''}`}
          onClick={() => {
            if (typeof onCategorySelect === 'function') onCategorySelect('SETTINGS');
          }}
          id="nav-settings"
        >
          <Settings size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Settings</span>
        </div>
      </div>

      {GROUP_ORDER.map(groupName => {
        const cats = grouped[groupName];
        if (!cats || cats.length === 0) return null;
        return (
          <div className="sidebar__section" key={groupName}>
            <div className="sidebar__section-title">{groupName}</div>
            {cats
              .sort((a, b) => a.order - b.order)
              .map(cat => (
                <div
                  key={cat.id}
                  className={`sidebar__item ${activeCategory === cat.id ? 'sidebar__item--active' : ''}`}
                  onClick={() => onCategorySelect(cat.id)}
                  id={`nav-${cat.slug}`}
                >
                  {getIcon(cat.id)}
                  <span className="sidebar__item-label">{cat.name}</span>
                  {cat.moduleCount > 0 && (
                    <span className="sidebar__item-badge">{cat.moduleCount}</span>
                  )}
                </div>
              ))}
          </div>
        );
      })}

      <div className="sidebar__section">
        <div className="sidebar__section-title">System Extras</div>
        <div
          className={`sidebar__item ${view === 'search' ? 'sidebar__item--active' : ''}`}
          onClick={() => {
            if (typeof onCategorySelect === 'function') onCategorySelect('SEARCH');
          }}
          id="nav-search-copy"
        >
          <Search size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Search</span>
        </div>
        <div
          className={`sidebar__item ${view === 'reports' ? 'sidebar__item--active' : ''}`}
          onClick={() => onCategorySelect('ARTIFACTS')}
          id="nav-artifacts-copy"
        >
          <FileText size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Artifacts</span>
        </div>
        <div
          className={`sidebar__item ${view === 'settings' ? 'sidebar__item--active' : ''}`}
          onClick={() => {
            if (typeof onCategorySelect === 'function') onCategorySelect('SETTINGS');
          }}
          id="nav-settings-copy"
        >
          <Settings size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Settings</span>
        </div>
      </div>

      <div className="sidebar__bottom">
        <div style={{ fontSize: '10px', color: 'var(--steel)', textAlign: 'center', opacity: 0.6 }}>
          JABBER V 5.5.0 · Funbinet
        </div>
      </div>
    </nav>
  );
}
