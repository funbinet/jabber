import React from 'react';
import {
  Search, Package, Lock, Shield, Zap, ArrowUp, Key, Globe,
  Wifi, Network, Users, FileSearch, Radio, GitBranch, Unlock,
  Server, Wrench, Home, Database, FileText
} from 'lucide-react';

const ICON_COMPONENTS = {
  Search, Package, Lock, Shield, Zap, ArrowUp, Key, Globe,
  Wifi, Network, Users, FileSearch, Radio, GitBranch, Unlock,
  Server, Wrench, Home, Database, FileText
};

const GROUP_ORDER = [
  'Intelligence & Planning',
  'Access & Penetration',
  'Privilege & Identity',
  'Operations & Assets',
  'Data & Utilities',
];

export default function SideNav({ categories, activeCategory, onCategorySelect, onHomeClick, iconMap }) {
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
    <nav className="sidebar" id="jrts-sidenav">
      <div className="sidebar__section">
        <div
          className={`sidebar__item ${!activeCategory ? 'sidebar__item--active' : ''}`}
          onClick={onHomeClick}
          id="nav-home"
        >
          <Home size={16} className="sidebar__item-icon" />
          <span className="sidebar__item-label">Dashboard</span>
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
    </nav>
  );
}
