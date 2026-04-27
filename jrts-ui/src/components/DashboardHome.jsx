import React from 'react';
import { Shield, Zap, Layers, Activity, Target, BarChart3 } from 'lucide-react';

const GROUP_ORDER = [
  'Intelligence & Planning',
  'Access & Penetration',
  'Privilege & Identity',
  'Operations & Assets',
  'Data & Utilities',
];

export default function DashboardHome({ categories, allModules, systemInfo, isConnected, onCategorySelect }) {
  const totalModules = allModules?.length || 0;
  const activeCategories = categories?.filter(c => c.moduleCount > 0).length || 0;
  const criticalModules = allModules?.filter(m => m.riskLevel === 'CRITICAL').length || 0;
  const highModules = allModules?.filter(m => m.riskLevel === 'HIGH').length || 0;
  const medModules = allModules?.filter(m => m.riskLevel === 'MEDIUM').length || 0;

  // Group categories
  const grouped = {};
  categories?.forEach(cat => {
    const g = cat.group || 'Other';
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(cat);
  });

  return (
    <div className="dashboard-home animate-fade-in">
      {/* Hero */}
      <div className="dashboard-home__hero">
        <div className="dashboard-home__hero-content">
          <h1>JABBER</h1>
          <h2>Red Teaming Suite V4.0</h2>
          <p className="dashboard-home__hero-desc">
            {isConnected
              ? `Engine online with ${totalModules} native modules across ${activeCategories} active categories. V4.0 — unified output management, target profiling, and 30 exploitation modules.`
              : 'Connecting to JRTS backend engine...'}
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="dashboard-home__stats">
        <div className="stat-card">
          <Layers size={22} style={{ color: 'var(--crimson)' }} />
          <div className="stat-card__value">{totalModules}</div>
          <div className="stat-card__label">Modules</div>
        </div>
        <div className="stat-card">
          <Shield size={22} style={{ color: 'var(--ice-blue)' }} />
          <div className="stat-card__value" style={{ color: 'var(--ice-blue)' }}>{activeCategories}</div>
          <div className="stat-card__label">Active</div>
        </div>
        <div className="stat-card">
          <Zap size={22} style={{ color: 'var(--risk-critical)' }} />
          <div className="stat-card__value" style={{ color: 'var(--risk-critical)' }}>{criticalModules}</div>
          <div className="stat-card__label">Critical</div>
        </div>
        <div className="stat-card">
          <Activity size={22} style={{ color: 'var(--risk-high)' }} />
          <div className="stat-card__value" style={{ color: 'var(--risk-high)' }}>{highModules}</div>
          <div className="stat-card__label">High</div>
        </div>
        <div className="stat-card">
          <Target size={22} style={{ color: 'var(--risk-medium)' }} />
          <div className="stat-card__value" style={{ color: 'var(--risk-medium)' }}>{medModules}</div>
          <div className="stat-card__label">Medium</div>
        </div>
        <div className="stat-card">
          <BarChart3 size={22} style={{ color: 'var(--emerald)' }} />
          <div className="stat-card__value" style={{ color: 'var(--emerald)' }}>{categories?.length || 0}</div>
          <div className="stat-card__label">Categories</div>
        </div>
      </div>

      {/* Category Groups */}
      {GROUP_ORDER.map(groupName => {
        const cats = grouped[groupName];
        if (!cats || cats.length === 0) return null;
        return (
          <div key={groupName}>
            <h3 className="dashboard-home__group-title">{groupName}</h3>
            <div className="module-grid" style={{ marginBottom: '1.5rem' }}>
              {cats.sort((a, b) => a.order - b.order).map(cat => {
                const catModules = allModules?.filter(m => m.category === cat.id) || [];
                const crit = catModules.filter(m => m.riskLevel === 'CRITICAL').length;
                const high = catModules.filter(m => m.riskLevel === 'HIGH').length;
                return (
                  <div className="module-card" key={cat.id} onClick={() => onCategorySelect(cat.id)}>
                    <div className="module-card__header">
                      <div className="module-card__name">{cat.name}</div>
                      <span className="sidebar__item-badge" style={{ fontSize: '11px' }}>
                        {cat.moduleCount} modules
                      </span>
                    </div>
                    <div className="module-card__description" style={{ WebkitLineClamp: 2 }}>
                      {catModules.length > 0
                        ? catModules.slice(0, 4).map(m => m.name).join(' · ') + (catModules.length > 4 ? ` +${catModules.length - 4} more` : '')
                        : 'No modules deployed yet'}
                    </div>
                    <div className="module-card__meta">
                      {crit > 0 && <span style={{ color: 'var(--risk-critical)' }}>{crit} critical</span>}
                      {high > 0 && <span style={{ color: 'var(--risk-high)' }}>{high} high</span>}
                      <span style={{ color: 'var(--ice-blue)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>
                        {cat.group}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
