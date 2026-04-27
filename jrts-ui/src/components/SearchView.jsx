import React, { useState, useMemo } from 'react';
import { Search, ArrowRight, Package, Zap, Shield } from 'lucide-react';

const RISK_ICONS = { CRITICAL: Zap, HIGH: Shield, MEDIUM: Package };

export default function SearchView({ allModules, categories, onModuleSelect, onCategorySelect }) {
  const [query, setQuery] = useState('');

  const results = useMemo(() => {
    if (!query.trim()) return { modules: [], categories: [] };
    const q = query.toLowerCase();
    return {
      modules: (allModules || []).filter(m =>
        m.name?.toLowerCase().includes(q) ||
        m.description?.toLowerCase().includes(q) ||
        m.category?.toLowerCase().includes(q)
      ).slice(0, 20),
      categories: (categories || []).filter(c =>
        c.name?.toLowerCase().includes(q) ||
        c.id?.toLowerCase().includes(q) ||
        c.group?.toLowerCase().includes(q)
      ).slice(0, 10),
    };
  }, [query, allModules, categories]);

  const total = results.modules.length + results.categories.length;

  return (
    <div className="search-view animate-fade-in">
      <div className="workspace__header">
        <h1 className="workspace__title">Search</h1>
        <p className="workspace__description">Find modules, categories, and tools across the platform</p>
      </div>

      <div className="search-view__input-wrap">
        <Search size={18} style={{ color: 'var(--steel)', flexShrink: 0, marginLeft: '0.5rem' }} />
        <input
          className="search-view__input"
          type="text"
          placeholder="Search modules, categories..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          autoFocus
        />
      </div>

      {query.trim() && (
        <div style={{ fontSize: '12px', color: 'var(--steel)', marginBottom: '1rem' }}>
          {total} result{total !== 1 ? 's' : ''} for "{query}"
        </div>
      )}

      <div className="search-view__results">
        {results.categories.length > 0 && (
          <div style={{ marginBottom: '1.5rem' }}>
            <div className="dashboard-home__group-title">Categories</div>
            {results.categories.map(cat => (
              <div
                key={cat.id}
                className="module-card"
                onClick={() => onCategorySelect(cat.id)}
                style={{ marginBottom: '0.5rem' }}
              >
                <div className="module-card__header">
                  <div className="module-card__name">{cat.name}</div>
                  <span className="sidebar__item-badge">{cat.moduleCount} modules</span>
                </div>
                <div className="module-card__meta">
                  <span style={{ color: 'var(--ice-blue)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>
                    {cat.group}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {results.modules.length > 0 && (
          <div>
            <div className="dashboard-home__group-title">Modules</div>
            <div className="module-grid">
              {results.modules.map(mod => (
                <div
                  key={mod.id}
                  className="module-card"
                  onClick={() => onModuleSelect(mod)}
                >
                  <div className="module-card__header">
                    <div className="module-card__name">{mod.name}</div>
                    <span className={`module-card__risk module-card__risk--${mod.riskLevel}`}>
                      {mod.riskLevel}
                    </span>
                  </div>
                  <div className="module-card__description">{mod.description}</div>
                  <div className="module-card__meta">
                    <span>{mod.category}</span>
                    {mod.version && <span>v{mod.version}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {query.trim() && total === 0 && (
          <div className="empty-state">
            <Search size={32} style={{ color: 'var(--steel)' }} />
            <div className="empty-state__text">No results found for "{query}"</div>
          </div>
        )}

        {!query.trim() && (
          <div className="empty-state">
            <Search size={32} style={{ color: 'var(--steel)' }} />
            <div className="empty-state__text">Start typing to search across modules and categories</div>
          </div>
        )}
      </div>
    </div>
  );
}
