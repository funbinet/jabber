import React from 'react';

export default function ModuleGrid({ modules, onModuleSelect }) {
  return (
    <div className="module-grid animate-fade-in">
      {modules.map((mod, idx) => (
        <div
          className="module-card"
          key={mod.id}
          onClick={() => onModuleSelect(mod)}
          id={`module-card-${mod.id}`}
          style={{ animationDelay: `${idx * 50}ms` }}
        >
          <div className="module-card__header">
            <div className="module-card__name">{mod.name}</div>
            <span className={`module-card__risk module-card__risk--${mod.riskLevel}`}>
              {mod.riskLevel}
            </span>
          </div>
          <div className="module-card__description">
            {mod.description}
          </div>
          <div className="module-card__meta">
            <span>v{mod.version}</span>
            {mod.sourceRef && (
              <span className="module-card__source">{mod.sourceRef}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
