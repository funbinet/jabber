import React from 'react';
import DashboardHome from './DashboardHome.jsx';
import ModuleGrid from './ModuleGrid.jsx';
import ModuleExecutor from './ModuleExecutor.jsx';
import DeviceEnumeratorExecutor from './DeviceEnumeratorExecutor.jsx';
import ReportManager from './ReportManager.jsx';
import TargetProfiler from './TargetProfiler.jsx';

export default function Workspace({
  view, activeCategory, activeModule, categories,
  modules, allModules, systemInfo, isConnected, onModuleSelect, onBack,
  onCategorySelect, onViewChange, profilerReportIds
}) {
  if (view === 'executor' && activeModule) {
    if (activeModule.category === 'PHONE_ENUMERATION') {
      return (
        <main className="workspace" id="jrts-workspace">
          <DeviceEnumeratorExecutor module={activeModule} isConnected={isConnected} onBack={onBack} />
        </main>
      );
    }
    return (
      <main className="workspace" id="jrts-workspace">
        <ModuleExecutor module={activeModule} isConnected={isConnected} onBack={onBack} />
      </main>
    );
  }

  if (view === 'reports') {
    return (
      <main className="workspace" id="jrts-workspace">
        <ReportManager
          isConnected={isConnected}
          onLaunchProfiler={(reportIds) => onViewChange('profiler', reportIds)}
        />
      </main>
    );
  }

  if (view === 'profiler') {
    return (
      <main className="workspace" id="jrts-workspace">
        <TargetProfiler
          isConnected={isConnected}
          initialReportIds={profilerReportIds}
          onBack={() => onViewChange('reports')}
        />
      </main>
    );
  }

  if (view === 'category' && activeCategory) {
    const catInfo = categories.find(c => c.id === activeCategory);
    return (
      <main className="workspace" id="jrts-workspace">
        <div className="workspace__header animate-fade-in">
          <h1 className="workspace__title">{catInfo?.name || activeCategory}</h1>
          <p className="workspace__description">
            {modules.length} module{modules.length !== 1 ? 's' : ''} available
            {catInfo?.group ? ` · ${catInfo.group}` : ''}
          </p>
        </div>
        {modules.length > 0 ? (
          <ModuleGrid modules={modules} onModuleSelect={onModuleSelect} />
        ) : (
          <div className="empty-state animate-fade-in">
            <div className="empty-state__icon">⚡</div>
            <div className="empty-state__text">
              No modules deployed in this category yet. Modules can be added via the @JRTSModule plugin system.
            </div>
          </div>
        )}
      </main>
    );
  }

  return (
    <main className="workspace" id="jrts-workspace">
      <DashboardHome
        categories={categories}
        allModules={allModules}
        systemInfo={systemInfo}
        isConnected={isConnected}
        onCategorySelect={onCategorySelect}
      />
    </main>
  );
}
