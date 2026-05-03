import React, { forwardRef } from 'react';
import DashboardHome from './DashboardHome.jsx';
import ModuleGrid from './ModuleGrid.jsx';
import ModuleExecutor from './ModuleExecutor.jsx';
import DeviceEnumeratorExecutor from './DeviceEnumeratorExecutor.jsx';
import ReportManager from './ReportManager.jsx';
import TargetProfiler from './TargetProfiler.jsx';
import SearchView from './SearchView.jsx';
import SettingsView from './SettingsView.jsx';

const Workspace = forwardRef(function Workspace({
  view, activeCategory, activeModule, categories,
  modules, allModules, systemInfo, isConnected, onModuleSelect, onBack,
  onCategorySelect, onViewChange, profilerReportIds, onScroll,
  settings, onSettingsChange
}, ref) {

  function renderContent() {
    if (view === 'executor' && activeModule) {
      if (activeModule.category === 'PHONE_ENUMERATION') {
        return <DeviceEnumeratorExecutor 
          module={activeModule} 
          isConnected={isConnected} 
          onBack={onBack} 
          onCategorySelect={onCategorySelect} 
        />;
      }
      return <ModuleExecutor 
        module={activeModule} 
        isConnected={isConnected} 
        onBack={onBack} 
        onCategorySelect={onCategorySelect} 
      />;
    }

    if (view === 'reports') {
      return (
        <ReportManager
          isConnected={isConnected}
          onLaunchProfiler={(reportIds) => onViewChange('profiler', reportIds)}
        />
      );
    }

    if (view === 'profiler') {
      return (
        <TargetProfiler
          isConnected={isConnected}
          initialReportIds={profilerReportIds}
          onBack={() => onViewChange('reports')}
        />
      );
    }

    if (view === 'search') {
      return (
        <SearchView
          allModules={allModules}
          categories={categories}
          onModuleSelect={onModuleSelect}
          onCategorySelect={onCategorySelect}
        />
      );
    }

    if (view === 'settings') {
      return (
        <SettingsView
          systemInfo={systemInfo}
          isConnected={isConnected}
          settings={settings}
          onSettingsChange={onSettingsChange}
        />
      );
    }

    if (view === 'category' && activeCategory) {
      const catInfo = categories.find(c => c.id === activeCategory);
      return (
        <>
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
                No modules deployed in this category yet. Modules can be added via the @JABBERModule plugin system.
              </div>
            </div>
          )}
        </>
      );
    }

    return (
      <DashboardHome
        categories={categories}
        allModules={allModules}
        systemInfo={systemInfo}
        isConnected={isConnected}
        onCategorySelect={onCategorySelect}
      />
    );
  }

  return (
    <main className="workspace" id="jabber-workspace" ref={ref} onScroll={onScroll}>
      {renderContent()}
    </main>
  );
});

export default Workspace;
