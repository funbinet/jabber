import React, { useState, useEffect } from 'react';
import Header from './components/Header.jsx';
import SideNav from './components/SideNav.jsx';
import Workspace from './components/Workspace.jsx';
import StatusBar from './components/StatusBar.jsx';
import { SessionProvider } from './components/SessionContext.jsx';
import { TerminalProvider } from './context/TerminalProvider.jsx';
import InteractiveTerminal from './components/InteractiveTerminal.jsx';
import { fetchCategories, fetchAllModules, fetchSystemInfo } from './api.js';

const CATEGORY_ICON_MAP = {
  RECONNAISSANCE: 'Search',
  VULNERABILITY_SCANNING: 'Shield',
  SOCIAL_ENGINEERING: 'Users',
  FORENSICS: 'FileSearch',
  EXPLOITATION: 'Zap',
  WEB_ASSESSMENT: 'Globe',
  WIRELESS_HACKING: 'Wifi',
  NETWORK_ATTACK_DEFENSE: 'Network',
  PRIVILEGE_ESCALATION: 'ArrowUp',
  LATERAL_MOVEMENT: 'GitBranch',
  CREDENTIAL_ACCESS: 'Unlock',
  PASSWORD_CRACKING: 'Key',
  PAYLOAD_CREATION: 'Package',
  CRYPTO_OPERATIONS: 'Lock',
  C2_PERSISTENCE: 'Radio',
  AD_MANAGEMENT: 'Server',
  SAVED_CREDENTIALS: 'Database',
  REPORTS: 'FileText',
  UTILITIES: 'Wrench',
};

export default function App() {
  const [categories, setCategories] = useState([]);
  const [modules, setModules] = useState([]);
  const [systemInfo, setSystemInfo] = useState(null);
  const [activeCategory, setActiveCategory] = useState(null);
  const [activeModule, setActiveModule] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [view, setView] = useState('dashboard');
  const [profilerReportIds, setProfilerReportIds] = useState([]);

  useEffect(() => { loadData(); }, []);

  async function loadData() {
    try {
      const [catData, modData, sysInfo] = await Promise.all([
        fetchCategories(),
        fetchAllModules(),
        fetchSystemInfo(),
      ]);
      setCategories(catData);
      setModules(modData);
      setSystemInfo(sysInfo);
      setIsConnected(true);
    } catch (err) {
      console.error('Backend connection failed, will retry...', err);
      setIsConnected(false);
      setTimeout(loadData, 3000);
    }
  }

  function getModulesForCategory(categoryId) {
    return modules.filter(m => m.category === categoryId);
  }

  function handleCategorySelect(catId) {
    if (catId === 'REPORTS') {
      setView('reports');
      setActiveCategory(catId);
      setActiveModule(null);
      return;
    }
    setActiveCategory(catId);
    setActiveModule(null);
    setView('category');
  }

  function handleModuleSelect(module) {
    setActiveModule(module);
    setView('executor');
  }

  function handleBackToCategory() {
    setActiveModule(null);
    setView('category');
  }

  function handleHomeClick() {
    setActiveCategory(null);
    setActiveModule(null);
    setView('dashboard');
  }

  function handleViewChange(newView, data) {
    setView(newView);
    if (newView === 'profiler' && data) {
      setProfilerReportIds(data);
    }
  }

  return (
    <SessionProvider>
      <TerminalProvider>
        <div className="app-container">
          <Header isConnected={isConnected} systemInfo={systemInfo} />
          <div className="app-body">
            <SideNav
              categories={categories}
              activeCategory={activeCategory}
              onCategorySelect={handleCategorySelect}
              onHomeClick={handleHomeClick}
              iconMap={CATEGORY_ICON_MAP}
            />
            <Workspace
              view={view}
              activeCategory={activeCategory}
              activeModule={activeModule}
              categories={categories}
              modules={activeCategory ? getModulesForCategory(activeCategory) : modules}
              allModules={modules}
              systemInfo={systemInfo}
              isConnected={isConnected}
              onModuleSelect={handleModuleSelect}
              onBack={handleBackToCategory}
              onCategorySelect={handleCategorySelect}
              onViewChange={handleViewChange}
              profilerReportIds={profilerReportIds}
            />
          </div>
          <StatusBar
            isConnected={isConnected}
            moduleCount={modules.length}
            categoryCount={categories.length}
          />
          <InteractiveTerminal />
        </div>
      </TerminalProvider>
    </SessionProvider>
  );
}
