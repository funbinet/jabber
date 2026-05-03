import React, { useState, useEffect, useCallback, useRef } from 'react';
import Header from './components/Header.jsx';
import SideNav from './components/SideNav.jsx';
import Workspace from './components/Workspace.jsx';
import StatusBar from './components/StatusBar.jsx';
import MobileTabBar from './components/MobileTabBar.jsx';
import { SessionProvider } from './components/SessionContext.jsx';
import { TerminalProvider } from './context/TerminalProvider.jsx';
import { ResponsiveProvider, useResponsive } from './context/ResponsiveProvider.jsx';
import { ModalProvider } from './context/ModalContext.jsx';
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
  PHONE_ENUMERATION: 'Smartphone',
};

function AppInner() {
  const [categories, setCategories] = useState([]);
  const [modules, setModules] = useState([]);
  const [systemInfo, setSystemInfo] = useState(null);
  const [activeCategory, setActiveCategory] = useState(null);
  const [activeModule, setActiveModule] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [view, setView] = useState('dashboard');
  const [profilerReportIds, setProfilerReportIds] = useState([]);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  
  // Settings State
  const [theme, setTheme] = useState(() => localStorage.getItem('jabber_theme') || 'dark');
  const [fontScale, setFontScale] = useState(() => localStorage.getItem('jabber_fontScale') || 'default');
  const [animationsEnabled, setAnimationsEnabled] = useState(() => localStorage.getItem('jabber_animations') !== 'false');
  const [terminalAutoScroll, setTerminalAutoScroll] = useState(() => localStorage.getItem('jabber_terminalAutoScroll') !== 'false');
  const [rawOutputDefault, setRawOutputDefault] = useState(() => localStorage.getItem('jabber_rawOutputDefault') === 'true');

  const workspaceRef = useRef(null);
  const { isMobile, isTablet } = useResponsive();

  useEffect(() => { loadData(); }, []);

  // Settings persistence
  useEffect(() => { 
    localStorage.setItem('jabber_theme', theme); 
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);
  useEffect(() => { localStorage.setItem('jabber_fontScale', fontScale); }, [fontScale]);
  useEffect(() => { localStorage.setItem('jabber_animations', animationsEnabled); }, [animationsEnabled]);
  useEffect(() => { localStorage.setItem('jabber_terminalAutoScroll', terminalAutoScroll); }, [terminalAutoScroll]);
  useEffect(() => { localStorage.setItem('jabber_rawOutputDefault', rawOutputDefault); }, [rawOutputDefault]);

  // Fullscreen change listener
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  // Close mobile nav on breakpoint change to desktop
  useEffect(() => {
    if (!isMobile && !isTablet) setMobileNavOpen(false);
  }, [isMobile, isTablet]);

  async function loadData() {
    try {
      const [catData, modData, sysInfo] = await Promise.all([
        fetchCategories(), fetchAllModules(), fetchSystemInfo(),
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
    if (catId === 'ARTIFACTS') {
      setView('reports');
      setActiveCategory(null); // Clear active category for the gallery view
      setActiveModule(null);
      setMobileNavOpen(false);
      return;
    }
    if (catId === 'SEARCH' || catId === 'MODULES_SEARCH') {
      setView('search');
      setActiveCategory(null);
      setActiveModule(null);
      setMobileNavOpen(false);
      return;
    }
    if (catId === 'SETTINGS') {
      setView('settings');
      setActiveCategory(null);
      setActiveModule(null);
      setMobileNavOpen(false);
      return;
    }
    setActiveCategory(catId);
    setActiveModule(null);
    setView('category');
    setMobileNavOpen(false);
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
    setMobileNavOpen(false);
  }

  function handleViewChange(newView, data) {
    setView(newView);
    setMobileNavOpen(false);
    if (newView === 'profiler' && data) {
      setProfilerReportIds(data);
    }
  }

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen?.();
    } else {
      document.exitFullscreen?.();
    }
  }, []);

  const toggleMobileNav = useCallback(() => {
    setMobileNavOpen(prev => !prev);
  }, []);

  const handleWorkspaceScroll = useCallback((e) => {
    setIsScrolled(e.target.scrollTop > 20);
  }, []);

  // Mobile tab bar navigation
  function handleTabSelect(tabView) {
    if (tabView === 'dashboard') { handleHomeClick(); return; }
    if (tabView === 'modules') {
      handleCategorySelect('MODULES_SEARCH');
      return;
    }
    if (tabView === 'reports' || tabView === 'artifacts') {
      handleCategorySelect('ARTIFACTS');
      return;
    }
    if (tabView === 'search') { setView('search'); return; }
    if (tabView === 'settings') { setView('settings'); return; }
  }

  const containerClasses = [
    'app-container',
    isFullscreen ? 'app-container--fullscreen' : '',
    !animationsEnabled ? 'no-animations' : ''
  ].filter(Boolean).join(' ');

  return (
    <div className={containerClasses} data-font-scale={fontScale}>
      <Header
        isConnected={isConnected}
        systemInfo={systemInfo}
        isScrolled={isScrolled}
        isFullscreen={isFullscreen}
        onToggleFullscreen={toggleFullscreen}
        onToggleMobileNav={toggleMobileNav}
        mobileNavOpen={mobileNavOpen}
      />
      {/* Sidebar overlay for mobile */}
      <div
        className={`sidebar-overlay ${mobileNavOpen ? 'sidebar-overlay--visible' : ''}`}
        onClick={() => setMobileNavOpen(false)}
      />
      <div className="app-body">
        <SideNav
          categories={categories}
          activeCategory={activeCategory}
          onCategorySelect={handleCategorySelect}
          onHomeClick={handleHomeClick}
          iconMap={CATEGORY_ICON_MAP}
          isOpen={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          view={view}
        />
        <Workspace
          ref={workspaceRef}
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
          onScroll={handleWorkspaceScroll}
          settings={{ theme, fontScale, animationsEnabled, terminalAutoScroll, rawOutputDefault }}
          onSettingsChange={{ setTheme, setFontScale, setAnimationsEnabled, setTerminalAutoScroll, setRawOutputDefault }}
        />
      </div>
      <StatusBar
        isConnected={isConnected}
        moduleCount={modules.length}
        categoryCount={categories.length}
      />
      {isMobile && (
        <MobileTabBar
          activeView={view}
          onSelect={handleTabSelect}
        />
      )}
      <InteractiveTerminal />
    </div>
  );
}

export default function App() {
  return (
    <ResponsiveProvider>
      <ModalProvider>
        <SessionProvider>
          <TerminalProvider>
            <AppInner />
          </TerminalProvider>
        </SessionProvider>
      </ModalProvider>
    </ResponsiveProvider>
  );
}
