import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ArrowLeft, Play, Download, AlertTriangle, Save, Eye, Code, FileText, Type, CheckCircle, Square, RotateCcw, ToggleLeft, ToggleRight, Archive, ShieldAlert, Lock } from 'lucide-react';
import { executeModule, fetchTaskLogs, fetchTaskProgress, fetchTaskResult, generateReport, fetchModuleSchema, saveReport, cancelTask, fetchModuleTools, downloadModuleTool, fetchModuleToolDownloadStatus, fetchModuleToolsForMode } from '../api.js';
import { useSession } from './SessionContext.jsx';

export default function ModuleExecutor({ module, isConnected, onBack, onCategorySelect }) {
  const { saveSession, restoreSession, clearSession } = useSession();

  const [formData, setFormData] = useState({});
  const [taskId, setTaskId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('IDLE');
  const [result, setResult] = useState(null);
  const [reportContent, setReportContent] = useState('');
  const [reportFormat, setReportFormat] = useState('json');
  const [schema, setSchema] = useState(module.inputSchema || []);
  const [schemaError, setSchemaError] = useState(false);
  const [toolStatuses, setToolStatuses] = useState([]);
  const [toolLoading, setToolLoading] = useState(false);
  const [toolError, setToolError] = useState(null);
  const [toolDownloads, setToolDownloads] = useState({});
  const [outputView, setOutputView] = useState('json'); // json, html, markdown, raw
  const [saveStatus, setSaveStatus] = useState(null); // null | 'saving' | 'saved' | 'error'
  const [savedInfo, setSavedInfo] = useState(null);
  const [sessionRestored, setSessionRestored] = useState(false);
  // Dynamic Tool-Selection Layer
  const [modeTools, setModeTools] = useState([]);        // tools available for the active mode
  const [selectedTools, setSelectedTools] = useState([]); // tool IDs the user has toggled on
  const [modeToolsLoading, setModeToolsLoading] = useState(false);
  // Sudo Password State
  const [showSudoModal, setShowSudoModal] = useState(false);
  const [sudoPassword, setSudoPassword] = useState(() => localStorage.getItem('jabber_sudo_pw') || '');
  const [sudoPendingExecute, setSudoPendingExecute] = useState(false);
  const terminalRef = useRef(null);
  const pollRef = useRef(null);
  const iframeRef = useRef(null);
  const toolPollRef = useRef({});

  const modeField = schema.find(field => field.name === 'mode' && Array.isArray(field.options) && field.options.length > 0);
  const activeMode = formData.mode || modeField?.defaultValue || modeField?.options?.[0] || '';

  // --- Session Restore on Mount ---
  useEffect(() => {
    const saved = restoreSession(module.id);
    if (saved) {
      if (saved.formData) setFormData(saved.formData);
      if (saved.taskId) setTaskId(saved.taskId);
      if (saved.logs) setLogs(saved.logs);
      if (saved.progress !== undefined) setProgress(saved.progress);
      if (saved.status) setStatus(saved.status);
      if (saved.result) setResult(saved.result);
      if (saved.reportContent) setReportContent(saved.reportContent);
      if (saved.reportFormat) setReportFormat(saved.reportFormat);
      if (saved.outputView) setOutputView(saved.outputView);
      if (saved.savedInfo) setSavedInfo(saved.savedInfo);
      if (saved.saveStatus) setSaveStatus(saved.saveStatus);
      setSessionRestored(true);

      // If task was running, resume polling
      if (saved.status === 'RUNNING' && saved.taskId && isConnected) {
        resumePolling(saved.taskId);
      }

      // Auto-hide restored indicator after 3s
      setTimeout(() => setSessionRestored(false), 3000);
    }
  }, [module.id]);

  // --- Session Save on State Change ---
  const persistState = useCallback(() => {
    saveSession(module.id, {
      formData, taskId, logs, progress, status, result,
      reportContent, reportFormat, outputView, savedInfo, saveStatus,
    });
  }, [module.id, formData, taskId, logs, progress, status, result, reportContent, reportFormat, outputView, savedInfo, saveStatus, saveSession]);

  useEffect(() => {
    // Debounce session saves
    const timer = setTimeout(persistState, 300);
    return () => clearTimeout(timer);
  }, [persistState]);

  // --- Cleanup on unmount ---
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      Object.values(toolPollRef.current || {}).forEach(timer => clearInterval(timer));
    };
  }, []);

  // --- Schema Loading ---
  useEffect(() => {
    if (isConnected) {
      fetchModuleSchema(module.id)
        .then(data => {
          if (data && Array.isArray(data) && data.length > 0) {
            setSchema(data);
            setSchemaError(false);
          } else if (!module.inputSchema || module.inputSchema.length === 0) {
            setSchemaError(true);
          }
        })
        .catch(() => {
          if (!module.inputSchema || module.inputSchema.length === 0) setSchemaError(true);
        });
    } else if (!module.inputSchema || module.inputSchema.length === 0) {
      setSchemaError(true);
    }
  }, [module.id, isConnected]);

  const loadToolStatuses = useCallback(async () => {
    if (!isConnected) {
      setToolStatuses([]);
      return;
    }
    setToolLoading(true);
    setToolError(null);
    try {
      const data = await fetchModuleTools(module.id);
      if (Array.isArray(data)) {
        setToolStatuses(data);
      } else {
        setToolStatuses([]);
      }
    } catch (e) {
      setToolError(e.message || 'Tool status unavailable');
      setToolStatuses([]);
    } finally {
      setToolLoading(false);
    }
  }, [module.id, isConnected]);

  useEffect(() => {
    setToolDownloads({});
    Object.values(toolPollRef.current || {}).forEach(timer => clearInterval(timer));
    toolPollRef.current = {};
    loadToolStatuses();
  }, [loadToolStatuses]);

  // --- Load mode-specific tools for Dynamic Tool-Selection Layer ---
  useEffect(() => {
    if (!isConnected || !activeMode) return;
    setModeToolsLoading(true);
    fetchModuleToolsForMode(module.id, activeMode)
      .then(data => {
        const tools = Array.isArray(data) ? data : [];
        setModeTools(tools);
        // Default: all tools selected
        setSelectedTools(tools.map(t => t.id));
      })
      .catch(() => {
        // Fallback: use toolStatuses if mode-specific endpoint not yet differentiated
        setModeTools(toolStatuses);
        setSelectedTools(toolStatuses.map(t => t.id));
      })
      .finally(() => setModeToolsLoading(false));
  }, [module.id, activeMode, isConnected]); // eslint-disable-line react-hooks/exhaustive-deps

  function handleToolToggle(toolId) {
    setSelectedTools(prev =>
      prev.includes(toolId) ? prev.filter(id => id !== toolId) : [...prev, toolId]
    );
  }

  function handleSelectAllTools() {
    setSelectedTools(modeTools.map(t => t.id));
  }

  function handleClearAllTools() {
    setSelectedTools([]);
  }

  useEffect(() => {
    if (!schema || schema.length === 0) return;

    setFormData(prev => {
      const next = { ...prev };
      const modeSchema = schema.find(field => field.name === 'mode' && Array.isArray(field.options) && field.options.length > 0);

      if (modeSchema && !next.mode) {
        next.mode = modeSchema.defaultValue || modeSchema.options[0] || '';
      }

      schema.forEach(field => {
        const current = next[field.name];
        const unset = current === undefined || current === null || current === '';
        if (unset && field.defaultValue !== undefined && field.defaultValue !== null && field.defaultValue !== '') {
          next[field.name] = field.defaultValue;
        }
      });

      return next;
    });
  }, [schema]);

  function handleInputChange(fieldName, value) {
    setFormData(prev => ({ ...prev, [fieldName]: value }));
  }

  function formatSegmentLabel(value) {
    return String(value || '').replace(/_/g, ' ');
  }

  function isFieldVisibleInMode(field, activeMode) {
    if (!field) return false;
    if (field.name === 'mode') return true;
    if (!Array.isArray(field.modes) || field.modes.length === 0) return true;
    if (!activeMode) return false;
    return field.modes.includes(activeMode);
  }

  function handleModeChange(nextMode) {
    setFormData(prev => {
      const next = { ...prev, mode: nextMode };

      schema.forEach(field => {
        if (field.name === 'mode') return;
        const fieldModes = Array.isArray(field.modes) ? field.modes : [];
        const modeScoped = fieldModes.length > 0;

        if (modeScoped && !fieldModes.includes(nextMode)) {
          delete next[field.name];
          return;
        }

        const current = next[field.name];
        const unset = current === undefined || current === null || current === '';
        if (unset && field.defaultValue !== undefined && field.defaultValue !== null && field.defaultValue !== '') {
          next[field.name] = field.defaultValue;
        }
      });

      return next;
    });
  }

  function resumePolling(tid) {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const [logData, progressData] = await Promise.all([
          fetchTaskLogs(tid),
          fetchTaskProgress(tid),
        ]);
        setLogs(logData);
        setProgress(progressData.progress);
        if (progressData.status === 'COMPLETED' || progressData.status === 'FAILED' || progressData.status === 'CANCELLED') {
          clearInterval(pollRef.current);
          setStatus(progressData.status);
          const resultData = await fetchTaskResult(tid);
          setResult(resultData);
          try {
            const report = await generateReport(tid, 'json');
            setReportContent(report.content);
          } catch (e) {}
        }
      } catch (err) { console.error('Poll error:', err); }
    }, 500);
  }

  // Check if any selected tools require sudo
  const sudoToolsSelected = modeTools
    .filter(t => selectedTools.includes(t.id) && t.requiresSudo)
    .map(t => t.id);
  const needsSudo = sudoToolsSelected.length > 0;

  async function handleExecute() {
    if (!isConnected) return;

    // If sudo is needed and no password cached, show modal
    if (needsSudo && !sudoPassword) {
      setShowSudoModal(true);
      setSudoPendingExecute(true);
      return;
    }

    try {
      setStatus('RUNNING');
      setLogs(['[*] Sending execution request to JABBER engine...']);
      setProgress(0);
      setSaveStatus(null);
      setSavedInfo(null);
      setResult(null);
      setReportContent('');

      const pw = needsSudo ? sudoPassword : '';
      const response = await executeModule(module.id, formData, selectedTools, pw);
      setTaskId(response.taskId);
      setLogs(prev => [...prev, `[+] Task created: ${response.taskId}`]);

      resumePolling(response.taskId);
    } catch (err) {
      setStatus('FAILED');
      setLogs(prev => [...prev, `[!] ERROR: ${err.message}`]);
    }
  }

  function handleSudoSubmit(pw) {
    setSudoPassword(pw);
    localStorage.setItem('jabber_sudo_pw', pw);
    setShowSudoModal(false);
    if (sudoPendingExecute) {
      setSudoPendingExecute(false);
      // Trigger execute after a tick so state is updated
      setTimeout(() => handleExecuteWithSudo(pw), 50);
    }
  }

  async function handleExecuteWithSudo(pw) {
    if (!isConnected) return;
    try {
      setStatus('RUNNING');
      setLogs(['[*] Sending execution request to JABBER engine...']);
      setProgress(0);
      setSaveStatus(null);
      setSavedInfo(null);
      setResult(null);
      setReportContent('');

      const response = await executeModule(module.id, formData, selectedTools, pw);
      setTaskId(response.taskId);
      setLogs(prev => [...prev, `[+] Task created: ${response.taskId}`]);

      resumePolling(response.taskId);
    } catch (err) {
      setStatus('FAILED');
      setLogs(prev => [...prev, `[!] ERROR: ${err.message}`]);
    }
  }

  async function handleCancel() {
    if (!taskId) return;
    try {
      setLogs(prev => [...prev, '[!] Requesting task cancellation...']);
      const response = await cancelTask(taskId);
      if (response.cancelled) {
        if (pollRef.current) clearInterval(pollRef.current);
        setStatus('CANCELLED');
        setProgress(0);
        setLogs(prev => [...prev, '[!] Task cancelled successfully.']);
      } else {
        setLogs(prev => [...prev, `[!] Cancel failed: ${response.reason || 'Unknown'}`]);
      }
    } catch (err) {
      setLogs(prev => [...prev, `[!] Cancel error: ${err.message}`]);
    }
  }

  function handleReset() {
    if (pollRef.current) clearInterval(pollRef.current);
    setTaskId(null);
    setLogs([]);
    setProgress(0);
    setStatus('IDLE');
    setResult(null);
    setReportContent('');
    setReportFormat('json');
    setSaveStatus(null);
    setSavedInfo(null);
    setOutputView('json');
    clearSession(module.id);
  }

  function startToolPolling(toolId) {
    if (toolPollRef.current[toolId]) {
      clearInterval(toolPollRef.current[toolId]);
    }
    toolPollRef.current[toolId] = setInterval(async () => {
      try {
        const status = await fetchModuleToolDownloadStatus(module.id, toolId);
        setToolDownloads(prev => ({ ...prev, [toolId]: status }));
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(toolPollRef.current[toolId]);
          delete toolPollRef.current[toolId];
          loadToolStatuses();
        }
      } catch (e) {
        clearInterval(toolPollRef.current[toolId]);
        delete toolPollRef.current[toolId];
      }
    }, 1000);
  }

  async function handleToolDownload(toolId) {
    if (!isConnected) return;
    setToolDownloads(prev => ({
      ...prev,
      [toolId]: { status: 'downloading', progress: 0, message: 'Starting download...' },
    }));
    try {
      const status = await downloadModuleTool(module.id, toolId);
      setToolDownloads(prev => ({ ...prev, [toolId]: status }));
      if (status.status === 'downloading') {
        startToolPolling(toolId);
      } else {
        loadToolStatuses();
      }
    } catch (e) {
      setToolDownloads(prev => ({
        ...prev,
        [toolId]: { status: 'failed', error: e.message || 'Download failed' },
      }));
    }
  }



  async function handleViewChange(format) {
    setOutputView(format);
    if (!taskId && !result) return;
    const tid = taskId || result?.taskId;
    if (!tid) return;
    try {
      const report = await generateReport(tid, format);
      setReportContent(report.content);
      setReportFormat(format);
    } catch (e) {
      setReportContent('Error generating ' + format + ' view: ' + e.message);
    }
  }

  async function handleSave() {
    if (!taskId) return;
    setSaveStatus('saving');
    try {
      const response = await saveReport(taskId, reportFormat);
      if (response.success) {
        setSaveStatus('saved');
        setSavedInfo(response);
      } else {
        setSaveStatus('error');
      }
    } catch (e) {
      setSaveStatus('error');
    }
  }

  function handleDownload() {
    if (!reportContent) return;
    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${module.id}_${reportFormat || 'json'}_${Date.now()}.${reportFormat === 'markdown' ? 'md' : reportFormat}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Dynamically resize iframe to fit content
  function handleIframeLoad() {
    if (iframeRef.current) {
      try {
        const doc = iframeRef.current.contentDocument || iframeRef.current.contentWindow?.document;
        if (doc && doc.body) {
          const height = Math.max(doc.body.scrollHeight, 400);
          iframeRef.current.style.height = Math.min(height + 20, 800) + 'px';
        }
      } catch {}
    }
  }

  // Group schema fields (mode-aware visibility)
  const visibleSchema = schema.filter(field => isFieldVisibleInMode(field, activeMode));
  const groups = {};
  visibleSchema.forEach(field => {
    const g = field.group || 'General';
    if (!groups[g]) groups[g] = [];
    groups[g].push(field);
  });

  const viewTabs = [
    { id: 'json', label: 'JSON', icon: Code },
    { id: 'html', label: 'HTML', icon: Eye },
    { id: 'markdown', label: 'Markdown', icon: FileText },
    { id: 'txt', label: 'Raw', icon: Type },
  ];

  const isFinished = status === 'COMPLETED' || status === 'FAILED' || status === 'CANCELLED';

  return (
    <div className="executor-panel animate-fade-in">
      <div className="executor-panel__header">
        <button className="executor-panel__back" onClick={onBack} id="executor-back-btn">
          <ArrowLeft size={16} /> Back to modules
        </button>
        <div className="executor-panel__title">{module.name}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {sessionRestored && (
            <span className="session-indicator">Session restored</span>
          )}
          <span className={`module-card__risk module-card__risk--${module.riskLevel}`}>
            {module.riskLevel}
          </span>
        </div>
      </div>

      {status === 'RUNNING' && (
        <div className="progress">
          <div className="progress__bar" style={{ width: `${progress}%` }} />
        </div>
      )}

      <div className="executor-panel__body">
        {/* Form panel */}
        <div className="executor-panel__form">
          <p style={{ fontSize: '12px', color: 'var(--steel)', marginBottom: '1rem', lineHeight: '1.6' }}>
            {module.description}
          </p>
          {module.sourceRef && (
            <p style={{ fontSize: '11px', color: 'var(--ice-blue)', marginBottom: '1rem', fontFamily: 'var(--font-mono)' }}>
              Source: {module.sourceRef}
            </p>
          )}

          {toolStatuses.length > 0 && (
            <div className="tool-readiness">
              <div className="tool-readiness__header">
                <div>
                  <div className="tool-readiness__title">Tool Readiness</div>
                  <div className="tool-readiness__subtitle">Verify and install required crawler binaries</div>
                </div>
                <button className="btn btn--secondary tool-readiness__refresh" onClick={loadToolStatuses} disabled={toolLoading}>
                  {toolLoading ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>
              {toolError && (
                <div className="tool-readiness__error">{toolError}</div>
              )}
              <div className="tool-readiness__list">
                {toolStatuses.map(tool => {
                  const download = toolDownloads[tool.id] || {};
                  const downloading = download.status === 'downloading';
                  const progress = download.progress ?? (tool.installed ? 100 : 0);
                  return (
                    <div className="tool-readiness__item" key={tool.id}>
                      <div className="tool-readiness__meta">
                        <div className="tool-readiness__name">{tool.name}</div>
                        <div className="tool-readiness__desc">{tool.description}</div>
                        {tool.version && (
                          <div className="tool-readiness__version">Version: {tool.version}</div>
                        )}
                        {tool.path && (
                          <div className="tool-readiness__path">{tool.path}</div>
                        )}
                      </div>
                      <div className="tool-readiness__actions">
                        <div className={`tool-readiness__status ${tool.installed ? 'ready' : 'missing'}`}>
                          {tool.installed ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
                          {tool.installed ? 'Ready' : 'Missing'}
                        </div>
                        <button
                          className="btn btn--secondary tool-readiness__download"
                          onClick={() => handleToolDownload(tool.id)}
                          disabled={downloading || tool.installed}
                        >
                          {downloading ? <span className="tool-spinner" /> : <Download size={12} />}
                          {tool.installed ? 'Installed' : downloading ? 'Downloading' : 'Download'}
                        </button>
                        {downloading && (
                          <div className="tool-readiness__progress">
                            <div className="tool-readiness__progress-bar" style={{ width: `${Math.min(progress, 100)}%` }} />
                            <span>{Math.min(progress, 100)}%</span>
                          </div>
                        )}
                        {download.status === 'failed' && (
                          <div className="tool-readiness__error">{download.error || 'Download failed'}</div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Dynamic Tool-Selection Layer — shown after Tool Readiness, before inputs */}
          {modeTools.length > 0 && (
            <div className="tool-selection" style={{
              marginBottom: '1.25rem',
              padding: '1rem',
              background: 'rgba(30,40,60,0.6)',
              border: '1px solid rgba(99,179,237,0.2)',
              borderRadius: 'var(--radius-md)',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--foreground)', letterSpacing: '0.05em' }}>
                    Tool Selection
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--steel)' }}>
                    {selectedTools.length === 0
                      ? 'No tools selected — select at least one to run'
                      : `${selectedTools.length} of ${modeTools.length} tool${modeTools.length !== 1 ? 's' : ''} selected`}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <button
                    className="btn btn--secondary"
                    style={{ fontSize: '10px', padding: '3px 8px' }}
                    onClick={handleSelectAllTools}
                    id="tool-select-all"
                  >
                    All
                  </button>
                  <button
                    className="btn btn--secondary"
                    style={{ fontSize: '10px', padding: '3px 8px' }}
                    onClick={handleClearAllTools}
                    id="tool-select-none"
                  >
                    None
                  </button>
                </div>
              </div>
              {modeToolsLoading ? (
                <div style={{ fontSize: '11px', color: 'var(--steel)' }}>Loading tools...</div>
              ) : (
                <div style={{
                  display: 'flex', flexWrap: 'wrap', gap: '0.5rem',
                }}>
                  {modeTools.map(tool => {
                    const active = selectedTools.includes(tool.id);
                    return (
                      <button
                        key={tool.id}
                        id={`tool-toggle-${tool.id}`}
                        onClick={() => handleToolToggle(tool.id)}
                        title={tool.description || tool.name}
                        style={{
                          display: 'flex', alignItems: 'center', gap: '6px',
                          padding: '5px 10px',
                          borderRadius: '6px',
                          border: active
                            ? '1px solid rgba(99,179,237,0.6)'
                            : '1px solid rgba(139,148,158,0.25)',
                          background: active
                            ? 'rgba(99,179,237,0.12)'
                            : 'rgba(139,148,158,0.06)',
                          color: active ? 'var(--ice-blue)' : 'var(--steel)',
                          fontSize: '11px', fontWeight: active ? 600 : 400,
                          cursor: 'pointer', transition: 'all 0.15s ease',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {active
                          ? <ToggleRight size={13} />
                          : <ToggleLeft size={13} />}
                        {tool.id}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}


          {schemaError && schema.length === 0 && (
            <div className="schema-error" style={{
              padding: '1.25rem', background: 'rgba(248, 81, 73, 0.08)',
              border: '1px solid rgba(248, 81, 73, 0.3)', borderRadius: 'var(--radius-md)',
              marginBottom: '1rem', display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
            }}>
              <AlertTriangle size={18} style={{ color: 'var(--risk-critical)', flexShrink: 0, marginTop: 2 }} />
              <div>
                <div style={{ color: 'var(--risk-critical)', fontWeight: 600, fontSize: '13px', marginBottom: '0.25rem' }}>
                  Schema Unavailable
                </div>
                <div style={{ color: 'var(--steel)', fontSize: '12px', lineHeight: 1.6 }}>
                  This module's input schema could not be loaded. Connect to the JABBER backend engine.
                </div>
              </div>
            </div>
          )}

          {Object.entries(groups).map(([groupName, fields]) => (
            <div key={groupName}>
              <div className="form-section">{groupName}</div>
              {fields.map(field => (
                <div className="form-group" key={field.name}>
                  <label className="form-group__label">
                    {field.label}
                    {field.required && <span className="form-group__required">*</span>}
                  </label>
                  {field.type === 'select' && field.name === 'mode' && Array.isArray(field.options) && field.options.length > 0 ? (
                    <div
                      className="mode-segmented"
                      style={{ gridTemplateColumns: `repeat(${field.options.length}, minmax(0, 1fr))` }}
                      role="tablist"
                      aria-label={`${field.label} mode selector`}
                      id={`input-${field.name}`}
                    >
                      {field.options.map(opt => {
                        const isActive = activeMode === opt;
                        return (
                          <button
                            type="button"
                            key={opt}
                            role="tab"
                            aria-selected={isActive}
                            className={`mode-segmented__segment ${isActive ? 'mode-segmented__segment--active' : ''}`}
                            onClick={() => handleModeChange(opt)}
                            id={`input-${field.name}-${opt}`}
                          >
                            {formatSegmentLabel(opt)}
                          </button>
                        );
                      })}
                    </div>
                  ) : field.type === 'select' ? (
                    <select className="form-group__select" value={formData[field.name] || field.defaultValue || ''}
                      onChange={e => handleInputChange(field.name, e.target.value)} id={`input-${field.name}`}>
                      <option value="">-- Select --</option>
                      {(field.options || []).map(opt => <option key={opt} value={opt}>{opt}</option>)}
                    </select>
                  ) : field.type === 'checkbox' ? (
                    <label className="form-group__checkbox">
                      <input type="checkbox" checked={formData[field.name] === 'true'}
                        onChange={e => handleInputChange(field.name, e.target.checked ? 'true' : 'false')}
                        id={`input-${field.name}`} />
                      {field.label}
                    </label>
                  ) : field.type === 'textarea' ? (
                    <textarea className="form-group__textarea" value={formData[field.name] || ''}
                      onChange={e => handleInputChange(field.name, e.target.value)}
                      placeholder={field.placeholder} id={`input-${field.name}`} />
                  ) : field.type === 'number' ? (
                    <input className="form-group__input" type="number" value={formData[field.name] || ''}
                      onChange={e => handleInputChange(field.name, e.target.value)}
                      placeholder={field.placeholder} id={`input-${field.name}`} />
                  ) : (
                    <input className="form-group__input"
                      type={field.type === 'password' ? 'password' : 'text'}
                      value={formData[field.name] || ''}
                      onChange={e => handleInputChange(field.name, e.target.value)}
                      placeholder={field.placeholder} id={`input-${field.name}`} />
                  )}
                  {field.helpText && <div className="form-group__help">{field.helpText}</div>}
                </div>
              ))}
            </div>
          ))}

          <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.5rem', flexDirection: 'column' }}>
            {/* Artifact Gallery link — shown after completion */}
            {isFinished && (
              <button
                id="view-artifacts-link"
                onClick={() => onCategorySelect('ARTIFACTS')}
                style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  padding: '10px 16px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid rgba(0, 255, 65, 0.3)',
                  background: 'rgba(0, 255, 65, 0.08)',
                  color: 'var(--emerald)',
                  fontSize: '12px', fontWeight: 700,
                  textDecoration: 'none', cursor: 'pointer',
                  justifyContent: 'center',
                  transition: 'all 0.2s ease',
                  boxShadow: '0 4px 12px rgba(0, 255, 65, 0.1)',
                  marginBottom: '0.5rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}
                className="view-artifacts-btn"
              >
                <Archive size={14} /> Open Artifacts Gallery
              </button>
            )}
            <div style={{ display: 'flex', gap: '0.5rem' }}>
            {status === 'RUNNING' ? (
              <button className="kill-btn" onClick={handleCancel} id="cancel-btn"
                style={{ flex: 1, justifyContent: 'center' }}>
                <Square size={12} /> Stop Execution
              </button>
            ) : (
              <button className="btn btn--primary" onClick={handleExecute}
                disabled={status === 'RUNNING'} id="execute-btn"
                style={{ flex: 1, justifyContent: 'center' }}>
                <Play size={14} />
                Execute Module
              </button>
            )}
            {isFinished && (
              <button className="btn btn--secondary" onClick={handleReset}
                style={{ padding: '0.5rem 0.75rem' }} title="Reset">
                <RotateCcw size={14} />
              </button>
            )}
            </div>
          </div>
        </div>

        {/* Output panel */}
        <div className="executor-panel__output">
          <div className="terminal" ref={terminalRef} id="execution-terminal">
            {logs.length === 0 ? (
              <div style={{ color: 'var(--steel)', opacity: 0.5 }}>
                {'>'} Awaiting execution...{'\n'}
                {'>'} Configure parameters and click Execute to begin.
              </div>
            ) : (
              logs.map((line, i) => (
                <div key={i} className={`terminal__line ${
                  line.startsWith('[!]') ? 'terminal__line--error' :
                  line.startsWith('[+]') ? 'terminal__line--success' :
                  line.startsWith('[*]') ? 'terminal__line--info' :
                  line.startsWith('[~]') ? 'terminal__line--warn' : ''
                }`}>{line}</div>
              ))
            )}
          </div>

          {/* V 5.5: Output View Tabs + Save/Download */}
          {isFinished && (
            <div className="report-panel" style={{ margin: 0 }}>
              <div className="report-panel__toolbar">
                {/* View Tabs */}
                <div className="view-tabs">
                  {viewTabs.map(tab => (
                    <button key={tab.id}
                      className={`view-tab ${outputView === tab.id ? 'view-tab--active' : ''}`}
                      onClick={() => handleViewChange(tab.id)}>
                      <tab.icon size={12} /> {tab.label}
                    </button>
                  ))}
                </div>
                {/* Save / Download */}
                <div className="report-panel__actions">
                  <button className="btn btn--primary" onClick={handleSave}
                    disabled={saveStatus === 'saving' || !taskId} style={{ fontSize: '11px', padding: '4px 10px' }}>
                    {saveStatus === 'saved' ? <CheckCircle size={12} /> : <Save size={12} />}
                    {saveStatus === 'saving' ? 'Saving...' : saveStatus === 'saved' ? 'Saved' : 'Save'}
                  </button>
                  <button className="btn btn--secondary" onClick={handleDownload}
                    disabled={!reportContent} style={{ fontSize: '11px', padding: '4px 10px' }}>
                    <Download size={12} /> Download
                  </button>
                </div>
              </div>

              {/* Save confirmation */}
              {saveStatus === 'saved' && savedInfo && (
                <div style={{
                  padding: '0.5rem 0.75rem', background: 'rgba(63, 185, 80, 0.1)',
                  borderBottom: '1px solid rgba(63, 185, 80, 0.2)',
                  fontSize: '11px', color: 'var(--emerald)',
                  fontFamily: 'var(--font-mono)',
                }}>
                  ✓ Saved to {savedInfo.filePath?.split('/').pop()} ({savedInfo.fileSize} bytes)
                  {savedInfo.attachments && Object.keys(savedInfo.attachments).length > 0 && (
                    <>
                      <br />
                      ↳ Attachments: {Object.values(savedInfo.attachments).map(path => path.split('/').pop()).join(', ')}
                    </>
                  )}
                </div>
              )}

              {reportContent && (
                <div className="report-panel__content">
                  {outputView === 'html' ? (
                    <iframe
                      ref={iframeRef}
                      srcDoc={reportContent}
                      sandbox="allow-same-origin"
                      className="report-iframe"
                      title="HTML Report Preview"
                      onLoad={handleIframeLoad}
                    />
                  ) : (
                    <pre>{reportContent}</pre>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      {/* ─── Sudo Password Modal ─── */}
      {showSudoModal && (
        <div className="modal-overlay" onClick={() => { setShowSudoModal(false); setSudoPendingExecute(false); }}>
          <div className="modal-container animate-scale-in" onClick={e => e.stopPropagation()} style={{ maxWidth: 420 }}>
            <div className="modal__header">
              <div className="modal__icon-wrap">
                <Lock className="modal__icon modal__icon--warning" size={24} />
              </div>
              <h2 className="modal__title">Sudo Password Required</h2>
            </div>
            <div className="modal__body">
              <p className="modal__message" style={{ marginBottom: '0.75rem' }}>
                The following tools require elevated privileges: <strong>{sudoToolsSelected.join(', ')}</strong>
              </p>
              <input
                id="sudo-password-input"
                type="password"
                className="input-field"
                placeholder="Enter sudo password"
                autoFocus
                style={{ width: '100%', padding: '0.6rem 0.8rem', borderRadius: '0.4rem', border: '1px solid var(--border-secondary)', background: 'var(--bg-tertiary)', color: 'var(--text-primary)', fontSize: '0.95rem' }}
                onKeyDown={e => {
                  if (e.key === 'Enter' && e.target.value) {
                    handleSudoSubmit(e.target.value);
                  }
                }}
              />
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Password is stored locally and never logged.
              </p>
            </div>
            <div className="modal__footer">
              <button className="modal__btn modal__btn--secondary" onClick={() => { setShowSudoModal(false); setSudoPendingExecute(false); }}>Cancel</button>
              <button className="modal__btn modal__btn--primary" onClick={() => {
                const pw = document.getElementById('sudo-password-input')?.value;
                if (pw) handleSudoSubmit(pw);
              }}>Authenticate & Execute</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
