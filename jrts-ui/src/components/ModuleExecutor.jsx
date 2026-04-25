import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ArrowLeft, Play, Download, AlertTriangle, Save, Eye, Code, FileText, Type, CheckCircle, Square, RotateCcw } from 'lucide-react';
import { executeModule, fetchTaskLogs, fetchTaskProgress, fetchTaskResult, generateReport, fetchModuleSchema, saveReport, cancelTask } from '../api.js';
import { useSession } from './SessionContext.jsx';

export default function ModuleExecutor({ module, isConnected, onBack }) {
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
  const [outputView, setOutputView] = useState('json'); // json, html, markdown, raw
  const [saveStatus, setSaveStatus] = useState(null); // null | 'saving' | 'saved' | 'error'
  const [savedInfo, setSavedInfo] = useState(null);
  const [sessionRestored, setSessionRestored] = useState(false);
  const terminalRef = useRef(null);
  const pollRef = useRef(null);
  const iframeRef = useRef(null);

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

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [logs]);

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

  async function handleExecute() {
    if (!isConnected) { simulateExecution(); return; }
    try {
      setStatus('RUNNING');
      setLogs(['[*] Sending execution request to JRTS engine...']);
      setProgress(0);
      setSaveStatus(null);
      setSavedInfo(null);
      setResult(null);
      setReportContent('');

      const response = await executeModule(module.id, formData);
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

  function simulateExecution() {
    setStatus('RUNNING');
    setLogs([]);
    setProgress(0);
    const targetField = formData.target || formData.target_url || formData.domain ||
                        formData.rhost || Object.values(formData).find(v => v) || 'demo-target';
    const demoLogs = [
      `[*] ${module.name} starting...`,
      `[*] Target: ${targetField}`,
      `[*] Initializing module engine...`,
      `[+] Configuration validated`,
      `[*] Executing primary operation...`,
      `[+] Phase 1: Initialization complete`,
      `[*] Processing results...`,
      `[+] Phase 2: Execution complete`,
      `[+] ${module.name} finished successfully.`,
    ];
    let idx = 0;
    const interval = setInterval(() => {
      if (idx < demoLogs.length) {
        setLogs(prev => [...prev, demoLogs[idx]]);
        setProgress(Math.round(((idx + 1) / demoLogs.length) * 100));
        idx++;
      } else {
        clearInterval(interval);
        setStatus('COMPLETED');
        setResult({
          taskId: 'demo-' + Date.now(), moduleId: module.id, status: 'COMPLETED',
          findings: [], logLines: demoLogs,
          output: { mode: 'DEMO', target: targetField },
        });
      }
    }, 400);
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

  const modeField = schema.find(field => field.name === 'mode' && Array.isArray(field.options) && field.options.length > 0);
  const activeMode = formData.mode || modeField?.defaultValue || modeField?.options?.[0] || '';

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
                  This module's input schema could not be loaded. Connect to the JRTS backend engine.
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

          <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.5rem' }}>
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

          {/* V3.5: Output View Tabs + Save/Download */}
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
    </div>
  );
}
