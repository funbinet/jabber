import React, { useState, useEffect, useRef } from 'react';
import { ArrowLeft, Play, Download, AlertTriangle, Save, Eye, Code, FileText, Type, CheckCircle } from 'lucide-react';
import { executeModule, fetchTaskLogs, fetchTaskProgress, fetchTaskResult, generateReport, fetchModuleSchema, saveReport } from '../api.js';

export default function ModuleExecutor({ module, isConnected, onBack }) {
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
  const terminalRef = useRef(null);
  const pollRef = useRef(null);

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
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [module.id, isConnected]);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [logs]);

  function handleInputChange(fieldName, value) {
    setFormData(prev => ({ ...prev, [fieldName]: value }));
  }

  async function handleExecute() {
    if (!isConnected) { simulateExecution(); return; }
    try {
      setStatus('RUNNING');
      setLogs(['[*] Sending execution request to JRTS engine...']);
      setProgress(0);
      setSaveStatus(null);
      setSavedInfo(null);

      const response = await executeModule(module.id, formData);
      setTaskId(response.taskId);
      setLogs(prev => [...prev, `[+] Task created: ${response.taskId}`]);

      pollRef.current = setInterval(async () => {
        try {
          const [logData, progressData] = await Promise.all([
            fetchTaskLogs(response.taskId),
            fetchTaskProgress(response.taskId),
          ]);
          setLogs(logData);
          setProgress(progressData.progress);
          if (progressData.status === 'COMPLETED' || progressData.status === 'FAILED') {
            clearInterval(pollRef.current);
            setStatus(progressData.status);
            const resultData = await fetchTaskResult(response.taskId);
            setResult(resultData);
            // Auto-load JSON view
            try {
              const report = await generateReport(response.taskId, 'json');
              setReportContent(report.content);
            } catch (e) {}
          }
        } catch (err) { console.error('Poll error:', err); }
      }, 500);
    } catch (err) {
      setStatus('FAILED');
      setLogs(prev => [...prev, `[!] ERROR: ${err.message}`]);
    }
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

  // Group schema fields
  const groups = {};
  schema.forEach(field => {
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

  return (
    <div className="executor-panel animate-fade-in">
      <div className="executor-panel__header">
        <button className="executor-panel__back" onClick={onBack} id="executor-back-btn">
          <ArrowLeft size={16} /> Back to modules
        </button>
        <div className="executor-panel__title">{module.name}</div>
        <span className={`module-card__risk module-card__risk--${module.riskLevel}`}>
          {module.riskLevel}
        </span>
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
                  {field.type === 'select' ? (
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

          <div style={{ marginTop: '1.5rem' }}>
            <button className="btn btn--primary" onClick={handleExecute}
              disabled={status === 'RUNNING'} id="execute-btn"
              style={{ width: '100%', justifyContent: 'center' }}>
              <Play size={14} />
              {status === 'RUNNING' ? 'Executing...' : 'Execute Module'}
            </button>
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
                  line.startsWith('[*]') ? 'terminal__line--info' : ''
                }`}>{line}</div>
              ))
            )}
          </div>

          {/* V3: Output View Tabs + Save/Download */}
          {status === 'COMPLETED' && (
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
                </div>
              )}

              {reportContent && (
                <div className="report-panel__content">
                  {outputView === 'html' ? (
                    <div dangerouslySetInnerHTML={{ __html: reportContent }} />
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
