import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ArrowLeft, RefreshCw, Smartphone, MonitorSmartphone, Play, Download, AlertTriangle, Search, ChevronRight, X, FileText, CheckCircle, Code, Eye, Type, Save, XOctagon, Package } from 'lucide-react';
import { executeModule, fetchTaskLogs, fetchTaskProgress, fetchTaskResult, generateReport, saveReport, cancelTask } from '../api.js';
import { useSession } from './SessionContext.jsx';

const ACTION_MAPS = {
  'phone-enum-android': [
    { group: 'Device Control', actions: [
        { id: 'shell_whoami', label: 'Check Root Access', desc: 'adb shell whoami' }
    ]},
    { group: 'Media & Screen', actions: [
        { id: 'screenshot', label: 'Take Screenshot', desc: 'Screencap and pull' },
        { id: 'record_screen', label: 'Screen Recording', desc: 'Record 5s MP4 snippet' }
    ]},
    { group: 'File Extraction', actions: [
        { id: 'pull_sdcard', label: 'Pull SD Card', desc: 'Pull /sdcard/ fully' },
        { id: 'pull_downloads', label: 'Pull Downloads', desc: '/sdcard/Download' },
        { id: 'pull_app_data', label: 'Pull App Data', desc: '/data/data/ (requires root)' },
        { id: 'pull_file', label: 'Pull Specific File', desc: 'Extract via absolute path', requiresParam: true, paramPlaceholder: '/sdcard/target.txt' }
    ]},
    { group: 'Logs & Intelligence', actions: [
        { id: 'logcat_dump', label: 'Full Logcat Dump', desc: 'adb logcat -d' },
        { id: 'logcat_filter', label: 'Filter Logs', desc: 'Grep logs by keyword', requiresParam: true, paramPlaceholder: 'e.g., token|password|auth' },
        { id: 'crash_logs', label: 'Crash Logs', desc: 'Grep logcat for "fatal"' },
        { id: 'dumpsys', label: 'System Services Array', desc: 'adb shell dumpsys' },
        { id: 'running_activities', label: 'Running Activities', desc: 'dumpsys activity' }
    ]},
    { group: 'Identity & Auth', actions: [
        { id: 'dump_accounts', label: 'Dump OS Accounts', desc: 'dumpsys account' },
        { id: 'extract_emails', label: 'Extract Emails', desc: 'Grep valid email vectors' }
    ]},
    { group: 'Content Providers', actions: [
        { id: 'contacts', label: 'Extract Contacts', desc: 'content://contacts/phones/' },
        { id: 'call_logs', label: 'Call History', desc: 'content://call_log/calls' },
        { id: 'sms', label: 'Extract SMS', desc: 'content://sms/' }
    ]},
    { group: 'App Reconnaissance', actions: [
        { id: 'list_apps', label: 'List All Packages', desc: 'pm list packages' },
        { id: 'list_third_party', label: 'List 3rd Party Apps', desc: 'pm list packages -3' },
        { id: 'app_path', label: 'Get Package Path', desc: 'pm path <com.pkg>', requiresParam: true, paramPlaceholder: 'com.target.app' },
        { id: 'pull_apk', label: 'Extract Remote APK', desc: 'Resolve path and pull binary', requiresParam: true, paramPlaceholder: 'com.target.app' },
        { id: 'dump_app_info', label: 'Dump Application Info', desc: 'dumpsys package <com.pkg>', requiresParam: true, paramPlaceholder: 'com.target.app' }
    ]},
    { group: 'Secrets & Misconfigurations', actions: [
        { id: 'search_config_files', label: 'Find Config Files', desc: 'Search .env/.json/.xml' },
        { id: 'grep_secrets', label: 'Grep For Secrets', desc: 'Search memory/storage for tokens' }
    ]},
    { group: 'Network Exposure', actions: [
        { id: 'ip_addr', label: 'Interface Map', desc: 'ip addr' },
        { id: 'netstat', label: 'Open Sockets', desc: 'netstat -tuln' },
        { id: 'wifi_info', label: 'WiFi Handshakes/Config', desc: 'dumpsys wifi' }
    ]}
  ],
  'phone-enum-ios': [
    { group: 'Device Discovery', actions: [
        { id: 'device_info', label: 'Full Device Info', desc: 'ideviceinfo dump' },
        { id: 'device_name', label: 'Device Name', desc: 'ideviceinfo -k DeviceName' },
        { id: 'ios_version', label: 'iOS OS Version', desc: 'ideviceinfo -k ProductVersion' },
        { id: 'device_model', label: 'Device Hardware Model', desc: 'ideviceinfo -k ProductType' }
    ]},
    { group: 'System Logs', actions: [
        { id: 'live_logs', label: 'Live System Logs', desc: '5s idevicesyslog capture' },
        { id: 'log_secret_filter', label: 'Secret Log Filter', desc: 'Grep logs for auth tokens' },
        { id: 'crash_logs', label: 'Crash Logs', desc: 'Fetch stored diagnostics' }
    ]},
    { group: 'Backups (Non-Jailbreak Extraction)', actions: [
        { id: 'create_backup', label: 'Generate Standard Backup', desc: 'idevicebackup2' },
        { id: 'encrypted_backup', label: 'Encrypted Full Backup', desc: 'Requires passcode authentication' },
        { id: 'extract_backup_contents', label: 'List Backup Tree', desc: 'Examine extracted payload' },
        { id: 'parse_sms_db', label: 'Parse Backup SMS', desc: 'sms.db SQLite mapping' },
        { id: 'parse_contacts', label: 'Parse Contacts DB', desc: 'AddressBook SQLite extract' },
        { id: 'extract_call_history', label: 'Call History Storedata', desc: 'CallHistory.storedata extract' }
    ]},
    { group: 'Filesystem Mount', actions: [
        { id: 'mount_filesystem', label: 'Mount Filesystem', desc: 'ifuse mount into workspace' },
        { id: 'browse_media', label: 'Enumerate Media Store', desc: 'ls DCIM tree via mount' },
        { id: 'extract_photos', label: 'Extract Photos', desc: 'Clone DCIM into workspace' }
    ]},
    { group: 'App Containers', actions: [
        { id: 'list_backup_apps', label: 'List Discovered Apps', desc: 'Parse CFBundleIdentifier' },
        { id: 'extract_app_containers', label: 'Dump App Application Data', desc: 'Extract sandboxes via backup' },
        { id: 'sensitive_app_files', label: 'Seek App Plists/Secrets', desc: 'Grep app containers for keys' }
    ]},
    { group: 'Network & Tunneling (Root)', actions: [
        { id: 'port_forward_ssh', label: 'Forward SSH (usbmux)', desc: 'iproxy 2222 -> 22' },
        { id: 'ssh_access_check', label: 'Verify Jailbreak SSH', desc: 'Test SSH auth status' },
        { id: 'jailbreak_network_config', label: 'Root Network Map', desc: 'ifconfig over ssh' }
    ]},
    { group: 'Screen Interaction', actions: [
        { id: 'take_screenshot', label: 'Take Screenshot', desc: 'idevicescreenshot' },
        { id: 'screen_record_info', label: 'Screen Record Warning', desc: 'Native macOS Quicktime required' }
    ]},
    { group: 'Advanced Secrets', actions: [
        { id: 'dump_keychain', label: 'Dump Full Keychain', desc: 'Requires Jailbroken hook' },
        { id: 'extract_cookies', label: 'Exfil App Cookies', desc: 'Extract .binarycookies' },
        { id: 'extract_plists', label: 'Extract Configurations', desc: 'Dump all OS config defaults' }
    ]},
    { group: 'Instrumentation', actions: [
        { id: 'frida_attach', label: 'Attach Frida Hook', desc: 'frida -U -n <Bundle ID>', requiresParam: true, paramPlaceholder: 'com.apple.Maps' },
        { id: 'objection_explore', label: 'Objection Explore', desc: 'objection -g <id> explore', requiresParam: true, paramPlaceholder: 'com.apple.Maps' }
    ]}
  ]
};

function renderStructuredData(evidence) {
    if (!evidence || typeof evidence !== 'string') return null;
    if (evidence.includes('Row: 0') && evidence.includes('=')) {
        const rows = evidence.split('\n').filter(l => l.startsWith('Row:'));
        if (rows.length > 0) {
            const firstRowItems = rows[0].substring(rows[0].indexOf(' ') + 1).split(', ');
            const cols = firstRowItems.map(item => item.split('=')[0].trim()).filter(c => c && c !== 'Row:');
            return (
                <div className="table-responsive" style={{ border: '1px solid var(--border)', borderRadius: '4px', overflow: 'hidden' }}>
                    <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                        <thead style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                            <tr>{cols.map(c => <th key={c} style={{ padding: '8px' }}>{c}</th>)}</tr>
                        </thead>
                        <tbody>
                            {rows.map((row, rIdx) => {
                                const rowParts = row.substring(row.indexOf(' ') + 1).split(', ');
                                const rowData = {};
                                rowParts.forEach(part => {
                                    const eq = part.indexOf('=');
                                    if (eq > -1) rowData[part.substring(0, eq).trim()] = part.substring(eq + 1).trim();
                                });
                                return (
                                    <tr key={rIdx} style={{ borderBottom: '1px solid var(--border-dark)' }}>
                                        {cols.map(c => <td key={c} style={{ padding: '8px' }}>{rowData[c] || ''}</td>)}
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            );
        }
    }
    return <pre style={{ margin: 0, padding: '1rem', background: 'var(--bg-primary)', overflowX: 'auto', fontSize: '0.85rem' }}>{evidence}</pre>;
}

function DynamicArtifactRenderer({ result }) {
    if (!result || !result.findings || result.findings.length === 0) return null;
    return (
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {result.findings.map((f, i) => (
                <div key={i} style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
                    <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '14px', fontWeight: 'bold' }}>{f.title || 'Extracted Artifact'}</span>
                        <span className={`badge badge--${f.severity || 'low'}`}>{f.type}</span>
                    </div>
                    <div style={{ padding: '1rem' }}>
                        <p style={{ margin: '0 0 1rem 0', color: 'var(--steel)', fontSize: '0.9rem' }}>{f.description}</p>
                        {f.type === 'extracted_artifact' && (
                            <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: '4px', border: '1px dashed var(--border-dark)' }}>
                                {(() => {
                                    const pathStr = String(f.evidence || '');
                                    const downloadUrl = `/api/reports/download?path=${encodeURIComponent(pathStr.split('reports').pop() || pathStr)}`;
                                    
                                    if (pathStr.match(/\.(mp4|webm)$/i)) {
                                        return (
                                            <div style={{ textAlign: 'center' }}>
                                                <video controls src={downloadUrl} style={{ maxWidth: '100%', maxHeight: '400px', borderRadius: '4px', border: '1px solid var(--border)' }} />
                                                <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--steel)' }}>{pathStr}</div>
                                            </div>
                                        );
                                    } else if (pathStr.match(/\.(png|jpg|jpeg|gif)$/i)) {
                                        return (
                                            <div style={{ textAlign: 'center' }}>
                                                <a href={downloadUrl} target="_blank" rel="noreferrer">
                                                    <img src={downloadUrl} style={{ maxWidth: '100%', maxHeight: '400px', borderRadius: '4px' }} alt="Artifact" />
                                                </a>
                                                <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--steel)' }}>{pathStr}</div>
                                            </div>
                                        );
                                    } else if (pathStr.match(/\.apk$/i)) {
                                        return (
                                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--emerald)' }}>
                                                    <Package size={16} /> <strong>Android Package (APK) Captured</strong>
                                                </div>
                                                <div style={{ color: 'var(--steel)', fontSize: '0.85rem' }}>Location: {pathStr}</div>
                                                <a href={downloadUrl} className="btn btn--secondary" download style={{ display: 'inline-flex', padding: '6px 12px', fontSize: '0.85rem' }}>
                                                    <Download size={14} style={{ marginRight: '6px' }}/> Download Initial APK Dump
                                                </a>
                                            </div>
                                        );
                                    } else {
                                        return (
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontFamily: 'var(--font-mono)' }}>
                                                File Extracted: <a href={downloadUrl} style={{ color: 'var(--ice-blue)' }}>{pathStr}</a>
                                            </div>
                                        );
                                    }
                                })()}
                            </div>
                        )}
                        {f.type === 'enumerated_data' && renderStructuredData(f.evidence)}
                    </div>
                </div>
            ))}
        </div>
    );
}

export default function DeviceEnumeratorExecutor({ module, isConnected, onBack }) {
  const { saveSession, restoreSession, clearSession } = useSession();

  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState(null);
  
  // Execution state
  const [taskId, setTaskId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('IDLE');
  const [result, setResult] = useState(null);
  const [reportContent, setReportContent] = useState('');
  const [reportFormat, setReportFormat] = useState('json');
  const [outputView, setOutputView] = useState('json');
  const [saveStatus, setSaveStatus] = useState(null);
  const [savedInfo, setSavedInfo] = useState(null);
  
  // Prompt state
  const [activePromptAction, setActivePromptAction] = useState(null);
  const [promptParam, setPromptParam] = useState('');

  const terminalRef = useRef(null);
  const pollRef = useRef(null);
  const iframeRef = useRef(null);

  const viewTabs = [
    { id: 'json', label: 'JSON', icon: Code },
    { id: 'html', label: 'HTML', icon: Eye },
    { id: 'markdown', label: 'Markdown', icon: FileText },
    { id: 'txt', label: 'Raw', icon: Type },
  ];

  // Restore session
  useEffect(() => {
    const saved = restoreSession(module.id);
    if (saved) {
      if (saved.devices) setDevices(saved.devices);
      if (saved.selectedDevice) setSelectedDevice(saved.selectedDevice);
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

      if (saved.status === 'RUNNING' && saved.taskId && isConnected) {
        resumePolling(saved.taskId);
      }
    } else {
      if (isConnected) handleDiscover();
    }
  }, [module.id, isConnected]);

  // Persist session
  const persistState = useCallback(() => {
    saveSession(module.id, {
      devices, selectedDevice, taskId, logs, progress, status, result, reportContent, reportFormat, outputView, savedInfo, saveStatus
    });
  }, [module.id, devices, selectedDevice, taskId, logs, progress, status, result, reportContent, reportFormat, outputView, savedInfo, saveStatus, saveSession]);

  useEffect(() => {
    const timer = setTimeout(persistState, 300);
    return () => clearTimeout(timer);
  }, [persistState]);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [logs]);

  async function handleViewChange(viewId) {
    setOutputView(viewId);
    if (!taskId) return;
    try {
      const format = viewId === 'txt' ? 'raw' : viewId;
      setReportFormat(format);
      const report = await generateReport(taskId, format);
      setReportContent(report.content);
    } catch (e) {
      console.error('Failed to load report view:', e);
    }
  }

  async function handleSave() {
    if (!taskId) return;
    setSaveStatus('saving');
    try {
      const response = await saveReport(taskId, reportFormat || 'json');
      if (response && response.filePath) {
        setSavedInfo(response);
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus(null), 5000);
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

  function resumePolling(tid) {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const [logData, progressData] = await Promise.all([
          fetchTaskLogs(tid), fetchTaskProgress(tid),
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
            
            // If this was a discover task, parse the device list from output
            if (resultData?.output?.action === 'discover') {
                setDevices(resultData.output.devices || []);
            }
          } catch (e) {}
        }
      } catch (err) {}
    }, 500);
  }

  async function handleCancelTask() {
    if (!taskId) return;
    try {
        setLogs(prev => [...prev, '[!] Sending termination signal to execution engine...']);
        const response = await cancelTask(taskId);
        if (response.cancelled) {
            if (pollRef.current) clearInterval(pollRef.current);
            setStatus('CANCELLED');
            setProgress(0);
            setLogs(prev => [...prev, '[!] Operation manually killed by operator.']);
        } else {
            setLogs(prev => [...prev, `[!] Kill failed: ${response.reason || 'Unknown error'}`]);
        }
    } catch(e) {
        setLogs(prev => [...prev, '[!] Error during kill signal: ' + e.message]);
    }
  }

  async function handleDiscover() {
    if (!isConnected) return;
    try {
      setStatus('RUNNING');
      setLogs(['[*] Initiating device discovery sweep...']);
      setProgress(0); setTaskId(null); setResult(null); setReportContent('');
      const response = await executeModule(module.id, { action: 'discover' });
      setTaskId(response.taskId);
      resumePolling(response.taskId);
    } catch (err) {
      setStatus('FAILED');
      setLogs(prev => [...prev, `[!] Failed to initiate discovery: ${err.message}`]);
    }
  }

  async function handleExecuteAction(actionId, paramStr = '') {
    if (!isConnected || !selectedDevice) return;
    try {
      setStatus('RUNNING');
      setLogs([`[*] Dispatching operational action [${actionId}] to ${selectedDevice.id}...`]);
      setProgress(0); setResult(null); setReportContent(''); setActivePromptAction(null);
      
      const payload = { 
          action: actionId, 
          device_id: selectedDevice.id 
      };
      if (paramStr) payload.param = paramStr;
      
      const response = await executeModule(module.id, payload);
      setTaskId(response.taskId);
      resumePolling(response.taskId);
    } catch (err) {
      setStatus('FAILED');
      setLogs(prev => [...prev, `[!] Dispatch error: ${err.message}`]);
    }
  }
  
  function triggerActionClick(actionDef) {
      if (actionDef.requiresParam) {
          setPromptParam('');
          setActivePromptAction(actionDef);
      } else {
          handleExecuteAction(actionDef.id);
      }
  }

  const isAndroid = module.id === 'phone-enum-android';
  const myActions = ACTION_MAPS[module.id] || [];
  const discoveryRunning = status === 'RUNNING' && (!result || result.output?.action === 'discover');
  const isFinished = status === 'COMPLETED' || status === 'FAILED' || status === 'CANCELLED';

  return (
    <div className="executor-panel animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>
      <div className="executor-panel__header">
        <button className="executor-panel__back" onClick={onBack}>
          <ArrowLeft size={16} /> Back to modules
        </button>
        <div className="executor-panel__title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {isAndroid ? <Smartphone size={18}/> : <MonitorSmartphone size={18}/>}
            {module.name}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className={`module-card__risk module-card__risk--${module.riskLevel}`}>{module.riskLevel}</span>
        </div>
      </div>

      <div className="executor-layered-body" style={{ display: 'flex', flexDirection: 'column', gap: '2rem', padding: '1.5rem', width: '100%', overflowY: 'auto', flex: 1 }}>
        
        {/* Layer 1: Device Selection Panel */}
        <div className="device-selection-panel" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'white' }}>Connected Targets</h3>
                <button className="btn btn--secondary" onClick={handleDiscover} disabled={discoveryRunning} style={{ fontSize: '11px' }}>
                    <RefreshCw size={12} className={discoveryRunning ? 'spin' : ''} /> Rescan Host
                </button>
            </div>
            
            <div className="table-responsive" style={{ background: 'var(--bg-tertiary)', borderRadius: '8px', border: '1px solid var(--border)', overflow: 'hidden' }}>
                <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', margin: 0, border: 'none' }}>
                    <thead style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                        <tr>
                            <th style={{ padding: '12px' }}>Device ID</th>
                            <th style={{ padding: '12px' }}>Model</th>
                            <th style={{ padding: '12px' }}>OS Version</th>
                            <th style={{ padding: '12px' }}>Status</th>
                            <th style={{ padding: '12px' }}>Connection Type</th>
                            <th style={{ padding: '12px' }}>Authorization</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices.length === 0 ? (
                            <tr>
                                <td colSpan="6" style={{ textAlign: 'center', padding: '2rem', color: 'var(--steel)' }}>
                                    {discoveryRunning ? 'Scanning USB/TCP interfaces...' : 'No target devices discovered. Check USB connectivity or authorizations.'}
                                </td>
                            </tr>
                        ) : (
                            devices.map(dev => (
                                <tr key={dev.id} 
                                    className={selectedDevice?.id === dev.id ? 'active-row' : ''}
                                    style={{ cursor: 'pointer', background: selectedDevice?.id === dev.id ? 'rgba(88, 166, 255, 0.1)' : 'transparent', borderBottom: '1px solid var(--border)' }}
                                    onClick={() => setSelectedDevice(dev)}>
                                    <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{dev.id}</td>
                                    <td style={{ padding: '12px' }}>{dev.model || dev.name || 'Unknown User'}</td>
                                    <td style={{ padding: '12px' }}>{dev.os_version || dev.product || 'N/A'}</td>
                                    <td style={{ padding: '12px' }}>
                                        <span className={`badge ${dev.state === 'device' || dev.state === 'authorized' ? 'badge--success' : dev.state === 'unauthorized' ? 'badge--danger' : 'badge--warning'}`}>
                                            {dev.state === 'device' ? 'Active' : dev.state}
                                        </span>
                                    </td>
                                    <td style={{ padding: '12px' }}>{dev.transport || 'USB'}</td>
                                    <td style={{ padding: '12px' }}>
                                        {selectedDevice?.id === dev.id ? (
                                            <span style={{ color: 'var(--emerald)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                <CheckCircle size={12}/> Targeted
                                            </span>
                                        ) : (
                                            <span style={{ color: 'var(--steel)', fontSize: '11px' }}>Available</span>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>

        <hr style={{ border: 0, height: '1px', background: 'var(--border)', margin: '1rem 0' }} />

        {/* Layer 2: Action Grid (Enabled only when device selected) */}
        {!selectedDevice ? (
            <div style={{ textAlign: 'center', padding: '3rem', border: '1px dashed var(--border)', borderRadius: '8px', color: 'var(--steel)', width: '100%' }}>
                Target selection required. Click a device from the table above to unlock exploitation modules.
            </div>
        ) : (
            <div className="action-groups" style={{ width: '100%' }}>
                <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', color: 'white', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Play size={16} color="var(--ice-blue)"/> Operational Grid
                </h3>
                
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                    {myActions.map((group, gIdx) => (
                        <div key={gIdx} className="action-group" style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 1rem 0', fontSize: '12px', color: 'var(--steel-light)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{group.group}</h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {group.actions.map(act => (
                                    <button key={act.id} className="action-card-btn" onClick={() => triggerActionClick(act)} disabled={status === 'RUNNING'}>
                                        <div className="action-card-btn__title">{act.label}</div>
                                        <div className="action-card-btn__desc">{act.desc}</div>
                                        {act.requiresParam && <span className="action-card-btn__tag">Requires Map</span>}
                                    </button>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
                
                <hr style={{ border: 0, height: '1px', background: 'var(--border)', margin: '1.5rem 0' }} />

                {/* Layer 3: Output Panel (Terminal + Reports) */}
                <div className="terminal-container" style={{ width: '100%' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', padding: '0 4px' }}>
                        <span style={{ fontSize: '12px', color: 'var(--steel)', fontFamily: 'var(--font-mono)' }}>System Execution Log</span>
                        {status === 'RUNNING' && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <span className="pulsing-indicator" style={{ fontSize: '11px', color: 'var(--ice-blue)' }}>Running Executable...</span>
                                <button className="btn btn--danger" onClick={handleCancelTask} style={{ fontSize: '11px', padding: '4px 8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                    <XOctagon size={12} /> Stop Operation
                                </button>
                            </div>
                        )}
                    </div>
                    <div className="terminal" ref={terminalRef} style={{ height: '280px' }}>
                        {logs.length === 0 ? (
                        <div style={{ color: 'var(--steel)', opacity: 0.5 }}>{'>'} Awaiting input target queue...</div>
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
                </div>

                {/* V3.5: Artifact Dynamic Output Rendering */}
                {isFinished && result && result.findings && result.findings.length > 0 && (
                    <DynamicArtifactRenderer result={result} />
                )}

                {/* V3.5: Output View Tabs + Save/Download */}
                {isFinished && (
                  <div className="report-panel" style={{ marginTop: '2rem' }}>
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

                {/* Inline Action Prompt Modal */}
                {activePromptAction && (
                    <div className="prompt-modal-overlay">
                        <div className="prompt-modal" style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', padding: '1.5rem', borderRadius: '8px', width: '400px', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
                            <h3 style={{ margin: '0 0 0.5rem 0', color: 'white', fontSize: '1.1rem' }}>{activePromptAction.label}</h3>
                            <p style={{ margin: '0 0 1.5rem 0', color: 'var(--steel)', fontSize: '12px' }}>Parameter required for `{activePromptAction.desc}`.</p>
                            
                            <input 
                                type="text" 
                                autoFocus
                                className="form-group__input" 
                                placeholder={activePromptAction.paramPlaceholder}
                                value={promptParam}
                                onChange={e => setPromptParam(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter' && promptParam) handleExecuteAction(activePromptAction.id, promptParam); }}
                                style={{ marginBottom: '1.5rem', width: '100%', boxSizing: 'border-box' }}
                            />
                            
                            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                                <button className="btn btn--secondary" onClick={() => setActivePromptAction(null)}>Cancel</button>
                                <button className="btn btn--primary" disabled={!promptParam} onClick={() => handleExecuteAction(activePromptAction.id, promptParam)}>Execute Process</button>
                            </div>
                        </div>
                    </div>
                )}
                
            </div>
        )}
      </div>
    </div>
  );
}
