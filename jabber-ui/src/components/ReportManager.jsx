import React, { useState, useEffect, useRef } from 'react';
import { FileText, Trash2, Download, Edit3, Search, Filter, RefreshCw, Eye, Save, X, FolderOpen, Code, Wrench, Grid } from 'lucide-react';
import { fetchReports, fetchReportContent, editReport, deleteReport, downloadReport, renameReport, fetchReportStats } from '../api.js';
import { useModal } from '../context/ModalContext.jsx';
import GlobalToolRegistry from './GlobalToolRegistry.jsx';

export default function ReportManager({ isConnected, onLaunchProfiler }) {
  const [reports, setReports] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ category: '', module: '', target: '', type: '' });
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportContent, setReportContent] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [viewMode, setViewMode] = useState('rendered'); // 'rendered' | 'code'
  const [activeTab, setActiveTab] = useState('gallery'); // 'gallery' | 'registry'
  const iframeRef = useRef(null);

  useEffect(() => { loadReports(); loadStats(); }, []);

  async function loadReports() {
    if (!isConnected) return;
    setLoading(true);
    try {
      const data = await fetchReports(filters);
      setReports(data || []);
    } catch (e) { console.error('Failed to load reports', e); }
    setLoading(false);
  }

  async function loadStats() {
    if (!isConnected) return;
    try { setStats(await fetchReportStats()); } catch (e) {}
  }

  async function handleView(report) {
    setSelectedReport(report);
    setIsEditing(false);
    // Default to rendered view for HTML, code view for everything else
    setViewMode(isHtmlFormat(report.format) ? 'rendered' : 'code');
    try {
      const content = await fetchReportContent(report.id);
      setReportContent(content || 'No content');
    } catch (e) { setReportContent('Error loading content'); }
  }

  async function handleEdit() {
    setIsEditing(true);
    setEditContent(reportContent);
    setViewMode('code'); // Force code view when editing
  }

  const { showAlert, showConfirm } = useModal();

  async function handleSaveEdit() {
    if (!selectedReport) return;
    try {
      await editReport(selectedReport.id, editContent);
      setReportContent(editContent);
      setIsEditing(false);
      showAlert('Success', 'Artifact updated successfully', 'success');
    } catch (e) { 
      showAlert('Save Error', 'Failed to save: ' + e.message, 'error'); 
    }
  }

  async function handleDelete(report) {
    showConfirm(
      'Delete Artifact',
      `Are you sure you want to delete ${report.filePath?.split('/').pop() || report.id}? This action cannot be undone.`,
      async () => {
        try {
          await deleteReport(report.id);
          setReports(prev => prev.filter(r => r.id !== report.id));
          if (selectedReport?.id === report.id) { setSelectedReport(null); setReportContent(''); }
          loadStats();
          showAlert('Deleted', 'Artifact removed successfully', 'success');
        } catch (e) { 
          showAlert('Delete Error', 'Failed to delete: ' + e.message, 'error'); 
        }
      },
      'Delete Permanent',
      'Cancel'
    );
  }

  async function handleDownload(report) {
    try {
      const blob = await downloadReport(report.id, report.format || 'json');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = report.filePath?.split('/').pop() || `report_${report.id}.${report.format || 'json'}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { 
      showAlert('Download Error', 'Failed to download: ' + e.message, 'error'); 
    }
  }

  function toggleSelect(id) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function handleProfileSelected() {
    if (selectedIds.size === 0) { 
      showAlert('Selection Required', 'Please select at least one report to generate a profile.', 'warning'); 
      return; 
    }
    onLaunchProfiler([...selectedIds]);
  }

  function isHtmlFormat(fmt) {
    return fmt?.toLowerCase() === 'html';
  }

  function handleIframeLoad() {
    if (iframeRef.current) {
      try {
        const doc = iframeRef.current.contentDocument || iframeRef.current.contentWindow?.document;
        if (doc && doc.body) {
          const height = Math.max(doc.body.scrollHeight, 400);
          iframeRef.current.style.height = Math.min(height + 20, 700) + 'px';
        }
      } catch {}
    }
  }

  const typeColors = {
    OUTPUT: 'var(--ice-blue)', PAYLOAD: 'var(--risk-high)', ANALYSIS: 'var(--emerald)',
    ARTIFACT: '#bc8cff', LOG: '#d29922', PROFILE: '#4bb3fd'
  };
  const isTextFormat = (fmt) => ['json','md','txt','xml','csv','html','markdown','log','raw','py','sh','bash','ps1','js','rb','pl','java','c','cpp','h','yaml','yml'].includes(fmt?.toLowerCase());
  const isImageFormat = (fmt) => ['png','jpg','jpeg','gif','svg','webp','bmp','ico'].includes(fmt?.toLowerCase());
  const isVideoFormat = (fmt) => ['mp4','webm','avi','mkv','mov'].includes(fmt?.toLowerCase());
  const isAudioFormat = (fmt) => ['mp3','wav','ogg'].includes(fmt?.toLowerCase());
  const isPdfFormat = (fmt) => fmt?.toLowerCase() === 'pdf';
  const isScriptFormat = (fmt) => ['py','sh','bash','ps1','js','rb','pl','java','c','cpp','h'].includes(fmt?.toLowerCase());
  const formatBadgeColor = (fmt) => {
    const f = fmt?.toLowerCase();
    if (f === 'html') return { bg: 'rgba(248,81,73,0.12)', color: '#f85149' };
    if (f === 'json') return { bg: 'rgba(75,179,253,0.12)', color: '#4bb3fd' };
    if (f === 'md' || f === 'markdown') return { bg: 'rgba(188,140,255,0.12)', color: '#bc8cff' };
    if (f === 'log') return { bg: 'rgba(210,153,34,0.12)', color: '#d29922' };
    if (['png','jpg','jpeg','gif','svg','webp'].includes(f)) return { bg: 'rgba(63,185,80,0.12)', color: '#3fb950' };
    if (['mp4','webm','avi','mov'].includes(f)) return { bg: 'rgba(248,81,73,0.12)', color: '#f85149' };
    if (f === 'pdf') return { bg: 'rgba(240,136,62,0.12)', color: '#f0883e' };
    if (['py','sh','bash','ps1','js'].includes(f)) return { bg: 'rgba(188,140,255,0.12)', color: '#bc8cff' };
    if (['exe','elf','dll','bin','apk','msi'].includes(f)) return { bg: 'rgba(248,81,73,0.2)', color: '#f85149' };
    if (['pcap','pcapng','kirbi','ccache'].includes(f)) return { bg: 'rgba(210,153,34,0.12)', color: '#d29922' };
    return { bg: 'rgba(139,148,158,0.12)', color: '#8b949e' };
  };

  return (
    <div className="report-manager animate-fade-in">
      <div className="report-manager__header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 className="workspace__title">Artifacts System</h1>
            <p className="workspace__description">
              Centralized hub for forensic data, outputs, payloads, profiles, and global tool management
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              className={`btn ${activeTab === 'gallery' ? 'btn--primary' : 'btn--secondary'}`}
              onClick={() => setActiveTab('gallery')}
            >
              <Grid size={14} /> Artifact Gallery
            </button>
            <button
              className={`btn ${activeTab === 'registry' ? 'btn--primary' : 'btn--secondary'}`}
              onClick={() => setActiveTab('registry')}
            >
              <Wrench size={14} /> Tool Registry
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'registry' ? (
        <GlobalToolRegistry isConnected={isConnected} />
      ) : (
        <>
          {/* Stats Bar */}
          {stats && (
        <div className="report-manager__stats">
          <div className="rm-stat"><span className="rm-stat__val">{stats.totalReports}</span><span className="rm-stat__label">Total</span></div>
          <div className="rm-stat"><span className="rm-stat__val" style={{color:'var(--ice-blue)'}}>{stats.outputs}</span><span className="rm-stat__label">Outputs</span></div>
          <div className="rm-stat"><span className="rm-stat__val" style={{color:'var(--risk-high)'}}>{stats.payloads}</span><span className="rm-stat__label">Payloads</span></div>
          <div className="rm-stat"><span className="rm-stat__val" style={{color:'var(--emerald)'}}>{stats.analyses}</span><span className="rm-stat__label">Profiles</span></div>
          <div className="rm-stat"><span className="rm-stat__val" style={{color:'#bc8cff'}}>{stats.artifacts || 0}</span><span className="rm-stat__label">Artifacts</span></div>
          <div className="rm-stat"><span className="rm-stat__val" style={{color:'#d29922'}}>{stats.logs || 0}</span><span className="rm-stat__label">Logs</span></div>
          <div className="rm-stat"><span className="rm-stat__val">{stats.totalSizeHuman}</span><span className="rm-stat__label">Size</span></div>
        </div>
      )}

      {/* Filters */}
      <div className="report-manager__filters">
        <div className="rm-filter">
          <Search size={14} />
          <input placeholder="Filter by target..." value={filters.target}
            onChange={e => setFilters(p => ({...p, target: e.target.value}))}
            className="form-group__input" style={{fontSize:'12px'}} />
        </div>
        <div className="rm-filter">
          <Filter size={14} />
          <select className="form-group__select" style={{fontSize:'12px'}} value={filters.type}
            onChange={e => setFilters(p => ({...p, type: e.target.value}))}>
            <option value="">All Types</option>
            <option value="OUTPUT">Outputs</option>
            <option value="PAYLOAD">Payloads</option>
            <option value="ANALYSIS">Profiles</option>
            <option value="ARTIFACT">Artifacts</option>
            <option value="LOG">Logs</option>
            <option value="PROFILE">Profiles (HTML)</option>
          </select>
        </div>
        <input placeholder="Category..." value={filters.category}
          onChange={e => setFilters(p => ({...p, category: e.target.value}))}
          className="form-group__input" style={{fontSize:'12px', width:'clamp(120px, 15vw, 250px)'}} />
        <button className="btn btn--secondary" onClick={loadReports} style={{fontSize:'11px'}}>
          <RefreshCw size={12} /> Refresh
        </button>
        {selectedIds.size > 0 && (
          <button className="btn btn--primary" onClick={handleProfileSelected} style={{fontSize:'11px'}}>
            Generate Profile ({selectedIds.size})
          </button>
        )}
      </div>

      <div className="report-manager__body">
        {/* Report List */}
        <div className="report-manager__list">
          {loading ? (
            <div style={{textAlign:'center', color:'var(--steel)', padding:'2rem'}}>Loading...</div>
          ) : reports.length === 0 ? (
            <div className="empty-state">
              <FolderOpen size={32} style={{color:'var(--steel)', marginBottom:'0.5rem'}} />
              <div className="empty-state__text">No artifacts found. Execute a module to generate outputs.</div>
            </div>
          ) : (
            reports.map(r => (
              <div key={r.id} className={`rm-item ${selectedReport?.id === r.id ? 'rm-item--active' : ''}`}
                onClick={() => handleView(r)}>
                <div className="rm-item__checkbox">
                  <input type="checkbox" checked={selectedIds.has(r.id)}
                    onChange={(e) => { e.stopPropagation(); toggleSelect(r.id); }}
                    onClick={e => e.stopPropagation()} />
                </div>
                <div className="rm-item__info">
                  <div className="rm-item__name">
                    <FileText size={12} />
                    {r.filePath?.split('/').pop() || r.id}
                  </div>
                  <div className="rm-item__meta">
                    <span className="rm-item__badge" style={{background: typeColors[r.type] + '20', color: typeColors[r.type]}}>
                      {r.type}
                    </span>
                    {r.format && (() => {
                      const fb = formatBadgeColor(r.format);
                      return <span className="rm-item__badge" style={{background: fb.bg, color: fb.color}}>.{r.format}</span>;
                    })()}
                    <span>{r.moduleName || r.moduleId}</span>
                    <span>{r.target && r.target !== 'unknown' ? r.target : ''}</span>
                    <span>{r.timestamp ? new Date(r.timestamp).toLocaleDateString() : ''}</span>
                  </div>
                </div>
                <div className="rm-item__actions">
                  <button title="Download" onClick={e => {e.stopPropagation(); handleDownload(r);}}
                    className="rm-action-btn"><Download size={13} /></button>
                  <button title="Delete" onClick={e => {e.stopPropagation(); handleDelete(r);}}
                    className="rm-action-btn rm-action-btn--danger"><Trash2 size={13} /></button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Report Viewer/Editor */}
        <div className="report-manager__viewer">
          {selectedReport ? (
            <>
              <div className="rm-viewer__header">
                <span className="rm-viewer__title">{selectedReport.filePath?.split('/').pop()}</span>
                <div className="rm-viewer__actions">
                  {/* SHA256 Integrity Badge */}
                  {selectedReport.sha256 && (
                    <span title={`SHA256: ${selectedReport.sha256}`} style={{
                      fontSize: '10px', fontFamily: 'var(--font-mono)',
                      background: 'rgba(63,185,80,0.1)', color: 'var(--emerald)',
                      border: '1px solid rgba(63,185,80,0.25)', borderRadius: '4px',
                      padding: '2px 6px', display: 'flex', alignItems: 'center', gap: '4px',
                      maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      ✓ SHA256: {selectedReport.sha256.substring(0, 12)}…
                    </span>
                  )}
                  {/* Rendered/Code toggle for HTML reports */}
                  {isHtmlFormat(selectedReport.format) && !isEditing && (
                    <div className="rm-viewer__toggle">
                      <button
                        className={`rm-toggle-btn ${viewMode === 'rendered' ? 'rm-toggle-btn--active' : ''}`}
                        onClick={() => setViewMode('rendered')}
                        title="Rendered View"
                      >
                        <Eye size={12} /> Rendered
                      </button>
                      <button
                        className={`rm-toggle-btn ${viewMode === 'code' ? 'rm-toggle-btn--active' : ''}`}
                        onClick={() => setViewMode('code')}
                        title="Code View"
                      >
                        <Code size={12} /> Code
                      </button>
                    </div>
                  )}
                  {isTextFormat(selectedReport.format) && !isEditing && (
                    <button className="btn btn--secondary" onClick={handleEdit} style={{fontSize:'11px'}}>
                      <Edit3 size={12} /> Edit
                    </button>
                  )}
                  {isEditing && (
                    <>
                      <button className="btn btn--primary" onClick={handleSaveEdit} style={{fontSize:'11px'}}>
                        <Save size={12} /> Save
                      </button>
                      <button className="btn btn--secondary" onClick={() => setIsEditing(false)} style={{fontSize:'11px'}}>
                        <X size={12} /> Cancel
                      </button>
                    </>
                  )}
                  <button className="btn btn--secondary" onClick={() => handleDownload(selectedReport)} style={{fontSize:'11px'}}>
                    <Download size={12} /> Download
                  </button>
                </div>
              </div>
              <div className="rm-viewer__content">
                {isEditing ? (
                  <textarea className="rm-editor" value={editContent}
                    onChange={e => setEditContent(e.target.value)} />
                ) : isImageFormat(selectedReport.format) ? (
                  <div style={{textAlign:'center', padding:'1rem'}}>
                    <img
                      src={`/api/reports/${selectedReport.id}/serve`}
                      alt={selectedReport.filePath?.split('/').pop()}
                      style={{maxWidth:'100%', maxHeight:'600px', borderRadius:'8px', border:'1px solid var(--border-dim)'}}
                    />
                  </div>
                ) : isVideoFormat(selectedReport.format) ? (
                  <div style={{textAlign:'center', padding:'1rem'}}>
                    <video controls style={{maxWidth:'100%', maxHeight:'600px', borderRadius:'8px'}}>
                      <source src={`/api/reports/${selectedReport.id}/serve`} />
                      Your browser does not support video playback.
                    </video>
                  </div>
                ) : isAudioFormat(selectedReport.format) ? (
                  <div style={{textAlign:'center', padding:'2rem'}}>
                    <audio controls style={{width:'100%'}}>
                      <source src={`/api/reports/${selectedReport.id}/serve`} />
                    </audio>
                  </div>
                ) : isPdfFormat(selectedReport.format) ? (
                  <iframe
                    src={`/api/reports/${selectedReport.id}/serve`}
                    className="rm-viewer__iframe"
                    style={{height:'700px'}}
                    title="PDF Viewer"
                  />
                ) : isHtmlFormat(selectedReport.format) && viewMode === 'rendered' ? (
                  <iframe
                    ref={iframeRef}
                    srcDoc={reportContent}
                    sandbox="allow-same-origin"
                    className="rm-viewer__iframe"
                    title="Report Rendered View"
                    onLoad={handleIframeLoad}
                  />
                ) : isTextFormat(selectedReport.format) ? (
                  <pre className="rm-viewer__pre">{reportContent}</pre>
                ) : (
                  <div className="rm-viewer__binary">
                    <div style={{textAlign:'center', padding:'3rem', color:'var(--steel)'}}>
                      <div style={{fontSize:'48px', marginBottom:'1rem'}}>📦</div>
                      <div style={{fontSize:'14px', fontWeight:600, marginBottom:'0.5rem'}}>Binary File</div>
                      <div style={{fontSize:'12px', marginBottom:'1rem', color:'var(--steel)'}}>
                        {selectedReport.filePath?.split('/').pop()} — {selectedReport.format?.toUpperCase() || 'BIN'} format
                      </div>
                      <button className="btn btn--primary" onClick={() => handleDownload(selectedReport)} style={{fontSize:'12px'}}>
                        <Download size={14} /> Download File
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="rm-viewer__empty">
              <Eye size={32} style={{color:'var(--steel)', marginBottom:'0.5rem'}} />
              <div>Select an artifact to view its contents</div>
            </div>
          )}
        </div>
      </div>
        </>
      )}
    </div>
  );
}
