import React, { useState, useEffect } from 'react';
import { Wrench, Download, Trash2, RefreshCw, CheckCircle, XCircle, Search, Package } from 'lucide-react';
import { fetchAllModules, fetchModuleTools, downloadModuleTool, fetchModuleToolDownloadStatus, deleteModuleTool } from '../api.js';
import { useModal } from '../context/ModalContext.jsx';

/**
 * GlobalToolRegistry — Centralized tool management aggregating tools from every module's ToolManager.
 *
 * Blueprint Section 4:
 * - Aggregation: Scans all active modules to build a master list of binaries.
 * - Sorting: Alphabetical by tool name.
 * - Grouping: Grouped by category.
 * - Association: Shows which module(s) utilize each tool.
 * - Actions: Download, Delete, Bulk Manage, Status Indicators.
 */
export default function GlobalToolRegistry({ isConnected }) {
  const [tools, setTools] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [downloadingTools, setDownloadingTools] = useState(new Set());

  useEffect(() => { if (isConnected) loadAllTools(); }, [isConnected]);

  async function loadAllTools() {
    setLoading(true);
    try {
      const modules = await fetchAllModules();
      const toolMap = new Map(); // toolId -> { ...toolData, modules: [] }

      for (const mod of modules) {
        try {
          const moduleTools = await fetchModuleTools(mod.id);
          if (!Array.isArray(moduleTools)) continue;
          for (const tool of moduleTools) {
            const existing = toolMap.get(tool.id);
            if (existing) {
              if (!existing.modules.includes(mod.name)) {
                existing.modules.push(mod.name);
              }
              if (!existing.categories.includes(mod.category)) {
                existing.categories.push(mod.category);
              }
              // Update status if this one is installed and previous wasn't
              if (tool.installed && !existing.installed) {
                Object.assign(existing, tool);
              }
            } else {
              toolMap.set(tool.id, {
                ...tool,
                modules: [mod.name],
                categories: [mod.category],
                moduleId: mod.id,
              });
            }
          }
        } catch (e) {
          // Module may not support tools endpoint
        }
      }

      // Sort alphabetically
      const sorted = [...toolMap.values()].sort((a, b) =>
        (a.name || a.id).localeCompare(b.name || b.id)
      );
      setTools(sorted);
    } catch (e) {
      console.error('Failed to load global tools', e);
    }
    setLoading(false);
  }

  async function handleDownload(tool) {
    setDownloadingTools(prev => new Set([...prev, tool.id]));
    try {
      await downloadModuleTool(tool.moduleId, tool.id);
      // Poll for completion
      const poll = setInterval(async () => {
        try {
          const status = await fetchModuleToolDownloadStatus(tool.moduleId, tool.id);
          if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(poll);
            setDownloadingTools(prev => {
              const next = new Set(prev);
              next.delete(tool.id);
              return next;
            });
            loadAllTools(); // Refresh
          }
        } catch {
          clearInterval(poll);
        }
      }, 2000);
    } catch (e) {
      setDownloadingTools(prev => {
        const next = new Set(prev);
        next.delete(tool.id);
        return next;
      });
    }
  }
  const { showConfirm, showAlert } = useModal();

  async function handleDeleteTool(tool) {
    showConfirm(
      'Delete Tool',
      `Are you sure you want to delete ${tool.name || tool.id}? This will remove the binary from the system.`,
      async () => {
        try {
          await deleteModuleTool(tool.moduleId, tool.id);
          loadAllTools(); // Refresh
        } catch (e) {
          showAlert('Deletion Error', 'Failed to delete tool: ' + e.message, 'error');
        }
      },
      'Delete Binary',
      'Cancel'
    );
  }
  function handleDownloadAll() {
    tools.filter(t => !t.installed).forEach(t => handleDownload(t));
  }

  const filtered = tools.filter(t => {
    if (!searchTerm) return true;
    const s = searchTerm.toLowerCase();
    return (t.name || '').toLowerCase().includes(s) ||
           (t.id || '').toLowerCase().includes(s) ||
           (t.description || '').toLowerCase().includes(s) ||
           t.modules.some(m => m.toLowerCase().includes(s));
  });

  // Group by category
  const grouped = {};
  filtered.forEach(tool => {
    const cat = tool.categories?.[0] || 'Other';
    const label = formatCategory(cat);
    if (!grouped[label]) grouped[label] = [];
    grouped[label].push(tool);
  });

  const installedCount = tools.filter(t => t.installed).length;
  const missingCount = tools.filter(t => !t.installed).length;

  return (
    <div className="tool-registry animate-fade-in">
      {/* Header Stats */}
      <div style={{
        display: 'flex', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap',
      }}>
        <div className="rm-stat">
          <span className="rm-stat__val">{tools.length}</span>
          <span className="rm-stat__label">Total</span>
        </div>
        <div className="rm-stat">
          <span className="rm-stat__val" style={{color:'var(--emerald)'}}>{installedCount}</span>
          <span className="rm-stat__label">Installed</span>
        </div>
        <div className="rm-stat">
          <span className="rm-stat__val" style={{color:'var(--risk-high)'}}>{missingCount}</span>
          <span className="rm-stat__label">Missing</span>
        </div>
      </div>

      {/* Controls */}
      <div style={{
        display: 'flex', gap: '0.5rem', marginBottom: '1rem', alignItems: 'center', flexWrap: 'wrap',
      }}>
        <div className="rm-filter">
          <Search size={14} />
          <input placeholder="Search tools..." value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="form-group__input" style={{fontSize:'12px'}} />
        </div>
        <button className="btn btn--secondary" onClick={loadAllTools} style={{fontSize:'11px'}} id="tool-registry-refresh">
          <RefreshCw size={12} /> Refresh
        </button>
        {missingCount > 0 && (
          <button className="btn btn--primary" onClick={handleDownloadAll} style={{fontSize:'11px'}} id="tool-registry-download-all">
            <Download size={12} /> Download All Missing ({missingCount})
          </button>
        )}
      </div>

      {/* Tool List */}
      {loading ? (
        <div style={{textAlign:'center', color:'var(--steel)', padding:'2rem'}}>Scanning modules for tools...</div>
      ) : Object.keys(grouped).length === 0 ? (
        <div className="empty-state">
          <Wrench size={32} style={{color:'var(--steel)', marginBottom:'0.5rem'}} />
          <div className="empty-state__text">No tools found. Connect to the backend to scan modules.</div>
        </div>
      ) : (
        Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, categoryTools]) => (
          <div key={category} style={{ marginBottom: '1.25rem' }}>
            <div style={{
              fontSize: '11px', fontWeight: 600, color: 'var(--steel)',
              textTransform: 'uppercase', letterSpacing: '0.08em',
              marginBottom: '0.5rem', paddingLeft: '2px',
            }}>
              {category} ({categoryTools.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {categoryTools.map(tool => (
                <div key={tool.id} style={{
                  display: 'flex', alignItems: 'center', gap: '0.75rem',
                  padding: '8px 12px',
                  background: 'rgba(30,40,60,0.5)',
                  border: '1px solid rgba(99,179,237,0.08)',
                  borderRadius: '6px',
                  transition: 'border-color 0.15s ease',
                }}>
                  {/* Status Indicator */}
                  <div style={{ flexShrink: 0 }}>
                    {tool.installed
                      ? <CheckCircle size={14} style={{ color: 'var(--emerald)' }} />
                      : <XCircle size={14} style={{ color: 'var(--risk-high)' }} />}
                  </div>

                  {/* Tool Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontSize: '12px', fontWeight: 600, color: 'var(--foreground)',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {tool.name || tool.id}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--steel)', lineHeight: 1.4 }}>
                      {tool.description || ''}
                    </div>
                    {tool.version && (
                      <div style={{
                        fontSize: '10px', color: 'var(--ice-blue)',
                        fontFamily: 'var(--font-mono)', marginTop: '2px',
                      }}>
                        v{tool.version}{tool.source ? ` · ${tool.source}` : ''}
                      </div>
                    )}
                  </div>

                  {/* Module Associations */}
                  <div style={{
                    display: 'flex', flexWrap: 'wrap', gap: '3px',
                    maxWidth: '200px', justifyContent: 'flex-end',
                  }}>
                    {tool.modules.map(mod => (
                      <span key={mod} style={{
                        fontSize: '9px', padding: '1px 5px',
                        background: 'rgba(99,179,237,0.1)',
                        border: '1px solid rgba(99,179,237,0.2)',
                        borderRadius: '3px', color: 'var(--ice-blue)',
                        whiteSpace: 'nowrap',
                      }}>
                        {mod}
                      </span>
                    ))}
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                    {!tool.installed && (
                      <button
                        className="rm-action-btn"
                        title="Download"
                        disabled={downloadingTools.has(tool.id)}
                        onClick={() => handleDownload(tool)}
                        id={`tool-download-${tool.id}`}
                        style={{ opacity: downloadingTools.has(tool.id) ? 0.5 : 1 }}
                      >
                        {downloadingTools.has(tool.id)
                          ? <RefreshCw size={13} className="spin" />
                          : <Download size={13} />}
                      </button>
                    )}
                    {tool.installed && tool.homepage && (
                      <a href={tool.homepage} target="_blank" rel="noopener noreferrer"
                        className="rm-action-btn" title="Homepage" style={{ textDecoration: 'none' }}>
                        <Package size={13} />
                      </a>
                    )}
                    <button
                      className="rm-action-btn rm-action-btn--danger"
                      title="Delete Tool"
                      onClick={() => handleDeleteTool(tool)}
                      id={`tool-delete-${tool.id}`}
                      style={{ color: 'var(--risk-high)' }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function formatCategory(cat) {
  return (cat || 'Other')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase()) + ' Tools';
}
