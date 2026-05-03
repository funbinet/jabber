import React, { useState, useEffect } from 'react';
import { Target, Shield, Activity, Download, Save, ArrowLeft, CheckCircle, AlertTriangle, Info } from 'lucide-react';
import { fetchReports, generateProfile, downloadReport } from '../api.js';
import { useModal } from '../context/ModalContext.jsx';

export default function TargetProfiler({ isConnected, initialReportIds, onBack }) {
  const [reports, setReports] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set(initialReportIds || []));
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [profileFormat, setProfileFormat] = useState('html');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => { loadReports(); }, []);
  useEffect(() => {
    if (initialReportIds?.length > 0) setSelectedIds(new Set(initialReportIds));
  }, [initialReportIds]);

  async function loadReports() {
    if (!isConnected) return;
    try { setReports(await fetchReports()); } catch (e) {}
  }

  function toggleReport(id) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  const { showAlert } = useModal();

  async function handleGenerate() {
    if (selectedIds.size === 0) return;
    setLoading(true);
    try {
      const result = await generateProfile([...selectedIds], true, profileFormat);
      setProfile(result);
    } catch (e) { 
      showAlert('Generation Failed', 'Profile generation failed: ' + e.message, 'error'); 
    }
    setLoading(false);
  }

  async function handleDownloadProfile() {
    if (!profile?.savedId) return;
    try {
      const blob = await downloadReport(profile.savedId, profileFormat);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `profile_${profile.profileId}.${profileFormat}`;
      a.click(); URL.revokeObjectURL(url);
    } catch (e) { 
      showAlert('Download Failed', 'Failed to download profile artifact.', 'error'); 
    }
  }

  const filteredReports = reports.filter(r => {
    if (!searchTerm) return true;
    const s = searchTerm.toLowerCase();
    return (r.moduleName || '').toLowerCase().includes(s) ||
           (r.target || '').toLowerCase().includes(s) ||
           (r.category || '').toLowerCase().includes(s);
  });

  const confColors = { HIGH: 'var(--emerald)', MEDIUM: 'var(--risk-medium)', LOW: 'var(--risk-high)' };
  const sevColors = { CRITICAL: 'var(--risk-critical)', HIGH: 'var(--risk-high)', MEDIUM: 'var(--risk-medium)', LOW: 'var(--ice-blue)' };

  return (
    <div className="profiler animate-fade-in">
      <div className="profiler__header">
        <button className="executor-panel__back" onClick={onBack}><ArrowLeft size={16} /> Back</button>
        <h1 className="workspace__title">Target Profiling Engine</h1>
        <p className="workspace__description">
          Select reports to correlate findings and generate a structured target profile with confidence scoring
        </p>
      </div>

      {!profile ? (
        <div className="profiler__body">
          {/* Report Selector */}
          <div className="profiler__selector">
            <div className="profiler__selector-header">
              <h3>Select Source Reports ({selectedIds.size} selected)</h3>
              <input placeholder="Search reports..." value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="form-group__input" style={{fontSize:'12px', maxWidth:'clamp(200px, 20vw, 400px)'}} />
            </div>
            <div className="profiler__report-list">
              {filteredReports.map(r => (
                <label key={r.id} className={`profiler__report-item ${selectedIds.has(r.id) ? 'profiler__report-item--selected' : ''}`}>
                  <input type="checkbox" checked={selectedIds.has(r.id)} onChange={() => toggleReport(r.id)} />
                  <div>
                    <div style={{fontSize:'12px', fontWeight:500}}>{r.moduleName || r.moduleId}</div>
                    <div style={{fontSize:'11px', color:'var(--steel)'}}>
                      {r.target !== 'unknown' ? r.target : ''} · {r.type} · {r.format}
                    </div>
                  </div>
                </label>
              ))}
            </div>
            <div style={{marginTop:'1rem', display:'flex', gap:'0.5rem', alignItems:'center'}}>
              <select className="form-group__select" style={{fontSize:'12px', width:'clamp(100px, 15vw, 250px)'}} value={profileFormat}
                onChange={e => setProfileFormat(e.target.value)}>
                <option value="html">HTML (Primary)</option>
                <option value="json">JSON</option>
                <option value="md">Markdown</option>
                <option value="txt">TXT (Fast Review)</option>
                <option value="raw">RAW (Forensic)</option>
              </select>
              <button className="btn btn--primary" onClick={handleGenerate}
                disabled={selectedIds.size === 0 || loading} style={{flex:1}}>
                <Target size={14} />
                {loading ? 'Generating...' : `Generate Profile (${selectedIds.size} reports)`}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="profiler__results">
          {/* Risk Score */}
          <div className="profiler__risk-header">
            <div className="profiler__risk-gauge">
              <div className="profiler__risk-score" style={{
                background: `conic-gradient(${profile.overallRiskScore > 70 ? 'var(--risk-critical)' : profile.overallRiskScore > 40 ? 'var(--risk-high)' : 'var(--emerald)'} ${profile.overallRiskScore * 3.6}deg, var(--deep-navy) 0deg)`
              }}>
                <span>{profile.overallRiskScore}</span>
              </div>
              <div>Risk Score</div>
            </div>
            <div className="profiler__confidence" style={{color: confColors[profile.confidenceLevel]}}>
              <Shield size={20} /> Confidence: {profile.confidenceLevel}
            </div>
            <div style={{display:'flex', gap:'0.5rem'}}>
              <button className="btn btn--primary" onClick={handleDownloadProfile} style={{fontSize:'11px'}}>
                <Download size={12} /> Download Profile
              </button>
              <button className="btn btn--secondary" onClick={() => setProfile(null)} style={{fontSize:'11px'}}>
                New Profile
              </button>
            </div>
          </div>

          {/* Identifiers */}
          <div className="profiler__section">
            <h3><Info size={14} /> Identifiers</h3>
            <div className="profiler__tags">
              {[...(profile.ipAddresses || [])].map(ip => <span key={ip} className="profiler__tag profiler__tag--ip">{ip}</span>)}
              {[...(profile.hostnames || [])].map(h => <span key={h} className="profiler__tag profiler__tag--host">{h}</span>)}
              {[...(profile.domains || [])].map(d => <span key={d} className="profiler__tag profiler__tag--domain">{d}</span>)}
            </div>
          </div>

          {/* Services */}
          {profile.services?.length > 0 && (
            <div className="profiler__section">
              <h3><Activity size={14} /> Services ({profile.services.length})</h3>
              <table className="profiler__table">
                <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th><th>Confidence</th></tr></thead>
                <tbody>
                  {profile.services.map((s, i) => (
                    <tr key={i}>
                      <td>{s.port}</td><td>{s.protocol}</td><td>{s.product}</td><td>{s.version}</td>
                      <td><span className="profiler__state-badge">{s.state}</span></td>
                      <td><span style={{color: confColors[s.confidence]}}>{s.confidence}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Vulnerabilities */}
          {profile.vulnerabilities?.length > 0 && (
            <div className="profiler__section">
              <h3><AlertTriangle size={14} /> Vulnerabilities ({profile.vulnerabilities.length})</h3>
              {profile.vulnerabilities.map((v, i) => (
                <div key={i} className="profiler__vuln-card">
                  <div className="profiler__vuln-header">
                    <span className="profiler__vuln-cve">{v.cveId || 'N/A'}</span>
                    <span className="profiler__sev-badge" style={{color: sevColors[v.severity]}}>{v.severity}</span>
                    <span style={{color: confColors[v.confidence], fontSize:'11px'}}>{v.confidence}</span>
                  </div>
                  <div className="profiler__vuln-title">{v.title}</div>
                  {v.evidence && <div className="profiler__vuln-evidence">{v.evidence}</div>}
                </div>
              ))}
            </div>
          )}

          {/* Technologies */}
          {profile.technologies?.length > 0 && (
            <div className="profiler__section">
              <h3>Technologies ({profile.technologies.length})</h3>
              <div className="profiler__tags">
                {profile.technologies.map((t, i) => (
                  <span key={i} className="profiler__tag profiler__tag--tech">
                    {t.name} {t.version && `v${t.version}`}
                    <span style={{fontSize:'9px', opacity:0.7}}> ({t.category})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Behavioral Insights */}
          {profile.behavioralInsights && Object.keys(profile.behavioralInsights).length > 0 && (
            <div className="profiler__section">
              <h3>Behavioral Insights</h3>
              <div className="profiler__insights">
                {Object.entries(profile.behavioralInsights).map(([k, v]) => (
                  <div key={k} className="profiler__insight-item">
                    <span className="profiler__insight-key">{k.replace(/_/g, ' ')}</span>
                    <span className="profiler__insight-val">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
