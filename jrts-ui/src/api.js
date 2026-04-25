const API_BASE = '/api';

export async function fetchSystemInfo() {
  const res = await fetch(`${API_BASE}/info`);
  return res.json();
}

export async function fetchCategories() {
  const res = await fetch(`${API_BASE}/categories`);
  return res.json();
}

export async function fetchAllModules() {
  const res = await fetch(`${API_BASE}/modules`);
  return res.json();
}

export async function fetchModulesByCategory(category) {
  const res = await fetch(`${API_BASE}/modules/category/${category}`);
  return res.json();
}

export async function fetchModule(id) {
  const res = await fetch(`${API_BASE}/modules/${id}`);
  return res.json();
}

export async function fetchModuleSchema(id) {
  const res = await fetch(`${API_BASE}/modules/${id}/schema`);
  return res.json();
}

export async function executeModule(moduleId, input) {
  const res = await fetch(`${API_BASE}/tasks/execute/${moduleId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  return res.json();
}

export async function fetchTaskInfo(taskId) {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`);
  return res.json();
}

export async function fetchTaskLogs(taskId) {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/logs`);
  return res.json();
}

export async function fetchTaskResult(taskId) {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/result`);
  if (!res.ok) return null;
  return res.json();
}

export async function fetchTaskProgress(taskId) {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/progress`);
  return res.json();
}

export async function cancelTask(taskId) {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/cancel`, {
    method: 'POST',
  });
  return res.json();
}

export async function generateReport(taskId, format) {
  const res = await fetch(`${API_BASE}/reports/generate/${taskId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ format }),
  });
  return res.json();
}

// =============== V3.5: REPORTS MANAGEMENT ===============

export async function fetchReports(filters = {}) {
  const params = new URLSearchParams();
  if (filters.category) params.set('category', filters.category);
  if (filters.module) params.set('module', filters.module);
  if (filters.target) params.set('target', filters.target);
  if (filters.type) params.set('type', filters.type);
  const qs = params.toString();
  const res = await fetch(`${API_BASE}/reports${qs ? '?' + qs : ''}`);
  return res.json();
}

export async function fetchReportContent(reportId) {
  const res = await fetch(`${API_BASE}/reports/${reportId}/content`);
  if (!res.ok) return null;
  return res.text();
}

export async function fetchReportMeta(reportId) {
  const res = await fetch(`${API_BASE}/reports/${reportId}/meta`);
  return res.json();
}

export async function saveReport(taskId, format) {
  const res = await fetch(`${API_BASE}/reports/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ taskId, format }),
  });
  return res.json();
}

export async function editReport(reportId, content) {
  const res = await fetch(`${API_BASE}/reports/${reportId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  return res.json();
}

export async function renameReport(reportId, name) {
  const res = await fetch(`${API_BASE}/reports/${reportId}/rename`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  return res.json();
}

export async function deleteReport(reportId) {
  const res = await fetch(`${API_BASE}/reports/${reportId}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function downloadReport(reportId, format) {
  const res = await fetch(`${API_BASE}/reports/${reportId}/download?format=${format}`);
  const blob = await res.blob();
  return blob;
}

export async function fetchReportStats() {
  const res = await fetch(`${API_BASE}/reports/stats`);
  return res.json();
}

// =============== V3.5: TARGET PROFILING ===============

export async function generateProfile(reportIds, save = false, format = 'json') {
  const res = await fetch(`${API_BASE}/profiling/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reportIds, save, format }),
  });
  return res.json();
}
