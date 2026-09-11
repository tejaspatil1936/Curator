// The browser calls the API directly; compose publishes it on localhost:8000.
export const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export async function getHealth({ signal } = {}) {
  const res = await fetch(`${API_URL}/health`, { signal })
  if (!res.ok) throw new Error(`GET /health returned ${res.status}`)
  return res.json()
}

export async function getAuditStatus({ signal } = {}) {
  const res = await fetch(`${API_URL}/audit/verify`, { signal })
  if (!res.ok) throw new Error(`GET /audit/verify returned ${res.status}`)
  return res.json()
}

export async function getIncidents({ includeSuppressed = false, signal } = {}) {
  const res = await fetch(`${API_URL}/incidents?include_suppressed=${includeSuppressed}`, { signal })
  if (!res.ok) throw new Error(`GET /incidents returned ${res.status}`)
  return res.json()
}

export async function getIncident(id, { signal } = {}) {
  const res = await fetch(`${API_URL}/incidents/${id}`, { signal })
  if (!res.ok) throw new Error(`GET /incidents/${id} returned ${res.status}`)
  return res.json()
}

export async function getEvidence(eventIds, incidentId, { signal } = {}) {
  const url = `${API_URL}/evidence?event_ids=${eventIds}${incidentId ? `&incident_id=${incidentId}` : ''}`
  const res = await fetch(url, { signal })
  if (!res.ok) throw new Error(`GET /evidence returned ${res.status}`)
  return res.json()
}

export async function generateNarrative(id, { signal } = {}) {
  const res = await fetch(`${API_URL}/incidents/${id}/narrative`, {
    method: 'POST',
    signal,
  })
  if (!res.ok) throw new Error(`POST /incidents/${id}/narrative returned ${res.status}`)
  return res.json()
}

export async function getAccuracy(incidentId, { signal } = {}) {
  const url = incidentId ? `${API_URL}/incidents/${incidentId}/accuracy` : `${API_URL}/accuracy`
  const res = await fetch(url, { signal })
  if (!res.ok) throw new Error(`GET /accuracy returned ${res.status}`)
  return res.json()
}


