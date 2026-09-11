// The browser calls the API directly; compose publishes it on localhost:8000.
export const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export async function getHealth({ signal } = {}) {
  const res = await fetch(`${API_URL}/health`, { signal })
  if (!res.ok) throw new Error(`GET /health returned ${res.status}`)
  return res.json()
}
