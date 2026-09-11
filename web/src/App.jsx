import { useEffect, useState } from 'react'
import { API_URL, getHealth } from './api.js'

// Step 1 placeholder: proves browser -> api -> db end to end. Replaced at Step 4.

const POLL_MS = 2000
const REQUEST_TIMEOUT_MS = 5000

const PHASES = {
  checking: { label: 'checking', tone: 'text-ink-muted', db: 'unknown' },
  connected: { label: 'connected', tone: 'text-verified', db: 'reachable' },
  degraded: { label: 'database unreachable', tone: 'text-unsupported', db: 'not reachable' },
  unreachable: { label: 'disconnected', tone: 'text-unsupported', db: 'unknown' },
}

function formatTime(date) {
  return date.toLocaleTimeString('en-GB', { hour12: false })
}

function Detail({ phase, lastOk }) {
  switch (phase) {
    case 'connected':
      return <p>The API responded and its database check passed.</p>
    case 'degraded':
      return (
        <p>
          The API responded but cannot reach Postgres. Run{' '}
          <code className="font-mono text-mono">make logs</code> and check curator-db.
        </p>
      )
    case 'unreachable':
      return (
        <>
          <p>Could not reach the investigation service.</p>
          <p>
            {lastOk ? (
              <>
                Last successful update{' '}
                <span className="font-mono text-mono">{formatTime(lastOk)}</span>.
              </>
            ) : (
              'No successful update yet.'
            )}{' '}
            Retrying every {POLL_MS / 1000}s.
          </p>
        </>
      )
    default:
      return <p>Waiting for the first response.</p>
  }
}

export default function App() {
  const [phase, setPhase] = useState('checking')
  const [version, setVersion] = useState(null)
  const [lastOk, setLastOk] = useState(null)
  const [lastCheck, setLastCheck] = useState(null)

  useEffect(() => {
    let cancelled = false
    let timer

    // Schedules the next poll only after the current one settles, so slow
    // responses never stack up.
    async function poll() {
      try {
        const body = await getHealth({ signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
        if (cancelled) return
        const now = new Date()
        setVersion(body.version)
        setLastOk(now)
        setLastCheck(now)
        setPhase(body.db === true ? 'connected' : 'degraded')
      } catch {
        if (cancelled) return
        setLastCheck(new Date())
        setPhase('unreachable')
      }
      timer = setTimeout(poll, POLL_MS)
    }

    poll()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [])

  const { label, tone, db } = PHASES[phase]

  return (
    <div className="min-h-screen">
      <header className="flex h-12 items-center border-b bg-paper px-6">
        <span className="text-subhead">Curator</span>
      </header>

      <main className="px-6 py-12">
        <div className="max-w-2xl">
          <h1 className="text-heading">Service status</h1>
          <p className="mt-2 text-ink-secondary">
            Step 1 placeholder. Checks <code className="font-mono text-mono">GET /health</code>{' '}
            every {POLL_MS / 1000} seconds.
          </p>

          <section className="mt-8 rounded border bg-paper">
            <div className="border-b px-6 py-4" role="status">
              <p className={`text-heading ${tone}`}>{label}</p>
              <div className="mt-1 text-ink-secondary">
                <Detail phase={phase} lastOk={lastOk} />
              </div>
            </div>

            <dl className="grid grid-cols-[8rem_1fr] gap-y-3 px-6 py-4">
              <dt className="text-ink-muted">API</dt>
              <dd className="font-mono text-mono">{API_URL}</dd>

              <dt className="text-ink-muted">Database</dt>
              <dd>{db}</dd>

              <dt className="text-ink-muted">Version</dt>
              <dd className="font-mono text-mono">{version ?? 'unknown'}</dd>

              <dt className="text-ink-muted">Last check</dt>
              <dd className="font-mono text-mono">{lastCheck ? formatTime(lastCheck) : 'none yet'}</dd>
            </dl>
          </section>
        </div>
      </main>
    </div>
  )
}
