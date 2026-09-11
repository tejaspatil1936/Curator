/**
 * ChallengePanel — DESIGN.md §5.6
 *
 * Layout:
 *   Current reading with confidence
 *   Counter-arguments list
 *   Missing evidence list
 *   [Run the check] button
 *   → Results inline: query result count + confidence animating old → new
 */
import { useEffect, useRef, useState } from 'react'
import { challengeIncident } from '../api'

// Animate a number from `from` to `to` over `durationMs`
function useCountAnimation(from, to, durationMs = 400) {
  const [display, setDisplay] = useState(from)
  const rafRef = useRef(null)

  useEffect(() => {
    if (from === to || to === null) {
      setDisplay(to ?? from)
      return
    }
    const start = performance.now()
    const diff = to - from

    function step(now) {
      const elapsed = now - start
      const progress = Math.min(elapsed / durationMs, 1)
      // ease-out quad
      const eased = 1 - (1 - progress) ** 2
      setDisplay(parseFloat((from + diff * eased).toFixed(3)))
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(step)
      } else {
        setDisplay(to)
      }
    }

    rafRef.current = requestAnimationFrame(step)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [from, to, durationMs])

  return display
}

export default function ChallengePanel({ incident }) {
  const incidentId = incident?.id
  const initialConfidence = incident?.confidence ?? null

  const [status, setStatus] = useState('idle') // idle | running | done | error
  const [result, setResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState(null)

  // Confidence animation: from old → new
  const animFrom = result ? result.old_confidence : (initialConfidence ?? 0.5)
  const animTo = result ? result.new_confidence : (initialConfidence ?? 0.5)
  const displayConf = useCountAnimation(animFrom, animTo)

  async function runCheck() {
    if (!incidentId || status === 'running') return
    setStatus('running')
    setResult(null)
    setErrorMsg(null)
    try {
      const data = await challengeIncident(incidentId)
      setResult(data)
      setStatus('done')
    } catch (err) {
      setErrorMsg(err.message || 'Challenge request failed.')
      setStatus('error')
    }
  }

  if (!incident) {
    return (
      <section className="challenge-panel challenge-panel--empty">
        <p className="challenge-empty">Select an incident to run challenge analysis.</p>
      </section>
    )
  }

  return (
    <section className="challenge-panel" aria-label="Challenge analysis">

      {/* ── Current reading ── */}
      <div className="challenge-header">
        <div className="challenge-reading">
          <span className="challenge-label">Current reading</span>
          <span
            className={`challenge-confidence${result && result.confidence_delta < 0 ? ' challenge-confidence--reduced' : ''}`}
            aria-live="polite"
            aria-label={`Confidence ${(displayConf * 100).toFixed(0)} percent`}
          >
            confidence {displayConf.toFixed(2)}
            {result && result.confidence_delta < 0 && (
              <span className="challenge-delta" aria-hidden="true">
                {' '}({result.confidence_delta > 0 ? '+' : ''}{result.confidence_delta.toFixed(2)})
              </span>
            )}
          </span>
        </div>
        <p className="challenge-title-text">
          {incident.title || `Incident #${incidentId}`}
        </p>
      </div>

      {/* ── Dry-run badge ── */}
      {result?.dry_run && (
        <div className="challenge-dryrun-badge" role="status">
          Fixture — live analysis requires API credits
        </div>
      )}

      {/* ── Counter-arguments (pre-run: static description; post-run: actual) ── */}
      <div className="challenge-section">
        <h3 className="challenge-section-title">Counter-arguments</h3>
        {status === 'idle' && (
          <ul className="challenge-list">
            <li className="challenge-list-item challenge-placeholder">
              A legitimate admin script may produce the same parent-child chain.
            </li>
            <li className="challenge-list-item challenge-placeholder">
              No network indicator confirms external delivery.
            </li>
          </ul>
        )}
        {status === 'running' && (
          <p className="challenge-status">Analysing…</p>
        )}
        {(status === 'done' || status === 'error') && result?.alternative_hypotheses?.length > 0 && (
          <ol className="challenge-list">
            {result.alternative_hypotheses.map((h, i) => (
              <li key={i} className="challenge-list-item">{h}</li>
            ))}
          </ol>
        )}
      </div>

      {/* ── Missing evidence ── */}
      <div className="challenge-section">
        <h3 className="challenge-section-title">Missing evidence</h3>
        {status === 'idle' && (
          <ul className="challenge-list">
            <li className="challenge-list-item challenge-placeholder">
              Email gateway logs for the delivery vector
            </li>
            <li className="challenge-list-item challenge-placeholder">
              Process command line for the initial parent process
            </li>
          </ul>
        )}
        {status === 'running' && (
          <p className="challenge-status">Analysing…</p>
        )}
        {(status === 'done' || status === 'error') && result?.missing_evidence?.length > 0 && (
          <ul className="challenge-list">
            {result.missing_evidence.map((e, i) => (
              <li key={i} className="challenge-list-item">
                <span className="challenge-bullet">·</span> {e}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* ── Run button ── */}
      <button
        id={`challenge-run-${incidentId}`}
        className={`challenge-run-btn${status === 'running' ? ' challenge-run-btn--running' : ''}`}
        onClick={runCheck}
        disabled={status === 'running'}
        aria-busy={status === 'running'}
      >
        {status === 'running' ? 'Running…' : 'Run the check'}
      </button>

      {/* ── Error ── */}
      {status === 'error' && errorMsg && (
        <p className="challenge-error" role="alert">{errorMsg}</p>
      )}

      {/* ── Results ── */}
      {status === 'done' && result && (
        <div className="challenge-results" aria-live="polite">

          {/* Reasoning */}
          {result.reasoning && (
            <div className="challenge-reasoning">
              <h3 className="challenge-section-title">Reasoning</h3>
              <p className="challenge-reasoning-text">{result.reasoning}</p>
            </div>
          )}

          {/* Query results */}
          {result.query_results !== undefined && (
            <div className="challenge-query-results">
              <h3 className="challenge-section-title">
                Event search results
                <span className="challenge-result-count">
                  {' '}— {result.query_results.length} event{result.query_results.length !== 1 ? 's' : ''}
                </span>
              </h3>
              {result.query_results.length === 0 ? (
                <p className="challenge-no-results">No supporting events found.</p>
              ) : (
                <div className="challenge-events">
                  {result.query_results.slice(0, 10).map((ev) => (
                    <div key={ev.id} className="challenge-event-row">
                      <span className="challenge-event-ts mono-sm">
                        {ev.ts ? ev.ts.replace('T', ' ').slice(0, 19) : '—'}
                      </span>
                      <span className="challenge-event-host">{ev.host || '—'}</span>
                      <span className="challenge-event-code">ev.{ev.event_code}</span>
                      <span className="challenge-event-proc">
                        {ev.process_name?.split('\\').pop() || '—'}
                      </span>
                      {ev.command_line && (
                        <span className="challenge-event-cmd mono-sm" title={ev.command_line}>
                          {ev.command_line.slice(0, 80)}
                          {ev.command_line.length > 80 ? '…' : ''}
                        </span>
                      )}
                    </div>
                  ))}
                  {result.query_results.length > 10 && (
                    <p className="challenge-overflow">
                      +{result.query_results.length - 10} more events
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
