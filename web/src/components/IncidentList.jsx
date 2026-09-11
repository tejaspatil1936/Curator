import { useState } from 'react'

function getSeverityColor(priority) {
  if (priority >= 80) return 'var(--sev-critical)'
  if (priority >= 50) return 'var(--sev-high)'
  if (priority >= 20) return 'var(--sev-medium)'
  return 'var(--sev-low)'
}

function formatTime(isoStr) {
  if (!isoStr) return ''
  try {
    const d = new Date(isoStr)
    return d.toISOString().substring(11, 19) + 'Z'
  } catch {
    return ''
  }
}

export default function IncidentList({
  incidents,
  selectedId,
  onSelectIncident,
  totalAlertsCount = 666,
}) {
  const [activeReasonId, setActiveReasonId] = useState(null)

  return (
    <aside className="w-[260px] flex-shrink-0 border-r border-rule bg-canvas flex flex-col h-[calc(100vh-48px)] select-none">
      {/* Chrome header showing headline ratio: N alerts → M incidents */}
      <div className="h-12 border-b border-rule px-4 flex items-center justify-between bg-canvas">
        <span className="text-small text-ink font-mono font-medium">
          {totalAlertsCount} alerts → {incidents.length} incidents
        </span>
      </div>

      {/* Incident list items */}
      <div className="flex-1 overflow-y-auto divide-y divide-rule" role="list">
        {incidents.length === 0 ? (
          <div className="p-4 text-small text-ink-muted">No surfaced incidents.</div>
        ) : (
          incidents.map((inc) => {
            const isSelected = inc.id === selectedId
            const sevColor = getSeverityColor(inc.priority)
            const hostsText = (inc.hosts || []).join(', ') || 'Unknown'
            const timeText = formatTime(inc.first_seen)
            const isReasonOpen = activeReasonId === inc.id

            return (
              <div
                key={inc.id}
                role="listitem"
                tabIndex={0}
                onClick={() => onSelectIncident(inc.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    onSelectIncident(inc.id)
                  }
                }}
                className={`group relative flex flex-col px-3.5 py-3 cursor-pointer transition-colors duration-120 focus-visible:outline-none ${
                  isSelected ? 'bg-paper' : 'hover:bg-paper/60'
                }`}
                style={{
                  borderLeft: isSelected
                    ? '3px solid var(--primary)'
                    : `3px solid ${sevColor}`,
                }}
              >
                <div className="flex items-baseline justify-between gap-2">
                  <span
                    className="font-mono text-mono font-semibold text-ink hover:underline cursor-help"
                    onClick={(e) => {
                      e.stopPropagation()
                      setActiveReasonId(isReasonOpen ? null : inc.id)
                    }}
                    title="Click for priority breakdown"
                  >
                    {inc.priority}
                  </span>
                  <span className="text-small text-ink-muted font-mono">{timeText}</span>
                </div>

                <div className="mt-1 text-ui text-ink line-clamp-2 leading-[1.35]">
                  {inc.title || `Incident #${inc.id}`}
                </div>

                <div className="mt-1.5 flex items-center justify-between text-small text-ink-muted">
                  <span className="truncate max-w-[170px]" title={hostsText}>
                    {hostsText}
                  </span>
                  <span className="font-mono text-[11px] text-ink-faint">
                    {inc.raw_alert_count} alerts
                  </span>
                </div>

                {/* Priority Reason Popover Breakdown */}
                {isReasonOpen && inc.priority_reason && (
                  <div
                    className="absolute left-6 top-10 z-30 w-56 rounded border border-rule bg-paper p-3 shadow-pop text-small text-ink font-mono"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-center justify-between border-b border-rule pb-1.5 font-semibold">
                      <span>Priority {inc.priority} Breakdown</span>
                      <button
                        className="text-ink-muted hover:text-ink px-1"
                        onClick={() => setActiveReasonId(null)}
                      >
                        ×
                      </button>
                    </div>
                    <div className="mt-2 space-y-1 text-mono-sm">
                      {inc.priority_reason.factors && inc.priority_reason.factors.length > 0 ? (
                        inc.priority_reason.factors.map((f, i) => (
                          <div key={i} className="flex justify-between gap-2">
                            <span className="text-ink-secondary truncate">{f.name || f.factor}</span>
                            <span className="text-ink font-medium">+{f.score || f.weight}</span>
                          </div>
                        ))
                      ) : (
                        <div className="text-ink-faint">Base score: {inc.priority}</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </aside>
  )
}
