import { useEffect, useState } from 'react'
import { getAccuracy } from '../api.js'

export default function Scoreboard({ incidentId }) {
  const [data, setData] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedTid, setExpandedTid] = useState(null)

  useEffect(() => {
    let cancelled = false
    setIsLoading(true)
    setError(null)

    async function loadAccuracy() {
      try {
        const res = await getAccuracy(incidentId)
        if (cancelled) return
        setData(res)
      } catch (err) {
        if (cancelled) return
        console.error('Failed to load accuracy data:', err)
        setError('Failed to load accuracy scoreboard.')
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    loadAccuracy()
    return () => {
      cancelled = true
    }
  }, [incidentId])

  if (isLoading) {
    return (
      <div className="py-16 text-center text-ink-muted text-small font-mono">
        Evaluating recovered techniques against ground truth...
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="py-12 text-center text-unsupported text-small">
        {error || 'No accuracy data available.'}
      </div>
    )
  }

  const {
    executed = 0,
    recovered = 0,
    not_in_evidence = 0,
    beyond_ground_truth = 0,
    precision = 0,
    recall = 0,
    time_to_narrative_seconds = 88,
    ground_truth_techniques = [],
    recovered_techniques = [],
    beyond_ground_truth_techniques = [],
  } = data

  const isNotInEvidenceZero = not_in_evidence === 0

  return (
    <div className="py-6 space-y-10" role="region" aria-label="Accuracy Scoreboard">
      {/* Four Big Centred Numbers (DESIGN.md §5.7 & Step 6.1b) */}
      <div className="flex flex-wrap items-center justify-center gap-10 sm:gap-14 pt-4 pb-4 border-b border-rule">
        {/* Executed */}
        <div className="text-center min-w-[90px]">
          <div className="font-sans font-bold text-[48px] leading-tight text-ink tracking-tight">
            {executed}
          </div>
          <div className="mt-1 text-small text-ink-muted uppercase tracking-wider font-medium">
            executed
          </div>
        </div>

        {/* Recovered */}
        <div className="text-center min-w-[90px]">
          <div className="font-sans font-bold text-[48px] leading-tight text-ink tracking-tight">
            {recovered}
          </div>
          <div className="mt-1 text-small text-ink-muted uppercase tracking-wider font-medium">
            recovered
          </div>
        </div>

        {/* Not In Evidence - Visual Weight & --verified when zero */}
        <div className="text-center min-w-[110px]">
          <div
            className={`font-sans font-bold text-[48px] leading-tight tracking-tight ${
              isNotInEvidenceZero ? 'text-verified font-extrabold' : 'text-unsupported'
            }`}
          >
            {not_in_evidence}
          </div>
          <div
            className={`mt-1 text-small uppercase tracking-wider font-semibold ${
              isNotInEvidenceZero ? 'text-verified' : 'text-unsupported'
            }`}
          >
            not in evidence
          </div>
        </div>

        {/* Beyond Ground Truth - Neutral visual weight */}
        <div className="text-center min-w-[130px]">
          <div className="font-sans font-bold text-[48px] leading-tight text-ink tracking-tight">
            {beyond_ground_truth}
          </div>
          <div className="mt-1 text-small text-ink-muted uppercase tracking-wider font-medium">
            beyond ground truth
          </div>
        </div>
      </div>

      {/* Secondary Metrics Bar */}
      <div className="flex items-center justify-center gap-8 text-small font-mono text-ink-secondary">
        <div>
          Precision: <span className="font-semibold text-ink">{(precision * 100).toFixed(1)}%</span>
        </div>
        <span>·</span>
        <div>
          Recall: <span className="font-semibold text-ink">{(recall * 100).toFixed(1)}%</span>
        </div>
        <span>·</span>
        <div>
          Exact matches: <span className="font-semibold text-ink">{data.exact_matches_count || 0}</span>
        </div>
        <span>·</span>
        <div>
          Parent/Child matches: <span className="font-semibold text-ink">{data.parent_child_matches_count || 0}</span>
        </div>
      </div>

      {/* Two Columns: Ground Truth vs Recovered */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-2">
        {/* Left Column: Ground Truth */}
        <div className="space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-rule">
            <h3 className="text-ui font-semibold text-ink">
              Ground Truth ({ground_truth_techniques.length})
            </h3>
            <span className="text-mono-sm font-mono text-ink-muted">APT29 Plan</span>
          </div>

          <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-2">
            {ground_truth_techniques.map((gt, idx) => {
              const isExact = gt.match_type === 'exact'
              const isParentChild = gt.match_type === 'parent_child'
              const isMissed = !gt.recovered

              return (
                <div
                  key={idx}
                  className={`grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 p-2 rounded border transition-colors text-small overflow-hidden ${
                    isMissed
                      ? 'bg-paper/40 border-rule/40 text-ink-muted'
                      : 'bg-paper hover:bg-paper-sunk border-rule/60 text-ink'
                  }`}
                >
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className={`font-mono text-mono-sm font-semibold w-4 text-center ${
                        isExact
                          ? 'text-verified'
                          : isParentChild
                          ? 'text-amber-600'
                          : 'text-ink-muted'
                      }`}
                    >
                      {isExact && '✓'}
                      {isParentChild && '⚠'}
                      {isMissed && '✗'}
                    </span>
                    <span className="font-mono text-primary font-medium text-mono-sm">
                      {gt.technique_id}
                    </span>
                  </div>
                  <span className="truncate min-w-0" title={gt.name}>
                    {gt.name}
                  </span>
                  <div className="flex items-center gap-1.5 flex-shrink-0 justify-end text-mono-sm font-mono text-ink-muted max-w-[210px]">
                    {gt.shipped_id !== gt.technique_id && (
                      <span className="text-ink-muted/80 text-[11px] flex-shrink-0" title={`Shipped as ${gt.shipped_id}`}>
                        (ex-{gt.shipped_id})
                      </span>
                    )}
                    <span className="truncate" title={gt.step}>{gt.step}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Column: Recovered Techniques */}
        <div className="space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-rule">
            <h3 className="text-ui font-semibold text-ink">
              Recovered by Curator ({recovered_techniques.length})
            </h3>
            <span className="text-mono-sm font-mono text-ink-muted">Supported Claims</span>
          </div>

          <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-2">
            {recovered_techniques.map((rec, idx) => {
              const isExact = rec.match_type === 'exact'
              const isParentChild = rec.match_type === 'parent_child'
              const isBeyondGt = rec.match_type === 'beyond_gt'
              const beyondItem = isBeyondGt
                ? beyond_ground_truth_techniques.find((b) => b.technique_id === rec.technique_id)
                : null
              const isExpanded = expandedTid === rec.technique_id

              return (
                <div
                  key={idx}
                  className="rounded bg-paper hover:bg-paper-sunk border border-rule/60 transition-colors text-small overflow-hidden"
                >
                  <div
                    className={`grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 p-2 ${
                      isBeyondGt ? 'cursor-pointer select-none' : ''
                    }`}
                    onClick={() => {
                      if (isBeyondGt) {
                        setExpandedTid(isExpanded ? null : rec.technique_id)
                      }
                    }}
                  >
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span
                        className={`font-mono text-mono-sm font-semibold w-4 text-center ${
                          isExact
                            ? 'text-verified'
                            : isParentChild
                            ? 'text-amber-600'
                            : 'text-ink-secondary'
                        }`}
                      >
                        {isExact && '✓'}
                        {isParentChild && '⚠'}
                        {isBeyondGt && '+'}
                      </span>
                      <span className="font-mono text-primary font-medium text-mono-sm">
                        {rec.technique_id}
                      </span>
                    </div>
                    <span className="truncate text-ink min-w-0" title={rec.name}>
                      {rec.name}
                    </span>
                    <div className="flex items-center gap-1.5 text-mono-sm font-mono text-ink-muted flex-shrink-0 justify-end">
                      {isExact && 'exact'}
                      {isParentChild && 'parent/child'}
                      {isBeyondGt && (
                        <span className="text-ink-secondary font-medium flex items-center gap-1">
                          beyond GT {isExpanded ? '▲' : '▼'}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Expandable Justification for Beyond Ground Truth */}
                  {isBeyondGt && isExpanded && beyondItem && (
                    <div className="px-3 pb-3 pt-1 border-t border-rule/40 bg-paper-sunk/50 text-small space-y-2">
                      <div className="text-ink-muted text-[11px] uppercase tracking-wider font-semibold">
                        Justification Telemetry
                      </div>
                      {beyondItem.justifications.map((j, jIdx) => (
                        <div key={jIdx} className="space-y-1 bg-paper p-2 rounded border border-rule/40 text-xs">
                          <p className="text-ink font-sans text-xs italic">
                            "{j.text}"
                          </p>
                          {j.commands.map((cmd, cIdx) => (
                            <div key={cIdx} className="font-mono text-[11px] text-ink-secondary break-all bg-paper-sunk px-1.5 py-1 rounded">
                              <span className="text-ink-muted">{cmd.process_name ? `${cmd.process_name}: ` : ''}</span>
                              {cmd.command_line}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Quiet Line at the Bottom (DESIGN.md §5.7) */}
      <div className="pt-6 pb-2 border-t border-rule text-center">
        <p className="text-small text-ink-muted font-mono tracking-tight select-none">
          first event to complete narrative — {time_to_narrative_seconds}s
        </p>
      </div>
    </div>
  )
}
