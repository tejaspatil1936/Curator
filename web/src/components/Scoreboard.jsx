import { useEffect, useState } from 'react'
import { getAccuracy } from '../api.js'

export default function Scoreboard({ incidentId }) {
  const [data, setData] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

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
    invented = 0,
    precision = 0,
    recall = 0,
    time_to_narrative_seconds = 88,
    ground_truth_techniques = [],
    recovered_techniques = [],
  } = data

  const isInventedZero = invented === 0

  return (
    <div className="py-6 space-y-10" role="region" aria-label="Accuracy Scoreboard">
      {/* Three Big Centred Numbers (DESIGN.md §5.7) */}
      <div className="flex items-center justify-center gap-12 sm:gap-20 pt-4 pb-2 border-b border-rule">
        {/* Executed */}
        <div className="text-center min-w-[100px]">
          <div className="font-sans font-bold text-[48px] leading-tight text-ink tracking-tight">
            {executed}
          </div>
          <div className="mt-1 text-small text-ink-muted uppercase tracking-wider font-medium">
            executed
          </div>
        </div>

        {/* Recovered */}
        <div className="text-center min-w-[100px]">
          <div className="font-sans font-bold text-[48px] leading-tight text-ink tracking-tight">
            {recovered}
          </div>
          <div className="mt-1 text-small text-ink-muted uppercase tracking-wider font-medium">
            recovered
          </div>
        </div>

        {/* Invented - Visual Weight & --verified when zero */}
        <div className="text-center min-w-[100px]">
          <div
            className={`font-sans font-bold text-[48px] leading-tight tracking-tight ${
              isInventedZero ? 'text-verified font-extrabold' : 'text-unsupported'
            }`}
          >
            {invented}
          </div>
          <div
            className={`mt-1 text-small uppercase tracking-wider font-semibold ${
              isInventedZero ? 'text-verified' : 'text-unsupported'
            }`}
          >
            invented
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
                  className="flex items-baseline justify-between p-2 rounded bg-paper hover:bg-paper-sunk border border-rule/60 transition-colors text-small"
                >
                  <div className="flex items-baseline gap-2 min-w-0 pr-2">
                    <span
                      className={`font-mono text-mono-sm font-semibold flex-shrink-0 ${
                        isExact
                          ? 'text-verified'
                          : isParentChild
                          ? 'text-amber-600'
                          : 'text-ink-faint'
                      }`}
                    >
                      {isExact && '✓'}
                      {isParentChild && '⚠'}
                      {isMissed && '✗'}
                    </span>
                    <span className="font-mono text-primary font-medium text-mono-sm flex-shrink-0">
                      {gt.technique_id}
                    </span>
                    <span className="truncate text-ink" title={gt.name}>
                      {gt.name}
                    </span>
                  </div>
                  <span className="text-mono-sm font-mono text-ink-muted flex-shrink-0" title={gt.step}>
                    {gt.step}
                  </span>
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
              const isInvented = rec.match_type === 'invented'

              return (
                <div
                  key={idx}
                  className="flex items-baseline justify-between p-2 rounded bg-paper hover:bg-paper-sunk border border-rule/60 transition-colors text-small"
                >
                  <div className="flex items-baseline gap-2 min-w-0 pr-2">
                    <span
                      className={`font-mono text-mono-sm font-semibold flex-shrink-0 ${
                        isExact
                          ? 'text-verified'
                          : isParentChild
                          ? 'text-amber-600'
                          : 'text-unsupported'
                      }`}
                    >
                      {isExact && '✓'}
                      {isParentChild && '⚠'}
                      {isInvented && '✗'}
                    </span>
                    <span className="font-mono text-primary font-medium text-mono-sm flex-shrink-0">
                      {rec.technique_id}
                    </span>
                    <span className="truncate text-ink" title={rec.name}>
                      {rec.name}
                    </span>
                  </div>
                  <span className="text-mono-sm font-mono text-ink-muted flex-shrink-0">
                    {isExact && 'exact'}
                    {isParentChild && 'parent/child'}
                    {isInvented && (
                      <span className="text-unsupported font-medium">untracked</span>
                    )}
                  </span>
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
