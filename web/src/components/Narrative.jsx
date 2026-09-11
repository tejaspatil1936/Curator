export default function Narrative({
  narrative,
  selectedSeq,
  onSelectSentence,
  isLoading = false,
  onGenerateNarrative,
}) {
  if (isLoading) {
    return (
      <div className="py-12 max-w-[720px] text-ink-secondary" role="status">
        <p className="text-heading text-ink font-semibold">Reconstructing timeline…</p>
        <p className="mt-2 text-ui text-ink-muted">Correlating events and generating evidence-grounded narrative</p>
      </div>
    )
  }

  if (!narrative || narrative.length === 0) {
    return (
      <div className="py-12 max-w-[720px]">
        <p className="text-heading text-ink font-semibold">No narrative generated yet.</p>
        <p className="mt-2 text-body text-ink-muted">
          Generate an evidence-grounded narrative with MITRE ATT&CK technique mapping.
        </p>
        <button
          onClick={onGenerateNarrative}
          className="mt-6 inline-flex items-center px-4 py-2 bg-primary text-paper rounded text-ui font-medium hover:bg-primary-hover transition-colors"
        >
          Generate narrative
        </button>
      </div>
    )
  }

  return (
    <div className="max-w-[720px] space-y-4 py-4" role="region" aria-label="Incident narrative">
      {narrative.map((item) => {
        const isSelected = selectedSeq === item.seq
        const hasEvidence = item.evidence_event_ids && item.evidence_event_ids.length > 0
        const isSupported = item.verification
          ? item.verification.supported
          : (item.supported !== undefined ? item.supported : hasEvidence)
        const isUnsupported = isSupported === false

        return (
          <div key={item.seq} className="group">
            <button
              type="button"
              onClick={() => onSelectSentence(item)}
              aria-label={isUnsupported ? `Unsupported claim: ${item.text}` : item.text}
              className={`w-full text-left font-sans text-body transition-colors duration-120 block px-2.5 py-1.5 rounded-sm focus-visible:outline-none ${
                isSelected
                  ? `bg-evidence ${isUnsupported ? 'line-through text-ink/70' : 'text-ink'}`
                  : isUnsupported
                  ? 'text-ink-faint line-through hover:bg-paper-sunk'
                  : 'text-ink hover:bg-paper-sunk hover:underline hover:decoration-dotted hover:decoration-ink-faint'
              }`}
              style={{
                borderLeft: isSelected ? '2px solid var(--evidence-edge)' : '2px solid transparent',
              }}
            >
              {item.text}
            </button>

            {/* Unsupported warning label (DESIGN.md §5.2) */}
            {isUnsupported && (
              <div
                className="pl-5 pt-1 text-small text-unsupported font-medium select-none"
                title={item.verification?.reason || item.verification_reason || 'No supporting evidence'}
              >
                ⚠ No supporting evidence
              </div>
            )}

            {/* MITRE ATT&CK Technique Badge (DESIGN.md §5.2) */}
            {item.technique_id && !isUnsupported && (
              <div className="pl-5 pt-1">
                <span
                  className="font-mono text-mono-sm text-primary cursor-help select-none hover:underline"
                  title={item.technique_name || item.technique_id}
                >
                  ▸ {item.technique_id}
                </span>
                {item.technique_name && (
                  <span className="ml-2 text-small text-ink-muted opacity-0 group-hover:opacity-100 transition-opacity">
                    {item.technique_name}
                  </span>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
