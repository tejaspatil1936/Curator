import { useEffect, useState } from 'react'

export default function EvidencePanel({
  isOpen,
  onClose,
  sentence,
  evidenceEvents = [],
  isLoading = false,
}) {
  const [copiedId, setCopiedId] = useState(null)
  const [evidenceWashActive, setEvidenceWashActive] = useState(false)

  // Orchestrated motion sequence (DESIGN.md §6):
  // 1. Sentence background transitions to --evidence (120ms)
  // 2. Drawer slides in (200ms cubic-bezier(0.32, 0.72, 0, 1))
  // 3. Evidence row wash fades in (120ms, starting 80ms after drawer settles)
  useEffect(() => {
    if (isOpen) {
      setEvidenceWashActive(false)
      const timer = setTimeout(() => {
        setEvidenceWashActive(true)
      }, 280) // 200ms slide + 80ms settle
      return () => clearTimeout(timer)
    } else {
      setEvidenceWashActive(false)
    }
  }, [isOpen, sentence?.seq])

  // Close on Esc
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  return (
    <>
      {/* Transparent scrim — narrative stays visible and readable (DESIGN.md §5.3) */}
      <div
        className="fixed inset-0 z-40 bg-transparent"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* 420px Drawer sliding from right with cubic-bezier */}
      <aside
        role="complementary"
        aria-label="Supporting evidence"
        aria-live="polite"
        className="fixed right-0 top-12 bottom-0 w-[420px] z-50 bg-paper border-l border-rule shadow-drawer flex flex-col transition-transform duration-200 ease-[cubic-bezier(0.32,0.72,0,1)] translate-x-0"
      >
        {/* Drawer Header */}
        <div className="h-14 border-b border-rule px-5 flex items-center justify-between flex-shrink-0">
          <div>
            <h2 className="text-subhead text-ink font-semibold">Evidence</h2>
            <p className="text-small text-ink-muted">
              {isLoading
                ? 'Loading telemetry records…'
                : sentence?.supported === false || sentence?.verification?.supported === false
                ? `${evidenceEvents.length} event${evidenceEvents.length === 1 ? '' : 's'} cited · Claim unsupported`
                : `${evidenceEvents.length} event${evidenceEvents.length === 1 ? '' : 's'} support this sentence`}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-ink-secondary hover:text-ink p-1.5 rounded-sm hover:bg-paper-sunk focus-visible:outline-none"
            aria-label="Close evidence panel"
          >
            <span className="text-heading leading-none">×</span>
          </button>
        </div>

        {/* Evidence List */}
        <div className="flex-1 overflow-y-auto divide-y divide-rule p-5 space-y-6">
          {(sentence?.supported === false || sentence?.verification?.supported === false) && (
            <div className="p-3 bg-unsupported/10 border border-unsupported/30 rounded text-small text-unsupported">
              <span className="font-semibold block mb-0.5">⚠ Claim unsupported by cited evidence</span>
              <span className="text-ink-secondary text-small block">
                {sentence?.verification?.reason || sentence?.verification_reason || 'The cited events do not substantiate the claim.'}
              </span>
            </div>
          )}

          {isLoading ? (
            <div className="py-8 text-center text-small text-ink-muted">
              Retrieving byte-identical telemetry…
            </div>
          ) : evidenceEvents.length === 0 ? (
            <div className="py-8 text-center text-small text-ink-muted">
              No evidence records returned for this claim.
            </div>
          ) : (
            evidenceEvents.map((ev, idx) => {
              const isFirst = idx === 0
              let parsedJson = null
              try {
                parsedJson = JSON.parse(ev.raw)
              } catch {
                parsedJson = null
              }

              return (
                <div
                  key={ev.id}
                  className={`pt-4 first:pt-0 transition-colors duration-120 ${
                    isFirst && evidenceWashActive ? 'bg-evidence/30 -mx-3 px-3 py-2 rounded' : ''
                  }`}
                  style={{
                    borderLeft:
                      isFirst && evidenceWashActive
                        ? '3px solid var(--evidence-edge)'
                        : '3px solid transparent',
                  }}
                >
                  {/* Labelled header row */}
                  <div className="flex items-center justify-between text-mono-sm font-mono text-ink">
                    <span className="font-semibold text-primary">event {ev.id}</span>
                    <span className="text-ink-secondary">
                      {ev.source} {ev.event_code ? `EventID ${ev.event_code}` : ''}
                    </span>
                    <span className="text-ink-muted">{ev.ts ? ev.ts.substring(11, 19) + 'Z' : ''}</span>
                  </div>

                  {/* Metadata field table */}
                  <table className="mt-3 w-full text-small text-ink font-sans">
                    <tbody className="divide-y divide-rule/50">
                      {ev.host && (
                        <tr>
                          <td className="py-1 text-ink-muted w-20">host</td>
                          <td className="py-1 font-mono text-mono-sm text-ink truncate">{ev.host}</td>
                        </tr>
                      )}
                      {parsedJson?.user_name && (
                        <tr>
                          <td className="py-1 text-ink-muted w-20">user</td>
                          <td className="py-1 font-mono text-mono-sm text-ink truncate">
                            {parsedJson.user_name}
                          </td>
                        </tr>
                      )}
                      {parsedJson?.process_name && (
                        <tr>
                          <td className="py-1 text-ink-muted w-20">process</td>
                          <td className="py-1 font-mono text-mono-sm text-ink truncate">
                            {parsedJson.process_name}
                          </td>
                        </tr>
                      )}
                      {parsedJson?.command_line && (
                        <tr>
                          <td className="py-1 text-ink-muted w-20 align-top">cmd</td>
                          <td className="py-1 font-mono text-[11px] text-ink break-all">
                            {parsedJson.command_line}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>

                  {/* Byte-identical Raw Text in --paper-sunk block */}
                  <div className="mt-3">
                    <div className="flex items-center justify-between text-[11px] text-ink-muted mb-1">
                      <span className="font-mono">Raw telemetry (unmodified)</span>
                      <button
                        onClick={() => copyToClipboard(ev.raw, ev.id)}
                        className="text-primary hover:text-primary-hover font-mono underline focus-visible:outline-none"
                      >
                        {copiedId === ev.id ? 'Copied' : 'Copy raw event'}
                      </button>
                    </div>
                    <pre className="p-2.5 rounded bg-paper-sunk border border-rule font-mono text-[11px] text-ink overflow-x-auto max-h-48 whitespace-pre-wrap break-all select-all">
                      {ev.raw}
                    </pre>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </aside>
    </>
  )
}
