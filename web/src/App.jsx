import { useEffect, useState } from 'react'
import {
  getAuditStatus,
  getEvidence,
  getIncident,
  getIncidents,
  generateNarrative,
} from './api.js'
import IncidentList from './components/IncidentList.jsx'
import Narrative from './components/Narrative.jsx'
import EvidencePanel from './components/EvidencePanel.jsx'

export default function App() {
  const [incidents, setIncidents] = useState([])
  const [selectedIncidentId, setSelectedIncidentId] = useState(null)
  const [currentIncident, setCurrentIncident] = useState(null)
  const [auditStatus, setAuditStatus] = useState({ valid: true, rows: 0 })
  const [selectedSentence, setSelectedSentence] = useState(null)
  const [evidenceEvents, setEvidenceEvents] = useState([])
  const [isEvidenceOpen, setIsEvidenceOpen] = useState(false)
  const [isLoadingEvidence, setIsLoadingEvidence] = useState(false)
  const [isLoadingNarrative, setIsLoadingNarrative] = useState(false)
  const [activeTab, setActiveTab] = useState('narrative')

  // Initial load: fetch incidents list and audit chain status
  useEffect(() => {
    async function init() {
      try {
        const [incs, audit] = await Promise.all([
          getIncidents(),
          getAuditStatus().catch(() => ({ valid: true, rows: 0 })),
        ])
        setIncidents(incs)
        setAuditStatus(audit)
        if (incs.length > 0) {
          // Select top surfaced incident by default
          setSelectedIncidentId(incs[0].id)
        }
      } catch (err) {
        console.error('Failed to load initial data:', err)
      }
    }
    init()
  }, [])

  // Load full incident details when selection changes
  useEffect(() => {
    if (!selectedIncidentId) return
    let cancelled = false

    async function loadIncident() {
      try {
        const data = await getIncident(selectedIncidentId)
        if (cancelled) return
        setCurrentIncident(data)
        setSelectedSentence(null)
        setIsEvidenceOpen(false)
        setEvidenceEvents([])
      } catch (err) {
        console.error('Failed to load incident detail:', err)
      }
    }

    loadIncident()
    return () => {
      cancelled = true
    }
  }, [selectedIncidentId])

  // Handle clicking a narrative sentence -> open evidence drawer
  const handleSelectSentence = async (sentence) => {
    setSelectedSentence(sentence)
    setIsEvidenceOpen(true)

    const eids = sentence.evidence_event_ids || []
    if (eids.length === 0) {
      setEvidenceEvents([])
      return
    }

    setIsLoadingEvidence(true)
    try {
      const rows = await getEvidence(eids.join(','), selectedIncidentId)
      setEvidenceEvents(rows)
    } catch (err) {
      console.error('Failed to fetch evidence:', err)
      setEvidenceEvents([])
    } finally {
      setIsLoadingEvidence(false)
    }
  }

  // Handle generating narrative on demand
  const handleGenerateNarrative = async () => {
    if (!selectedIncidentId) return
    setIsLoadingNarrative(true)
    try {
      await generateNarrative(selectedIncidentId)
      const refreshed = await getIncident(selectedIncidentId)
      setCurrentIncident(refreshed)
      // Also update title in incident list
      const updatedList = await getIncidents()
      setIncidents(updatedList)
    } catch (err) {
      console.error('Failed to generate narrative:', err)
    } finally {
      setIsLoadingNarrative(false)
    }
  }

  const inc = currentIncident?.incident
  const narrative = currentIncident?.narrative || []

  return (
    <div className="min-h-screen bg-canvas text-ink font-sans antialiased flex flex-col selection:bg-evidence">
      {/* Top Bar (DESIGN.md §4 — 48px hairline) */}
      <header className="h-12 border-b border-rule bg-paper px-5 flex items-center justify-between flex-shrink-0 z-30">
        <div className="flex items-center gap-4">
          <span className="text-subhead font-semibold text-ink tracking-tight">Curator</span>
          <span className="text-mono-sm font-mono text-ink-muted px-2 py-0.5 rounded bg-paper-sunk border border-rule">
            apt29 dataset
          </span>
        </div>

        <div className="flex items-center gap-5 text-small">
          <span className="flex items-center gap-1.5 text-ink-secondary">
            <span className="inline-block w-2 h-2 rounded-full bg-verified"></span>
            live
          </span>
          <span className="flex items-center gap-1 text-verified font-mono text-mono-sm">
            ✓ chain ok ({auditStatus.rows} rows)
          </span>
        </div>
      </header>

      {/* Main Workspace: Left Rail + Center Case File + Evidence Drawer */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Left Rail (IncidentList) */}
        <IncidentList
          incidents={incidents}
          selectedId={selectedIncidentId}
          onSelectIncident={setSelectedIncidentId}
          totalAlertsCount={666}
        />

        {/* Center Case File Document View */}
        <main className="flex-1 overflow-y-auto px-8 py-8 flex justify-center bg-canvas">
          <div className="w-full max-w-[720px]">
            {inc ? (
              <>
                {/* Incident Title (Display 28px/34px/600/-0.02em) */}
                <h1 className="text-display text-ink font-semibold">
                  {inc.title || `Incident #${inc.id}`}
                </h1>

                {/* Metadata row (Time · Events · Alerts) */}
                <div className="mt-2 text-small text-ink-secondary font-sans flex items-center gap-3">
                  <span>
                    {inc.first_seen ? inc.first_seen.substring(11, 16) : ''} –{' '}
                    {inc.last_seen ? inc.last_seen.substring(11, 16) : ''}
                  </span>
                  <span>·</span>
                  <span>
                    {inc.event_count} events from {inc.raw_alert_count} alerts
                  </span>
                  <span>·</span>
                  <span className="font-mono text-mono-sm text-ink-muted">
                    {(inc.hosts || []).join(', ')}
                  </span>
                </div>

                {/* Tab Strip */}
                <div className="mt-6 border-b border-rule flex gap-6 text-ui font-medium">
                  {['narrative', 'timeline', 'attack', 'challenge', 'accuracy'].map((tab) => {
                    const isActive = activeTab === tab
                    return (
                      <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`pb-2.5 transition-colors capitalize ${
                          isActive
                            ? 'text-ink border-b-2 border-primary font-semibold'
                            : 'text-ink-muted hover:text-ink'
                        }`}
                      >
                        {tab === 'attack' ? 'ATT&CK' : tab}
                      </button>
                    )
                  })}
                </div>

                {/* Active Tab Content */}
                <div className="mt-6">
                  {activeTab === 'narrative' && (
                    <Narrative
                      narrative={narrative}
                      selectedSeq={selectedSentence?.seq}
                      onSelectSentence={handleSelectSentence}
                      isLoading={isLoadingNarrative}
                      onGenerateNarrative={handleGenerateNarrative}
                    />
                  )}

                  {activeTab === 'timeline' && (
                    <div className="py-8 text-ink-secondary text-ui">
                      <p className="font-semibold text-ink mb-2">Deterministic Timeline</p>
                      <div className="border-l-2 border-rule pl-4 space-y-3">
                        {(currentIncident?.timeline || []).slice(0, 15).map((t, idx) => (
                          <div key={idx} className="text-small">
                            <span className="font-mono text-ink-muted mr-3">
                              {t.ts ? t.ts.substring(11, 19) + 'Z' : ''}
                            </span>
                            <span className="text-ink font-medium">{t.source}</span>:{' '}
                            <span className="text-ink-secondary">{t.summary}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeTab === 'attack' && (
                    <div className="py-8 text-ink-secondary text-ui">
                      <p className="font-semibold text-ink mb-2">MITRE ATT&CK Matrix Grounding</p>
                      <div className="grid grid-cols-2 gap-3 mt-4">
                        {narrative
                          .filter((n) => n.technique_id)
                          .map((n, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded bg-paper border border-rule flex items-baseline justify-between"
                            >
                              <div>
                                <span className="font-mono text-primary font-semibold">
                                  {n.technique_id}
                                </span>
                                <div className="text-small text-ink mt-0.5">
                                  {n.technique_name || 'Mapped technique'}
                                </div>
                              </div>
                              <span className="text-mono-sm font-mono text-ink-muted">
                                {n.technique_conf ? `${Math.round(n.technique_conf * 100)}%` : ''}
                              </span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {activeTab === 'challenge' && (
                    <div className="py-8 text-ink-secondary text-ui">
                      <p className="font-semibold text-ink mb-2">Adversarial Challenge Dialogue</p>
                      <p className="text-small text-ink-muted">
                        Available in Step 5 adversarial challenge verification.
                      </p>
                    </div>
                  )}

                  {activeTab === 'accuracy' && (
                    <div className="py-8 text-ink-secondary text-ui">
                      <p className="font-semibold text-ink mb-2">Evaluation Accuracy Ground Truth</p>
                      <p className="text-small text-ink-muted">
                        Available in Step 6 accuracy verification harness.
                      </p>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="py-16 text-center text-ink-muted">
                Select an incident from the left rail to view the investigation case file.
              </div>
            )}
          </div>
        </main>

        {/* Evidence Drawer Panel (DESIGN.md §5.3) */}
        <EvidencePanel
          isOpen={isEvidenceOpen}
          onClose={() => {
            setIsEvidenceOpen(false)
            setSelectedSentence(null)
          }}
          sentence={selectedSentence}
          evidenceEvents={evidenceEvents}
          isLoading={isLoadingEvidence}
        />
      </div>
    </div>
  )
}
