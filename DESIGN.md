# Curator — Interface Design

> Supersedes Section 9 of `system_design.md`. Where the two disagree, this document
> wins. (Notably: the interface is **light**, not dark.)

---

## 1. What this interface is

An analyst opens Curator when 500 alerts have fired and they need to know which one
matters and whether they can believe what they're told.

So the interface has exactly two jobs:

1. **Rank** — make the important incident obvious within two seconds of page load.
2. **Prove** — let the analyst verify any claim in one click, without leaving the page.

Everything on screen serves one of those. Anything that serves neither gets cut.

### The governing idea

**Curator is a case file, not a dashboard.**

The product's argument is evidentiary: every sentence traced to a source, a tamper-evident
record, nothing asserted without proof. That is the vernacular of archives, legal
exhibits, and forensic reports — not of neon threat-intel consoles.

So the centre of the screen is a **document you read**, with a measured line length and
real leading. The evidence sits beside it like a reference volume. The interface should
feel closer to reading a well-set report than to operating a control panel.

This is also why the colour is calm. A tool whose purpose is to solve alert fatigue
should not itself be a wall of red.

---

## 2. The one memorable thing

**The highlighter.**

Click a sentence in the narrative. The evidence panel opens and the supporting log
line is washed in highlighter yellow — the same gesture as a researcher marking the
passage that backs a footnote.

That is the product's entire thesis expressed as one interaction. It is the only place
in the interface that uses yellow, the only place with a deliberate motion sequence, and
the only visual flourish anywhere.

**Everything else stays quiet so this lands.** If a new element competes with the
highlight for attention, the new element is wrong.

---

## 3. Tokens

### 3.1 Colour

```css
:root {
  /* surfaces */
  --canvas:        #F7F8FA;   /* app background — cool, not cream */
  --paper:         #FFFFFF;   /* content surfaces */
  --paper-sunk:    #F2F4F7;   /* inset areas, code blocks, table headers */

  /* ink */
  --ink:           #1A1D23;   /* primary text */
  --ink-secondary: #4B5563;   /* supporting text */
  --ink-muted:     #6B7280;   /* labels, metadata */
  --ink-faint:     #9CA3AF;   /* disabled, placeholder */

  /* structure */
  --rule:          #E3E6EB;   /* hairline borders — the main structural device */
  --rule-strong:   #CDD2DA;   /* emphasis borders, focused inputs */

  /* primary action — deep institutional blue */
  --primary:       #26408B;
  --primary-hover: #1D3170;
  --primary-wash:  #EDF1FA;

  /* ★ evidence — used NOWHERE else */
  --evidence:      #FDE68A;   /* the highlight wash */
  --evidence-edge: #D9A521;   /* left marker on a highlighted row */

  /* severity — deliberately muted */
  --sev-critical:  #B42318;
  --sev-high:      #B54708;
  --sev-medium:    #854D0E;
  --sev-low:       #6B7280;
  --sev-wash-crit: #FEF3F2;
  --sev-wash-high: #FFFAEB;

  /* verification */
  --unsupported:   #B42318;
  --verified:      #067647;
}
```

**Why these and not the obvious ones.** The base is a cool near-white, not the warm cream
that every generated page defaults to. The primary is a deep navy — the colour of
institutional documents, not of SaaS marketing. Severity colours are dark and desaturated
because an analyst reads them for eight hours; a bright alarm palette is exactly the
fatigue this product exists to solve. Yellow appears once, for one purpose.

**Rules:**
- Yellow is evidence. Never a warning, never a badge, never decoration.
- Severity colour appears as *text and a 2px left rule*, never as a filled block.
- No gradients anywhere. No coloured shadows. No tinted glass.

### 3.2 Type

**IBM Plex Sans** for everything readable. **IBM Plex Mono** for machine data.

One family, two widths. Plex was drawn for an engineering organisation — it carries
technical seriousness without novelty, and it is deliberately *not* Inter, which is the
house default of every generated dashboard.

```
Display   28px / 34px  / 600  / -0.02em   incident title
Heading   20px / 28px  / 600  / -0.01em   section heads
Subhead   15px / 22px  / 600              panel titles
Body      15px / 26px  / 400              narrative prose (note the leading)
UI        14px / 20px  / 400              controls, lists, tables
Small     13px / 18px  / 400              metadata
Mono      13px / 20px  / 400              IDs, IPs, hashes, command lines, paths
Mono-sm   12px / 18px  / 400              dense log tables
```

**Body is 15/26.** That is more leading than a dashboard usually gets, and it is the
point — the narrative is read, not scanned.

**Measure: 68–72 characters** in the narrative column. Do not let it stretch on wide
screens.

**Monospace is for data the analyst might copy** — event IDs, IP addresses, SHA-256
hashes, command lines, file paths, technique IDs, timestamps. It is never used for
decoration, and never for labels.

**Forbidden typographic moves** (these are the tells):
- ALL-CAPS tracked-out eyebrow labels above headings
- Metadata strung together with middle dots (`Host · User · Time`) — use a table or
  labelled pairs
- One word in a heading coloured or italicised for emphasis
- `→` appended to button or link text
- A label above content that only restates the content

### 3.3 Space and shape

4px base scale: `4 8 12 16 24 32 48 64`.

```css
--radius-sm: 3px;   /* badges, inputs */
--radius:    5px;   /* panels, cards */
--radius-lg: 8px;   /* drawer, modal */
```

Small radii. Large rounding reads consumer; this is a professional tool.

**Shadows: almost none.** Structure comes from hairline rules and surface contrast, not
from floating cards. Two shadows exist in the whole system:

```css
--shadow-drawer: -8px 0 24px rgba(16, 24, 40, 0.06);  /* evidence drawer only */
--shadow-pop:    0 4px 12px rgba(16, 24, 40, 0.08);   /* dropdowns, tooltips */
```

Nothing else has a shadow. No identical rounded cards with the same soft grey glow — that
kit is the single clearest generated-UI signature.

### 3.4 Two densities, on purpose

| Region | Density | Why |
| --- | --- | --- |
| Incident list, log tables, ATT&CK grid | Tight — 32–36px rows, 13px type | Scanning many items |
| Narrative, challenge, recommendations | Open — 26px leading, generous margin | Reading and judging |

Mixing these deliberately is what stops the interface feeling like a template applied
uniformly to different content.

---

## 4. Layout

```
┌───────────────────────────────────────────────────────────────────────────┐
│ Curator                          apt29 dataset     ●live    chain ok      │ 48px
├──────────────┬────────────────────────────────────────────────────────────┤
│              │                                                            │
│ 6 incidents  │  Credential theft on WIN-DC01, spreading to WIN-WS02        │
│ 1,247 alerts │  09:14 – 09:41 · 41 events from 312 alerts                  │
│              │  ──────────────────────────────────────────────────────     │
│ ┌──────────┐ │  Timeline   Narrative   ATT&CK   Challenge   Accuracy       │
│ │▌92 Cred… │ │  ──────────                                                 │
│ │  WIN-DC01│ │                                                            │
│ │  09:14   │ │  At 09:14:22 a PowerShell process started on WIN-DC01       │
│ └──────────┘ │  under the account j.rivera, launched by winword.exe.       │
│              │  ▸ T1059.001                                               │
│ ┌──────────┐ │                                                            │
│ │▌64 Persi…│ │  Four minutes later the same process wrote to the Run       │
│ │  WIN-WS02│ │  registry key, establishing persistence across reboots.     │
│ └──────────┘ │  ▸ T1547.001                                               │
│              │                                                            │
│ ┌──────────┐ │  ̶T̶h̶e̶ ̶a̶t̶t̶a̶c̶k̶e̶r̶ ̶e̶x̶f̶i̶l̶t̶r̶a̶t̶e̶d̶ ̶2̶.̶4̶ ̶G̶B̶ ̶t̶o̶ ̶a̶n̶ ̶e̶x̶t̶e̶r̶n̶a̶l̶ ̶h̶o̶s̶t̶.̶     │
│ │  31 Recon│ │  ⚠ No supporting evidence                                   │
│ └──────────┘ │                                                            │
│              │                                                            │
└──────────────┴────────────────────────────────────────────────────────────┘
     260px                        fluid, content max 720px

              Evidence drawer slides in from right when a sentence is clicked:

              ┌──────────────────────────────────────┐
              │ Evidence                          ×  │
              │ 2 events support this sentence       │
              │ ──────────────────────────────────── │
              │▌event 1182    Sysmon 1    09:14:22Z  │ ← yellow wash
              │ host      WIN-DC01                   │
              │ user      j.rivera                   │
              │ process   powershell.exe             │
              │ parent    winword.exe                │
              │ ──────────────────────────────────── │
              │ Raw                        [copy]    │
              │ { "EventID": 1, "UtcTime": "…" }     │
              └──────────────────────────────────────┘
                              420px
```

**Alignment:** everything left-aligned. No centred body text anywhere. The only centred
elements are the three headline numbers on the Accuracy view.

**Why three panes:** the analyst needs the ranked list persistently visible (that's the
triage job) while reading one case (that's the judgement job), with evidence arriving
beside the claim rather than replacing it. Losing the narrative to look at a log is the
exact failure this layout prevents.

---

## 5. Components

### 5.1 Incident list (left rail)

Each row: a 3px left rule in the severity colour, the priority number in mono, a title
truncated to two lines, then host and time in Small.

Selected row: `--paper` background, left rule thickens to 3px in `--primary`. Not a blue
fill, not a shadow.

The priority number is clickable → tooltip showing the `priority_reason` breakdown:

```
92  = 30  credential access
    + 25  two hosts involved
    + 20  lateral movement
    + 15  external connection
    +  2  tactic spread
```

Explainable prioritisation is a graded criterion. Make it visible, not buried.

**Header shows `1,247 alerts → 6 incidents`.** That ratio is a headline result; it lives
in the chrome, permanently.

### 5.2 Narrative — ★ the core component

A sentence is a `<button>`, not a `<span>` — it is interactive and must be reachable by
keyboard.

**Supported sentence.** Normal body text. On hover: a 1px dotted underline in
`--ink-faint` and a subtle `--paper-sunk` background. No colour change, no lift, no
shadow. The hover says "this is clickable" and nothing more.

**Selected sentence.** `--evidence` background wash, 2px `--evidence-edge` left border.
The sentence and its evidence are highlighted in the same yellow at the same moment —
that visual rhyme is what makes the link legible.

**Unsupported sentence.** `line-through`, `--ink-faint` text, and beneath it, indented, in
Small:

```
⚠ No supporting evidence
```

in `--unsupported`. Not a red box, not a toast, not an alert banner. Quiet and damning.

**Technique badge.** Inline after the sentence, on its own line, indented:
`▸ T1059.001` in Mono-sm, `--primary` — with the technique name appearing on hover. Not a
pill, not a coloured chip.

### 5.3 Evidence drawer

Slides in from the right, 420px, over a **transparent** scrim — the narrative must stay
readable while evidence is open. Do not dim the page.

Each event: a header row (`event 1182 · Sysmon 1 · timestamp` — as a labelled row, not a
dot-joined string), then a two-column field table, then the raw JSON in a
`--paper-sunk` block with a copy button.

The first evidence row carries the `--evidence` wash and the left edge marker.

Closes on `Esc`, on the ×, or on clicking another sentence (which re-fills it rather than
closing).

### 5.4 Timeline

A vertical rule down the left with event markers. Numbering **is** appropriate here — this
is a genuine sequence — so steps are numbered 1…n.

Row: mono timestamp, source badge, host, and a one-line summary. Clicking a row opens
the same evidence drawer.

Events belonging to a narrative sentence get a faint `--evidence` tick on the rule, so
the analyst can see which moments are cited and which are not.

### 5.5 ATT&CK grid

Tactics as columns, techniques as cells. Observed techniques get `--primary-wash` fill
and `--ink` text; unobserved stay `--paper` with `--ink-faint`. No heatmap gradient —
binary observed/not is the honest encoding, and a gradient would imply a confidence the
data doesn't have.

Cell shows the ID in Mono-sm; name on hover. Click → filters the narrative to sentences
mapped to that technique.

### 5.6 Challenge

Presented as a dialogue between two positions, because that is what it is.

```
Current reading                                   confidence 0.82
The account was compromised via a malicious document.

Counter-arguments
  1. A legitimate admin script produces the same parent-child chain.
  2. No network indicator confirms external delivery.

Missing evidence
  · Email gateway logs for the delivery vector
  · Process command line for the initial winword.exe

  [ Run the check ]
```

After the query runs: results appear inline and the confidence updates with a visible
transition — `0.82 → 0.61` — animating the number, not flashing the panel. The change
*is* the content.

### 5.7 Accuracy — the reveal

The one place with big centred numbers. Three, in Display at 48px:

```
        12                11                 0
   executed          recovered           invented
```

Below, two columns — ground truth and recovered — with ✓ / ✗ markers per technique.

`invented = 0` is the money number. Give it more weight than the others, and set it in
`--verified` when it is zero.

Below that, one quiet line: `first event to complete narrative — 94s`.

### 5.8 Chain status

In the top bar: `chain ok` with a small check, in `--verified`. Clicking opens a panel
listing recent audit rows with their hashes in Mono-sm.

Never animate this. It is a fact, not a feature.

---

## 6. Motion

**One orchestrated sequence exists**, the evidence reveal:

1. Sentence background transitions to `--evidence` — 120ms
2. Drawer slides in — 200ms, `cubic-bezier(0.32, 0.72, 0, 1)`
3. Evidence row wash fades in — 120ms, 80ms after the drawer settles

That stagger is what makes the link feel causal rather than coincidental.

**Everywhere else:**
- State changes: 120ms on colour only
- Confidence number: 400ms count transition
- New incident enters the list: 150ms fade, no slide

**Banned:** fade-and-slide-up on section entrance, hover lift or scale on cards, skeleton
shimmer, pulsing live indicators, animated gradients, spinners longer than 400ms (use a
determinate progress bar or a stable status line instead).

`prefers-reduced-motion: reduce` disables all of it; the highlight still applies
instantly.

---

## 7. Words

The interface is written for someone who knows security and is short on time.

**Do:**
- Sentence case everywhere. Never Title Case On Buttons.
- Name the action: `Run the check`, `Copy raw event`, `Isolate host (simulated)`.
- Plain nouns: "Evidence", "Timeline", "Counter-arguments".
- State facts without hedging: `No supporting evidence` — not "This claim may not be
  fully supported."

**Don't:**
- No exclamation marks. Nothing is exciting; things are true or they aren't.
- No "Oops" or apologies in errors. State what happened and what to do.
- No marketing verbs: nothing is "powerful", "seamless", or "intelligent".
- Never imply certainty the system lacks. `confidence 0.61`, not "likely malicious".

**Empty state**, incident list:
```
No incidents yet.
Load the sample dataset to begin.
[ Load apt29 dataset ]
```

**Loading the narrative** — never a blank panel:
```
Reconstructing timeline…
41 events correlated · generating narrative
```

**Error:**
```
Could not reach the investigation service.
Last successful update 09:41:18. Retrying every 5s.
```

**The simulated action label is mandatory.** Any containment button must read
`Isolate host (simulated)` and open a dialog that states no live system is touched.
Overstating capability in a security tool is a credibility failure in front of judges who
do this for a living.

---

## 8. Quality floor

- **Contrast:** body text ≥ 7:1, all UI text ≥ 4.5:1. The evidence yellow is a background
  under `--ink` — check it passes.
- **Focus:** 2px `--primary` outline at 2px offset. Visible on every interactive element,
  including narrative sentences. Never `outline: none`.
- **Keyboard:** `Tab` through sentences, `Enter` opens evidence, `Esc` closes the drawer,
  `↑`/`↓` move through the incident list.
- **Screen readers:** unsupported sentences carry
  `aria-label="Unsupported claim: {text}"`. The drawer is `role="complementary"` with
  `aria-live="polite"`.
- **Colour is never the only signal.** Severity carries a number. Unsupported carries
  strike-through and an icon. Evidence carries a left marker as well as the wash.
- **Responsive:** below 1280px the incident rail collapses to a toggle. Below 900px the
  drawer becomes full-width. It does not need to work on a phone — say so rather than
  faking it.
- **Presentation:** verify legibility at 1920×1080 projected. If the three accuracy
  numbers aren't readable from the back of a room, they're too small.

---

## 9. Explicitly not doing this

A checklist to run before any UI is called done. Each of these is a generated-interface
signature:

- [ ] No warm cream background with a serif display and a terracotta accent
- [ ] No near-black background with one acid accent
- [ ] No identical rounded cards with identical soft grey shadows
- [ ] No gradient washes, mesh backgrounds, or glassmorphism
- [ ] No ALL-CAPS tracked eyebrow labels
- [ ] No `A · B · C` dot-joined metadata strings
- [ ] No `→` in button text
- [ ] No emoji in the interface
- [ ] No one-word colour emphasis inside headings
- [ ] No `01 / 02 / 03` markers except on the timeline, which is a real sequence
- [ ] No hover lift, scale, or glow on any card
- [ ] No monospace used decoratively for labels — only for copyable machine data
- [ ] No spinner where a determinate state is available
- [ ] No Inter

---

## 10. Build order for the UI

1. Tokens as CSS custom properties; Tailwind config extends them. No arbitrary hex values
   in components, ever.
2. Shell: top bar, incident rail, tab strip. Static data.
3. **Narrative + evidence drawer.** Build this second-to-first; it is the product.
4. Timeline.
5. ATT&CK grid.
6. Challenge.
7. Accuracy.
8. Empty, loading, and error states for all of the above — not an afterthought.
9. Run the Section 9 checklist honestly and fix what fails.

Step 3 is where the hackathon is won. If the schedule slips, ship steps 1–4 polished
rather than 1–7 rough.
