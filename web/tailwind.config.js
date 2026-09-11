// Every value maps onto a DESIGN.md §3 custom property defined in src/index.css.
// index.css is the only place a hex value may appear; components use these utilities.

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      // §3.1 colour
      colors: {
        canvas: 'var(--canvas)',
        paper: {
          DEFAULT: 'var(--paper)',
          sunk: 'var(--paper-sunk)',
        },
        ink: {
          DEFAULT: 'var(--ink)',
          secondary: 'var(--ink-secondary)',
          muted: 'var(--ink-muted)',
          faint: 'var(--ink-faint)',
        },
        rule: {
          DEFAULT: 'var(--rule)',
          strong: 'var(--rule-strong)',
        },
        primary: {
          DEFAULT: 'var(--primary)',
          hover: 'var(--primary-hover)',
          wash: 'var(--primary-wash)',
        },
        // Evidence only. Never a warning, badge, or decoration.
        evidence: {
          DEFAULT: 'var(--evidence)',
          edge: 'var(--evidence-edge)',
        },
        sev: {
          critical: 'var(--sev-critical)',
          high: 'var(--sev-high)',
          medium: 'var(--sev-medium)',
          low: 'var(--sev-low)',
          'wash-crit': 'var(--sev-wash-crit)',
          'wash-high': 'var(--sev-wash-high)',
        },
        unsupported: 'var(--unsupported)',
        verified: 'var(--verified)',
      },
      // Bare `border` draws the hairline rule.
      borderColor: {
        DEFAULT: 'var(--rule)',
      },

      // §3.2 type
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        display: ['28px', { lineHeight: '34px', letterSpacing: '-0.02em', fontWeight: '600' }],
        heading: ['20px', { lineHeight: '28px', letterSpacing: '-0.01em', fontWeight: '600' }],
        subhead: ['15px', { lineHeight: '22px', fontWeight: '600' }],
        body: ['15px', { lineHeight: '26px', fontWeight: '400' }],
        ui: ['14px', { lineHeight: '20px', fontWeight: '400' }],
        small: ['13px', { lineHeight: '18px', fontWeight: '400' }],
        mono: ['13px', { lineHeight: '20px', fontWeight: '400' }],
        'mono-sm': ['12px', { lineHeight: '18px', fontWeight: '400' }],
      },

      // §3.3 shape. Tailwind's default spacing is already the 4px scale.
      borderRadius: {
        sm: 'var(--radius-sm)',
        DEFAULT: 'var(--radius)',
        lg: 'var(--radius-lg)',
      },
      boxShadow: {
        drawer: 'var(--shadow-drawer)',
        pop: 'var(--shadow-pop)',
      },
    },
  },
  plugins: [],
}
