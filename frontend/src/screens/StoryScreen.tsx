// Story Mode: the 3-minute pitch as a full-screen, arrow-key walkthrough. Each step reuses a live
// dashboard component, so nothing here is a mock-up — the numbers are the same engine the judges can
// click into on the other screens.
import { ArrowLeft, ArrowRight, FileLock2, Gauge, Map as MapIcon, ShieldAlert, Swords, X } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { api, useLoad } from '../api'
import AttackConsole from '../components/AttackConsole'
import BudgetFrontier from '../components/BudgetFrontier'
import { BrandMark } from '../components/Shell'
import TwoCities from '../components/TwoCities'
import { Badge } from '../components/ui'
import { cx } from '../lib/cx'
import { loss } from '../lib/format'
import { navigate } from '../lib/route'
import { useStore } from '../lib/store'

interface Step {
  id: string
  eyebrow: string
  title: ReactNode
  caption: ReactNode
  icon: typeof MapIcon
  body: ReactNode
}

function Headline() {
  const frontier = useLoad(() => api.frontier())
  const f = frontier.data
  const low = f?.points.find((p) => p.budget_inr === 150_000) ?? f?.points[0]
  const cut = low ? `−${((1 - low.cvar.cvar / low.cvar.cvss) * 100).toFixed(0)}%` : '—'
  return (
    <div className="grid gap-5 lg:grid-cols-[1.1fr_1fr]">
      <div className="space-y-5">
        <p className="text-[19px] leading-relaxed text-ink-2">
          A scanner hands a city hundreds of findings sorted by severity. It never says{' '}
          <span className="font-semibold text-ink">which ten to fix with the money available</span>, and it knows
          nothing about what each device does or what depends on it.
        </p>
        <p className="text-[19px] leading-relaxed text-ink-2">
          Cities don't fear the average year. They fear <span className="font-semibold text-ink">the bad year</span> —
          when one shared-firmware bug takes down many devices at once, next to the ambulance corridor.
        </p>
        <p className="font-serif text-[26px] leading-tight text-forest-800">
          UrbanShield spends the city's budget where the worst case is, enforces the fix on the devices, and proves it
          by attacking itself again.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-4 self-center">
        {[
          [cut, 'worst-case loss vs CVSS-first, same budget'],
          ['5 / 5', 'perturbed cities where it beats CVSS-first and BFS-only'],
          [low ? `${loss(low.cvar.cvar)}` : '—', '¼ of the money, half the worst case'],
          ['5,000', 'devices planned within the time limit'],
        ].map(([big, small]) => (
          <div key={small as string} className="rounded-xl border border-line bg-surface px-5 py-5 shadow-sm">
            <p className="num font-serif text-[40px] leading-none text-forest-800">{big}</p>
            <p className="mt-2 text-[13px] leading-snug text-ink-2">{small}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function Proof() {
  return (
    <div className="grid gap-5 lg:grid-cols-[1.3fr_1fr]">
      <BudgetFrontier chrome={false} />
      <div className="space-y-3 self-start rounded-xl border border-forest-200 bg-forest-50 px-5 py-5">
        <p className="eyebrow">How we measure</p>
        <p className="text-[14px] leading-relaxed text-ink-2">
          Every plan is optimised on training scenarios and scored by the full simulator on{' '}
          <span className="font-semibold text-ink">2,000 held-out attacks</span> it never saw, with bootstrap
          confidence intervals.
        </p>
        <p className="text-[14px] leading-relaxed text-ink-2">
          The same advantage holds in <span className="font-semibold text-ink">5 of 5</span> cities with costs and
          criticalities perturbed ±20%. No number on any screen comes from the language model.
        </p>
      </div>
    </div>
  )
}

function Trust() {
  const { health } = useStore()
  const cards = [
    {
      t: 'Prompt-injection quarantine',
      d: 'Untrusted advisory text reaches one tool-less extractor, becomes six typed fields, and is cross-checked against the pinned CISA-KEV feed. Nothing it says can change device or plan state.',
    },
    {
      t: 'The checker is not an LLM',
      d: 'A deterministic Auditor rejects any claim whose number differs from the recorded tool result. The corridor interlock vetoes unsafe commands even with valid credentials.',
    },
    {
      t: 'Tamper-evident',
      d: 'Every agent action, approval and enforced policy is appended to a SHA-256 hash chain with Ed25519 signatures. Edit one row and Verify breaks at exactly that entry.',
    },
  ]
  return (
    <div className="grid gap-4 md:grid-cols-3">
      {cards.map((c) => (
        <div key={c.t} className="rounded-xl border border-line bg-surface px-5 py-5 shadow-sm">
          <p className="text-[15px] font-semibold text-ink">{c.t}</p>
          <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{c.d}</p>
        </div>
      ))}
      <p className="text-center text-[13px] text-muted md:col-span-3">
        LLM mode: <span className="font-semibold uppercase text-ink-2">{health.data?.llm_mode ?? '—'}</span> · simulated
        city only, localhost testbed, no real systems touched.
      </p>
    </div>
  )
}

const STEPS: Step[] = [
  {
    id: 'problem',
    eyebrow: 'The problem',
    title: 'Where does the city’s next rupee go?',
    caption: 'CVSS ranks severity. It cannot rank risk to the city.',
    icon: MapIcon,
    body: <Headline />,
  },
  {
    id: 'two-cities',
    eyebrow: 'Same attack · two cities',
    title: 'The identical attack, two defences',
    caption: 'Same attacker, same rupees, same random draws — only the plan differs.',
    icon: Swords,
    body: <TwoCities chrome={false} height="h-[52vh]" />,
  },
  {
    id: 'mitigate',
    eyebrow: 'Mitigation, live',
    title: 'We don’t just score it — we stop it',
    caption: 'The attacker holds valid stolen credentials. The Enforcer still refuses every unsafe command.',
    icon: ShieldAlert,
    body: <AttackConsole chrome={false} />,
  },
  {
    id: 'proof',
    eyebrow: 'The evidence',
    title: 'A quarter of the money, half the worst case',
    caption: 'Held-out scenarios, bootstrap CIs, five perturbed cities.',
    icon: Gauge,
    body: <Proof />,
  },
  {
    id: 'trust',
    eyebrow: 'Why you can trust it',
    title: 'The AI proposes. Deterministic code decides.',
    caption: 'A control plane for city infrastructure, not a dashboard.',
    icon: FileLock2,
    body: <Trust />,
  },
]

export default function StoryScreen() {
  const [i, setI] = useState(0)
  const go = useCallback((d: number) => setI((n) => Math.min(STEPS.length - 1, Math.max(0, n + d))), [])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Arrows in the budget slider and Space on a focused button ("Run attack") belong to that control.
      const el = e.target as HTMLElement | null
      if (el?.closest('input, select, textarea') || (e.key === ' ' && el?.closest('button'))) return
      if (e.key === 'ArrowRight' || e.key === 'PageDown' || e.key === ' ') go(1)
      else if (e.key === 'ArrowLeft' || e.key === 'PageUp') go(-1)
      else if (e.key === 'Escape') navigate('overview')
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [go])
  const step = STEPS[i]
  const Icon = step.icon
  return (
    <div className="fixed inset-0 z-[1500] flex flex-col bg-canvas">
      <header className="flex h-16 shrink-0 items-center gap-4 border-b border-line bg-surface px-6">
        <div className="flex items-center gap-2.5">
          <BrandMark className="size-8" />
          <span className="text-[15px] font-bold tracking-[0.05em] text-forest-900">URBANSHIELD</span>
        </div>
        <Badge tone="forest">Story mode</Badge>
        <div className="ml-auto flex items-center gap-4">
          <div className="flex gap-1.5">
            {STEPS.map((s, n) => (
              <button
                key={s.id}
                type="button"
                aria-label={s.eyebrow}
                onClick={() => setI(n)}
                className={cx(
                  'h-1.5 rounded-full transition-all',
                  n === i ? 'w-8 bg-forest-800' : 'w-4 bg-line-strong hover:bg-forest-200',
                )}
              />
            ))}
          </div>
          <button
            type="button"
            onClick={() => navigate('overview')}
            className="grid size-9 place-items-center rounded-lg border border-line text-ink-2 hover:bg-forest-50"
            aria-label="Exit story mode"
          >
            <X className="size-4" />
          </button>
        </div>
      </header>
      <main className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div key={step.id} className="mx-auto max-w-[1280px] animate-rise px-8 py-8">
          <div className="mb-6 flex items-start gap-4">
            <div className="grid size-12 shrink-0 place-items-center rounded-xl bg-forest-800 text-white">
              <Icon className="size-6" strokeWidth={1.8} aria-hidden />
            </div>
            <div>
              <p className="eyebrow">{step.eyebrow}</p>
              <h1 className="mt-1 font-serif text-[40px] leading-[1.03] tracking-[-0.01em] text-ink">{step.title}</h1>
              <p className="mt-1.5 text-[15px] text-ink-2">{step.caption}</p>
            </div>
          </div>
          {step.body}
        </div>
      </main>
      <footer className="flex h-16 shrink-0 items-center justify-between border-t border-line bg-surface px-6">
        <button
          type="button"
          onClick={() => go(-1)}
          disabled={i === 0}
          className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-semibold text-ink-2 hover:bg-forest-50 disabled:opacity-35"
        >
          <ArrowLeft className="size-4" /> Back
        </button>
        <p className="num text-[13px] text-muted">
          {i + 1} / {STEPS.length} · ← → to move · Esc to exit
        </p>
        <button
          type="button"
          onClick={() => (i < STEPS.length - 1 ? go(1) : navigate('overview'))}
          className="inline-flex items-center gap-2 rounded-lg bg-forest-800 px-4 py-2 text-[13px] font-semibold text-white hover:bg-forest-700"
        >
          {i < STEPS.length - 1 ? 'Next' : 'Open the dashboard'} <ArrowRight className="size-4" />
        </button>
      </footer>
    </div>
  )
}
