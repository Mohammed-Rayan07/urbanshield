// Response & Mitigation: the live agent loop, from a pasted advisory to controls applied in the twin.
import {
  AlertOctagon,
  ArrowRight,
  Bot,
  Check,
  ChevronDown,
  CircleDollarSign,
  Clock3,
  Crosshair,
  KeyRound,
  ListChecks,
  Loader2,
  Network,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Swords,
  TriangleAlert,
  WifiOff,
  Wrench,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import CityMap from '../components/CityMap'
import {
  Badge,
  Button,
  Card,
  CardHeader,
  CountUp,
  Delta,
  Dot,
  Empty,
  Kpi,
  Metric,
  PageHeader,
  Segmented,
  Skeleton,
  type Tone,
} from '../components/ui'
import { cx } from '../lib/cx'
import { C } from '../lib/colors'
import { family, riskById, sum } from '../lib/derive'
import {
  AGENT_LABEL,
  CATEGORY_PLURAL,
  CONTROL_LABEL,
  change,
  clock,
  hours,
  inr,
  inrShort,
  int,
  loss,
  pct,
  plural,
  share,
} from '../lib/format'
import { STAGES, type Hole, type StageStatus } from '../lib/run'
import { useRoute } from '../lib/route'
import { useStore } from '../lib/store'
import type { AgentEvent, AgentName, ControlKind, Device } from '../types'

const AGENT_TONE: Record<AgentName, { color: string; tone: Tone }> = {
  sentinel: { color: C.info, tone: 'info' },
  analyst: { color: '#b07a0f', tone: 'warn' },
  planner: { color: C.forest800, tone: 'forest' },
  redteam: { color: C.danger, tone: 'danger' },
  auditor: { color: C.ink2, tone: 'neutral' },
  human: { color: C.high, tone: 'high' },
  system: { color: C.muted, tone: 'neutral' },
}

const CONTROL_ICON: Record<ControlKind, LucideIcon> = {
  patch: Wrench,
  segment: Network,
  disable_remote: WifiOff,
  rotate_creds: KeyRound,
  virtual_patch: ShieldHalf,
}

const KIND_LABEL = { normal: 'Normal advisories', poisoned: 'Poisoned (prompt injection)', wrong: 'Valid-looking but wrong' } as const
const DEFAULT_CONSTRAINT = 'Surathkal festival this weekend, no streetlight downtime'

// ------------------------------------------------------------------ pipeline

function Stepper(props: { stages: Record<string, StageStatus>; running: boolean }) {
  return (
    <ol className="grid grid-cols-3 gap-y-4 md:grid-cols-6">
      {STAGES.map((s, i) => {
        const st = props.stages[s.id]
        const color =
          st === 'done' ? C.forest800 : st === 'active' ? C.forest700 : st === 'warn' ? C.warn : st === 'failed' ? C.danger : C.lineStrong
        const next = STAGES[i + 1] ? props.stages[STAGES[i + 1].id] : null
        const filled = st === 'done' || st === 'warn'
        return (
          <li key={s.id} className="relative flex flex-col items-center text-center">
            {i < STAGES.length - 1 && (
              <span className="absolute left-[calc(50%+18px)] right-[calc(-50%+18px)] top-[15px] hidden h-[2px] overflow-hidden rounded bg-line md:block">
                <span
                  className="block h-full bg-forest-700 transition-transform duration-700 ease-out"
                  style={{ transform: `scaleX(${filled && next && next !== 'idle' ? 1 : 0})`, transformOrigin: 'left' }}
                />
              </span>
            )}
            <span
              className={cx(
                'relative grid size-8 place-items-center rounded-full border-2 bg-surface transition-colors duration-300',
                st === 'active' && 'shadow-[0_0_0_5px_rgb(35_103_71/0.12)]',
              )}
              style={{ borderColor: color, background: filled ? color : st === 'failed' ? C.danger : C.surface }}
            >
              {st === 'active' && <span className="absolute inset-[-6px] animate-ping rounded-full border border-forest-700/40" />}
              {filled && st !== 'warn' ? (
                <Check className="size-4 text-white" strokeWidth={3} />
              ) : st === 'warn' ? (
                <TriangleAlert className="size-3.5 text-white" strokeWidth={2.6} />
              ) : st === 'failed' ? (
                <X className="size-4 text-white" strokeWidth={3} />
              ) : st === 'active' ? (
                <Loader2 className="size-4 animate-spin text-forest-700" />
              ) : (
                <span className="num text-[12px] font-semibold text-muted">{i + 1}</span>
              )}
            </span>
            <span className={cx('mt-2 text-[12.5px] font-semibold', st === 'idle' || st === 'skipped' ? 'text-muted' : 'text-ink')}>
              {s.label}
            </span>
            <span className="text-[11px] text-muted">{st === 'skipped' ? 'not needed' : s.caption}</span>
          </li>
        )
      })}
      <li className="sr-only" aria-live="polite">
        {props.running ? 'Incident running' : 'Idle'}
      </li>
    </ol>
  )
}

// ------------------------------------------------------------------ approval

function HoldToApprove(props: { onConfirm: () => void; disabled?: boolean }) {
  const [holding, setHolding] = useState(false)
  const timer = useRef<number | null>(null)
  const start = () => {
    if (props.disabled) return
    setHolding(true)
    timer.current = window.setTimeout(() => {
      setHolding(false)
      props.onConfirm()
    }, 800)
  }
  const stop = () => {
    setHolding(false)
    if (timer.current) window.clearTimeout(timer.current)
  }
  return (
    <button
      type="button"
      disabled={props.disabled}
      onPointerDown={start}
      onPointerUp={stop}
      onPointerLeave={stop}
      onKeyDown={(e) => (e.key === ' ' || e.key === 'Enter') && !e.repeat && start()}
      onKeyUp={stop}
      className="relative flex-1 cursor-pointer overflow-hidden rounded-lg bg-forest-800 px-4 py-2.5 text-[13px] font-semibold text-white transition-transform active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-50"
    >
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 bg-forest-700"
        style={{ width: holding ? '100%' : '0%', transition: holding ? 'width 800ms linear' : 'width 150ms ease-out' }}
      />
      <span className="relative flex items-center justify-center gap-2">
        <ShieldCheck className="size-4" aria-hidden />
        {holding ? 'Keep holding…' : 'Hold to approve'}
      </span>
    </button>
  )
}

function Countdown(props: { from: string; seconds: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])
  const left = Math.max(0, props.seconds - (now - new Date(props.from).getTime()) / 1000)
  const frac = left / props.seconds
  const r = 15
  return (
    <span className="flex items-center gap-2 text-[12px] text-ink-2" title="Nothing with downtime is applied if the approver does not answer in time">
      <svg width="36" height="36" className="-rotate-90" aria-hidden>
        <circle cx="18" cy="18" r={r} fill="none" stroke={C.line} strokeWidth="3" />
        <circle
          cx="18"
          cy="18"
          r={r}
          fill="none"
          stroke={frac < 0.2 ? C.danger : C.forest700}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={2 * Math.PI * r}
          strokeDashoffset={2 * Math.PI * r * (1 - frac)}
          style={{ transition: 'stroke-dashoffset 1s linear' }}
        />
      </svg>
      <span className="num font-semibold text-ink">
        {Math.floor(left / 60)}:{String(Math.floor(left % 60)).padStart(2, '0')}
      </span>
      left to decide
    </span>
  )
}

// ------------------------------------------------------------------ timeline

function TimelineRow(props: { e: AgentEvent; runId: string; prev?: AgentEvent }) {
  const { e } = props
  const t = AGENT_TONE[e.agent]
  const isTool = e.kind === 'tool_call'
  return (
    <li
      className={cx(
        'relative grid animate-rise grid-cols-[62px_86px_1fr_auto] items-start gap-2 border-l-2 py-1.5 pl-3 pr-2 text-[12.5px]',
        e.kind === 'hole' ? 'border-danger bg-danger-soft/60' : e.kind === 'apply' ? 'border-ok bg-ok-soft/50' : e.kind === 'error' || e.kind === 'reject' ? 'border-danger' : e.kind === 'approval' ? 'border-high bg-high-soft/50' : 'border-transparent',
      )}
    >
      <span className="num pt-px text-[11.5px] text-muted">{clock(e.ts)}</span>
      <span>
        {props.prev?.agent !== e.agent && (
          <span className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: t.color }}>
            <span className="size-1.5 rounded-full" style={{ background: t.color }} />
            {AGENT_LABEL[e.agent]}
          </span>
        )}
      </span>
      <span className={cx('min-w-0 break-words', isTool ? 'font-mono text-[11.5px] text-ink-2' : 'text-ink', e.kind === 'hole' && 'font-semibold text-danger')}>
        {isTool && <span className="text-muted">→ </span>}
        {e.tool_call_id && isTool ? (
          <Metric source={{ toolCallId: e.tool_call_id, runId: props.runId, label: e.summary }} className="text-left">
            {e.summary}
          </Metric>
        ) : (
          e.summary
        )}
      </span>
      <span className="flex items-center gap-1">
        {e.usage && (
          <span className="num whitespace-nowrap rounded border border-line bg-surface-muted px-1.5 text-[10.5px] text-muted" title={`${e.usage.model}`}>
            {int(e.usage.prompt_tokens + e.usage.completion_tokens)} tok
            {e.usage.cached ? ' · cached' : e.usage.latency_ms ? ` · ${(e.usage.latency_ms / 1000).toFixed(1)}s` : ''}
          </span>
        )}
        {e.tool_call_id && !isTool && (
          <Metric source={{ toolCallId: e.tool_call_id, runId: props.runId, label: e.summary }} className="text-[10.5px] text-forest-800">
            {e.tool_call_id}
          </Metric>
        )}
      </span>
    </li>
  )
}

// ------------------------------------------------------------------ screen

interface Group {
  kind: ControlKind
  devices: Device[]
  cost: number
  downtime: number
  auto: boolean
  covered: number
}

export default function AgentsScreen() {
  const route = useRoute()
  const { city, plans, risk, presets, devices, run, health } = useStore()
  const v = run.view
  const param = route.params.get('advisory')
  // A deep link (?advisory=…) picks the preset until the user chooses another one.
  const [choice, setChoice] = useState<{ param: string | null; id: string } | null>(null)
  const presetId = choice && choice.param === param ? choice.id : (param ?? 'normal_01_lumenos')
  const setPresetId = (id: string) => setChoice({ param, id })
  const [constraint, setConstraint] = useState(DEFAULT_CONSTRAINT)
  const [open, setOpen] = useState<ControlKind | null>(null)
  const [sortBy, setSortBy] = useState<'covered' | 'cost'>('covered')
  const [decision, setDecision] = useState<{ busy: boolean; error: string | null }>({ busy: false, error: null })
  const [follow, setFollow] = useState(true)
  const listRef = useRef<HTMLOListElement>(null)

  const linked = route.params.get('run')
  const { attach } = run
  useEffect(() => {
    if (linked) attach(linked)
  }, [linked, attach])
  useEffect(() => {
    if (follow && listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight
  }, [run.events.length, follow])

  const preset = presets.data?.find((p) => p.id === presetId)
  const running = !!run.runId && !run.done
  const standing = plans.data?.find((p) => p.objective === 'cvar') ?? null
  const plan = v.plan ?? standing
  const baseRisk = useMemo(() => riskById(risk.data?.baseline), [risk.data])
  const cvarNone = risk.data?.histograms.find((h) => h.label === 'none')?.cvar ?? 1

  const groups: Group[] = useMemo(() => {
    if (!plan || !city.data) return []
    const m = new Map<ControlKind, Group>()
    for (const [id, kind] of Object.entries(plan.choices)) {
      const d = devices.get(id)
      const opt = d?.controls.find((c) => c.kind === kind)
      if (!d || !opt) continue
      const g = m.get(kind) ?? { kind, devices: [], cost: 0, downtime: 0, auto: true, covered: 0 }
      g.devices.push(d)
      g.cost += opt.cost_inr
      g.downtime += opt.downtime_h
      g.auto &&= opt.autonomy === 'auto'
      g.covered += (baseRisk.get(id)?.tail_loss ?? 0) / cvarNone
      m.set(kind, g)
    }
    return [...m.values()].sort((a, b) => (sortBy === 'cost' ? b.cost - a.cost : b.covered - a.covered))
  }, [plan, city.data, devices, baseRisk, cvarNone, sortBy])

  const holeEntries = useMemo(() => new Set(v.holes.flatMap((h) => h.strategy.entry_points)), [v.holes])
  const attackPaths = useMemo(() => {
    if (!city.data) return []
    const paths: [string, string][] = []
    const last = new Map<string, Hole>()
    for (const h of v.holes) last.set(h.strategy.id, h)
    for (const h of last.values()) {
      for (const entry of h.strategy.entry_points) {
        const src = devices.get(entry)
        if (!src) continue
        const targets = city.data.devices.filter(
          (d) =>
            d.id !== entry &&
            ((h.strategy.pivot_shared_firmware && family(d) === family(src)) ||
              (h.strategy.target_category && d.category === h.strategy.target_category) ||
              (h.strategy.campaign_cve && d.vulns.some((x) => x.cve_id === h.strategy.campaign_cve))),
        )
        targets.slice(0, 12).forEach((t) => paths.push([entry, t.id]))
      }
    }
    return paths
  }, [v.holes, city.data, devices])

  const matched = new Set(v.matches)
  const applied = v.applied
  const pending = v.pending

  const approve = async (yes: boolean) => {
    if (!run.runId || !pending) return
    setDecision({ busy: true, error: null })
    try {
      await api.approve(run.runId, pending.request.plan_id, yes)
      setDecision({ busy: false, error: null })
    } catch (e) {
      setDecision({ busy: false, error: (e as Error).message })
    }
  }

  const before = v.outcome?.before.cvar ?? v.cvarBefore
  const after = v.outcome?.after.cvar ?? v.plan?.metrics?.cvar ?? null
  const runSrc = (id: string | null | undefined, label?: string) => (id && run.runId ? { toolCallId: id, runId: run.runId, label } : null)
  const outcomeSrc = runSrc(v.outcome?.event.tool_call_id, 'Re-simulated CVaR95 after applying')
  const autoCount = plan ? Object.entries(plan.choices).filter(([id, k]) => devices.get(id)?.controls.find((c) => c.kind === k)?.autonomy === 'auto').length : 0
  const accepted = sum(v.auditor.map((a) => a.accepted.length))
  const rejected = sum(v.auditor.map((a) => a.rejected.length))
  const placeholder = health.data?.data === 'placeholder'

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Response & mitigation"
        title="From Advisory to Action"
        subtitle="Pick an advisory. The agents quarantine it, size the blast radius, plan under the same budget, attack their own plan, and wait for a human before anything with downtime touches the twin."
      />

      {/* console */}
      <Card i={1} className="p-5">
        <div className="grid items-end gap-3 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_auto]">
          <div>
            <label htmlFor="advisory" className="mb-1.5 block text-[12px] font-medium text-ink-2">
              Advisory
            </label>
            <div className="relative">
              <select
                id="advisory"
                value={presetId}
                onChange={(e) => setPresetId(e.target.value)}
                disabled={running}
                className="h-10 w-full cursor-pointer appearance-none rounded-lg border border-line bg-surface pl-3 pr-9 text-[13px] font-medium text-ink outline-none focus:border-forest-700 disabled:opacity-60"
              >
                {(['normal', 'poisoned', 'wrong'] as const).map((k) => (
                  <optgroup key={k} label={KIND_LABEL[k]}>
                    {(presets.data ?? [])
                      .filter((p) => p.kind === k)
                      .map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.title}
                        </option>
                      ))}
                  </optgroup>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
            </div>
          </div>
          <div>
            <label htmlFor="constraint" className="mb-1.5 block text-[12px] font-medium text-ink-2">
              Operating constraint <span className="text-muted">(plain language, optional)</span>
            </label>
            <input
              id="constraint"
              value={constraint}
              onChange={(e) => setConstraint(e.target.value)}
              disabled={running}
              className="h-10 w-full rounded-lg border border-line bg-surface px-3 text-[13px] text-ink outline-none focus:border-forest-700 disabled:opacity-60"
            />
          </div>
          <div className="flex gap-2">
            {run.runId && !running && (
              <Button variant="secondary" icon={RotateCcw} onClick={run.reset}>
                Clear
              </Button>
            )}
            <Button
              icon={running ? Loader2 : Play}
              disabled={!preset || running || run.starting}
              onClick={() => preset && run.start(preset, constraint)}
              className={cx('h-10 min-w-[150px]', running && '[&_svg]:animate-spin')}
            >
              {running ? 'Running…' : run.starting ? 'Starting…' : 'Run incident'}
            </Button>
          </div>
        </div>
        {preset && (
          <p className="mt-2.5 flex items-center gap-2 text-[12px] text-muted">
            <Badge tone={preset.kind === 'normal' ? 'forest' : preset.kind === 'poisoned' ? 'danger' : 'warn'}>{preset.kind}</Badge>
            {preset.kind === 'poisoned'
              ? 'Contains instructions aimed at the LLM. Watch the quarantine keep them out of the plan.'
              : preset.kind === 'wrong'
                ? 'Plausible but contradicts the pinned feed or the inventory. Watch the cross-check stop it.'
                : 'A real CISA KEV entry that the demo city actually runs.'}
            {placeholder && <span className="text-high"> · Placeholder mode replays a canned run.</span>}
          </p>
        )}
        {run.error && <p className="mt-2 text-[12.5px] text-danger">{run.error}</p>}
        <div className="mt-6 border-t border-line pt-5">
          <Stepper stages={v.stages} running={running} />
        </div>
      </Card>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Kpi
          i={2}
          icon={Crosshair}
          tone="warn"
          label="Devices affected"
          value={run.runId ? <CountUp value={v.matches.length} format={(n) => int(n)} /> : '–'}
          foot={v.advisory ? `${v.advisory.cve_id} · ${v.advisory.firmware_family} < ${v.advisory.affected_below}` : 'Run an incident'}
        />
        <Kpi
          i={3}
          icon={ListChecks}
          label={v.plan ? 'Controls in plan' : 'Standing plan controls'}
          value={plan ? <CountUp value={Object.keys(plan.choices).length} format={(n) => int(n)} /> : <Skeleton className="h-8 w-12" />}
          foot={plan ? `${autoCount} auto · ${Object.keys(plan.choices).length - autoCount} need approval` : ' '}
        />
        <Kpi
          i={4}
          icon={CircleDollarSign}
          tone="warn"
          label="Plan cost"
          value={plan ? inrShort(plan.cost_inr) : <Skeleton className="h-8 w-20" />}
          foot={plan ? `${hours(plan.downtime_h)} downtime · within budget` : ' '}
        />
        <Kpi
          i={5}
          icon={ShieldCheck}
          tone="ok"
          label={v.outcome ? 'Worst case, re-simulated' : 'Worst case (CVaR 95%)'}
          value={
            before !== null && after !== null ? (
              <span className="flex items-baseline gap-1.5">
                <span className="text-[18px] font-semibold text-muted line-through decoration-1">{loss(before)}</span>
                <Metric source={outcomeSrc}>
                  <CountUp value={after} format={(n) => loss(n)} />
                </Metric>
              </span>
            ) : (
              '–'
            )
          }
          delta={before !== null && after !== null && <Delta good={after <= before}>{pct(change(before, after), 0)}</Delta>}
          foot={v.outcome ? `${v.outcome.after.controls_applied} controls in place` : v.cvarBefore !== null ? 'Analyst estimate → plan' : 'Before → after'}
        />
        <Kpi
          i={6}
          icon={Swords}
          tone="danger"
          label="Red-Team holes"
          value={run.runId ? <CountUp value={v.holes.length} format={(n) => int(n)} /> : '–'}
          unit={v.rounds ? `in ${plural(v.rounds, 'round')}` : undefined}
          foot={v.residual.length ? `${plural(v.residual.length, 'hole')} flagged to the approver` : v.rounds ? 'All closed by replanning' : 'Attacks its own plan'}
        />
      </div>

      {/* controls + map */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(360px,1fr)]">
        <Card i={7} className="flex flex-col pb-3">
          <CardHeader
            title={v.plan ? 'Recommended controls' : 'Standing city-wide plan'}
            sub={
              v.plan
                ? `${v.plan.id} · ${v.plan.solver.toUpperCase()} · grouped by control, ranked by worst-case loss covered`
                : 'No incident yet: this is the CVaR plan for the whole city under the same budget'
            }
            right={
              <Segmented
                label="Sort controls"
                size="sm"
                value={sortBy}
                onChange={setSortBy}
                options={[
                  { id: 'covered', label: 'Risk covered' },
                  { id: 'cost', label: 'Cost' },
                ]}
              />
            }
          />
          <ul className="mt-3 space-y-2 px-4">
            {!plan && Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-[74px]" />)}
            {groups.map((g, i) => {
              const Icon = CONTROL_ICON[g.kind]
              const appliedHere = g.devices.filter((d) => applied[d.id] === g.kind).length
              const isOpen = open === g.kind
              const cats = [...new Set(g.devices.map((d) => d.category))]
              const zones = [...new Set(g.devices.map((d) => d.zone))]
              return (
                <li key={g.kind} className="animate-rise rounded-xl border border-line transition-colors hover:border-line-strong" style={{ animationDelay: `${i * 60}ms` }}>
                  <button
                    type="button"
                    onClick={() => setOpen(isOpen ? null : g.kind)}
                    aria-expanded={isOpen}
                    className="grid w-full cursor-pointer grid-cols-[28px_40px_minmax(0,1fr)_auto_16px] items-center gap-3 px-3 py-3 text-left"
                  >
                    <span className="num grid size-7 place-items-center rounded-lg bg-forest-50 text-[12.5px] font-bold text-forest-800">{i + 1}</span>
                    <span className="grid size-10 place-items-center rounded-lg border border-line bg-surface-muted text-forest-800">
                      <Icon className="size-5" strokeWidth={1.8} aria-hidden />
                    </span>
                    <span className="min-w-0">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="text-[14px] font-semibold text-ink">{CONTROL_LABEL[g.kind]}</span>
                        <Badge tone={g.auto ? 'ok' : 'warn'}>{g.auto ? 'AUTO' : 'NEEDS APPROVAL'}</Badge>
                        {appliedHere > 0 && <Badge tone="ok"><Check className="size-3" /> {appliedHere} applied</Badge>}
                      </span>
                      <span className="mt-0.5 block truncate text-[12px] text-ink-2">
                        {plural(g.devices.length, 'device')} · {cats.map((c) => CATEGORY_PLURAL[c]).join(', ')}
                      </span>
                      <span className="mt-1 flex gap-1 overflow-hidden">
                        {zones.map((z) => (
                          <span key={z} className="rounded border border-line px-1.5 text-[10.5px] text-muted">
                            {z}
                          </span>
                        ))}
                      </span>
                    </span>
                    <span className="grid grid-cols-[74px_84px_58px] gap-2">
                    <span>
                      <span className="block text-[10.5px] text-muted">Est. cost</span>
                      <span className="num text-[13px] font-semibold text-ink">{inrShort(g.cost)}</span>
                    </span>
                    <span>
                      <span className="block text-[10.5px] text-muted">Risk covered</span>
                      <span className="num text-[13px] font-semibold text-forest-800">{share(g.covered, 1)}</span>
                    </span>
                    <span>
                      <span className="block text-[10.5px] text-muted">Downtime</span>
                      <span className="num text-[13px] font-semibold text-ink">{hours(g.downtime)}</span>
                    </span>
                    </span>
                    <ChevronDown className={cx('size-4 text-muted transition-transform', isOpen && 'rotate-180')} aria-hidden />
                  </button>
                  {isOpen && (
                    <div className="animate-fade border-t border-line px-3 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {g.devices.map((d) => (
                          <span
                            key={d.id}
                            className={cx(
                              'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11.5px]',
                              applied[d.id] ? 'border-ok/30 bg-ok-soft text-ok' : matched.has(d.id) ? 'border-warn/40 bg-warn-soft text-[#8a6212]' : 'border-line text-ink-2',
                            )}
                          >
                            {applied[d.id] && <Check className="size-3" />}
                            {d.name}
                            <span className="num text-muted">{share((baseRisk.get(d.id)?.tail_loss ?? 0) / cvarNone, 1)}</span>
                          </span>
                        ))}
                      </div>
                      <p className="mt-2 text-[11.5px] text-muted">
                        “Risk covered” is the share of the uncontrolled worst case these devices carry; the simulator, not this
                        sum, decides the plan.
                      </p>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        </Card>

        <Card i={8} className="flex flex-col overflow-hidden">
          <CardHeader title="Geographic impact" sub={run.runId ? 'Live: matched, attacked and protected devices' : 'Devices protected by the standing plan'} />
          <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 px-5 text-[11.5px] text-ink-2">
            {[
              [C.warn, 'Matched by advisory'],
              [C.danger, 'Red-Team entry'],
              [C.forest800, 'In plan'],
              [C.ok, 'Applied'],
            ].map(([c, l]) => (
              <span key={l} className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-full" style={{ background: c }} /> {l}
              </span>
            ))}
            <span className="flex items-center gap-1.5">
              <span className="w-4 border-t-2 border-dashed border-danger" /> Attack path
            </span>
          </div>
          <div className="relative mx-4 mb-4 mt-3 min-h-[340px] flex-1 overflow-hidden rounded-lg border border-line">
            <div className="absolute inset-0">
            {city.data ? (
              <CityMap
                city={city.data}
                risk={risk.data}
                mode="risk"
                compact
                showZones={false}
                attackPaths={attackPaths}
                styleFor={(d) => {
                  if (applied[d.id]) return { fill: C.ok }
                  if (holeEntries.has(d.id)) return { fill: C.danger, ping: true }
                  if (matched.has(d.id)) return { fill: C.warn, ping: running }
                  if (plan && d.id in plan.choices) return { fill: C.forest800 }
                  return { fill: C.idle, dim: true }
                }}
                className="h-full"
              />
            ) : (
              <Skeleton className="h-full rounded-none" />
            )}
            </div>
          </div>
        </Card>
      </div>

      {/* timeline + approval + outcome */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Card i={9} className="flex flex-col">
          <CardHeader
            title="Agent timeline"
            sub="Every event is signed into the audit log before it appears here. Dotted values open their tool call."
            right={
              run.runId ? (
                <span className="flex items-center gap-3 text-[12px] text-ink-2">
                  <span className="num">{plural(run.events.length, 'event')}</span>
                  <span className="num">{int(v.tokens)} tok · {plural(v.llmCalls, 'LLM call')}</span>
                  <label className="flex cursor-pointer items-center gap-1.5">
                    <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} className="accent-forest-800" />
                    Follow
                  </label>
                </span>
              ) : undefined
            }
          />
          {run.runId ? (
            <ol ref={listRef} className="scroll-thin mt-3 max-h-[460px] space-y-0.5 overflow-y-auto px-3 pb-3" aria-live="polite">
              {run.events.map((e, i) => (
                <TimelineRow key={e.id} e={e} prev={run.events[i - 1]} runId={run.runId!} />
              ))}
              {running && (
                <li className="flex items-center gap-2 py-2 pl-3 text-[12px] text-muted">
                  <Dot color={C.forest700} pulse /> waiting for the next event…
                </li>
              )}
            </ol>
          ) : (
            <Empty icon={Bot} title="No incident yet" className="flex-1">
              Pick an advisory and press <b>Run incident</b>. Events stream in live over SSE, each one already hash-chained and signed.
            </Empty>
          )}
        </Card>

        <div className="space-y-4">
          <Card i={10} className={cx('pb-4', pending && 'border-high/40 shadow-[0_0_0_4px_rgb(240_120_50/0.08)]')}>
            <CardHeader
              title={
                <span className="flex items-center gap-2">
                  {pending ? <ShieldAlert className="size-4 text-high" /> : <ShieldCheck className="size-4 text-forest-800" />}
                  Human approval
                </span>
              }
              sub="Controls with downtime never apply without an approver (demo RBAC: X-Role header)"
            />
            <div className="px-5 pt-3">
              {pending ? (
                <div className="animate-rise">
                  {pending.request.kind === 'plan' ? (
                    <>
                      <p className="text-[13.5px] text-ink">
                        Apply <b>{plural(Object.keys(pending.request.controls ?? {}).length, 'control')}</b> from{' '}
                        <span className="font-mono text-[12px]">{pending.request.plan_id}</span>
                      </p>
                      <div className="mt-3 grid grid-cols-3 gap-2">
                        {[
                          ['Cost', inr(pending.request.cost_inr ?? 0)],
                          ['Downtime', hours(pending.request.downtime_h ?? 0)],
                          ['Plan CVaR', v.plan?.metrics ? loss(v.plan.metrics.cvar) : '–'],
                        ].map(([k, val]) => (
                          <div key={k} className="rounded-lg border border-line bg-surface-muted px-2.5 py-2">
                            <p className="text-[10.5px] text-muted">{k}</p>
                            <p className="num text-[14px] font-semibold text-ink">{val}</p>
                          </div>
                        ))}
                      </div>
                      {!!pending.request.residual_holes?.length && (
                        <p className="mt-3 flex items-start gap-2 rounded-lg border border-danger/20 bg-danger-soft px-3 py-2 text-[12px] text-danger">
                          <AlertOctagon className="mt-0.5 size-3.5 shrink-0" />
                          {plural(pending.request.residual_holes.length, 'Red-Team hole')} still open: CVaR{' '}
                          {pending.request.residual_holes.map((h) => `${loss(h.cvar_before)} → ${loss(h.cvar_after_attack)}`).join(', ')} under
                          attack.
                        </p>
                      )}
                    </>
                  ) : (
                    <>
                      <p className="text-[13.5px] font-semibold text-ink">The advisory disagrees with the pinned sources</p>
                      <ul className="mt-2 space-y-1">
                        {(pending.request.discrepancies ?? []).map((d) => (
                          <li key={d} className="flex gap-2 text-[12px] text-danger">
                            <X className="mt-0.5 size-3.5 shrink-0" /> {d}
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                  <div className="mt-3">
                    <Countdown from={pending.event.ts} seconds={600} />
                  </div>
                  <div className="mt-3 flex gap-2">
                    <HoldToApprove onConfirm={() => approve(true)} disabled={decision.busy} />
                    <Button variant="danger" onClick={() => approve(false)} disabled={decision.busy}>
                      Reject
                    </Button>
                  </div>
                  {decision.error && <p className="mt-2 text-[12px] text-danger">{decision.error}</p>}
                </div>
              ) : v.approvals.length ? (
                <ul className="space-y-1.5">
                  {v.approvals.map((a) => (
                    <li key={a.id} className={cx('flex items-center gap-2 text-[12.5px]', a.kind === 'approval' ? 'text-ok' : 'text-danger')}>
                      {a.kind === 'approval' ? <Check className="size-4" /> : <X className="size-4" />}
                      {a.summary}
                      <span className="num ml-auto text-[11px] text-muted">{clock(a.ts)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="flex items-center gap-2 pb-1 text-[12.5px] text-muted">
                  <Clock3 className="size-4" /> {running ? 'Waiting for the planner and Red-Team…' : 'Nothing waiting.'}
                </p>
              )}
            </div>
          </Card>

          <Card i={11} className="pb-4">
            <CardHeader title="Outcome" sub="Re-simulated in the twin after applying, same held-out scenarios" />
            <div className="px-5 pt-3">
              {v.outcome ? (
                <div className="animate-rise space-y-3">
                  {(
                    [
                      ['Worst case (CVaR95)', v.outcome.before.cvar, v.outcome.after.cvar],
                      ['Expected loss', v.outcome.before.mean_loss, v.outcome.after.mean_loss],
                      ['Largest cascade', v.outcome.before.max_cascade, v.outcome.after.max_cascade],
                    ] as [string, number, number][]
                  ).map(([label, b, a], i) => (
                    <div key={label}>
                      <div className="mb-1 flex justify-between text-[12px]">
                        <span className="text-ink-2">{label}</span>
                        <span className="num">
                          <span className="text-muted">{loss(b, i === 2 ? 0 : 2)}</span> →{' '}
                          <Metric source={outcomeSrc} className="font-semibold text-forest-800">
                            {loss(a, i === 2 ? 0 : 2)}
                          </Metric>{' '}
                          <Delta good={a <= b}>{pct(change(b, a), 0)}</Delta>
                        </span>
                      </div>
                      <div className="relative h-2 rounded-full bg-surface-muted">
                        <div className="absolute inset-y-0 left-0 rounded-full bg-danger/25" style={{ width: '100%' }} />
                        <div className="grow-x absolute inset-y-0 left-0 rounded-full bg-forest-800" style={{ width: `${(a / (b || 1)) * 100}%`, animationDelay: `${i * 120}ms` }} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-muted">Appears once controls are applied.</p>
              )}
              <div className="mt-4 border-t border-line pt-3">
                <p className="mb-1.5 flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-ink">Auditor</span>
                  <span className="num text-muted">
                    {accepted} accepted · {rejected} rejected
                    {accepted + rejected > 0 && ` · ${share(rejected / (accepted + rejected))} rejection rate`}
                  </span>
                </p>
                <div className="flex h-2 overflow-hidden rounded-full bg-surface-muted">
                  <div className="grow-x bg-ok" style={{ width: `${accepted + rejected ? (accepted / (accepted + rejected)) * 100 : 0}%` }} />
                  <div className="bg-danger" style={{ width: `${accepted + rejected ? (rejected / (accepted + rejected)) * 100 : 0}%` }} />
                </div>
                <ul className="mt-2 space-y-1">
                  {v.auditor.flatMap((a) => a.accepted.map((t) => ({ t, ok: true, e: a.event })).concat(a.rejected.map((t) => ({ t, ok: false, e: a.event })))).map((c, i) => (
                    <li key={i} className={cx('flex gap-1.5 text-[11.5px]', c.ok ? 'text-ink-2' : 'text-danger')}>
                      {c.ok ? <Check className="mt-0.5 size-3 shrink-0 text-ok" /> : <X className="mt-0.5 size-3 shrink-0" />}
                      <span>{c.t}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-[11px] text-muted">The LLM writes claims; the Auditor checks each number against the tool result it cites.</p>
              </div>
              {v.final && (
                <a href="#/audit" className="mt-3 flex items-center gap-1.5 text-[12px] font-semibold text-forest-800">
                  {v.final.summary} · verify the audit chain <ArrowRight className="size-3.5" />
                </a>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
