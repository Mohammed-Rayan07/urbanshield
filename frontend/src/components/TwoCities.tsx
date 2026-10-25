// "Same attack, two cities": one held-out worst-case scenario replayed hop by hop under CVSS-first and
// under UrbanShield. The simulator draws every random number before controls apply, so both maps face
// the identical attack; only the plan differs. Every number here is the /replay tool result.
import { Ambulance, Pause, Play, RotateCcw, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { api, useLoad } from '../api'
import { C } from '../lib/colors'
import { cx } from '../lib/cx'
import { inr, int } from '../lib/format'
import { useStore } from '../lib/store'
import type { Device, Plan, ReplayView, TwoCities as Replay } from '../types'
import CityMap, { type DeviceStyle } from './CityMap'
import { Button, Card, ErrorState, Metric, Skeleton } from './ui'

const STEP_MS = 1100
const SIDES = [
  { label: 'cvss', title: 'Patched by CVSS score', note: 'Highest severity first', tone: C.high },
  { label: 'cvar', title: 'UrbanShield', note: 'Worst-case optimal plan', tone: C.forest800 },
] as const

const REDUCED_MOTION = window.matchMedia('(prefers-reduced-motion: reduce)').matches

/** The replayed hop: starts shortly after the data arrives and stops at `max` (shown at once with
 *  reduced motion). `playing` is derived, so reaching the end needs no extra state update. */
function useHop(max: number, ready: boolean) {
  const [hop, setHop] = useState(-1)
  const [wantPlay, setPlaying] = useState(false)
  useEffect(() => {
    if (!ready || REDUCED_MOTION) return
    const t = window.setTimeout(() => setPlaying(true), 700)
    return () => window.clearTimeout(t)
  }, [ready])
  const playing = wantPlay && hop < max
  useEffect(() => {
    if (!playing) return
    const t = window.setTimeout(() => setHop((h) => h + 1), hop < 0 ? 300 : STEP_MS)
    return () => window.clearTimeout(t)
  }, [playing, hop])
  const restart = () => {
    setHop(-1)
    setPlaying(true)
  }
  return { hop: REDUCED_MOTION ? max : Math.min(hop, max), playing, setPlaying, restart }
}

function styleAt(view: ReplayView, plan: Plan | undefined, hop: number) {
  return (d: Device): DeviceStyle => {
    const at = view.hops[d.id]
    if (at !== undefined && at <= hop) return { fill: C.danger, ping: at === hop }
    if (plan && d.id in plan.choices) return { fill: C.forest700, stroke: C.forest100 }
    return { fill: C.idle }
  }
}

function lostBy(view: ReplayView, hop: number, ids?: string[]) {
  const keep = ids ? new Set(ids) : null
  return Object.entries(view.hops).filter(([id, h]) => h <= hop && (!keep || keep.has(id))).length
}

function CityPanel(props: {
  side: (typeof SIDES)[number]
  view: ReplayView
  plan: Plan | undefined
  replay: Replay
  hop: number
  height: string
}) {
  const { city } = useStore()
  const { side, view, plan, replay, hop } = props
  const lost = lostBy(view, hop)
  const corridorLost = lostBy(view, hop, replay.corridor_ids)
  const blocked = corridorLost > 0
  const styleFor = useMemo(() => styleAt(view, plan, hop), [view, plan, hop])
  if (!city.data) return <Skeleton className={props.height} />
  return (
    <div className="relative overflow-hidden rounded-xl border border-line">
      <CityMap
        city={city.data}
        risk={null}
        mode="network"
        compact
        showZones={false}
        showCorridor
        styleFor={styleFor}
        className={props.height}
      />
      <div className="pointer-events-none absolute inset-x-0 top-0 z-[600] flex items-start justify-between gap-3 p-3">
        <div className="rounded-lg bg-surface/95 px-3 py-2 shadow-sm backdrop-blur-sm">
          <p className="flex items-center gap-2 text-[14px] font-semibold text-ink">
            <span className="size-2.5 rounded-full" style={{ background: side.tone }} />
            {side.title}
          </p>
          <p className="text-[11.5px] text-muted">
            {side.note}
            {plan ? ` · ${inr(plan.cost_inr)} · ${int(Object.keys(plan.choices).length)} controls` : ''}
          </p>
        </div>
      </div>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 z-[600] grid grid-cols-2 gap-2 p-3">
        <div className="rounded-lg bg-surface/95 px-3 py-2.5 shadow-sm backdrop-blur-sm">
          <p className="text-[11.5px] font-medium text-ink-2">Devices lost</p>
          <p
            className={cx(
              'num text-[32px] font-[680] leading-none tracking-[-0.02em]',
              lost ? 'text-danger' : 'text-ink',
            )}
          >
            {lost}
            <span className="ml-1 text-[13px] font-medium text-muted">/ {city.data.devices.length}</span>
          </p>
        </div>
        <div
          className={cx(
            'rounded-lg px-3 py-2.5 shadow-sm backdrop-blur-sm transition-colors duration-300',
            blocked ? 'bg-danger text-white' : 'bg-surface/95 text-ink',
          )}
        >
          <p
            className={cx(
              'flex items-center gap-1.5 text-[11.5px] font-medium',
              blocked ? 'text-white/85' : 'text-ink-2',
            )}
          >
            <Ambulance className="size-3.5" aria-hidden /> Ambulance corridor
          </p>
          <p className="mt-1 text-[20px] font-[680] leading-none tracking-[-0.01em]">
            {blocked ? `Blocked · ${corridorLost} signal${corridorLost > 1 ? 's' : ''} lost` : 'Clear'}
          </p>
        </div>
      </div>
    </div>
  )
}

/** The hero replay. `height` sizes each map (Tailwind class); `chrome=false` drops the card frame. */
export default function TwoCities(props: { height?: string; chrome?: boolean }) {
  const { plans } = useStore()
  const replay = useLoad(() => api.replay())
  const data = replay.data
  const { hop, playing, setPlaying, restart } = useHop(data?.max_hop ?? 0, !!data)
  const byId = useMemo(() => new Map((plans.data ?? []).map((p) => [p.id, p])), [plans.data])
  const height = props.height ?? 'h-[460px]'

  if (replay.error) return <ErrorState error={replay.error} retry={replay.reload} />
  if (!data) {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Skeleton className={height} />
        <Skeleton className={height} />
      </div>
    )
  }
  const views = new Map(data.views.map((v) => [v.label, v]))
  const cvss = views.get('cvss')!
  const ours = views.get('cvar')!
  const source = data.tool_call_id ? { toolCallId: data.tool_call_id, label: 'Same attack, two cities' } : null
  const done = hop >= data.max_hop

  const body = (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[80ch] text-[13px] text-ink-2">
          Scenario <Metric source={source}>#{data.scenario}</Metric>, ranked{' '}
          <span className="num font-semibold text-ink">{data.tail_rank}</span> of{' '}
          <span className="num">{int(data.n_scenarios)}</span> held-out attacks on the undefended city. Identical
          attacker, identical random draws; <span className="font-semibold text-ink">only the plan differs</span>.
          Same budget.
        </p>
        <div className="flex items-center gap-2">
          <span className="num rounded-md border border-line bg-surface-muted px-2.5 py-1.5 text-[12.5px] text-ink-2">
            Spread hop {Math.max(hop, 0)} / {data.max_hop}
          </span>
          {done ? (
            <Button variant="secondary" icon={RotateCcw} onClick={restart}>
              Replay attack
            </Button>
          ) : (
            <Button variant="secondary" icon={playing ? Pause : Play} onClick={() => setPlaying(!playing)}>
              {playing ? 'Pause' : 'Play'}
            </Button>
          )}
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {SIDES.map((side) => {
          const view = side.label === 'cvss' ? cvss : ours
          return (
            <CityPanel
              key={side.label}
              side={side}
              view={view}
              plan={view.plan_id ? byId.get(view.plan_id) : undefined}
              replay={data}
              hop={hop}
              height={height}
            />
          )
        })}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-forest-200 bg-forest-50 px-4 py-3 text-[13px] text-ink-2">
        <ShieldCheck className="size-4 shrink-0 text-forest-800" aria-hidden />
        <span className="min-w-0 flex-1">
          Not a cherry-pick: across <span className="font-semibold text-ink">all worst-5% attacks</span>, CVSS-first
          loses{' '}
          <Metric source={source} className="font-semibold text-high">
            {cvss.tail_devices_lost.toFixed(1)}
          </Metric>{' '}
          devices on average and a corridor signal in{' '}
          <span className="num font-semibold text-ink">{(cvss.tail_corridor_share * 100).toFixed(0)}%</span> of them;
          UrbanShield loses{' '}
          <Metric source={source} className="font-semibold text-forest-800">
            {ours.tail_devices_lost.toFixed(1)}
          </Metric>{' '}
          and <span className="num font-semibold text-ink">{(ours.tail_corridor_share * 100).toFixed(0)}%</span>.
        </span>
      </div>
    </div>
  )
  if (props.chrome === false) return body
  return (
    <Card className="px-5 py-4" aria-label="Same attack, two cities">
      <div className="mb-3">
        <p className="eyebrow">Same attack · two cities</p>
        <h2 className="mt-1 font-serif text-[28px] leading-tight text-ink">One of the worst attacks, replayed twice</h2>
      </div>
      {body}
    </Card>
  )
}
