// Budget slider: held-out worst-case loss (CVaR95) of each planner as the budget grows. Precomputed by
// scripts/build_frontier.py with the same compare() as /plans; nothing is solved while dragging.
import { useMemo, useState } from 'react'
import { api, useLoad } from '../api'
import { useSize } from '../lib/chart'
import { C, SERIES } from '../lib/colors'
import { inr, inrShort, loss } from '../lib/format'
import { cheapestWin } from '../lib/derive'
import type { Frontier } from '../types'
import { Card, ErrorState, Skeleton } from './ui'

const LINES = [
  { key: 'cvss', label: 'CVSS-first', color: SERIES.cvss },
  { key: 'bfs_centrality', label: 'BFS-only', color: SERIES.bfs_centrality },
  { key: 'cvar', label: 'UrbanShield', color: SERIES.cvar },
] as const

function Chart(props: { frontier: Frontier; index: number; onIndex: (i: number) => void }) {
  const [ref, size] = useSize<HTMLDivElement>()
  const pts = props.frontier.points
  const pad = { l: 44, r: 16, t: 14, b: 34 }
  const w = Math.max(size.w, 320)
  const h = 260
  const max = Math.max(...pts.flatMap((p) => LINES.map((l) => p.cvar[l.key] ?? 0))) * 1.08
  const x = (i: number) => pad.l + (i * (w - pad.l - pad.r)) / Math.max(pts.length - 1, 1)
  const y = (v: number) => pad.t + (1 - v / max) * (h - pad.t - pad.b)
  const ticks = [0, max / 4, max / 2, (3 * max) / 4]
  return (
    <div ref={ref} className="w-full">
      <svg width={w} height={h} role="img" aria-label="Worst-case loss by budget for each planner">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} stroke={C.line} />
            <text x={pad.l - 8} y={y(t) + 4} textAnchor="end" className="num" fontSize={11} fill={C.muted}>
              {t.toFixed(0)}
            </text>
          </g>
        ))}
        <line
          x1={x(props.index)}
          x2={x(props.index)}
          y1={pad.t}
          y2={h - pad.b}
          stroke={C.lineStrong}
          strokeDasharray="3 4"
        />
        {LINES.map((l) => (
          <g key={l.key}>
            <polyline
              fill="none"
              stroke={l.color}
              strokeWidth={l.key === 'cvar' ? 3 : 2}
              strokeLinejoin="round"
              points={pts.map((p, i) => `${x(i)},${y(p.cvar[l.key])}`).join(' ')}
            />
            {pts.map((p, i) => (
              <circle
                key={i}
                cx={x(i)}
                cy={y(p.cvar[l.key])}
                r={i === props.index ? 5.5 : 3}
                fill={i === props.index ? l.color : C.surface}
                stroke={l.color}
                strokeWidth={2}
              />
            ))}
          </g>
        ))}
        {pts.map((p, i) => (
          <text
            key={p.budget_inr}
            x={x(i)}
            y={h - 10}
            textAnchor="middle"
            fontSize={11.5}
            className="num cursor-pointer"
            fill={i === props.index ? C.ink : C.muted}
            fontWeight={i === props.index ? 650 : 400}
            onClick={() => props.onIndex(i)}
          >
            {inrShort(p.budget_inr)}
          </text>
        ))}
      </svg>
    </div>
  )
}

export default function BudgetFrontier(props: { chrome?: boolean }) {
  const frontier = useLoad(() => api.frontier())
  const f = frontier.data
  const initial = useMemo(() => (f ? Math.max(0, f.points.findIndex((p) => p.budget_inr === 150_000)) : 0), [f])
  const [picked, setPicked] = useState<number | null>(null)
  if (frontier.error) return <ErrorState error={frontier.error} retry={frontier.reload} />
  if (!f) return <Skeleton className="h-[360px]" />
  const index = picked ?? initial
  const p = f.points[index]
  const cut = 1 - p.cvar.cvar / p.cvar.cvss
  const win = cheapestWin(f)

  const body = (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[12.5px] font-medium text-ink-2">Budget</p>
          <p className="num text-[30px] font-[680] leading-none tracking-[-0.02em] text-ink">{inr(p.budget_inr)}</p>
        </div>
        <div className="flex gap-6 text-right">
          {LINES.map((l) => (
            <div key={l.key}>
              <p className="flex items-center justify-end gap-1.5 text-[12px] font-medium text-ink-2">
                <span className="size-2 rounded-full" style={{ background: l.color }} />
                {l.label}
              </p>
              <p
                className="num text-[22px] font-[650] leading-tight"
                style={{ color: l.key === 'cvar' ? C.forest800 : C.ink }}
              >
                {loss(p.cvar[l.key])}
              </p>
            </div>
          ))}
          <div>
            <p className="text-[12px] font-medium text-ink-2">vs CVSS-first</p>
            <p className="num text-[22px] font-[650] leading-tight text-ok">−{(cut * 100).toFixed(0)}%</p>
          </div>
        </div>
      </div>
      <input
        type="range"
        min={0}
        max={f.points.length - 1}
        step={1}
        value={index}
        onChange={(e) => setPicked(Number(e.target.value))}
        aria-label="Budget"
        className="w-full cursor-pointer accent-[var(--color-forest-800)]"
      />
      <Chart frontier={f} index={index} onIndex={setPicked} />
      {win && (
        <p className="rounded-lg border border-forest-200 bg-forest-50 px-4 py-3 text-[13.5px] text-ink-2">
          With <span className="num font-semibold text-ink">{inr(win.ours.budget_inr)}</span>, UrbanShield's worst case (
          <span className="num font-semibold text-forest-800">{loss(win.ours.cvar.cvar)}</span>) is already lower than
          CVSS-first with <span className="num font-semibold text-ink">{inr(win.theirs.budget_inr)}</span> (
          <span className="num font-semibold text-high">{loss(win.theirs.cvar.cvss)}</span>).
        </p>
      )}
      <p className="text-[11.5px] text-muted">
        Worst-case loss = CVaR95 on {f.n_scenarios.toLocaleString('en-IN')} held-out scenarios (test seed {f.test_seed}
        ), {f.downtime_h} h downtime window; precomputed by <code>{f.generated_by}</code>.
      </p>
    </div>
  )
  if (props.chrome === false) return body
  return (
    <Card className="px-5 py-4" aria-label="Budget frontier">
      <div className="mb-3">
        <p className="eyebrow">Where the next rupee goes</p>
        <h2 className="mt-1 font-serif text-[26px] leading-tight text-ink">Worst-case loss by budget</h2>
      </div>
      {body}
    </Card>
  )
}
