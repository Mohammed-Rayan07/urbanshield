// Hand-built SVG charts. The tail chart is the product's argument, so it gets exact control over
// shading, markers and motion that a generic chart library would fight.
import { useState, type ReactNode } from 'react'
import { seriesColor, seriesLabel, useSize } from '../lib/chart'
import { C } from '../lib/colors'
import { cx } from '../lib/cx'
import { loss, share } from '../lib/format'
import type { CityRisk, LossHistogram } from '../types'

function niceTicks(max: number, count = 5): number[] {
  if (max <= 0) return [0]
  const raw = max / count
  const pow = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 2.5, 5, 10].map((m) => m * pow).find((s) => s >= raw) ?? raw
  const out: number[] = []
  for (let v = 0; v <= max + 1e-9; v += step) out.push(+v.toFixed(6))
  return out
}

/** Distribution of total simulated loss per strategy, with the CVaR tail shaded for the focus series. */
export function LossDistribution(props: {
  risk: CityRisk
  labels: LossHistogram['label'][]
  focus: LossHistogram['label']
  tailOnly?: boolean
  height?: number
  onFocus?: (l: LossHistogram['label']) => void
}) {
  const [ref, { w }] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const h = props.height ?? 300
  const pad = { l: 46, r: 18, t: 30, b: 34 }
  const edges = props.risk.bin_edges
  const hists = props.labels
    .map((l) => props.risk.histograms.find((x) => x.label === l))
    .filter((x): x is LossHistogram => !!x)
  const focus = hists.find((x) => x.label === props.focus) ?? hists[0]

  const lo = props.tailOnly ? Math.max(0, Math.min(...hists.map((x) => x.var)) * 0.85) : 0
  // trim empty right-hand bins so the tail is not a hairline at the edge
  const lastBin = Math.max(0, ...hists.map((x) => x.counts.findLastIndex((c) => c > 0)))
  const hiIdx = Math.min(edges.length - 1, lastBin + 2)
  const hi = edges[hiIdx]
  const firstBin = Math.max(0, edges.findIndex((e) => e >= lo) - 1)
  const visible = (i: number) => i >= firstBin && i < hiIdx
  const ymax = Math.max(1, ...hists.flatMap((x) => x.counts.filter((_, i) => visible(i))))
  const iw = Math.max(10, w - pad.l - pad.r)
  const ih = h - pad.t - pad.b
  const sx = (v: number) => pad.l + ((v - lo) / (hi - lo || 1)) * iw
  // sqrt keeps a 2-scenario tail bin visible next to a 900-scenario body
  const sy = (c: number) => pad.t + ih - Math.sqrt(c / ymax) * ih

  const path = (x: LossHistogram, close: boolean) => {
    let d = ''
    let started = false
    for (let i = firstBin; i < hiIdx; i++) {
      const x0 = sx(Math.max(lo, edges[i]))
      const x1 = sx(edges[i + 1])
      const y = sy(x.counts[i])
      d += started ? `L${x0},${y}L${x1},${y}` : `M${x0},${sy(0)}L${x0},${y}L${x1},${y}`
      started = true
    }
    if (close) d += `L${sx(edges[hiIdx])},${sy(0)}Z`
    return d
  }

  const tailPath = (x: LossHistogram) => {
    let d = ''
    for (let i = firstBin; i < hiIdx; i++) {
      if (edges[i + 1] <= x.var || x.counts[i] === 0) continue
      const x0 = sx(Math.max(lo, edges[i], x.var))
      const x1 = sx(edges[i + 1])
      d += `M${x0},${sy(0)}L${x0},${sy(x.counts[i])}L${x1},${sy(x.counts[i])}L${x1},${sy(0)}Z`
    }
    return d
  }

  const xTicks =niceTicks(hi - lo, 6).map((t) => t + (props.tailOnly ? Math.ceil(lo) : 0)).filter((t) => t >= lo && t <= hi)
  const yTicks = [0, 0.25, 0.5, 1].map((f) => Math.round(f * f * ymax)).filter((v, i, a) => a.indexOf(v) === i)

  return (
    <div ref={ref} className="relative w-full" style={{ height: h }}>
      {w > 0 && focus && (
        <svg width={w} height={h} role="img" aria-label="Distribution of simulated total loss per strategy">
          <defs>
            <pattern id="tailHatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <rect width="6" height="6" fill={seriesColor(focus.label)} opacity="0.16" />
              <line x1="0" y1="0" x2="0" y2="6" stroke={seriesColor(focus.label)} strokeWidth="1.6" opacity="0.55" />
            </pattern>
            <clipPath id="plot">
              <rect x={pad.l} y={pad.t - 4} width={iw} height={ih + 4} />
            </clipPath>
          </defs>
          {/* grid */}
          {yTicks.map((t) => (
            <g key={`y${t}`}>
              <line x1={pad.l} x2={pad.l + iw} y1={sy(t)} y2={sy(t)} stroke={C.line} />
              <text x={pad.l - 8} y={sy(t) + 4} textAnchor="end" className="num fill-muted text-[10.5px]">
                {t}
              </text>
            </g>
          ))}
          {xTicks.map((t) => (
            <text key={`x${t}`} x={sx(t)} y={h - pad.b + 18} textAnchor="middle" className="num fill-muted text-[10.5px]">
              {t}
            </text>
          ))}
          <text x={pad.l + iw} y={h - 4} textAnchor="end" className="fill-muted text-[10.5px]">
            total loss per scenario (criticality units) →
          </text>
          <text x={12} y={pad.t - 14} className="fill-muted text-[10.5px]">
            scenarios (√ scale)
          </text>

          <g clipPath="url(#plot)">
            {/* the focus series' worst 5%: the scenario mass at or above its VaR */}
            <path
              key={`tail-${focus.label}-${props.tailOnly}`}
              d={tailPath(focus)}
              fill="url(#tailHatch)"
              stroke={seriesColor(focus.label)}
              strokeOpacity={0.35}
              className="animate-fade"
            />
            <line
              x1={sx(Math.max(lo, focus.var))}
              x2={sx(Math.max(lo, focus.var))}
              y1={pad.t + ih - 46}
              y2={pad.t + ih}
              stroke={seriesColor(focus.label)}
              strokeWidth={1}
            />
            <text
              x={sx(Math.max(lo, focus.var)) + 4}
              y={pad.t + ih - 36}
              className="text-[10px] font-semibold"
              fill={seriesColor(focus.label)}
              style={{ paintOrder: 'stroke', stroke: '#fff', strokeWidth: 3 }}
            >
              worst 5% ▸
            </text>
            {hists.map((x, k) => {
              const isFocus = x.label === focus.label
              const color = seriesColor(x.label)
              return (
                <g key={`${x.label}-${props.tailOnly}`} className="grow-y" style={{ animationDelay: `${k * 90}ms` }}>
                  <path d={path(x, true)} fill={color} opacity={isFocus ? 0.16 : 0.05} />
                  <path
                    d={path(x, false)}
                    fill="none"
                    stroke={color}
                    strokeWidth={isFocus ? 2.2 : 1.4}
                    opacity={isFocus ? 1 : 0.8}
                    strokeLinejoin="round"
                  />
                </g>
              )
            })}
          </g>

          {/* CVaR markers */}
          {hists.map((x, k) => {
            const X = sx(x.cvar)
            if (X < pad.l || X > pad.l + iw) return null
            const color = seriesColor(x.label)
            const isFocus = x.label === focus.label
            return (
              <g key={`m-${x.label}`} className="animate-fade" style={{ animationDelay: `${300 + k * 90}ms` }}>
                <line x1={X} x2={X} y1={pad.t - 2} y2={pad.t + ih} stroke={color} strokeWidth={isFocus ? 1.8 : 1.2} strokeDasharray="4 3" />
                <circle cx={X} cy={pad.t - 2} r={3} fill={color} />
                <text
                  x={X + 5}
                  y={pad.t + 10 + k * 13}
                  className="num text-[10.5px] font-semibold"
                  fill={color}
                  style={{ paintOrder: 'stroke', stroke: '#fff', strokeWidth: 3 }}
                >
                  CVaR {loss(x.cvar)}
                </text>
              </g>
            )
          })}

          {/* hover */}
          <rect
            x={pad.l}
            y={pad.t}
            width={iw}
            height={ih}
            fill="transparent"
            onMouseMove={(e) => {
              const box = (e.currentTarget as SVGRectElement).getBoundingClientRect()
              const v = lo + ((e.clientX - box.left) / iw) * (hi - lo)
              const i = edges.findIndex((edge, j) => v >= edge && v < edges[j + 1])
              setHover(i >= 0 ? i : null)
            }}
            onMouseLeave={() => setHover(null)}
          />
          {hover !== null && (
            <line
              x1={sx((edges[hover] + edges[hover + 1]) / 2)}
              x2={sx((edges[hover] + edges[hover + 1]) / 2)}
              y1={pad.t}
              y2={pad.t + ih}
              stroke={C.ink2}
              strokeWidth={1}
              pointerEvents="none"
            />
          )}
        </svg>
      )}
      {hover !== null && w > 0 && (
        <div
          className="pointer-events-none absolute z-10 min-w-[180px] rounded-lg bg-forest-950 px-3 py-2 text-[12px] text-white shadow-lg"
          style={{
            left: Math.min(w - 196, Math.max(0, sx((edges[hover] + edges[hover + 1]) / 2) + 12)),
            top: pad.t + 6,
          }}
        >
          <p className="num mb-1 font-semibold">
            Loss {loss(edges[hover], 1)}–{loss(edges[hover + 1], 1)}
          </p>
          {hists.map((x) => (
            <p key={x.label} className="num flex items-center justify-between gap-4 opacity-90">
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full" style={{ background: seriesColor(x.label) }} />
                {seriesLabel(x.label)}
              </span>
              <span>{x.counts[hover]}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  )
}

export function SeriesLegend(props: {
  items: { label: LossHistogram['label']; on: boolean }[]
  focus: LossHistogram['label']
  onToggle: (l: LossHistogram['label']) => void
  onFocus: (l: LossHistogram['label']) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {props.items.map(({ label, on }) => (
        <button
          key={label}
          type="button"
          aria-pressed={on}
          onClick={() => (on && props.focus !== label ? props.onFocus(label) : props.onToggle(label))}
          title={on ? 'Click to shade this strategy’s tail; click again to hide it' : 'Show'}
          className={cx(
            'flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-[12px] font-medium transition-all',
            on ? 'border-line bg-surface text-ink' : 'border-dashed border-line text-muted opacity-60',
            props.focus === label && on && 'border-line-strong bg-surface-muted shadow-sm',
          )}
        >
          <span className="h-[3px] w-3.5 rounded-full" style={{ background: seriesColor(label) }} />
          {seriesLabel(label)}
        </button>
      ))}
    </div>
  )
}

/** Horizontal ranked bars with an optional "after" ghost bar. */
export function RankBars(props: {
  rows: { key: string; label: ReactNode; value: number; after?: number; color: string; text: ReactNode; onClick?: () => void; active?: boolean }[]
  max?: number
}) {
  const max = props.max ?? Math.max(1e-9, ...props.rows.map((r) => r.value))
  return (
    <ul className="space-y-2.5">
      {props.rows.map((r, i) => (
        <li key={r.key}>
          <button
            type="button"
            onClick={r.onClick}
            disabled={!r.onClick}
            className={cx(
              'grid w-full grid-cols-[minmax(84px,30%)_1fr_auto] items-center gap-3 rounded-md px-1 py-0.5 text-left text-[12.5px] transition-colors',
              r.onClick && 'cursor-pointer hover:bg-forest-50',
              r.active && 'bg-forest-50',
            )}
          >
            <span className="truncate text-ink-2">{r.label}</span>
            <span className="relative h-2.5 rounded-full bg-surface-muted">
              <span
                className="grow-x absolute inset-y-0 left-0 rounded-full"
                style={{ width: `${(r.value / max) * 100}%`, background: r.color, animationDelay: `${i * 70}ms` }}
              />
              {r.after !== undefined && (
                <span
                  className="absolute -bottom-[5px] h-[3px] rounded-full bg-forest-800"
                  style={{ width: `${(r.after / max) * 100}%` }}
                  title="With the UrbanShield plan"
                />
              )}
            </span>
            <span className="num min-w-[44px] text-right font-semibold text-ink">{r.text}</span>
          </button>
        </li>
      ))}
    </ul>
  )
}

/** Donut with a centred figure. Segments animate in; hover highlights. */
export function Donut(props: {
  segments: { key: string; label: string; value: number; color: string }[]
  center: ReactNode
  caption: ReactNode
  size?: number
}) {
  const size = props.size ?? 148
  const r = size / 2 - 12
  const circ = 2 * Math.PI * r
  const total = props.segments.reduce((a, s) => a + s.value, 0) || 1
  const [hover, setHover] = useState<string | null>(null)
  const lengths = props.segments.map((s) => (s.value / total) * circ)
  const offsets = lengths.map((_, i) => -lengths.slice(0, i).reduce((a, b) => a + b, 0))
  return (
    <div className="flex items-center gap-5">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={C.surfaceMuted} strokeWidth={18} />
          {props.segments.map((s, i) => {
            const dash = `${Math.max(0, lengths[i] - 2)} ${circ}`
            const off = offsets[i]
            return (
              <circle
                key={s.key}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={hover === s.key ? 22 : 18}
                strokeDasharray={dash}
                strokeDashoffset={off}
                className="animate-fade transition-[stroke-width] duration-200"
                style={{ animationDelay: `${i * 90}ms` }}
                onMouseEnter={() => setHover(s.key)}
                onMouseLeave={() => setHover(null)}
              />
            )
          })}
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-[26px] font-bold leading-none tracking-[-0.02em] text-ink">{props.center}</div>
            <div className="mt-1 text-[10.5px] font-medium leading-tight text-muted">{props.caption}</div>
          </div>
        </div>
      </div>
      <ul className="min-w-0 flex-1 space-y-2 text-[12.5px]">
        {props.segments.map((s) => (
          <li
            key={s.key}
            onMouseEnter={() => setHover(s.key)}
            onMouseLeave={() => setHover(null)}
            className={cx('flex items-center gap-2 rounded px-1 transition-colors', hover === s.key && 'bg-forest-50')}
          >
            <span className="size-2.5 shrink-0 rounded-full" style={{ background: s.color }} />
            <span className="flex-1 truncate text-ink-2">{s.label}</span>
            <span className="num font-semibold text-ink">{share(s.value / total)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
