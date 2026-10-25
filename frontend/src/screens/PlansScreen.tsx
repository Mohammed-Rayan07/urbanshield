// Risk Intelligence: why the CVaR plan wins under the same budget. Analysis-first, small context map.
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpDown,
  Boxes,
  CircleDollarSign,
  FlaskConical,
  Gauge,
  Lightbulb,
  Shield,
  Sigma,
  Workflow,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { api, useLoad } from '../api'
import CityMap from '../components/CityMap'
import { LossDistribution, SeriesLegend } from '../components/charts'
import {
  Badge,
  Card,
  CardHeader,
  CountUp,
  Delta,
  ErrorState,
  Kpi,
  LinkButton,
  Metric,
  PageHeader,
  Rows,
  Segmented,
  Skeleton,
} from '../components/ui'
import { cx } from '../lib/cx'
import { C, SERIES } from '../lib/colors'
import { CATEGORIES, overlap, planCost, riskById, sum } from '../lib/derive'
import {
  CATEGORY_LABEL,
  CONTROL_LABEL,
  OBJECTIVE_LABEL,
  OBJECTIVE_NOTE,
  change,
  hours,
  inr,
  inrShort,
  int,
  loss,
  ms,
  pct,
  share,
} from '../lib/format'
import { href } from '../lib/route'
import { useStore } from '../lib/store'
import type { LossHistogram, Objective, Plan } from '../types'
import BudgetFrontier from '../components/BudgetFrontier'

const BASELINES: { id: Objective; label: string }[] = [
  { id: 'cvss', label: 'CVSS-first' },
  { id: 'cvss_kev_epss', label: 'CVSS+KEV+EPSS' },
  { id: 'bfs_centrality', label: 'BFS-only' },
  { id: 'mean', label: 'Mean-loss' },
  { id: 'patch_only', label: 'Patch-only' },
  { id: 'greedy_tail', label: 'Greedy' },
]

const SHORT: Record<Objective, string> = {
  cvar: 'UrbanShield',
  greedy_tail: 'Greedy',
  mean: 'Mean-loss',
  patch_only: 'Patch-only',
  loss_per_inr: 'Loss / ₹',
  bfs_centrality: 'BFS-only',
  cvss: 'CVSS-first',
  cvss_kev_epss: 'CVSS+KEV',
}

type SortKey = 'cvar' | 'mean_loss' | 'max_cascade' | 'cost_inr' | 'solve_ms'

function heat(rank: number, n: number) {
  // best → green tint, worst → red tint; rank 0 is best
  const t = n <= 1 ? 0 : rank / (n - 1)
  const from = [229, 242, 232]
  const to = [253, 232, 229]
  const mix = from.map((f, i) => Math.round(f + (to[i] - f) * t))
  return `rgb(${mix.join(' ')})`
}

export default function PlansScreen() {
  const { city, plans, risk, devices } = useStore()
  const record = useLoad(() => api.toolResult('tc-plans'))
  const [baselineId, setBaselineId] = useState<Objective>('cvss')
  const [selectedId, setSelectedId] = useState<Objective>('cvar')
  const [shown, setShown] = useState<LossHistogram['label'][]>(['none', 'cvss', 'bfs_centrality', 'cvar'])
  const [focus, setFocus] = useState<LossHistogram['label']>('cvar')
  const [tail, setTail] = useState<'all' | 'tail'>('all')
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: 'cvar', asc: true })

  const byObjective = useMemo(() => new Map((plans.data ?? []).map((p) => [p.objective, p])), [plans.data])
  const ours = byObjective.get('cvar')
  const base = byObjective.get(baselineId)
  const selected = byObjective.get(selectedId) ?? ours
  const budget = (record.data?.args.budget_inr as number | undefined) ?? null
  const downtime = (record.data?.args.downtime_h as number | undefined) ?? null
  const src = ours?.tool_call_id ? { toolCallId: ours.tool_call_id } : null
  const riskSrc = risk.data?.tool_call_id ? { toolCallId: risk.data.tool_call_id } : null

  const sorted = useMemo(() => {
    const list = [...(plans.data ?? [])]
    const val = (p: Plan) =>
      sort.key === 'cost_inr' || sort.key === 'solve_ms' ? p[sort.key] : (p.metrics?.[sort.key] ?? Infinity)
    return list.sort((a, b) => (sort.asc ? val(a) - val(b) : val(b) - val(a)))
  }, [plans.data, sort])
  const cvarRank = useMemo(
    () => new Map([...(plans.data ?? [])].sort((a, b) => (a.metrics?.cvar ?? 0) - (b.metrics?.cvar ?? 0)).map((p, i) => [p.id, i])),
    [plans.data],
  )

  if (plans.error) return <ErrorState error={plans.error} retry={plans.reload} />
  const om = ours?.metrics
  const bm = base?.metrics

  const spend = (p: Plan | undefined) =>
    CATEGORIES.map((cat) =>
      p && city.data ? planCost(city.data, p, Object.keys(p.choices).filter((id) => devices.get(id)?.category === cat)) : 0,
    )
  const oursSpend = spend(ours)
  const baseSpend = spend(base)
  const spendMax = Math.max(1, ...oursSpend, ...baseSpend)

  const onlyOurs = ours && base ? Object.keys(ours.choices).filter((d) => !(d in base.choices)) : []
  const onlyBase = ours && base ? Object.keys(base.choices).filter((d) => !(d in ours.choices)) : []
  const changed = ours && base ? Object.keys(ours.choices).filter((d) => d in base.choices && base.choices[d] !== ours.choices[d]) : []

  const matrixPlans = (['cvar', 'greedy_tail', 'mean', 'loss_per_inr', 'bfs_centrality', 'cvss'] as Objective[])
    .map((o) => byObjective.get(o))
    .filter((p): p is Plan => !!p)

  // evidence-linked findings, computed from the data on screen
  const baseRisk = riskById(risk.data?.baseline)
  const none = risk.data?.histograms.find((h) => h.label === 'none')
  const topDevice = [...(risk.data?.baseline ?? [])].sort((a, b) => b.tail_loss - a.tail_loss)[0]
  const top = topDevice ? devices.get(topDevice.device_id) : undefined
  const findings: { text: React.ReactNode; source: { toolCallId: string } | null }[] = []
  if (om && bm && base)
    findings.push({
      text: (
        <>
          Same budget, <b>{pct(change(bm.cvar, om.cvar))}</b> worst-case loss vs {OBJECTIVE_LABEL[base.objective]} (CVaR{' '}
          {loss(bm.cvar)} → {loss(om.cvar)})
          {om.ci_high < bm.ci_low ? ', and the 95% intervals do not overlap.' : '; the 95% intervals overlap, so treat the gap as indicative.'}
        </>
      ),
      source: src,
    })
  if (top && topDevice && none)
    findings.push({
      text: (
        <>
          {top.name} alone carries <b>{share(topDevice.tail_loss / none.cvar)}</b> of the uncontrolled worst case.
          UrbanShield {ours?.choices[top.id] ? `buys ${CONTROL_LABEL[ours.choices[top.id]].toLowerCase()} there` : 'leaves it'};{' '}
          {base ? OBJECTIVE_LABEL[base.objective] : 'the baseline'}{' '}
          {base?.choices[top.id] ? `buys ${CONTROL_LABEL[base.choices[top.id]].toLowerCase()}` : 'leaves it unprotected'}.
        </>
      ),
      source: riskSrc,
    })
  if (om && byObjective.get('mean')?.metrics)
    findings.push({
      text: (
        <>
          Optimising the average instead (same solver, same budget) leaves the tail <b>{pct(change(om.cvar, byObjective.get('mean')!.metrics!.cvar), 0)}</b>{' '}
          higher: the objective, not the solver, is what moves the worst case.
        </>
      ),
      source: src,
    })
  if (om)
    findings.push({
      text: (
        <>
          The planner's additive model is off by <b>{pct(om.linear_gap)}</b> on held-out scenarios; every figure on this page is
          the full simulator's, not the model's.
        </>
      ),
      source: src,
    })

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Risk intelligence"
        title="Same Budget, Smaller Worst Case"
        subtitle={
          <>
            Eight strategies, one budget{budget ? ` (${inr(budget)} · ${hours(downtime ?? 0)} downtime)` : ''}, each scored on{' '}
            {risk.data ? int(risk.data.n_scenarios) : '2,000'} simulated attack scenarios none of them was planned on.
          </>
        }
        aside={
          <div>
            <p className="mb-1.5 text-[12px] font-medium text-ink-2">Compare UrbanShield against</p>
            <Segmented label="Baseline strategy" size="sm" value={baselineId} onChange={setBaselineId} options={BASELINES} />
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
        <Kpi
          i={1}
          icon={Shield}
          label="UrbanShield worst case"
          value={om ? <Metric source={src && { ...src, label: 'CVaR95 of the CVaR plan, held-out' }}><CountUp value={om.cvar} format={(n) => loss(n)} /></Metric> : <Skeleton className="h-8 w-20" />}
          foot={om ? `95% CI ${loss(om.ci_low)}–${loss(om.ci_high)}` : ' '}
        />
        <Kpi
          i={2}
          icon={ArrowDownRight}
          tone="ok"
          label={`vs ${base ? OBJECTIVE_LABEL[base.objective] : '…'}`}
          value={om && bm ? <Metric source={src}><CountUp value={change(bm.cvar, om.cvar)} format={(n) => pct(n)} /></Metric> : <Skeleton className="h-8 w-20" />}
          foot={bm ? `Their CVaR ${loss(bm.cvar)} [${loss(bm.ci_low)}–${loss(bm.ci_high)}]` : ' '}
        />
        <Kpi
          i={3}
          icon={Sigma}
          tone="info"
          label="Expected loss"
          value={om ? <Metric source={src}><CountUp value={om.mean_loss} format={(n) => loss(n)} /></Metric> : <Skeleton className="h-8 w-16" />}
          delta={om && bm && <Delta good={om.mean_loss <= bm.mean_loss}>{pct(change(bm.mean_loss, om.mean_loss), 0)}</Delta>}
          foot={bm ? `${OBJECTIVE_LABEL[baselineId]}: ${loss(bm.mean_loss)}` : ' '}
        />
        <Kpi
          i={4}
          icon={Workflow}
          tone="high"
          label="Largest cascade"
          value={om ? <Metric source={src}>{om.max_cascade}</Metric> : <Skeleton className="h-8 w-12" />}
          unit="devices"
          delta={om && bm && <Delta good={om.max_cascade <= bm.max_cascade}>{om.max_cascade - bm.max_cascade > 0 ? '+' : ''}{om.max_cascade - bm.max_cascade}</Delta>}
          foot="Most devices lost in one scenario"
        />
        <Kpi
          i={5}
          icon={CircleDollarSign}
          tone="warn"
          label="Budget used"
          value={ours ? <Metric source={src}>{inrShort(ours.cost_inr)}</Metric> : <Skeleton className="h-8 w-20" />}
          foot={ours && budget ? `${share(ours.cost_inr / budget)} of ${inr(budget)} · ${hours(ours.downtime_h)}` : ' '}
        />
        <Kpi
          i={6}
          icon={Gauge}
          tone="neutral"
          label="Model gap (honesty check)"
          value={om ? <Metric source={src}>{pct(om.linear_gap)}</Metric> : <Skeleton className="h-8 w-16" />}
          foot="Planner's model vs full simulator"
        />
      </div>

      {/* forecast-equivalent: the distribution */}
      <BudgetFrontier />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
        <Card i={7} className="pb-4">
          <CardHeader
            title="Loss distribution (held-out)"
            sub="How often each total loss occurs. The hatched band is the worst 5% of the shaded strategy; CVaR is its average."
            right={
              <Segmented
                label="Range"
                size="sm"
                value={tail}
                onChange={setTail}
                options={[
                  { id: 'all', label: 'All scenarios' },
                  { id: 'tail', label: 'Zoom to tail' },
                ]}
              />
            }
          />
          <div className="px-5 pt-3">
            {risk.data && (
              <SeriesLegend
                items={(['none', 'cvss', 'cvss_kev_epss', 'bfs_centrality', 'cvar'] as LossHistogram['label'][])
                  .filter((l) => risk.data!.histograms.some((h) => h.label === l))
                  .map((label) => ({ label, on: shown.includes(label) }))}
                focus={focus}
                onFocus={setFocus}
                onToggle={(l) => {
                  setShown((s) => (s.includes(l) ? s.filter((x) => x !== l) : [...s, l]))
                  if (!shown.includes(l)) setFocus(l)
                }}
              />
            )}
          </div>
          <div className="px-3 pt-2">
            {risk.error ? (
              <ErrorState error={risk.error} retry={risk.reload} className="mx-2" />
            ) : risk.data ? (
              <LossDistribution risk={risk.data} labels={shown} focus={shown.includes(focus) ? focus : shown[0]} tailOnly={tail === 'tail'} height={330} />
            ) : (
              <Skeleton className="mx-2 h-[330px]" />
            )}
          </div>
          {risk.data && (
            <p className="px-5 pt-1 text-[12px] text-muted">
              Click a legend entry to shade its tail, again to hide it. Source:{' '}
              <Metric source={riskSrc}>{risk.data.tool_call_id}</Metric> · {int(risk.data.n_scenarios)} scenarios · α ={' '}
              {risk.data.alpha}
            </p>
          )}
        </Card>

        <Card i={8} className="flex flex-col pb-4">
          <CardHeader
            title="Selected strategy"
            sub={selected ? OBJECTIVE_NOTE[selected.objective] : ' '}
            right={<LinkButton href={href('overview')}>Full map <ArrowRight className="size-3.5" /></LinkButton>}
          />
          <div className="px-5 pt-3">
            <label className="sr-only" htmlFor="plan-select">
              Strategy
            </label>
            <select
              id="plan-select"
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value as Objective)}
              className="h-9 w-full cursor-pointer rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink outline-none focus:border-forest-700"
            >
              {(plans.data ?? []).map((p) => (
                <option key={p.id} value={p.objective}>
                  {OBJECTIVE_LABEL[p.objective]}
                </option>
              ))}
            </select>
          </div>
          <div className="mx-5 mt-3 h-[236px] overflow-hidden rounded-lg border border-line">
            {city.data && selected ? (
              <CityMap
                key={selected.id}
                city={city.data}
                risk={risk.data}
                mode="risk"
                compact
                showZones={false}
                styleFor={(d) =>
                  d.id in selected.choices
                    ? { fill: SERIES[selected.objective] ?? C.forest800, stroke: '#fff' }
                    : { fill: C.idle, dim: true }
                }
                className="h-full"
              />
            ) : (
              <Skeleton className="h-full rounded-none" />
            )}
          </div>
          {selected && (
            <div className="px-5 pt-3">
              <Rows
                rows={[
                  ['Controls bought', <Metric key="Controls bought" source={src}>{Object.keys(selected.choices).length} devices</Metric>],
                  ['Cost · downtime', <Metric key="Cost · downtime" source={src}>{`${inr(selected.cost_inr)} · ${hours(selected.downtime_h)}`}</Metric>],
                  [
                    'Worst case (CI)',
                    selected.metrics ? (
                      <Metric key="Worst case (CI)" source={src}>{`${loss(selected.metrics.cvar)}  [${loss(selected.metrics.ci_low)}–${loss(selected.metrics.ci_high)}]`}</Metric>
                    ) : (
                      '–'
                    ),
                  ],
                  [
                    'Solver',
                    <span key="Solver" className="flex items-center gap-1.5">
                      <Badge tone={selected.solver === 'milp' ? 'forest' : selected.solver === 'greedy' ? 'info' : 'neutral'}>
                        {selected.solver.toUpperCase()}
                      </Badge>
                      <span className="num text-muted">{ms(selected.solve_ms)}</span>
                    </span>,
                  ],
                ]}
              />
            </div>
          )}
        </Card>
      </div>

      {/* middle row */}
      <div className="grid gap-4 xl:grid-cols-[1fr_1.45fr_1fr]">
        <Card i={9} className="pb-5">
          <CardHeader title="Where the budget goes" sub={`Rupees per device category · UrbanShield vs ${OBJECTIVE_LABEL[baselineId]}`} />
          <ul className="space-y-4 px-5 pt-4">
            {CATEGORIES.map((cat, i) => (
              <li key={cat}>
                <div className="mb-1 flex justify-between text-[12.5px]">
                  <span className="text-ink-2">{CATEGORY_LABEL[cat]}</span>
                  <span className="num text-muted">
                    <span className="font-semibold text-forest-800">{inrShort(oursSpend[i])}</span> · {inrShort(baseSpend[i])}
                  </span>
                </div>
                <div className="space-y-1">
                  <div className="h-2 rounded-full bg-surface-muted">
                    <div className="grow-x h-2 rounded-full bg-forest-800" style={{ width: `${(oursSpend[i] / spendMax) * 100}%`, animationDelay: `${i * 70}ms` }} />
                  </div>
                  <div className="h-2 rounded-full bg-surface-muted">
                    <div className="grow-x h-2 rounded-full" style={{ width: `${(baseSpend[i] / spendMax) * 100}%`, background: SERIES[baselineId], animationDelay: `${i * 70 + 40}ms` }} />
                  </div>
                </div>
              </li>
            ))}
          </ul>
          <div className="mt-4 flex gap-4 px-5 text-[11.5px] text-ink-2">
            <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm bg-forest-800" /> UrbanShield</span>
            <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: SERIES[baselineId] }} /> {OBJECTIVE_LABEL[baselineId]}</span>
          </div>
        </Card>

        <Card i={10} className="pb-3">
          <CardHeader title="Strategy comparison" sub="All eight plans, same budget and constraints. Click a header to sort." />
          <div className="scroll-thin mt-3 overflow-x-auto px-3">
            <table className="w-full min-w-[620px] text-[12.5px]">
              <thead>
                <tr className="border-b border-line text-left text-[11.5px] text-muted">
                  <th className="px-2 py-2 font-medium">#</th>
                  <th className="px-2 py-2 font-medium">Strategy</th>
                  {(
                    [
                      ['cvar', 'Worst case'],
                      ['mean_loss', 'Mean'],
                      ['max_cascade', 'Cascade'],
                      ['cost_inr', 'Cost'],
                      ['solve_ms', 'Solve'],
                    ] as [SortKey, string][]
                  ).map(([k, l]) => (
                    <th
                      key={k}
                      className="px-2 py-2 text-right font-medium"
                      aria-sort={sort.key === k ? (sort.asc ? 'ascending' : 'descending') : 'none'}
                    >
                      <button
                        type="button"
                        onClick={() => setSort((s) => ({ key: k, asc: s.key === k ? !s.asc : true }))}
                        className={cx('inline-flex cursor-pointer items-center gap-1 hover:text-ink', sort.key === k && 'text-ink')}
                      >
                        {l}
                        <ArrowUpDown className="size-3" aria-hidden />
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {!plans.data && (
                  <tr>
                    <td colSpan={7} className="p-2">
                      <Skeleton className="h-48" />
                    </td>
                  </tr>
                )}
                {sorted.map((p, i) => {
                  const isOurs = p.objective === 'cvar'
                  const isBase = p.objective === baselineId
                  return (
                    <tr
                      key={p.id}
                      onClick={() => setSelectedId(p.objective)}
                      className={cx(
                        'cursor-pointer border-b border-line/70 transition-colors hover:bg-forest-50',
                        p.objective === selectedId && 'bg-forest-50',
                      )}
                    >
                      <td className="num px-2 py-2 text-muted">{i + 1}</td>
                      <td className="px-2 py-2">
                        <span key="solve_ms" className="flex items-center gap-2">
                          <span className="size-2 rounded-full" style={{ background: SERIES[p.objective] }} />
                          <span className={cx('font-medium', isOurs ? 'text-forest-800' : 'text-ink')}>{OBJECTIVE_LABEL[p.objective]}</span>
                          {isBase && <Badge tone="high">baseline</Badge>}
                        </span>
                      </td>
                      <td className="num px-2 py-2 text-right">
                        <span className="rounded px-1.5 py-0.5 font-semibold" style={{ background: heat(cvarRank.get(p.id) ?? 0, plans.data?.length ?? 1) }}>
                          {p.metrics ? loss(p.metrics.cvar) : '–'}
                        </span>
                      </td>
                      <td className="num px-2 py-2 text-right">{p.metrics ? loss(p.metrics.mean_loss) : '–'}</td>
                      <td className="num px-2 py-2 text-right">{p.metrics?.max_cascade ?? '–'}</td>
                      <td className="num px-2 py-2 text-right">{inrShort(p.cost_inr)}</td>
                      <td className="num px-2 py-2 text-right text-muted">
                        {p.solver === 'ranking' ? 'rank' : p.solver} · {ms(p.solve_ms)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>

        <Card i={11} className="pb-4">
          <CardHeader title="Evaluation & uncertainty" sub="How the numbers on this page were produced" />
          <div className="px-5 pt-2">
            {record.error ? (
              <ErrorState error={record.error} />
            ) : (
              <Rows
                rows={[
                  ['Risk measure', 'CVaR at α = 0.95 (mean of the worst 5%)'],
                  ['Test scenarios', risk.data ? <Metric key="Test scenarios" source={riskSrc}>{`${int(risk.data.n_scenarios)} held-out (separate seed)`}</Metric> : '–'],
                  ['Uncertainty', 'Bootstrap 95% CI, 500 resamples'],
                  ['Optimiser', 'MILP (SciPy HiGHS), Rockafellar–Uryasev'],
                  ['Model gap', om ? <Metric key="Model gap" source={src}>{pct(om.linear_gap)}</Metric> : '–'],
                  ['Budget', budget ? <Metric key="Budget" source={src}>{`${inr(budget)} · ${hours(downtime ?? 0)}`}</Metric> : '–'],
                  ['Provenance', <Metric key="Provenance" source={src}>{ours?.tool_call_id ?? 'tc-plans'}</Metric>],
                ]}
              />
            )}
            <p className="mt-3 flex items-start gap-2 rounded-lg bg-surface-muted p-2.5 text-[11.5px] text-ink-2">
              <FlaskConical className="mt-0.5 size-3.5 shrink-0 text-forest-800" aria-hidden />
              Every number is a deterministic tool output. Click any dotted value to see the call, its arguments and result.
            </p>
          </div>
        </Card>
      </div>

      {/* bottom row */}
      <div className="grid gap-4 xl:grid-cols-[1fr_1.1fr_1fr]">
        <Card i={12} className="pb-5">
          <CardHeader title="Plan overlap" sub="Share of protected devices two strategies have in common (Jaccard)" />
          <div className="scroll-thin overflow-x-auto px-5 pt-4">
            <table className="text-[11.5px]">
              <thead>
                <tr>
                  <th />
                  {matrixPlans.map((p) => (
                    <th key={p.id} className="px-0.5 pb-1.5 align-bottom font-medium text-muted">
                      <span className="block w-[50px] text-center leading-tight">{SHORT[p.objective]}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matrixPlans.map((a) => (
                  <tr key={a.id}>
                    <th className="whitespace-nowrap pr-2 text-right font-medium text-ink-2">
                      {SHORT[a.objective]}
                    </th>
                    {matrixPlans.map((b) => {
                      const v = overlap(a, b)
                      return (
                        <td key={b.id} className="p-0.5">
                          <div
                            className="num grid h-8 w-[50px] place-items-center rounded-md font-semibold animate-fade"
                            style={{
                              background: `color-mix(in srgb, ${C.forest800} ${Math.round(v * 92)}%, ${C.surfaceMuted})`,
                              color: v > 0.55 ? '#fff' : C.ink,
                            }}
                            title={`${OBJECTIVE_LABEL[a.objective]} ∩ ${OBJECTIVE_LABEL[b.objective]}`}
                          >
                            {v.toFixed(2)}
                          </div>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            {ours && matrixPlans.length > 1 && (() => {
              const others = matrixPlans.filter((p) => p.id !== ours.id)
              const closest = others.reduce((a, b) => (overlap(ours, a) >= overlap(ours, b) ? a : b))
              return (
                <p className="mt-3 text-[11.5px] text-muted">
                  Closest to UrbanShield: {OBJECTIVE_LABEL[closest.objective]} ({overlap(ours, closest).toFixed(2)}). Overlap is not
                  quality: a few different devices can move the tail a lot.
                </p>
              )
            })()}
          </div>
        </Card>

        <Card i={13} className="flex flex-col pb-4">
          <CardHeader
            title="Where the money moved"
            sub={`Devices only one plan protects · vs ${OBJECTIVE_LABEL[baselineId]}${changed.length ? ` · ${changed.length} with a different control` : ''}`}
          />
          <div className="grid flex-1 grid-cols-2 gap-3 px-5 pt-3">
            {[
              { title: 'Only UrbanShield', ids: onlyOurs, plan: ours, color: C.forest800, sign: '+' },
              { title: `Only ${BASELINES.find((b) => b.id === baselineId)?.label}`, ids: onlyBase, plan: base, color: SERIES[baselineId], sign: '−' },
            ].map((col) => (
              <div key={col.title} className="min-w-0">
                <p className="mb-1.5 flex items-center justify-between text-[12px] font-semibold text-ink">
                  {col.title}
                  <span className="num text-muted">{col.ids.length}</span>
                </p>
                <ul className="scroll-thin max-h-[208px] space-y-1 overflow-y-auto pr-1">
                  {[...col.ids]
                    .sort((a, b) => (baseRisk.get(b)?.tail_loss ?? 0) - (baseRisk.get(a)?.tail_loss ?? 0))
                    .map((id) => {
                      const d = devices.get(id)
                      const kind = col.plan?.choices[id]
                      return (
                        <li key={id} className="flex items-center gap-2 rounded-md border border-line px-2 py-1.5 text-[12px]">
                          <span className="num w-3 font-bold" style={{ color: col.color }}>
                            {col.sign}
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="block truncate font-medium text-ink">{d?.name ?? id}</span>
                            <span className="block truncate text-[11px] text-muted">{kind ? CONTROL_LABEL[kind] : ''}</span>
                          </span>
                          <span className="num shrink-0 text-[11px] text-ink-2" title="Share of uncontrolled worst case">
                            {none ? share((baseRisk.get(id)?.tail_loss ?? 0) / none.cvar, 1) : ''}
                          </span>
                        </li>
                      )
                    })}
                  {!col.ids.length && <li className="text-[12px] text-muted">None</li>}
                </ul>
              </div>
            ))}
          </div>
          {none && (
            <p className="px-5 pt-3 text-[11.5px] text-muted">
              Right-hand figure: the device's share of the uncontrolled worst case. UrbanShield's extra devices hold{' '}
              <b className="text-ink">{share(sum(onlyOurs.map((id) => baseRisk.get(id)?.tail_loss ?? 0)) / none.cvar)}</b>; the
              baseline's hold <b className="text-ink">{share(sum(onlyBase.map((id) => baseRisk.get(id)?.tail_loss ?? 0)) / none.cvar)}</b>.
            </p>
          )}
        </Card>

        <Card i={14} className="pb-4">
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <Lightbulb className="size-4 text-warn" aria-hidden /> Key findings
              </span>
            }
            sub="Computed from the data above; each links to its source"
          />
          <ol className="space-y-3 px-5 pt-4">
            {findings.map((f, i) => (
              <li key={i} className="flex gap-3 text-[12.5px] leading-relaxed text-ink-2 animate-rise" style={{ animationDelay: `${300 + i * 80}ms` }}>
                <span className="num grid size-6 shrink-0 place-items-center rounded-full bg-forest-100 text-[11.5px] font-bold text-forest-800">
                  {i + 1}
                </span>
                <span>
                  {f.text}{' '}
                  {f.source && (
                    <Metric source={f.source} className="text-[11px] text-forest-800">
                      source
                    </Metric>
                  )}
                </span>
              </li>
            ))}
            {!findings.length && <Skeleton className="h-40" />}
          </ol>
          <div className="mx-5 mt-4 flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-[11.5px] text-ink-2">
            <Boxes className="size-3.5 text-forest-800" aria-hidden />
            Full tables and sensitivity runs: <span className="font-mono">docs/EVALS.md</span>
          </div>
        </Card>
      </div>
    </div>
  )
}
