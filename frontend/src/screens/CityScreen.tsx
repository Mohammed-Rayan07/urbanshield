// Overview: the city twin and where its worst-case loss sits. Map-first.
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Ambulance,
  Bug,
  ChevronRight,
  Globe2,
  Map as MapIcon,
  Network,
  Search,
  ShieldCheck,
  Siren,
  TrendingDown,
  X,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import CityMap, { BasemapToggle, RiskLegend, ShapeLegend, type Basemap, type MapMode } from '../components/CityMap'
import { Donut, LossDistribution, RankBars } from '../components/charts'
import { seriesColor, seriesLabel } from '../lib/chart'
import DevicePanel from '../components/DevicePanel'
import {
  Button,
  Card,
  CardHeader,
  CountUp,
  Delta,
  Empty,
  ErrorState,
  Kpi,
  LinkButton,
  Metric,
  Segmented,
  Skeleton,
} from '../components/ui'
import { cx, rise } from '../lib/cx'
import { C } from '../lib/colors'
import {
  CATEGORIES,
  DEVICE_THRESHOLDS,
  ZONE_THRESHOLDS,
  cveAlerts,
  isCorridor,
  levelOf,
  riskColor,
  riskById,
  sum,
  zones as deriveZones,
  type CveAlert,
} from '../lib/derive'
import { CATEGORY_LABEL, CATEGORY_PLURAL, change, int, loss, pct, plural, share } from '../lib/format'
import { href, navigate } from '../lib/route'
import { useStore } from '../lib/store'

const SEVERITY = {
  critical: { tone: 'danger' as const, icon: Siren, color: C.danger, label: 'Critical' },
  high: { tone: 'high' as const, icon: AlertTriangle, color: C.high, label: 'High' },
  medium: { tone: 'warn' as const, icon: Bug, color: C.warn, label: 'Medium' },
}

function AlertBanner(props: { alert: CveAlert; presetId: string | null; onShow: () => void }) {
  const a = props.alert
  const [hidden, setHidden] = useState(false)
  if (hidden) return null
  const cats = a.categories.map((c) => CATEGORY_PLURAL[c]).join(', ')
  return (
    <div className="relative flex max-w-[640px] flex-1 animate-rise items-center gap-4 rounded-xl border border-danger/20 bg-danger-soft py-4 pl-4 pr-5">
      <div className="grid size-11 shrink-0 place-items-center rounded-lg bg-white/70 text-danger">
        <AlertTriangle className="size-5" aria-hidden />
      </div>
      <div className="min-w-0 flex-1">
        <span className="inline-flex rounded bg-danger px-1.5 py-0.5 text-[10.5px] font-bold tracking-[0.06em] text-white">
          HIGHEST TAIL EXPOSURE
        </span>
        <p className="mt-1.5 text-[18px] font-semibold leading-snug tracking-[-0.01em] text-ink">
          {a.cve}: one bug, {plural(a.devices.length, 'device')}
        </p>
        <p className="mt-0.5 text-[13px] text-ink-2">
          {a.kev ? 'Listed in CISA KEV' : 'Not in KEV'} · CVSS {a.cvss.toFixed(1)} · EPSS {a.epss.toFixed(2)}. Shared{' '}
          {a.families.join(', ')} firmware on {cats}; its carriers hold{' '}
          <span className="font-semibold text-ink">{share(a.share)}</span> of the uncontrolled worst-case loss.
        </p>
      </div>
      <div className="flex shrink-0 flex-col gap-2">
        {props.presetId && (
          <Button icon={ArrowRight} onClick={() => navigate('response', { advisory: props.presetId! })}>
            Respond
          </Button>
        )}
        <Button variant="secondary" onClick={props.onShow}>
          Show on map
        </Button>
      </div>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => setHidden(true)}
        className="absolute right-2 top-2 grid size-6 cursor-pointer place-items-center rounded text-ink-2 hover:bg-white/60"
      >
        <X className="size-3.5" />
      </button>
    </div>
  )
}

function DeviceSearch(props: { onPick: (id: string) => void; onCve: (cve: string) => void; alerts: CveAlert[] }) {
  const { city } = useStore()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const needle = q.trim().toLowerCase()
  const devices = needle
    ? (city.data?.devices ?? [])
        .filter((d) => `${d.id} ${d.name} ${d.zone} ${d.firmware}`.toLowerCase().includes(needle))
        .slice(0, 6)
    : []
  const cves = needle ? props.alerts.filter((a) => a.cve.toLowerCase().includes(needle)).slice(0, 3) : []
  return (
    <div className="relative w-[230px]">
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
      <input
        value={q}
        onChange={(e) => {
          setQ(e.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 150)}
        placeholder="Search device, zone, firmware or CVE"
        aria-label="Search devices, zones, firmware or CVEs"
        className="h-9 w-full rounded-lg border border-line bg-surface pl-9 pr-3 text-[13px] text-ink outline-none transition-colors placeholder:text-muted focus:border-forest-700"
      />
      {open && (devices.length > 0 || cves.length > 0) && (
        <ul className="absolute left-0 right-0 top-10 z-[700] overflow-hidden rounded-lg border border-line bg-surface py-1 shadow-lg">
          {cves.map((a) => (
            <li key={a.cve}>
              <button
                type="button"
                onMouseDown={() => {
                  props.onCve(a.cve)
                  setQ('')
                }}
                className="flex w-full cursor-pointer items-center justify-between px-3 py-1.5 text-left text-[12.5px] hover:bg-forest-50"
              >
                <span className="font-mono">{a.cve}</span>
                <span className="text-muted">{plural(a.devices.length, 'device')}</span>
              </button>
            </li>
          ))}
          {devices.map((d) => (
            <li key={d.id}>
              <button
                type="button"
                onMouseDown={() => {
                  props.onPick(d.id)
                  setQ('')
                }}
                className="flex w-full cursor-pointer items-center justify-between px-3 py-1.5 text-left text-[12.5px] hover:bg-forest-50"
              >
                <span className="truncate">{d.name}</span>
                <span className="text-muted">{d.zone}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function CityScreen() {
  const { city, risk, plans, presets, selectedDevice, selectDevice, selectedCve, selectCve, devices } = useStore()
  const [mode, setMode] = useState<MapMode>('risk')
  const [basemap, setBasemap] = useState<Basemap>('map')
  const [focusIds, setFocusIds] = useState<string[] | null>(null)

  const alerts = useMemo(() => (city.data ? cveAlerts(city.data, risk.data) : []), [city.data, risk.data])
  const zones = useMemo(() => (city.data ? deriveZones(city.data, risk.data) : []), [city.data, risk.data])
  const presetFor = (cve: string) => presets.data?.find((p) => p.kind === 'normal' && p.text.includes(cve))?.id ?? null

  const none = risk.data?.histograms.find((h) => h.label === 'none')
  const ours = risk.data?.histograms.find((h) => h.label === 'cvar')
  const src = risk.data?.tool_call_id ? { toolCallId: risk.data.tool_call_id } : null
  const cvarPlan = plans.data?.find((p) => p.objective === 'cvar')
  const activeAlert = alerts.find((a) => a.cve === selectedCve) ?? null
  const ripple = activeAlert?.devices.map((d) => d.id)

  const showCve = (cve: string) => {
    const a = alerts.find((x) => x.cve === cve)
    selectCve(cve === selectedCve ? null : cve)
    selectDevice(null)
    setFocusIds(cve === selectedCve ? null : (a?.devices.map((d) => d.id) ?? null))
  }
  const pickDevice = (id: string | null) => {
    selectDevice(id)
    if (id) setFocusIds([id])
  }

  if (city.error) return <ErrorState error={city.error} retry={city.reload} />
  const c = city.data
  const kev = new Set(c?.devices.flatMap((d) => d.vulns.filter((v) => v.kev).map((v) => v.cve_id)))
  const corridor = c?.devices.filter(isCorridor) ?? []
  const base = riskById(risk.data?.baseline)
  const corridorP = Math.max(0, ...corridor.map((d) => base.get(d.id)?.p_compromised ?? 0))
  const exposed = c?.devices.filter((d) => d.exposed) ?? []
  const device = selectedDevice ? devices.get(selectedDevice) : undefined

  const categoryShare = CATEGORIES.map((cat) => ({
    key: cat,
    label: CATEGORY_LABEL[cat],
    value: sum((c?.devices ?? []).filter((d) => d.category === cat).map((d) => base.get(d.id)?.tail_loss ?? 0)),
    color: { signal: C.forest800, meter: C.info, streetlight: C.warn, ev_charger: C.high }[cat],
  }))

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-6">
        <div className="animate-rise">
          <p className="eyebrow">City overview</p>
          <h1 className="mt-1.5 font-serif text-[44px] leading-[1.02] tracking-[-0.01em]">Current Risk Status</h1>
          <p className="mt-2 max-w-[54ch] text-[14.5px] text-ink-2">
            Simulated cyber-risk posture of the Mangaluru digital twin:{' '}
            {c ? `${c.devices.length} connected devices, ${c.edges.length} network links` : 'loading…'}, measured on{' '}
            {risk.data ? int(risk.data.n_scenarios) : '–'} held-out attack scenarios.
          </p>
        </div>
        {alerts[0] && risk.data && (
          <AlertBanner alert={alerts[0]} presetId={presetFor(alerts[0].cve)} onShow={() => showCve(alerts[0].cve)} />
        )}
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Kpi
          i={1}
          icon={Activity}
          tone="danger"
          label="Worst-case loss (CVaR 95%)"
          value={none ? <Metric source={src && { ...src, label: 'Uncontrolled CVaR95' }}><CountUp value={none.cvar} format={(n) => loss(n)} /></Metric> : risk.error ? '–' : <Skeleton className="h-8 w-20" />}
          delta={none && ours && <Delta good>{pct(change(none.cvar, ours.cvar), 0)}</Delta>}
          foot={ours ? `No controls · ${loss(ours.cvar)} with UrbanShield` : 'No controls'}
        />
        <Kpi
          i={2}
          icon={TrendingDown}
          tone="high"
          label="Expected loss per scenario"
          value={none ? <Metric source={src}><CountUp value={none.mean_loss} format={(n) => loss(n)} /></Metric> : risk.error ? '–' : <Skeleton className="h-8 w-20" />}
          delta={none && ours && <Delta good>{pct(change(none.mean_loss, ours.mean_loss), 0)}</Delta>}
          foot="Average over all scenarios"
        />
        <Kpi
          i={3}
          icon={Globe2}
          tone="danger"
          label="Internet-exposed devices"
          value={c ? <CountUp value={exposed.length} format={(n) => int(n)} /> : <Skeleton className="h-8 w-12" />}
          unit={c ? `/ ${c.devices.length}` : undefined}
          foot={c ? `${c.devices.filter((d) => d.tags.includes('gateway')).length} gateways bridge into the grid` : ' '}
        />
        <Kpi
          i={4}
          icon={Bug}
          tone="warn"
          label="Known-exploited CVEs"
          value={c ? <CountUp value={kev.size} format={(n) => int(n)} /> : <Skeleton className="h-8 w-12" />}
          foot={c ? `CISA KEV · on ${c.devices.filter((d) => d.vulns.some((v) => v.kev)).length} devices` : ' '}
        />
        <Kpi
          i={5}
          icon={Ambulance}
          tone="info"
          label="Ambulance corridor"
          value={c ? <CountUp value={corridor.length} format={(n) => int(n)} /> : <Skeleton className="h-8 w-12" />}
          unit="signals"
          foot={risk.data ? <>Max P(compromised) <Metric source={src}>{share(corridorP, 1)}</Metric></> : ' '}
        />
      </div>

      {/* Map + alerts */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card i={6} className="overflow-hidden" aria-label="Risk map">
          <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
            <h2 className="mr-1 text-[16px] font-semibold">Risk Map</h2>
            <Segmented
              label="Map layer"
              size="sm"
              value={mode}
              onChange={setMode}
              options={[
                { id: 'risk', label: 'Worst case', icon: Activity, title: 'Share of the uncontrolled CVaR' },
                { id: 'protected', label: 'With UrbanShield', icon: ShieldCheck, title: 'Same scale, under the CVaR plan' },
                { id: 'exposure', label: 'Exposure', icon: Globe2 },
                { id: 'network', label: 'Network', icon: Network },
              ]}
            />
            <div className="ml-auto">
              <DeviceSearch alerts={alerts} onPick={pickDevice} onCve={showCve} />
            </div>
          </div>
          <div className="relative h-[540px]">
            {c ? (
              <CityMap
                city={c}
                risk={risk.data}
                mode={mode}
                basemap={basemap}
                selected={selectedDevice}
                onSelect={pickDevice}
                ripple={ripple}
                focus={focusIds}
                className="h-full"
              >
                <div className="absolute bottom-3 left-3 z-[500] w-[218px] space-y-2">
                  {(mode === 'risk' || mode === 'protected') && risk.data && (
                    <RiskLegend title="Device share of worst-case loss" thresholds={DEVICE_THRESHOLDS} />
                  )}
                  {mode === 'exposure' && (
                    <div className="rounded-lg border border-line bg-surface/95 px-3 py-2.5 text-[11.5px] shadow-sm">
                      <p className="mb-1.5 font-semibold">Exposure</p>
                      {[
                        [C.danger, 'Internet-exposed'],
                        [C.high, 'Gateway (bridges networks)'],
                        [C.idle, 'Internal only'],
                      ].map(([col, l]) => (
                        <p key={l} className="flex items-center gap-2 text-ink-2">
                          <span className="size-2.5 rounded-full" style={{ background: col }} />
                          {l}
                        </p>
                      ))}
                    </div>
                  )}
                  {mode === 'network' && (
                    <div className="rounded-lg border border-line bg-surface/95 px-3 py-2.5 text-[11.5px] text-ink-2 shadow-sm">
                      <p className="mb-1.5 font-semibold text-ink">Links</p>
                      <p className="flex items-center gap-2">
                        <span className="h-0.5 w-5 bg-forest-800" /> Depends on (loss cascades)
                      </p>
                      <p className="flex items-center gap-2">
                        <span className="h-0 w-5 border-t border-dashed border-muted" /> Reachable (attacker can pivot)
                      </p>
                    </div>
                  )}
                  <div className="rounded-lg border border-line bg-surface/95 px-3 py-2 shadow-sm">
                    <ShapeLegend />
                    <p className="mt-1 flex items-center gap-2 text-[11.5px] text-ink-2">
                      <span className="h-1 w-5 rounded-full bg-info" /> Ambulance corridor
                    </p>
                  </div>
                </div>
                <div className="absolute bottom-3 right-3 z-[500]">
                  <BasemapToggle value={basemap} onChange={setBasemap} />
                </div>
                {mode === 'protected' && none && ours && (
                  <div className="absolute left-1/2 top-3 z-[500] -translate-x-1/2 animate-rise rounded-lg border border-forest-200 bg-surface/95 px-3 py-1.5 text-[12.5px] text-ink-2 shadow-sm">
                    Same scale as “Worst-case risk”: CVaR <span className="num font-semibold text-ink">{loss(none.cvar)}</span> →{' '}
                    <span className="num font-semibold text-forest-800">{loss(ours.cvar)}</span> under the plan
                  </div>
                )}
                {device && (
                  <div className="scroll-thin absolute bottom-3 right-14 top-3 z-[600] w-[340px] animate-slide-in overflow-y-auto rounded-xl border border-line bg-surface p-4 shadow-[0_16px_40px_rgb(9_39_31/0.14)]">
                    <DevicePanel device={device} onClose={() => selectDevice(null)} />
                  </div>
                )}
              </CityMap>
            ) : (
              <Skeleton className="h-full rounded-none" />
            )}
          </div>
        </Card>

        <Card i={7} className="flex max-h-[600px] flex-col" aria-label="Active alerts">
          <CardHeader
            title="Active Alerts"
            sub="Inventory CVEs ranked by the worst-case loss their carriers hold"
            right={<LinkButton href={href('devices')}>View all <ArrowRight className="size-3.5" /></LinkButton>}
          />
          <ul className="scroll-thin mt-3 flex-1 divide-y divide-line overflow-y-auto px-2 pb-2">
            {!alerts.length && Array.from({ length: 5 }, (_, i) => <li key={i} className="p-3"><Skeleton className="h-14" /></li>)}
            {alerts.slice(0, 12).map((a, i) => {
              const s = SEVERITY[a.severity]
              const Icon = s.icon
              const on = a.cve === selectedCve
              return (
                <li key={a.cve} className="animate-rise" style={rise(8 + i)}>
                  <button
                    type="button"
                    onClick={() => showCve(a.cve)}
                    aria-pressed={on}
                    className={cx(
                      'flex w-full cursor-pointer items-start gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                      on ? 'bg-forest-50' : 'hover:bg-surface-muted',
                    )}
                  >
                    <span className="grid size-9 shrink-0 place-items-center rounded-lg" style={{ background: `${s.color}1a`, color: s.color }}>
                      <Icon className="size-[17px]" aria-hidden />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center justify-between gap-2">
                        <span className="truncate font-mono text-[13px] font-semibold" style={{ color: s.color }}>
                          {a.cve}
                        </span>
                        <span className="num shrink-0 text-[12px] font-semibold text-ink">{share(a.share, 1)}</span>
                      </span>
                      <span className="mt-0.5 block truncate text-[13px] font-medium text-ink">
                        {plural(a.devices.length, 'device')} · {a.categories.map((x) => CATEGORY_PLURAL[x]).join(', ')}
                      </span>
                      <span className="mt-0.5 block truncate text-[12px] text-muted">
                        {a.kev && 'KEV · '}CVSS {a.cvss.toFixed(1)} · EPSS {a.epss.toFixed(2)} · {a.zones.join(', ')}
                      </span>
                    </span>
                    <ChevronRight className={cx('mt-2 size-4 shrink-0 text-muted transition-transform', on && 'rotate-90')} aria-hidden />
                  </button>
                  {on && presetFor(a.cve) && (
                    <div className="animate-fade px-3 pb-3 pl-[60px]">
                      <Button icon={ShieldCheck} onClick={() => navigate('response', { advisory: presetFor(a.cve)! })}>
                        Run the agent loop on this advisory
                      </Button>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        </Card>
      </div>

      {/* bottom analytics */}
      <div className="grid gap-4 xl:grid-cols-[1.25fr_1fr_1fr]">
        <Card i={9} className="pb-4">
          <CardHeader
            title="Loss distribution"
            sub="Total loss per held-out scenario: no controls vs the UrbanShield plan"
            right={<LinkButton href={href('risk')}>Analyse <ArrowRight className="size-3.5" /></LinkButton>}
          />
          <div className="px-3 pt-2">
            {risk.error ? (
              <ErrorState error={risk.error} retry={risk.reload} />
            ) : risk.data ? (
              <>
                <LossDistribution risk={risk.data} labels={['none', 'cvar']} focus="none" height={210} />
                <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 px-2 text-[11.5px] text-ink-2">
                  {(['none', 'cvar'] as const).map((l) => (
                    <span key={l} className="flex items-center gap-1.5">
                      <span className="h-[3px] w-3.5 rounded-full" style={{ background: seriesColor(l) }} />
                      {seriesLabel(l)}
                    </span>
                  ))}
                  <span className="flex items-center gap-1.5">
                    <span className="hatch size-3 rounded-sm border border-line" /> Worst 5% (no controls)
                  </span>
                </div>
              </>
            ) : (
              <Skeleton className="h-[220px]" />
            )}
          </div>
        </Card>
        <Card i={10} className="pb-5">
          <CardHeader
            title="Risk by zone"
            sub="Share of uncontrolled worst-case loss · bar underneath = with UrbanShield"
          />
          <div className="px-4 pt-4">
            {zones.length && risk.data ? (
              <RankBars
                max={Math.max(...zones.map((z) => z.share))}
                rows={zones.map((z) => ({
                  key: z.name,
                  label: z.name,
                  value: z.share,
                  after: z.tailLossProtected / (none?.cvar || 1),
                  color: riskColor(levelOf(z.share, ZONE_THRESHOLDS)),
                  text: share(z.share),
                  onClick: () => {
                    selectCve(null)
                    setFocusIds(z.devices.map((d) => d.id))
                  },
                }))}
              />
            ) : risk.error ? (
              <Empty icon={MapIcon} title="Zone risk needs the simulator">{risk.error.message}</Empty>
            ) : (
              <Skeleton className="h-40" />
            )}
            {zones.length > 0 && risk.data && (
              <p className="mt-4 text-[11.5px] text-muted">
                Click a zone to frame it on the map. Shares sum to 100% of CVaR {none && loss(none.cvar)}.
              </p>
            )}
          </div>
        </Card>
        <Card i={11} className="pb-5">
          <CardHeader title="Risk composition" sub="Who carries the worst case, by device category" />
          <div className="px-5 pt-5">
            {risk.error ? (
              <ErrorState error={risk.error} retry={risk.reload} />
            ) : risk.data && none ? (
              <Donut
                segments={categoryShare}
                center={<Metric source={src}>{loss(none.cvar, 1)}</Metric>}
                caption={
                  <>
                    CVaR 95%
                    <br />
                    no controls
                  </>
                }
              />
            ) : (
              <Skeleton className="h-36" />
            )}
            {risk.data && c && (() => {
              const top = [...categoryShare].sort((a, b) => b.value - a.value)[0]
              const count = c.devices.filter((d) => d.category === top.key).length
              const total = sum(categoryShare.map((x) => x.value)) || 1
              return (
                <p className="mt-4 text-[11.5px] text-muted">
                  {CATEGORY_PLURAL[top.key].replace(/^./, (ch) => ch.toUpperCase())} are {share(count / c.devices.length)} of the fleet but carry{' '}
                  <span className="font-semibold text-ink">{share(top.value / total)}</span> of the worst case
                  {cvarPlan && (
                    <>
                      ; UrbanShield controls {Object.keys(cvarPlan.choices).filter((id) => devices.get(id)?.category === top.key).length}{' '}
                      of them
                    </>
                  )}
                  .
                </p>
              )
            })()}
          </div>
        </Card>
      </div>
    </div>
  )
}
