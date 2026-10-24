// Devices: the twin's inventory, searchable and sortable, with the spec sheet beside it.
import { ArrowUpDown, Cpu, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ShapeGlyph } from '../components/CityMap'
import DevicePanel from '../components/DevicePanel'
import { Badge, Card, CardHeader, Empty, ErrorState, PageHeader, Segmented, Skeleton } from '../components/ui'
import { cx } from '../lib/cx'
import { C } from '../lib/colors'
import { CATEGORIES, DEVICE_THRESHOLDS, hasKev, levelOf, maxCvss, maxEpss, riskById, riskColor } from '../lib/derive'
import { CATEGORY_LABEL, CONTROL_LABEL, share } from '../lib/format'
import { useStore } from '../lib/store'
import type { Category, Device } from '../types'

type Key = 'name' | 'zone' | 'cvss' | 'epss' | 'criticality' | 'share'

export default function DevicesScreen() {
  const { city, risk, plans, selectedDevice, selectDevice, devices } = useStore()
  const [q, setQ] = useState('')
  const [cat, setCat] = useState<Category | 'all'>('all')
  const [exposedOnly, setExposedOnly] = useState(false)
  const [sort, setSort] = useState<{ key: Key; asc: boolean }>({ key: 'share', asc: false })
  const base = useMemo(() => riskById(risk.data?.baseline), [risk.data])
  const cvar = risk.data?.histograms.find((h) => h.label === 'none')?.cvar ?? 1
  const ours = plans.data?.find((p) => p.objective === 'cvar')

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const val = (d: Device): number | string =>
      sort.key === 'name'
        ? d.name
        : sort.key === 'zone'
          ? d.zone
          : sort.key === 'cvss'
            ? maxCvss(d)
            : sort.key === 'epss'
              ? maxEpss(d)
              : sort.key === 'criticality'
                ? d.criticality
                : (base.get(d.id)?.tail_loss ?? 0)
    return (city.data?.devices ?? [])
      .filter((d) => cat === 'all' || d.category === cat)
      .filter((d) => !exposedOnly || d.exposed)
      .filter((d) => !needle || `${d.id} ${d.name} ${d.zone} ${d.firmware} ${d.vulns.map((v) => v.cve_id).join(' ')}`.toLowerCase().includes(needle))
      .sort((a, b) => {
        const x = val(a)
        const y = val(b)
        const c = typeof x === 'string' ? x.localeCompare(y as string) : x - (y as number)
        return sort.asc ? c : -c
      })
  }, [city.data, cat, exposedOnly, q, sort, base])

  const selected = selectedDevice ? devices.get(selectedDevice) : rows[0]
  if (city.error) return <ErrorState error={city.error} retry={city.reload} />

  const header = (key: Key, label: string, right = false) => (
    <th className={cx('px-2 py-2 font-medium', right && 'text-right')} aria-sort={sort.key === key ? (sort.asc ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => setSort((s) => ({ key, asc: s.key === key ? !s.asc : key === 'name' || key === 'zone' }))}
        className={cx('inline-flex cursor-pointer items-center gap-1 hover:text-ink', sort.key === key && 'text-ink')}
      >
        {label} <ArrowUpDown className="size-3" aria-hidden />
      </button>
    </th>
  )

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Devices"
        title="The Twin's Inventory"
        subtitle={`${city.data?.devices.length ?? '–'} simulated devices with real CISA KEV CVEs on fictional firmware. Simulation only: nothing here talks to real hardware.`}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card i={1} className="pb-2">
          <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
            <div className="relative w-[260px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search name, zone, firmware, CVE"
                aria-label="Search devices"
                className="h-9 w-full rounded-lg border border-line bg-surface pl-9 pr-3 text-[13px] outline-none focus:border-forest-700"
              />
            </div>
            <Segmented
              label="Category"
              size="sm"
              value={cat}
              onChange={setCat}
              options={[{ id: 'all' as const, label: 'All' }, ...CATEGORIES.map((c) => ({ id: c, label: CATEGORY_LABEL[c] }))]}
            />
            <label className="flex cursor-pointer items-center gap-2 text-[12.5px] text-ink-2">
              <input type="checkbox" checked={exposedOnly} onChange={(e) => setExposedOnly(e.target.checked)} className="accent-forest-800" />
              Internet-exposed only
            </label>
            <span className="num ml-auto text-[12px] text-muted">{rows.length} shown</span>
          </div>
          <div className="scroll-thin max-h-[640px] overflow-auto px-2">
            <table className="w-full min-w-[820px] text-[12.5px]">
              <thead className="sticky top-0 z-10 bg-surface">
                <tr className="border-b border-line text-left text-[11.5px] text-muted">
                  {header('name', 'Device')}
                  {header('zone', 'Zone')}
                  <th className="px-2 py-2 font-medium">Firmware</th>
                  {header('cvss', 'CVSS', true)}
                  {header('epss', 'EPSS', true)}
                  {header('criticality', 'Crit.', true)}
                  {header('share', 'Worst-case share', true)}
                  <th className="px-2 py-2 font-medium">UrbanShield</th>
                </tr>
              </thead>
              <tbody>
                {!city.data && (
                  <tr>
                    <td colSpan={8} className="p-2">
                      <Skeleton className="h-80" />
                    </td>
                  </tr>
                )}
                {rows.map((d) => {
                  const s = (base.get(d.id)?.tail_loss ?? 0) / cvar
                  const choice = ours?.choices[d.id]
                  return (
                    <tr
                      key={d.id}
                      onClick={() => selectDevice(d.id)}
                      className={cx(
                        'cursor-pointer border-b border-line/60 transition-colors hover:bg-forest-50',
                        selected?.id === d.id && 'bg-forest-50',
                      )}
                    >
                      <td className="px-2 py-2">
                        <span className="flex items-center gap-2">
                          <ShapeGlyph category={d.category} color={risk.data ? riskColor(levelOf(s, DEVICE_THRESHOLDS)) : C.idle} size={11} />
                          <span className="whitespace-nowrap font-medium text-ink">{d.name}</span>
                          {d.exposed && <Badge tone="danger">exposed</Badge>}
                          {d.tags.includes('gateway') && <Badge tone="high">gateway</Badge>}
                        </span>
                      </td>
                      <td className="px-2 py-2 text-ink-2">{d.zone}</td>
                      <td className="px-2 py-2 font-mono text-[11.5px] text-ink-2">{d.firmware}</td>
                      <td className="num whitespace-nowrap px-2 py-2 text-right">
                        {maxCvss(d).toFixed(1)} {hasKev(d) && <span className="text-[10px] font-bold text-danger">KEV</span>}
                      </td>
                      <td className="num px-2 py-2 text-right">{maxEpss(d).toFixed(2)}</td>
                      <td className="num px-2 py-2 text-right">{d.criticality.toFixed(2)}</td>
                      <td className="px-2 py-2 text-right">
                        <span className="inline-flex items-center gap-2">
                          <span className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-muted">
                            <span className="block h-full rounded-full" style={{ width: `${Math.min(100, s * 200)}%`, background: riskColor(levelOf(s, DEVICE_THRESHOLDS)) }} />
                          </span>
                          <span className="num w-11 text-right font-semibold">{risk.data ? share(s, 1) : '–'}</span>
                        </span>
                      </td>
                      <td className="px-2 py-2 text-[11.5px] text-ink-2">{choice ? CONTROL_LABEL[choice] : <span className="text-muted">–</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {city.data && !rows.length && <Empty icon={Cpu} title="No devices match">Clear the search or filters.</Empty>}
          </div>
        </Card>
        <Card i={2} className="self-start p-5 xl:sticky xl:top-0">
          {selected ? <DevicePanel device={selected} /> : <CardHeader title="Device" sub="Select a row" className="p-0" />}
        </Card>
      </div>
    </div>
  )
}
