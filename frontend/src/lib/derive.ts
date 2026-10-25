// Views derived from the city and the simulated risk. Pure functions: no fetching, no React.
import type { Category, City, CityRisk, Device, DeviceRisk, Frontier, Plan } from '../types'
import { C } from './colors'

export type LatLng = [number, number]

export const CATEGORIES: Category[] = ['signal', 'meter', 'streetlight', 'ev_charger']

export function byId<T extends { id: string }>(items: T[]): Map<string, T> {
  return new Map(items.map((x) => [x.id, x]))
}

export function riskById(rows: DeviceRisk[] | undefined): Map<string, DeviceRisk> {
  return new Map((rows ?? []).map((r) => [r.device_id, r]))
}

export const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0)

export const family = (d: Device) => d.firmware.split('/')[0]
export const version = (d: Device) => d.firmware.split('/')[1] ?? ''
export const isCorridor = (d: Device) => d.tags.includes('ambulance_corridor')
export const isGateway = (d: Device) => d.tags.includes('gateway')
export const maxCvss = (d: Device) => Math.max(0, ...d.vulns.map((v) => v.cvss))
export const maxEpss = (d: Device) => Math.max(0, ...d.vulns.map((v) => v.epss))
export const hasKev = (d: Device) => d.vulns.some((v) => v.kev)

// ------------------------------------------------------------------ risk classes

export type RiskLevel = 'very-high' | 'high' | 'moderate' | 'low' | 'very-low'

export const RISK_LEVELS: { level: RiskLevel; label: string; color: string }[] = [
  { level: 'very-high', label: 'Very high', color: C.danger },
  { level: 'high', label: 'High', color: C.high },
  { level: 'moderate', label: 'Moderate', color: C.warn },
  { level: 'low', label: 'Low', color: C.low },
  { level: 'very-low', label: 'Very low', color: C.ok },
]

export const riskColor = (level: RiskLevel) => RISK_LEVELS.find((r) => r.level === level)!.color

/** A device's share of the city's worst-case (CVaR) loss. Thresholds are shown in the map legend. */
export const DEVICE_THRESHOLDS = [0.1, 0.04, 0.015, 0.005] as const
export const ZONE_THRESHOLDS = [0.4, 0.3, 0.2, 0.1] as const

export function levelOf(fraction: number, thresholds: readonly number[]): RiskLevel {
  const levels: RiskLevel[] = ['very-high', 'high', 'moderate', 'low']
  const i = thresholds.findIndex((t) => fraction >= t)
  return i === -1 ? 'very-low' : levels[i]
}

// ------------------------------------------------------------------ zones

export interface Zone {
  name: string
  devices: Device[]
  center: LatLng
  hull: LatLng[]
  /** Share of the uncontrolled CVaR attributed to the zone's devices. */
  share: number
  tailLoss: number
  tailLossProtected: number
}

function cross(o: LatLng, a: LatLng, b: LatLng) {
  return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])
}

/** Convex hull (Andrew's monotone chain). */
export function convexHull(points: LatLng[]): LatLng[] {
  const pts = [...points].sort((a, b) => a[0] - b[0] || a[1] - b[1])
  if (pts.length < 3) return pts
  const lower: LatLng[] = []
  for (const p of pts) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop()
    lower.push(p)
  }
  const upper: LatLng[] = []
  for (const p of [...pts].reverse()) {
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop()
    upper.push(p)
  }
  return [...lower.slice(0, -1), ...upper.slice(0, -1)]
}

/** Push every hull point out from the centre, then round the corners (Chaikin), so a zone reads
 *  as an area around its devices rather than a polygon through them. */
function softHull(points: LatLng[], center: LatLng, pad = 0.0045): LatLng[] {
  let ring = convexHull(points).map(([la, lo]): LatLng => {
    const dy = la - center[0]
    const dx = lo - center[1]
    const len = Math.hypot(dx, dy) || 1
    return [la + (dy / len) * pad, lo + (dx / len) * pad]
  })
  for (let k = 0; k < 3 && ring.length >= 3; k++) {
    const next: LatLng[] = []
    ring.forEach((p, i) => {
      const q = ring[(i + 1) % ring.length]
      next.push([0.75 * p[0] + 0.25 * q[0], 0.75 * p[1] + 0.25 * q[1]])
      next.push([0.25 * p[0] + 0.75 * q[0], 0.25 * p[1] + 0.75 * q[1]])
    })
    ring = next
  }
  return ring
}

export function zones(city: City, risk: CityRisk | null): Zone[] {
  const base = riskById(risk?.baseline)
  const prot = riskById(risk?.protected)
  const cvar = sum((risk?.baseline ?? []).map((r) => r.tail_loss)) || 1
  const groups = new Map<string, Device[]>()
  for (const d of city.devices) groups.set(d.zone, [...(groups.get(d.zone) ?? []), d])
  return [...groups.entries()]
    .map(([name, devices]) => {
      const center: LatLng = [
        sum(devices.map((d) => d.lat)) / devices.length,
        sum(devices.map((d) => d.lon)) / devices.length,
      ]
      const tailLoss = sum(devices.map((d) => base.get(d.id)?.tail_loss ?? 0))
      return {
        name,
        devices,
        center,
        hull: softHull(
          devices.map((d): LatLng => [d.lat, d.lon]),
          center,
        ),
        share: tailLoss / cvar,
        tailLoss,
        tailLossProtected: sum(devices.map((d) => prot.get(d.id)?.tail_loss ?? 0)),
      }
    })
    .sort((a, b) => b.tailLoss - a.tailLoss)
}

// ------------------------------------------------------------------ alerts (one per CVE)

export type Severity = 'critical' | 'high' | 'medium'

export interface CveAlert {
  cve: string
  kev: boolean
  cvss: number
  epss: number
  devices: Device[]
  zones: string[]
  families: string[]
  categories: Category[]
  /** Share of the uncontrolled CVaR attributed to the carriers. */
  share: number
  severity: Severity
}

export const severityOf = (cvss: number): Severity => (cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : 'medium')

/** Every CVE the inventory lists, ranked by how much worst-case loss its carriers hold. */
export function cveAlerts(city: City, risk: CityRisk | null): CveAlert[] {
  const base = riskById(risk?.baseline)
  const cvar = sum((risk?.baseline ?? []).map((r) => r.tail_loss)) || 1
  const groups = new Map<string, { devices: Device[]; cvss: number; epss: number; kev: boolean }>()
  for (const d of city.devices)
    for (const v of d.vulns) {
      const g = groups.get(v.cve_id) ?? { devices: [], cvss: 0, epss: 0, kev: false }
      g.devices.push(d)
      g.cvss = Math.max(g.cvss, v.cvss)
      g.epss = Math.max(g.epss, v.epss)
      g.kev ||= v.kev
      groups.set(v.cve_id, g)
    }
  const uniq = <T,>(xs: T[]) => [...new Set(xs)]
  return [...groups.entries()]
    .map(([cve, g]) => ({
      cve,
      kev: g.kev,
      cvss: g.cvss,
      epss: g.epss,
      devices: g.devices,
      zones: uniq(g.devices.map((d) => d.zone)),
      families: uniq(g.devices.map(family)),
      categories: uniq(g.devices.map((d) => d.category)),
      share: sum(g.devices.map((d) => base.get(d.id)?.tail_loss ?? 0)) / cvar,
      severity: severityOf(g.cvss),
    }))
    .sort((a, b) => b.share - a.share || b.devices.length - a.devices.length)
}

// ------------------------------------------------------------------ plans

export function planCost(city: City, plan: Plan, ids?: string[]): number {
  const devices = byId(city.devices)
  return sum(
    (ids ?? Object.keys(plan.choices)).map((id) => {
      const d = devices.get(id)
      const kind = plan.choices[id]
      return d?.controls.find((c) => c.kind === kind)?.cost_inr ?? 0
    }),
  )
}

/** Jaccard similarity of two plans' protected device sets. */
export function overlap(a: Plan, b: Plan): number {
  const x = new Set(Object.keys(a.choices))
  const y = new Set(Object.keys(b.choices))
  const inter = [...x].filter((d) => y.has(d)).length
  const union = new Set([...x, ...y]).size
  return union === 0 ? 1 : inter / union
}

/** The cheapest budget at which UrbanShield's worst case beats CVSS-first at the largest budget. */
export function cheapestWin(f: Frontier) {
  const top = f.points[f.points.length - 1]
  const hit = f.points.find((p) => p.cvar.cvar < top.cvar.cvss)
  return hit ? { ours: hit, theirs: top } : null
}
