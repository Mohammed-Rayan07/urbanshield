import { describe, expect, it } from 'vitest'
import type { City, CityRisk, Device, Plan } from '../types'
import { convexHull, cveAlerts, DEVICE_THRESHOLDS, levelOf, overlap, planCost, zones } from './derive'
import { inr, pct, plural } from './format'

function device(id: string, zone: string, lat: number, lon: number, cve: string, cvss: number): Device {
  return {
    id,
    name: id,
    category: 'streetlight',
    zone,
    lat,
    lon,
    firmware: 'lumenos/4.1.3',
    vulns: [{ cve_id: cve, cvss, epss: 0.5, kev: true }],
    exposed: false,
    criticality: 0.5,
    controls: [
      { kind: 'patch', cost_inr: 1000, downtime_h: 2, exploit_mult: 0.1, spread_mult: 1, autonomy: 'approve' },
      { kind: 'rotate_creds', cost_inr: 200, downtime_h: 0, exploit_mult: 0.5, spread_mult: 1, autonomy: 'auto' },
    ],
    tags: [],
  }
}

const city: City = {
  id: 'c',
  name: 'c',
  seed: 0,
  edges: [],
  devices: [
    device('a', 'North', 13.0, 74.8, 'CVE-2024-0001', 9.8),
    device('b', 'North', 13.01, 74.81, 'CVE-2024-0001', 9.8),
    device('c', 'South', 12.9, 74.85, 'CVE-2024-0002', 5.3),
  ],
}
const risk: CityRisk = {
  city_id: 'c',
  n_scenarios: 10,
  alpha: 0.95,
  bin_edges: [0, 1],
  baseline: [
    { device_id: 'a', mean_loss: 1, tail_loss: 6, p_compromised: 0.5 },
    { device_id: 'b', mean_loss: 1, tail_loss: 2, p_compromised: 0.5 },
    { device_id: 'c', mean_loss: 1, tail_loss: 2, p_compromised: 0.5 },
  ],
  protected: [
    { device_id: 'a', mean_loss: 0, tail_loss: 1, p_compromised: 0.1 },
    { device_id: 'b', mean_loss: 0, tail_loss: 0, p_compromised: 0.1 },
    { device_id: 'c', mean_loss: 0, tail_loss: 2, p_compromised: 0.5 },
  ],
  histograms: [],
  tool_call_id: 'tc-risk',
}

describe('derive', () => {
  it('builds a convex hull without interior points', () => {
    const hull = convexHull([
      [0, 0],
      [0, 2],
      [2, 2],
      [2, 0],
      [1, 1],
    ])
    expect(hull).toHaveLength(4)
    expect(hull).not.toContainEqual([1, 1])
  })

  it('classifies shares against the thresholds, inclusive at each bound', () => {
    expect(levelOf(0.1, DEVICE_THRESHOLDS)).toBe('very-high')
    expect(levelOf(0.0999, DEVICE_THRESHOLDS)).toBe('high')
    expect(levelOf(0.004, DEVICE_THRESHOLDS)).toBe('very-low')
  })

  it('ranks CVEs by the tail loss their carriers hold', () => {
    const alerts = cveAlerts(city, risk)
    expect(alerts.map((a) => a.cve)).toEqual(['CVE-2024-0001', 'CVE-2024-0002'])
    expect(alerts[0].share).toBeCloseTo(0.8)
    expect(alerts[0].severity).toBe('critical')
    expect(alerts[1].severity).toBe('medium')
  })

  it('splits the CVaR across zones, before and under the plan', () => {
    const z = zones(city, risk)
    expect(z[0].name).toBe('North')
    expect(z[0].share).toBeCloseTo(0.8)
    expect(z[0].tailLossProtected).toBe(1)
    expect(z.reduce((s, x) => s + x.share, 0)).toBeCloseTo(1)
  })

  it('prices and compares plans', () => {
    const p = { choices: { a: 'patch', c: 'rotate_creds' } } as unknown as Plan
    const q = { choices: { a: 'rotate_creds', b: 'patch' } } as unknown as Plan
    expect(planCost(city, p)).toBe(1200)
    expect(overlap(p, q)).toBeCloseTo(1 / 3)
  })
})

describe('format', () => {
  it('uses Indian digit grouping and signed percentages', () => {
    expect(inr(600000)).toBe('₹6,00,000')
    expect(pct(-0.64)).toBe('−64.0%')
    expect(pct(0.125, 0)).toBe('+13%')
    expect(plural(1, 'hole')).toBe('1 hole')
    expect(plural(2, 'hole')).toBe('2 holes')
  })
})
