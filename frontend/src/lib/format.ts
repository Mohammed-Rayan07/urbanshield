// Number, money and label formatting. Every screen formats through here so units stay consistent.
import type { AgentName, Category, ControlKind, Objective } from '../types'

const inrFormat = new Intl.NumberFormat('en-IN', { maximumFractionDigits: 0 })

/** ₹ with Indian digit grouping: ₹4,85,682. */
export const inr = (n: number) => `₹${inrFormat.format(Math.round(n))}`

/** Compact rupees for tight spaces: ₹4.86 L, ₹1.2 Cr. */
export function inrShort(n: number): string {
  if (n >= 1e7) return `₹${(n / 1e7).toFixed(2)} Cr`
  if (n >= 1e5) return `₹${(n / 1e5).toFixed(2)} L`
  return inr(n)
}

/** Losses are reported to two decimals (the simulator's loss unit is criticality-weighted devices). */
export const loss = (n: number, digits = 2) => n.toFixed(digits)

export const int = (n: number) => inrFormat.format(Math.round(n))

/** Signed percentage: +12.4% / −64.0%. Input is a fraction (0.124). */
export function pct(fraction: number, digits = 1): string {
  const v = fraction * 100
  const sign = v > 0 ? '+' : v < 0 ? '−' : ''
  return `${sign}${Math.abs(v).toFixed(digits)}%`
}

/** Unsigned share: 46%. Input is a fraction. */
export const share = (fraction: number, digits = 0) => `${(fraction * 100).toFixed(digits)}%`

/** (b − a) / a as a fraction; 0 when a is 0. */
export const change = (a: number, b: number) => (a === 0 ? 0 : (b - a) / a)

export const hours = (h: number) => `${Number.isInteger(h) ? h : h.toFixed(1)} h`

export function ms(n: number): string {
  if (n < 1000) return `${n} ms`
  return `${(n / 1000).toFixed(n < 10000 ? 2 : 1)} s`
}

export const clock = (iso: string) =>
  new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

export const plural = (n: number, noun: string, many = `${noun}s`) => `${int(n)} ${n === 1 ? noun : many}`

export const OBJECTIVE_LABEL: Record<Objective, string> = {
  cvar: 'UrbanShield (CVaR)',
  mean: 'Mean-loss MILP',
  patch_only: 'Patch-only MILP',
  greedy_tail: 'Greedy tail',
  cvss: 'CVSS-first',
  cvss_kev_epss: 'CVSS + KEV + EPSS',
  loss_per_inr: 'Loss per ₹',
  bfs_centrality: 'BFS-only',
}

export const OBJECTIVE_NOTE: Record<Objective, string> = {
  cvar: 'Minimises the average of the worst 5% of simulated losses',
  mean: 'Ablation: same MILP, minimises the average loss',
  patch_only: 'Ablation: same MILP, may only patch',
  greedy_tail: 'Heuristic: buys the largest CVaR drop per rupee',
  cvss: 'Baseline: fix the highest CVSS first',
  cvss_kev_epss: 'Baseline: CVSS boosted by KEV and EPSS',
  loss_per_inr: 'Baseline: simulated loss per rupee',
  bfs_centrality: 'Baseline: fix the most reachable devices first',
}

export const CATEGORY_LABEL: Record<Category, string> = {
  signal: 'Traffic signal',
  meter: 'Smart meter',
  streetlight: 'Streetlight',
  ev_charger: 'EV charger',
}

export const CATEGORY_PLURAL: Record<Category, string> = {
  signal: 'traffic signals',
  meter: 'smart meters',
  streetlight: 'streetlights',
  ev_charger: 'EV chargers',
}

export const CONTROL_LABEL: Record<ControlKind, string> = {
  patch: 'Patch firmware',
  segment: 'Segment network',
  disable_remote: 'Disable remote access',
  rotate_creds: 'Rotate credentials',
  virtual_patch: 'Virtual patch (WAF/IPS)',
}

export const AGENT_LABEL: Record<AgentName, string> = {
  sentinel: 'Sentinel',
  analyst: 'Analyst',
  planner: 'Planner',
  redteam: 'Red-Team',
  auditor: 'Auditor',
  human: 'Approver',
  system: 'System',
}
