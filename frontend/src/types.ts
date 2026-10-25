// Mirrors backend/src/urbanshield/schemas.py. Keep the two in sync; the backend is the source of truth.

export type Category = 'signal' | 'meter' | 'streetlight' | 'ev_charger'
export type ControlKind = 'patch' | 'segment' | 'disable_remote' | 'rotate_creds' | 'virtual_patch'
export type Autonomy = 'auto' | 'approve'
export type EdgeKind = 'reach' | 'depends'
export type Objective =
  | 'cvar'
  | 'mean'
  | 'patch_only'
  | 'cvss'
  | 'cvss_kev_epss'
  | 'loss_per_inr'
  | 'greedy_tail'
  | 'bfs_centrality'
export type Solver = 'milp' | 'greedy' | 'ranking'
export type AgentName = 'sentinel' | 'analyst' | 'planner' | 'redteam' | 'auditor' | 'human' | 'system'
export type EventKind =
  | 'observe'
  | 'tool_call'
  | 'decision'
  | 'hole'
  | 'approval'
  | 'reject'
  | 'apply'
  | 'error'

export interface Vulnerability {
  cve_id: string
  cvss: number
  epss: number
  kev: boolean
}

export interface ControlOption {
  kind: ControlKind
  cost_inr: number
  downtime_h: number
  exploit_mult: number
  spread_mult: number
  autonomy: Autonomy
}

export interface Device {
  id: string
  name: string
  category: Category
  zone: string
  lat: number
  lon: number
  firmware: string
  vulns: Vulnerability[]
  exposed: boolean
  criticality: number
  controls: ControlOption[]
  tags: string[]
}

export interface Edge {
  src: string
  dst: string
  kind: EdgeKind
}

export interface City {
  id: string
  name: string
  seed: number
  devices: Device[]
  edges: Edge[]
}

export interface PlanMetrics {
  cvar: number
  mean_loss: number
  max_cascade: number
  ci_low: number
  ci_high: number
  linear_gap: number
  split: 'train' | 'test'
}

export interface Plan {
  id: string
  city_id: string
  objective: Objective
  choices: Record<string, ControlKind>
  cost_inr: number
  downtime_h: number
  solver: Solver
  solve_ms: number
  metrics: PlanMetrics | null
  tool_call_id: string | null
}

export interface DeviceRisk {
  device_id: string
  mean_loss: number
  /** Mean loss attributed to the device in the CVaR tail; summed over devices it is the CVaR. */
  tail_loss: number
  p_compromised: number
}

export interface LossHistogram {
  /** 'none' (no controls) or the plan's objective. */
  label: 'none' | Objective
  plan_id: string | null
  cvar: number
  /** Loss at the tail threshold (the smallest tail scenario). */
  var: number
  mean_loss: number
  /** Scenarios per bin of CityRisk.bin_edges. */
  counts: number[]
}

export interface CityRisk {
  city_id: string
  n_scenarios: number
  alpha: number
  bin_edges: number[]
  /** No controls. */
  baseline: DeviceRisk[]
  /** Under the CVaR plan. */
  protected: DeviceRisk[]
  histograms: LossHistogram[]
  tool_call_id: string | null
}

export interface LLMUsage {
  model: string
  prompt_tokens: number
  completion_tokens: number
  latency_ms: number
  cached: boolean
}

export interface AgentEvent {
  id: string
  ts: string
  city_id: string
  run_id: string
  agent: AgentName
  kind: EventKind
  summary: string
  payload: Record<string, unknown>
  tool_call_id: string | null
  parent_id: string | null
  usage: LLMUsage | null
}

export interface VerifyResult {
  ok: boolean
  entries: number
  first_bad_seq: number | null
  reason: string | null
  head_seq: number | null
  head_hash: string | null
  truncated: boolean
}

export interface Advisory {
  cve_id: string
  vendor: string
  product: string
  firmware_family: string
  affected_below: string
  cvss: number
  source_sha256: string
}

export interface ToolResult {
  id: string
  tool: string
  agent: AgentName
  args: Record<string, unknown>
  result: Record<string, unknown>
  ts: string
}

export interface QuarantinePreview {
  source_sha256: string
  flagged_spans: [number, number][]
  advisory: Advisory | null
  discrepancies: string[]
  error: string | null
}

export interface AdvisoryPreset {
  id: string
  kind: 'normal' | 'poisoned' | 'wrong'
  title: string
  text: string
}

export interface AuditEntry {
  seq: number
  event_id: string
  payload_sha256: string
  prev_hash: string
  hash: string
  signature: string
}

// ---------------------------------------------------------------- replay, frontier, enforcement
// Mirrors backend api/replay.py, api/frontier.py, guard/enforcer.py and guard/interlock.py.

export interface ReplayView {
  label: 'none' | 'cvss' | 'cvar'
  plan_id: string | null
  cost_inr: number
  /** device id -> spread hop at which it was lost (0 = first); devices not listed are never lost */
  hops: Record<string, number>
  devices_lost: number
  corridor_lost: number
  loss: number
  /** Mean devices lost over the whole worst-5% set (not just this scenario) */
  tail_devices_lost: number
  tail_corridor_share: number
}

export interface TwoCities {
  city_id: string
  scenario: number
  seed: number
  n_scenarios: number
  alpha: number
  tail_rank: number
  selection: string
  corridor_ids: string[]
  max_hop: number
  views: ReplayView[]
  tool_call_id: string | null
}

export interface FrontierPoint {
  budget_inr: number
  cvar: Record<string, number>
  cost_inr: Record<string, number>
  controls: Record<string, number>
}

export interface Frontier {
  city_id: string
  downtime_h: number
  n_scenarios: number
  test_seed: number
  generated_by: string
  points: FrontierPoint[]
}

export type SignalPhase = 'green_wave' | 'ns_green' | 'ew_green' | 'all_red' | 'flash' | 'both_green'

export interface SignalCommand {
  device_id: string
  phase: SignalPhase
  hold_s?: number
  remote?: boolean
}

export interface Verdict {
  allowed: boolean
  rule: string | null
  reason: string
  latency_us: number
}

export interface CorridorPaths {
  entry_points: number
  corridor: number
  reachable: string[]
  unfiltered: string[]
  status: 'open' | 'filtered' | 'closed'
}

export interface EnforcerDecision {
  ts: string
  kind: 'policy' | 'command'
  allowed: boolean
  summary: string
  rule: string | null
}

export interface EnforcerStatus {
  city_id: string
  version: number
  plan_id: string | null
  policy_sha256: string | null
  key_id: string
  rules: Record<string, number>
  flows_allowed: number
  flows_total: number
  corridor: CorridorPaths
  decisions: EnforcerDecision[]
}
