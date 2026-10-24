// Folds a run's event stream into what the Response screen shows. Pure: events in, view out.
import type { Advisory, AgentEvent, ControlKind, Plan } from '../types'

export type StageId = 'sentinel' | 'analyst' | 'planner' | 'redteam' | 'approval' | 'apply'
export type StageStatus = 'idle' | 'active' | 'done' | 'warn' | 'failed' | 'skipped'

export const STAGES: { id: StageId; label: string; caption: string }[] = [
  { id: 'sentinel', label: 'Sentinel', caption: 'Quarantine + cross-check' },
  { id: 'analyst', label: 'Analyst', caption: 'Blast radius + simulate' },
  { id: 'planner', label: 'Planner', caption: 'Optimise + audit claims' },
  { id: 'redteam', label: 'Red-Team', caption: 'Attack the plan' },
  { id: 'approval', label: 'Approval', caption: 'Human sign-off' },
  { id: 'apply', label: 'Apply', caption: 'Re-simulate the twin' },
]

export interface Probe {
  strategy_id: string
  cvar_before: number
  cvar_after_attack: number
  increase_pct: number
  hole?: boolean
  sim_calls?: number
}

export interface Strategy {
  id: string
  entry_points: string[]
  target_category: string | null
  pivot_shared_firmware: boolean
  campaign_cve: string | null
  label?: string
}

export interface Hole {
  event: AgentEvent
  strategy: Strategy
  probe: Probe
  round: number
}

export interface ApprovalRequest {
  kind: 'plan' | 'advisory'
  plan_id: string
  controls?: Record<string, ControlKind>
  cost_inr?: number
  downtime_h?: number
  residual_holes?: Probe[]
  discrepancies?: string[]
}

export interface Outcome {
  before: { cvar: number; mean_loss: number; max_cascade: number; ci_low: number; ci_high: number; controls_applied: number }
  after: { cvar: number; mean_loss: number; max_cascade: number; ci_low: number; ci_high: number; controls_applied: number }
  event: AgentEvent
}

export interface AuditorVerdict {
  accepted: string[]
  rejected: string[]
  rejection_rate: number
  event: AgentEvent
}

export interface RunView {
  stages: Record<StageId, StageStatus>
  advisory: Advisory | null
  matches: string[]
  discrepancies: string[]
  affected: string[]
  cvarBefore: number | null
  constraints: { kind: string; params: Record<string, unknown> }[]
  auditor: AuditorVerdict[]
  plan: Plan | null
  firstPlanId: string | null
  rounds: number
  holes: Hole[]
  residual: Probe[]
  pending: { request: ApprovalRequest; event: AgentEvent } | null
  approvals: AgentEvent[]
  applied: Record<string, ControlKind>
  autoApplied: Record<string, ControlKind>
  outcome: Outcome | null
  final: AgentEvent | null
  errors: AgentEvent[]
  tokens: number
  llmCalls: number
}

const has = (e: AgentEvent, key: string) => Object.prototype.hasOwnProperty.call(e.payload, key)
const get = <T>(e: AgentEvent, key: string) => e.payload[key] as T

export function foldRun(events: AgentEvent[], done: boolean): RunView {
  const v: RunView = {
    stages: { sentinel: 'idle', analyst: 'idle', planner: 'idle', redteam: 'idle', approval: 'idle', apply: 'idle' },
    advisory: null,
    matches: [],
    discrepancies: [],
    affected: [],
    cvarBefore: null,
    constraints: [],
    auditor: [],
    plan: null,
    firstPlanId: null,
    rounds: 0,
    holes: [],
    residual: [],
    pending: null,
    approvals: [],
    applied: {},
    autoApplied: {},
    outcome: null,
    final: null,
    errors: [],
    tokens: 0,
    llmCalls: 0,
  }
  const decided = new Set<string>()
  let lastStage: StageId | null = null
  const enter = (id: StageId) => {
    if (lastStage && lastStage !== id && v.stages[lastStage] === 'active') v.stages[lastStage] = 'done'
    if (v.stages[id] === 'idle' || v.stages[id] === 'done') v.stages[id] = 'active'
    lastStage = id
  }

  for (const e of events) {
    if (e.usage) {
      v.tokens += e.usage.prompt_tokens + e.usage.completion_tokens
      v.llmCalls += 1
    }
    if (e.kind === 'error') v.errors.push(e)
    switch (e.agent) {
      case 'sentinel':
        enter('sentinel')
        if (has(e, 'advisory')) v.advisory = get<Advisory>(e, 'advisory')
        if (has(e, 'matches')) v.matches = get<{ device_id: string }[]>(e, 'matches').map((m) => m.device_id)
        if (has(e, 'discrepancies')) v.discrepancies = get<string[]>(e, 'discrepancies')
        break
      case 'analyst':
        enter('analyst')
        if (has(e, 'assessment')) {
          const a = get<{ affected: string[]; cvar_before: number }>(e, 'assessment')
          v.affected = a.affected
          v.cvarBefore = a.cvar_before
        }
        break
      case 'planner':
        enter('planner')
        if (has(e, 'constraint')) v.constraints.push(get(e, 'constraint'))
        if (has(e, 'plan')) {
          v.plan = get<Plan>(e, 'plan')
          v.firstPlanId ??= v.plan.id
        }
        break
      case 'auditor':
        if (has(e, 'accepted'))
          v.auditor.push({
            accepted: get<string[]>(e, 'accepted'),
            rejected: get<string[]>(e, 'rejected') ?? [],
            rejection_rate: get<number>(e, 'rejection_rate') ?? 0,
            event: e,
          })
        break
      case 'redteam':
        enter('redteam')
        if (has(e, 'strategies')) v.rounds += 1
        if (e.kind === 'hole')
          v.holes.push({ event: e, strategy: get(e, 'strategy'), probe: get(e, 'probe'), round: v.rounds })
        if (has(e, 'residual')) v.residual = get<Probe[]>(e, 'residual')
        break
      case 'human':
        decided.add(String(e.payload.plan_id))
        v.approvals.push(e)
        v.stages.approval = e.kind === 'approval' ? 'done' : 'failed'
        break
      case 'system': {
        if (has(e, 'approval')) {
          const request = get<ApprovalRequest>(e, 'approval')
          if (e.kind === 'error') {
            decided.add(request.plan_id)
            v.stages.approval = 'failed'
          } else {
            enter('approval')
            v.pending = { request, event: e }
          }
        }
        if (e.kind === 'apply') {
          // Auto-applied controls land before the approval request; the stage starts after it.
          if (!e.summary.startsWith('Auto-applied')) enter('apply')
          const controls = get<Record<string, ControlKind>>(e, 'controls')
          if (controls) {
            Object.assign(v.applied, controls)
            if (e.summary.startsWith('Auto-applied')) Object.assign(v.autoApplied, controls)
          }
          if (has(e, 'before') && has(e, 'after'))
            v.outcome = { before: get(e, 'before'), after: get(e, 'after'), event: e }
        }
        if (e.kind === 'decision' && /^(Run complete|Monitor|Stopped)/.test(e.summary)) v.final = e
        if (e.kind === 'observe' && has(e, 'affected') && !v.affected.length) v.affected = get<string[]>(e, 'affected')
        break
      }
    }
  }
  if (v.pending && decided.has(v.pending.request.plan_id)) v.pending = null
  if (v.residual.length && v.stages.redteam !== 'idle') v.stages.redteam = 'warn'
  if (done || v.final) {
    for (const s of STAGES) {
      if (v.stages[s.id] === 'active') v.stages[s.id] = 'done'
      if (v.stages[s.id] === 'idle') v.stages[s.id] = 'skipped'
    }
    if (v.residual.length) v.stages.redteam = 'warn'
  }
  const stoppedAt = lastStage as StageId | null // assigned inside enter(); TS cannot see that
  if (v.errors.length && !v.final && done && stoppedAt) v.stages[stoppedAt] = 'failed'
  return v
}
