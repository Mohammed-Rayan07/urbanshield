import { describe, expect, it } from 'vitest'
import type { AgentEvent, AgentName, EventKind } from '../types'
import { foldRun } from './run'

let n = 0
function ev(agent: AgentName, kind: EventKind, summary: string, payload: Record<string, unknown> = {}): AgentEvent {
  n += 1
  return {
    id: `run-1:ev-${n}`,
    ts: new Date(Date.UTC(2026, 9, 24, 12, 0, n)).toISOString(),
    city_id: 'c',
    run_id: 'run-1',
    agent,
    kind,
    summary,
    payload,
    tool_call_id: null,
    parent_id: null,
    usage: kind === 'decision' && agent !== 'system' ? { model: 'mock', prompt_tokens: 100, completion_tokens: 10, latency_ms: 0, cached: false } : null,
  }
}

const plan = { id: 'plan-cvar-1', choices: { 'd-1': 'patch', 'd-2': 'rotate_creds' }, cost_inr: 10, downtime_h: 2, metrics: { cvar: 3 } }
const probe = { strategy_id: 's-1', cvar_before: 10, cvar_after_attack: 15, increase_pct: 0.5, hole: true }
const request = { kind: 'plan', plan_id: 'plan-cvar-1', controls: { 'd-1': 'patch' }, cost_inr: 8, downtime_h: 2, residual_holes: [probe] }

const upToApproval = [
  ev('system', 'observe', 'Incident started (LLM mode: mock)'),
  ev('sentinel', 'observe', 'Advisory received and quarantined'),
  ev('sentinel', 'decision', 'CVE-2024-0769: 2 devices affected → escalate', {
    decision: 'escalate',
    advisory: { cve_id: 'CVE-2024-0769', firmware_family: 'lumenos', affected_below: '4.2.0' },
    matches: [{ device_id: 'd-1' }, { device_id: 'd-2' }],
  }),
  ev('analyst', 'decision', 'Recommend replan', { assessment: { affected: ['d-1', 'd-2'], cvar_before: 18.8 } }),
  ev('planner', 'decision', 'Constraint: no downtime in zone Z', { constraint: { kind: 'no_downtime_zone', params: { zone: 'Z' } } }),
  ev('auditor', 'decision', 'Auditor: 2 claims verified, 1 rejected', { accepted: ['a', 'b'], rejected: ['c'], rejection_rate: 1 / 3 }),
  ev('planner', 'decision', 'Candidate plan-cvar-1', { plan }),
  ev('redteam', 'decision', 'Red-Team will try 2 strategies', { strategies: [{ id: 's-1' }, { id: 's-2' }] }),
  ev('redteam', 'hole', 'Hole: entry d-1', { strategy: { id: 's-1', entry_points: ['d-1'], pivot_shared_firmware: true }, probe }),
  ev('redteam', 'decision', '1 hole remains', { residual: [probe] }),
  ev('system', 'apply', 'Auto-applied 1 low-risk controls (policy: auto, no downtime)', { controls: { 'd-2': 'rotate_creds' } }),
  ev('system', 'decision', 'Approval needed: 1 control', { approval: request }),
]

describe('foldRun', () => {
  it('tracks the pipeline up to a pending approval', () => {
    const v = foldRun(upToApproval, false)
    expect(v.matches).toEqual(['d-1', 'd-2'])
    expect(v.advisory?.cve_id).toBe('CVE-2024-0769')
    expect(v.cvarBefore).toBe(18.8)
    expect(v.constraints).toHaveLength(1)
    expect(v.plan?.id).toBe('plan-cvar-1')
    expect(v.holes).toHaveLength(1)
    expect(v.holes[0].round).toBe(1)
    expect(v.residual).toHaveLength(1)
    expect(v.pending?.request.plan_id).toBe('plan-cvar-1')
    expect(v.autoApplied).toEqual({ 'd-2': 'rotate_creds' })
    expect(v.auditor[0].rejected).toEqual(['c'])
    expect(v.stages).toMatchObject({ sentinel: 'done', analyst: 'done', planner: 'done', redteam: 'warn', approval: 'active' })
    // auto-applied controls land before the approval and must not light up the Apply stage
    expect(v.stages.apply).toBe('idle')
    // every non-system decision in the fixture carries usage (110 tokens each)
    expect(v.llmCalls).toBe(7)
    expect(v.tokens).toBe(7 * 110)
  })

  it('clears the approval once the human answers and records the outcome', () => {
    const before = { cvar: 18.8, mean_loss: 6, max_cascade: 29, ci_low: 18, ci_high: 19, controls_applied: 0 }
    const after = { cvar: 10.9, mean_loss: 1.6, max_cascade: 19, ci_low: 10.6, ci_high: 11.2, controls_applied: 2 }
    const v = foldRun(
      [
        ...upToApproval,
        ev('human', 'approval', 'Approved plan-cvar-1 (role: approver)', { plan_id: 'plan-cvar-1', role: 'approver', kind: 'plan' }),
        ev('system', 'apply', 'Applied 1 approved controls in the twin', { controls: { 'd-1': 'patch' } }),
        ev('system', 'apply', 'Re-simulated: CVaR95 18.80 → 10.90', { before, after }),
        ev('system', 'decision', 'Run complete: 2 controls in place, 1 hole found', {}),
      ],
      true,
    )
    expect(v.pending).toBeNull()
    expect(v.applied).toEqual({ 'd-1': 'patch', 'd-2': 'rotate_creds' })
    expect(v.outcome?.after.cvar).toBe(10.9)
    expect(v.final?.summary).toMatch(/^Run complete/)
    expect(v.stages).toMatchObject({ approval: 'done', apply: 'done', redteam: 'warn' })
  })

  it('marks a timed-out approval as failed and stops waiting', () => {
    const v = foldRun(
      [...upToApproval, ev('system', 'error', 'Approval timed out after 600 s', { approval: request })],
      true,
    )
    expect(v.pending).toBeNull()
    expect(v.stages.approval).toBe('failed')
    expect(v.errors).toHaveLength(1)
  })

  it('skips the stages a monitor-only run never reaches', () => {
    const v = foldRun(
      [
        ev('sentinel', 'decision', 'CVE-2016-4523: no device affected → monitor', { decision: 'monitor', matches: [] }),
        ev('system', 'decision', 'Monitor: no device is affected; nothing to plan'),
      ],
      true,
    )
    expect(v.stages.sentinel).toBe('done')
    expect(v.stages.planner).toBe('skipped')
    expect(v.final?.summary).toMatch(/^Monitor/)
  })
})
