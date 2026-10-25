// Live Attack Console: fire an attacker's kill chain of signal commands at the real Enforcer and watch
// each step judged live. The corridor interlock vetoes unsafe commands in microseconds even with valid
// credentials; once a hardening plan is enforced, closed management refuses them earlier still. Every
// command is a real POST to /enforcer/commands and is appended to the signed audit log server-side.
import { Ban, Crosshair, Lock, Radio, ShieldAlert, Siren, Zap } from 'lucide-react'
import { useMemo, useState } from 'react'
import { api, useLoad } from '../api'
import { cx } from '../lib/cx'
import { useStore } from '../lib/store'
import type { Device, EnforcerStatus, SignalCommand, Verdict } from '../types'
import { Badge, Button, Card } from './ui'

interface Step {
  label: string
  detail: string
  command: SignalCommand
}

type RunStep = Step & { verdict: Verdict | null; state: 'idle' | 'running' | 'done' }

/** The attacker's goal: seize an ambulance-corridor signal and strand the green wave. */
function killChain(corridor: string): Step[] {
  return [
    {
      label: 'Freeze the junction',
      detail: 'Hold the corridor signal on all-red for 10 minutes',
      command: { device_id: corridor, phase: 'all_red', hold_s: 600, remote: true },
    },
    {
      label: 'Force conflicting greens',
      detail: 'Open crossing directions at once to cause a collision',
      command: { device_id: corridor, phase: 'both_green', remote: true },
    },
    {
      label: 'Blind the corridor',
      detail: 'Hold the signal on flash for 10 minutes so the green wave breaks',
      command: { device_id: corridor, phase: 'flash', hold_s: 600, remote: true },
    },
  ]
}

const LAYER: Record<string, { label: string; icon: typeof Lock }> = {
  management_closed: { label: 'Closed management port', icon: Lock },
  conflicting_greens: { label: 'Interlock · conflicting greens', icon: Ban },
  corridor_hold: { label: 'Interlock · corridor hold', icon: Siren },
  corridor_continuity: { label: 'Interlock · corridor continuity', icon: Ban },
}

function StepRow(props: { step: RunStep; i: number }) {
  const { step } = props
  const v = step.verdict
  const layer = v?.rule ? LAYER[v.rule] : null
  const Icon = layer?.icon ?? Zap
  return (
    <li
      className={cx(
        'flex items-start gap-3 rounded-lg border px-4 py-3 transition-colors',
        step.state === 'running' && 'border-warn/40 bg-warn-soft',
        step.state === 'done' && v && !v.allowed && 'border-ok/35 bg-ok-soft',
        step.state === 'done' && v?.allowed && 'border-danger/35 bg-danger-soft',
        step.state === 'idle' && 'border-line bg-surface-muted',
      )}
    >
      <div
        className={cx(
          'grid size-8 shrink-0 place-items-center rounded-full text-[13px] font-semibold',
          step.state === 'done' && v && !v.allowed ? 'bg-ok text-white' : 'bg-forest-900 text-white',
        )}
      >
        {step.state === 'done' && v ? (v.allowed ? '✕' : '✓') : props.i + 1}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-[13.5px] font-semibold text-ink">{step.label}</p>
        <p className="text-[12px] text-ink-2">{step.detail}</p>
        {v && (
          <p
            className={cx(
              'mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]',
              v.allowed ? 'text-danger' : 'text-ok',
            )}
          >
            <Icon className="size-3.5 shrink-0" aria-hidden />
            <span className="font-semibold">
              {v.allowed ? 'Got through' : `Blocked · ${layer?.label ?? v.rule}`}
            </span>
            <span className="text-ink-2">{v.reason}</span>
            <span className="num text-muted">· {v.latency_us.toFixed(0)} µs</span>
          </p>
        )}
      </div>
    </li>
  )
}

function Corridor(props: { status: EnforcerStatus | null }) {
  const s = props.status
  const corridor = s?.corridor
  const tone = corridor?.status === 'closed' ? 'ok' : corridor?.status === 'filtered' ? 'warn' : 'danger'
  const text =
    corridor?.status === 'closed'
      ? 'No path to the corridor'
      : corridor?.status === 'filtered'
        ? 'Reachable, every route filtered'
        : 'Reachable from the internet'
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-[12.5px]">
      <span className="flex items-center gap-2">
        <Lock className="size-3.5 text-forest-800" aria-hidden />
        Policy <span className="num font-semibold text-ink">v{s?.version ?? 0}</span>
        {s?.plan_id ? (
          <span className="text-muted">· {s.plan_id}</span>
        ) : (
          <span className="text-muted">· none enforced</span>
        )}
      </span>
      {s && (
        <span className="flex items-center gap-2">
          <Radio className="size-3.5 text-muted" aria-hidden />
          <span className="num text-ink-2">
            {s.flows_allowed}/{s.flows_total}
          </span>{' '}
          flows allowed
        </span>
      )}
      <Badge tone={tone}>{text}</Badge>
    </div>
  )
}

export default function AttackConsole(props: { chrome?: boolean }) {
  const { city } = useStore()
  const enforcer = useLoad(() => api.enforcer())
  const corridorIds = useMemo(
    () => (city.data?.devices ?? []).filter((d: Device) => d.tags.includes('ambulance_corridor')).map((d) => d.id),
    [city.data],
  )
  const [target, setTarget] = useState<string | null>(null)
  const pick = target ?? corridorIds[0] ?? null
  const [steps, setSteps] = useState<RunStep[]>([])
  const [running, setRunning] = useState(false)

  async function attack() {
    if (!pick) return
    setRunning(true)
    const chain: RunStep[] = killChain(pick).map((s) => ({ ...s, verdict: null, state: 'idle' }))
    setSteps(chain)
    for (let i = 0; i < chain.length; i++) {
      setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, state: 'running' } : s)))
      await new Promise((r) => setTimeout(r, 480))
      let verdict: Verdict
      try {
        verdict = await api.command(chain[i].command)
      } catch {
        verdict = { allowed: false, rule: 'error', reason: 'the command could not be sent', latency_us: 0 }
      }
      setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, verdict, state: 'done' } : s)))
    }
    enforcer.reload()
    setRunning(false)
  }

  const done = steps.length > 0 && steps.every((s) => s.state === 'done')
  // A command that never reached the Enforcer was not blocked by it: never count it as a block.
  const failed = steps.filter((s) => s.verdict?.rule === 'error').length
  const blocked = steps.filter((s) => s.verdict && !s.verdict.allowed && s.verdict.rule !== 'error').length
  const held = blocked === steps.length
  const targetDevice = city.data?.devices.find((d) => d.id === pick)

  const body = (
    <div className="space-y-4">
      <Corridor status={enforcer.data} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-[13px] text-ink-2">
          <Crosshair className="size-4 text-danger" aria-hidden />
          Target:
          <select
            value={pick ?? ''}
            onChange={(e) => setTarget(e.target.value)}
            className="num rounded-md border border-line bg-surface px-2 py-1 text-[12.5px] text-ink"
          >
            {corridorIds.map((id) => (
              <option key={id} value={id}>
                {city.data?.devices.find((d) => d.id === id)?.name ?? id}
              </option>
            ))}
          </select>
          <span className="text-muted">(attacker holds valid stolen credentials)</span>
        </div>
        <Button variant="danger" icon={ShieldAlert} onClick={attack} disabled={running || !pick}>
          {running ? 'Attacking…' : steps.length ? 'Re-run attack' : 'Run attack'}
        </Button>
      </div>
      {steps.length > 0 ? (
        <ul className="space-y-2">
          {steps.map((s, i) => (
            <StepRow key={i} step={s} i={i} />
          ))}
        </ul>
      ) : (
        <div className="rounded-lg border border-dashed border-line bg-surface-muted px-4 py-6 text-center text-[13px] text-muted">
          The attacker fires three commands at {targetDevice?.name ?? 'the corridor signal'}. Watch each one judged at
          the Enforcer — the interlock refuses unsafe commands even though the credentials are valid.
        </div>
      )}
      {done && (
        <div
          className={cx(
            'flex items-center gap-3 rounded-lg px-4 py-3 text-[13.5px]',
            held ? 'border border-ok/35 bg-ok-soft text-ink' : 'border border-danger/35 bg-danger-soft text-ink',
          )}
        >
          <Siren className={cx('size-5 shrink-0', held ? 'text-ok' : 'text-danger')} aria-hidden />
          <span>
            <span className="font-semibold">
              {blocked}/{steps.length} commands blocked.
            </span>{' '}
            {failed
              ? `${failed} could not reach the Enforcer; check the API and re-run.`
              : held
                ? 'The ambulance corridor stays passable. Every verdict was appended to the signed audit log.'
                : 'A command got through. Every verdict was appended to the signed audit log.'}
          </span>
        </div>
      )}
    </div>
  )
  if (props.chrome === false) return body
  return (
    <Card className="px-5 py-4" aria-label="Live attack console">
      <div className="mb-3">
        <p className="eyebrow">Mitigation, live</p>
        <h2 className="mt-1 font-serif text-[26px] leading-tight text-ink">Attack the corridor</h2>
      </div>
      {body}
    </Card>
  )
}
