// Persistent application shell: forest sidebar, status bar, and the main workspace.
import {
  Activity,
  CalendarDays,
  MonitorPlay,
  Cpu,
  FileLock2,
  FlaskConical,
  LayoutDashboard,
  MapPin,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { STAGES } from '../lib/run'
import { href, type RouteId } from '../lib/route'
import { useStore } from '../lib/store'
import { Dot } from './ui'
import { cx } from '../lib/cx'

interface NavItem {
  id: RouteId
  label: string
  icon: LucideIcon
  badge?: number
}

export function BrandMark(props: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" className={props.className} aria-hidden>
      <path d="M20 3 6 8.5v10.2C6 27.6 12 34.4 20 37c8-2.6 14-9.4 14-18.3V8.5L20 3Z" fill="#f1f5f0" />
      <path
        d="M20 30.5V19m0 0c0-4.8 3.2-8 8-8.4-.2 4.8-3.3 8.2-8 8.4Zm0 3c0-3.8-2.6-6.4-6.4-6.7.2 3.8 2.6 6.5 6.4 6.7Z"
        fill="none"
        stroke="#174a3a"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="20" cy="31" r="1.6" fill="#174a3a" />
    </svg>
  )
}

/** Line-drawn Mangaluru-ish skyline: palms, the port crane, low-rise blocks. Decorative. */
function Skyline() {
  return (
    <svg viewBox="0 0 220 90" className="w-full" aria-hidden>
      <g fill="none" stroke="rgb(229 239 231 / 0.22)" strokeWidth="1.2" strokeLinejoin="round">
        <path d="M0 86h220" />
        <path d="M8 86V58h16v28M28 86V44h14v42M46 86V62h12v24M62 86V36h18v50M84 86V54h12v32" />
        <path d="M100 86V48l10-6 10 6v38M124 86V60h14v26M142 86V30h12v56M158 86V52h16v34" />
        <path d="M180 86V40l22-14M202 26v60M196 32l12 0M188 86V56" />
        <path d="M36 44v-6M68 36v-8h6v8M148 30v-10" />
        <path d="M12 58c-2-10 2-18 8-22M20 36c-6-1-10 2-12 5M20 36c5-3 10-2 13 1M20 36c0 4-2 8-5 10" />
      </g>
      <g fill="rgb(229 239 231 / 0.35)">
        <rect x="66" y="42" width="3" height="3" />
        <rect x="72" y="50" width="3" height="3" />
        <rect x="146" y="38" width="3" height="3" />
        <rect x="146" y="48" width="3" height="3" />
        <rect x="104" y="56" width="3" height="3" />
      </g>
    </svg>
  )
}

function Sidebar(props: { route: RouteId }) {
  const { city, run } = useStore()
  const exposed = city.data?.devices.filter((d) => d.exposed).length
  const pending = run.view.pending ? 1 : 0
  const primary: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'story', label: 'Story Mode', icon: MonitorPlay },
    { id: 'risk', label: 'Risk Intelligence', icon: Activity },
    { id: 'response', label: 'Response & Mitigation', icon: ShieldCheck, badge: pending || undefined },
  ]
  const support: NavItem[] = [
    { id: 'devices', label: 'Devices', icon: Cpu, badge: exposed },
    { id: 'judge', label: 'Judge Mode', icon: FlaskConical },
    { id: 'audit', label: 'Audit Log', icon: FileLock2 },
  ]
  const item = (n: NavItem) => {
    const on = n.id === props.route
    const Icon = n.icon
    return (
      <li key={n.id}>
        <a
          href={href(n.id)}
          aria-current={on ? 'page' : undefined}
          className={cx(
            'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13.5px] font-medium transition-colors duration-200',
            on ? 'bg-forest-50 text-forest-900' : 'text-forest-100/80 hover:bg-white/[0.06] hover:text-white',
          )}
        >
          {on && <span className="absolute -left-3 top-1.5 bottom-1.5 w-[3px] rounded-r-full bg-[#7fc49b]" />}
          <Icon className={cx('size-[18px]', on ? 'text-forest-800' : 'text-forest-100/70')} strokeWidth={1.8} aria-hidden />
          <span className="flex-1">{n.label}</span>
          {n.badge ? (
            <span
              className={cx(
                'num grid h-5 min-w-5 place-items-center rounded-full px-1.5 text-[11px] font-semibold',
                n.id === 'response' ? 'bg-danger text-white' : on ? 'bg-forest-800 text-white' : 'bg-white/12 text-white',
              )}
              title={n.id === 'devices' ? `${n.badge} internet-exposed devices` : 'Approval waiting'}
            >
              {n.badge}
            </span>
          ) : null}
        </a>
      </li>
    )
  }
  return (
    <aside className="hidden w-[244px] shrink-0 flex-col bg-forest-900 text-white lg:flex">
      <a href={href('overview')} className="flex h-[72px] items-center gap-3 border-b border-white/[0.07] px-5">
        <BrandMark className="size-9" />
        <div className="leading-tight">
          <p className="text-[17px] font-bold tracking-[0.06em]">URBANSHIELD</p>
          <p className="text-[9.5px] font-medium tracking-[0.14em] text-forest-100/60">CYBER-RESILIENCE TWIN</p>
        </div>
      </a>
      <nav aria-label="Workspaces" className="flex flex-1 flex-col px-3 pt-5">
        <ul className="space-y-1">{primary.map(item)}</ul>
        <div className="mx-3 my-5 h-px bg-white/[0.08]" />
        <ul className="space-y-1">{support.map(item)}</ul>
      </nav>
      <div className="px-5 pb-5">
        <Skyline />
        <p className="mt-3 font-serif text-[19px] leading-snug text-forest-50">
          Same budget.
          <br />
          Smaller worst case.
        </p>
        <div className="mt-3 h-px w-8 bg-[#7fc49b]" />
        <p className="mt-3 text-[11px] text-forest-100/55">Digital twin · simulation only. No real devices are touched.</p>
      </div>
    </aside>
  )
}

function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1000 * 15)
    return () => window.clearInterval(t)
  }, [])
  return (
    <div className="flex items-center gap-2.5 whitespace-nowrap text-[13px] text-ink-2">
      <CalendarDays className="size-4 text-muted" aria-hidden />
      <span className="num font-medium text-ink">
        {now.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}
      </span>
      <span className="num">{now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</span>
    </div>
  )
}

function StatusBar() {
  const { health, city, run } = useStore()
  const h = health.data
  const engineOk = h?.engine_ready
  const auditOk = h?.audit === 'ok'
  const stage = STAGES.find((s) => run.view.stages[s.id] === 'active')
  const live = run.runId && !run.done
  return (
    <header className="flex h-[72px] shrink-0 items-center gap-5 border-b border-line bg-surface px-6">
      <div className="flex h-10 shrink-0 items-center gap-2.5 whitespace-nowrap rounded-lg border border-line bg-surface px-3 text-[13px]">
        <MapPin className="size-4 text-forest-800" aria-hidden />
        <span className="font-semibold text-ink">Mangaluru, Karnataka</span>
        <span className="hidden text-muted 2xl:inline">
          · twin seed {city.data?.seed ?? '–'} · {city.data?.devices.length ?? '–'} devices
        </span>
      </div>
      {live && (
        <a
          href={href('response')}
          className="hidden items-center gap-2 whitespace-nowrap rounded-lg border border-forest-200 bg-forest-50 px-3 py-2 text-[12.5px] font-semibold text-forest-800 2xl:flex"
        >
          <Dot color="var(--color-forest-700)" pulse />
          Incident running{stage ? ` · ${stage.label}` : ''}
        </a>
      )}
      {run.view.pending && (
        <a
          href={href('response')}
          className="hidden items-center gap-2 whitespace-nowrap rounded-lg border border-danger/25 bg-danger-soft px-3 py-2 text-[12.5px] font-semibold text-danger md:flex"
        >
          <Dot color="var(--color-danger)" pulse />
          Approval waiting
        </a>
      )}
      <div className="ml-auto flex items-center gap-5">
        <Clock />
        <div className="hidden h-8 w-px bg-line xl:block" />
        <div className="hidden items-center gap-4 xl:flex">
          <div className="whitespace-nowrap text-[12px] leading-tight">
            <p className="flex items-center gap-1.5 font-semibold text-ink">
              <Dot color={engineOk ? 'var(--color-ok)' : 'var(--color-warn)'} />
              {h ? (engineOk ? 'Engine live' : 'Placeholder data') : 'Connecting…'}
            </p>
            <p className="mt-0.5 text-muted">
              LLM <span className="font-semibold uppercase text-ink-2">{h?.llm_mode ?? '–'}</span>
              {h?.llm_mode === 'mock' && ' · deterministic'}
            </p>
          </div>
          <div className="whitespace-nowrap text-[12px] leading-tight">
            <p className="flex items-center gap-1.5 font-semibold text-ink">
              <Dot color={auditOk ? 'var(--color-ok)' : 'var(--color-danger)'} />
              Audit {auditOk ? 'signing' : 'down'}
            </p>
            <p className="mt-0.5 text-muted">
              Ed25519 · {h?.audit_key === 'fixed' ? 'fixed key' : 'ephemeral key'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5" title="Demo RBAC: approvals are sent with X-Role: approver">
          <div className="grid size-9 place-items-center rounded-full bg-forest-900 text-[13px] font-semibold text-white">R</div>
          <div className="hidden text-[12px] leading-tight 2xl:block">
            <p className="font-semibold text-ink">Rayan</p>
            <p className="text-muted">Approver</p>
          </div>
        </div>
      </div>
    </header>
  )
}

export default function Shell(props: { route: RouteId; children: ReactNode }) {
  const { health } = useStore()
  return (
    <div className="flex h-full">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-[2000] focus:rounded-md focus:bg-surface focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <Sidebar route={props.route} />
      <div className="flex min-w-0 flex-1 flex-col">
        {health.data?.data === 'placeholder' && (
          <div role="status" className="bg-warn px-6 py-1 text-center text-[12px] font-semibold text-forest-950">
            PLACEHOLDER DATA: the engine is not ready, numbers are not from the simulator
          </div>
        )}
        <StatusBar />
        <MobileNav route={props.route} />
        <main id="main" className="scroll-thin min-h-0 flex-1 overflow-y-auto">
          <div key={props.route} className="mx-auto max-w-[1680px] px-6 pb-10 pt-6">
            {props.children}
          </div>
        </main>
      </div>
    </div>
  )
}

/** Below the lg breakpoint the sidebar collapses into a scrollable tab row. */
function MobileNav(props: { route: RouteId }) {
  const items: [RouteId, string][] = [
    ['overview', 'Overview'],
    ['story', 'Story'],
    ['risk', 'Risk'],
    ['response', 'Response'],
    ['devices', 'Devices'],
    ['judge', 'Judge'],
    ['audit', 'Audit'],
  ]
  return (
    <nav aria-label="Workspaces" className="scroll-thin flex gap-1 overflow-x-auto border-b border-line bg-forest-900 px-3 py-2 lg:hidden">
      {items.map(([id, label]) => (
        <a
          key={id}
          href={href(id)}
          aria-current={id === props.route ? 'page' : undefined}
          className={cx(
            'whitespace-nowrap rounded-md px-3 py-1.5 text-[13px] font-medium',
            id === props.route ? 'bg-forest-50 text-forest-900' : 'text-forest-100/80',
          )}
        >
          {label}
        </a>
      ))}
    </nav>
  )
}
