// Shared building blocks. Screens compose these; they never style a card or a number by hand.
import { AlertTriangle, RotateCw, type LucideIcon } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cx, rise } from '../lib/cx'
import { useStore, type ProvenanceTarget } from '../lib/store'

// ------------------------------------------------------------------ layout

export function PageHeader(props: { eyebrow: string; title: string; subtitle: ReactNode; aside?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
      <div className="min-w-0 animate-rise">
        <p className="eyebrow">{props.eyebrow}</p>
        <h1 className="mt-1.5 font-serif text-[40px] leading-[1.05] tracking-[-0.01em] text-ink">{props.title}</h1>
        <p className="mt-2 max-w-[68ch] text-[14.5px] text-ink-2">{props.subtitle}</p>
      </div>
      {props.aside && (
        <div className="animate-rise" style={rise(2)}>
          {props.aside}
        </div>
      )}
    </header>
  )
}

export function Card(props: {
  children: ReactNode
  className?: string
  i?: number
  as?: 'section' | 'div' | 'article'
  'aria-label'?: string
}) {
  const Tag = props.as ?? 'section'
  return (
    <Tag
      aria-label={props['aria-label']}
      style={props.i !== undefined ? rise(props.i) : undefined}
      className={cx(
        'animate-rise rounded-xl border border-line bg-surface shadow-[0_1px_0_rgb(23_37_31/0.03)]',
        props.className,
      )}
    >
      {props.children}
    </Tag>
  )
}

export function CardHeader(props: { title: ReactNode; sub?: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <div className={cx('flex items-start justify-between gap-4 px-5 pt-4', props.className)}>
      <div className="min-w-0">
        <h2 className="text-[16px] font-semibold tracking-[-0.01em] text-ink">{props.title}</h2>
        {props.sub && <p className="mt-0.5 text-[12.5px] text-muted">{props.sub}</p>}
      </div>
      {props.right && <div className="shrink-0">{props.right}</div>}
    </div>
  )
}

// ------------------------------------------------------------------ numbers

/** Counts up to `value` once when it first appears (and again when it changes). */
export function CountUp(props: { value: number; format: (n: number) => string; ms?: number }) {
  const { value, format, ms = 750 } = props
  const [shown, setShown] = useState(value)
  const from = useRef(0)
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const start = performance.now()
    const a = from.current
    let raf = 0
    const tick = (now: number) => {
      const t = reduce ? 1 : Math.min(1, (now - start) / ms)
      const eased = 1 - Math.pow(1 - t, 3)
      setShown(a + (value - a) * eased)
      if (t < 1) raf = requestAnimationFrame(tick)
      else from.current = value
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, ms])
  return <span className="num">{format(shown)}</span>
}

/** A number with a source. Clicking opens the provenance drawer on the tool call that produced it. */
export function Metric(props: { children: ReactNode; source?: ProvenanceTarget | null; className?: string }) {
  const { openProvenance } = useStore()
  if (!props.source) return <span className={cx('num', props.className)}>{props.children}</span>
  const source = props.source
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        openProvenance(source)
      }}
      title={`Source: ${source.toolCallId} (click for provenance)`}
      className={cx(
        'num cursor-pointer rounded-sm underline decoration-forest-200 decoration-dotted decoration-[1.5px] underline-offset-[5px] transition-colors hover:decoration-forest-700',
        props.className,
      )}
    >
      {props.children}
    </button>
  )
}

export type Tone = 'neutral' | 'forest' | 'danger' | 'high' | 'warn' | 'ok' | 'info'

const TONE: Record<Tone, string> = {
  neutral: 'bg-surface-muted text-ink-2 border-line',
  forest: 'bg-forest-100 text-forest-800 border-forest-200',
  danger: 'bg-danger-soft text-danger border-danger/20',
  high: 'bg-high-soft text-[#b4531c] border-high/25',
  warn: 'bg-warn-soft text-[#8a6212] border-warn/30',
  ok: 'bg-ok-soft text-ok border-ok/20',
  info: 'bg-info-soft text-info border-info/20',
}

export function Badge(props: { tone?: Tone; children: ReactNode; className?: string; title?: string }) {
  return (
    <span
      title={props.title}
      className={cx(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-[1px] text-[11px] font-semibold leading-[18px]',
        TONE[props.tone ?? 'neutral'],
        props.className,
      )}
    >
      {props.children}
    </span>
  )
}

export function Dot(props: { color: string; className?: string; pulse?: boolean }) {
  return (
    <span className={cx('relative inline-flex size-2 shrink-0', props.className)}>
      {props.pulse && (
        <span className="absolute inset-0 animate-ping rounded-full opacity-60" style={{ background: props.color }} />
      )}
      <span className="relative size-2 rounded-full" style={{ background: props.color }} />
    </span>
  )
}

export function Kpi(props: {
  icon: LucideIcon
  label: string
  value: ReactNode
  unit?: ReactNode
  delta?: ReactNode
  foot?: ReactNode
  tone?: Tone
  i?: number
}) {
  const Icon = props.icon
  return (
    <Card as="div" i={props.i} className="flex min-w-0 gap-3.5 px-4 py-4">
      <div
        className={cx(
          'grid size-10 shrink-0 place-items-center rounded-lg border',
          TONE[props.tone ?? 'forest'],
        )}
      >
        <Icon className="size-[18px]" strokeWidth={1.9} aria-hidden />
      </div>
      <div className="min-w-0">
        <p className="text-[12.5px] font-medium leading-snug text-ink-2">{props.label}</p>
        <div className="mt-0.5 flex items-baseline gap-2">
          <span className="text-[27px] font-[650] leading-tight tracking-[-0.02em] text-ink">{props.value}</span>
          {props.unit && <span className="text-[13px] text-muted">{props.unit}</span>}
          {props.delta}
        </div>
        {props.foot && <div className="mt-0.5 text-[12px] leading-snug text-muted">{props.foot}</div>}
      </div>
    </Card>
  )
}

/** A signed change chip. `good` decides the colour: down is good for losses. */
export function Delta(props: { children: ReactNode; good: boolean }) {
  return (
    <span className={cx('num text-[12.5px] font-semibold', props.good ? 'text-ok' : 'text-danger')}>
      {props.children}
    </span>
  )
}

// ------------------------------------------------------------------ controls

export function Segmented<T extends string>(props: {
  options: { id: T; label: ReactNode; icon?: LucideIcon; title?: string }[]
  value: T
  onChange: (v: T) => void
  label: string
  size?: 'sm' | 'md'
}) {
  const sm = props.size === 'sm'
  return (
    <div role="radiogroup" aria-label={props.label} className="inline-flex rounded-lg border border-line bg-surface p-0.5">
      {props.options.map((o) => {
        const on = o.id === props.value
        const Icon = o.icon
        return (
          <button
            key={o.id}
            type="button"
            role="radio"
            aria-checked={on}
            title={o.title}
            onClick={() => props.onChange(o.id)}
            className={cx(
              'inline-flex cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-md font-medium transition-colors duration-200',
              sm ? 'px-2.5 py-1 text-[12px]' : 'px-3 py-1.5 text-[13px]',
              on ? 'bg-forest-800 text-white shadow-sm' : 'text-ink-2 hover:bg-forest-50 hover:text-ink',
            )}
          >
            {Icon && <Icon className="size-3.5" aria-hidden />}
            {o.label}
          </button>
        )
      })}
    </div>
  )
}

export function Button(props: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  disabled?: boolean
  icon?: LucideIcon
  className?: string
  type?: 'button' | 'submit'
  title?: string
}) {
  const Icon = props.icon
  return (
    <button
      type={props.type ?? 'button'}
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title}
      className={cx(
        'inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-[13px] font-semibold transition-all duration-200 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45',
        props.variant === 'secondary' && 'border border-line bg-surface text-ink hover:border-line-strong hover:bg-forest-50',
        props.variant === 'ghost' && 'text-forest-800 hover:bg-forest-50',
        props.variant === 'danger' && 'border border-danger/25 bg-surface text-danger hover:bg-danger-soft',
        (props.variant ?? 'primary') === 'primary' && 'bg-forest-800 text-white hover:bg-forest-700',
        props.className,
      )}
    >
      {Icon && <Icon className="size-4" aria-hidden />}
      {props.children}
    </button>
  )
}

export function LinkButton(props: { children: ReactNode; href?: string; onClick?: () => void }) {
  const cls =
    'inline-flex cursor-pointer items-center gap-1 rounded text-[12.5px] font-semibold text-forest-800 transition-colors hover:text-forest-700'
  return props.href ? (
    <a href={props.href} className={cls}>
      {props.children}
    </a>
  ) : (
    <button type="button" onClick={props.onClick} className={cls}>
      {props.children}
    </button>
  )
}

// ------------------------------------------------------------------ states

export function Skeleton(props: { className?: string }) {
  return <div aria-hidden className={cx('skeleton', props.className)} />
}

export function ErrorState(props: { error: Error; retry?: () => void; className?: string }) {
  return (
    <div role="alert" className={cx('flex items-start gap-3 rounded-lg border border-danger/20 bg-danger-soft p-4', props.className)}>
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
      <div className="min-w-0 text-[13px]">
        <p className="font-semibold text-danger">Could not load this panel</p>
        <p className="mt-0.5 break-words text-ink-2">{props.error.message}</p>
        {props.retry && (
          <button
            type="button"
            onClick={props.retry}
            className="mt-2 inline-flex cursor-pointer items-center gap-1 text-[12.5px] font-semibold text-forest-800"
          >
            <RotateCw className="size-3.5" aria-hidden /> Retry
          </button>
        )}
      </div>
    </div>
  )
}

export function Empty(props: { icon: LucideIcon; title: string; children?: ReactNode; className?: string }) {
  const Icon = props.icon
  return (
    <div className={cx('flex flex-col items-center justify-center px-6 py-8 text-center', props.className)}>
      <div className="grid size-10 place-items-center rounded-full border border-line bg-surface-muted">
        <Icon className="size-[18px] text-muted" aria-hidden />
      </div>
      <p className="mt-3 text-[13.5px] font-semibold text-ink">{props.title}</p>
      {props.children && <div className="mt-1 max-w-[44ch] text-[12.5px] text-muted">{props.children}</div>}
    </div>
  )
}

/** Key/value rows for spec-sheet style panels. */
export function Rows(props: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cx('divide-y divide-line text-[12.5px]', props.className)}>
      {props.rows.map(([k, v], i) => (
        <div key={i} className="grid grid-cols-[minmax(0,44%)_1fr] gap-3 py-[7px]">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  )
}
