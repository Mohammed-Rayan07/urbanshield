// The hash chain as linked blocks. Verify sweeps along it; a tampered block breaks it visibly.
import { Hammer, Link2, ShieldCheck, ShieldX } from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { Audit } from '../lib/audit'
import { Button } from './ui'
import { cx } from '../lib/cx'

export default function AuditChain(props: { audit: Audit; window?: number; allowTamper?: boolean }) {
  const { entries, verify, busy, error, tampered } = props.audit
  const shown = (entries ?? []).slice(-(props.window ?? 24))
  const bad = verify && !verify.ok ? verify.first_bad_seq : null
  const target = shown.length ? shown[Math.floor(shown.length / 2)].seq : null
  const strip = useRef<HTMLDivElement>(null)
  useEffect(() => {
    // keep the head, or the first broken block, in view
    const el = strip.current
    if (!el) return
    const block = bad !== null ? el.querySelector<HTMLElement>(`[data-seq="${bad}"]`) : null
    el.scrollTo({ left: block ? block.offsetLeft - el.clientWidth / 2 : el.scrollWidth, behavior: 'smooth' })
  }, [entries, bad])

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <Button icon={ShieldCheck} onClick={props.audit.runVerify} disabled={busy !== null}>
          {busy === 'verify' ? 'Verifying…' : 'Verify chain'}
        </Button>
        {props.allowTamper && (
          <Button
            variant="danger"
            icon={Hammer}
            onClick={() => target !== null && props.audit.tamper(target)}
            disabled={busy !== null || target === null}
            title="Edits one stored event behind the log's back (demo only)"
          >
            Tamper with entry {target !== null ? `#${target}` : ''}
          </Button>
        )}
        {!entries && (
          <Button variant="secondary" onClick={props.audit.load} disabled={busy !== null}>
            Load chain
          </Button>
        )}
        {verify && (
          <span
            key={`${verify.ok}-${verify.first_bad_seq}-${verify.head_seq}`}
            className={cx(
              'ml-1 flex animate-rise items-center gap-1.5 text-[13px] font-semibold',
              verify.ok ? 'text-ok' : 'text-danger',
            )}
            role="status"
          >
            {verify.ok ? <ShieldCheck className="size-4" /> : <ShieldX className="size-4" />}
            {verify.ok
              ? `Chain intact · ${verify.entries} entries · head #${verify.head_seq}`
              : `Chain breaks at #${verify.first_bad_seq ?? '?'}${verify.reason ? `: ${verify.reason}` : ''}`}
          </span>
        )}
        {tampered !== null && !verify && (
          <span className="ml-1 text-[12.5px] font-medium text-high">Entry #{tampered} was edited. Now verify the chain.</span>
        )}
      </div>
      {error && <p className="mt-2 text-[12.5px] text-danger">{error}</p>}

      <div ref={strip} className="scroll-thin mt-4 overflow-x-auto pb-2">
        <ol className="flex min-w-max items-center">
          {!entries &&
            Array.from({ length: 14 }, (_, i) => (
              <li key={i} className="flex items-center">
                <span className="skeleton h-[58px] w-[64px]" />
                {i < 13 && <span className="h-px w-3 bg-line" />}
              </li>
            ))}
          {shown.map((e, i) => {
            const broken = bad !== null && e.seq === bad
            const after = bad !== null && e.seq > bad
            const ok = verify?.ok
            return (
              <li key={e.seq} data-seq={e.seq} className="flex items-center">
                <div
                  className={cx(
                    'relative w-[64px] overflow-hidden rounded-lg border px-2 py-1.5 transition-all duration-300',
                    broken
                      ? 'animate-[shake_420ms_ease-in-out] border-danger bg-danger-soft'
                      : after
                        ? 'border-dashed border-line bg-surface-muted opacity-45'
                        : ok
                          ? 'border-ok/40 bg-ok-soft'
                          : 'border-line bg-surface',
                  )}
                  title={`#${e.seq} ${e.event_id}\nhash ${e.hash}\nprev ${e.prev_hash}`}
                  style={ok ? { transitionDelay: `${i * 35}ms` } : undefined}
                >
                  {ok && (
                    <span
                      aria-hidden
                      className="absolute inset-0 bg-linear-to-r from-transparent via-white/70 to-transparent"
                      style={{ animation: `sweep 700ms ease-out ${i * 35}ms both` }}
                    />
                  )}
                  <p className={cx('num relative text-[12px] font-bold', broken ? 'text-danger' : 'text-ink')}>#{e.seq}</p>
                  <p className="relative font-mono text-[9.5px] leading-tight text-muted">{e.hash.slice(0, 6)}</p>
                  <p className="relative font-mono text-[9.5px] leading-tight text-muted">{e.signature.slice(0, 6)}</p>
                </div>
                {i < shown.length - 1 && (
                  <Link2
                    className={cx('mx-0.5 size-3.5 shrink-0', after || broken ? 'text-danger/60' : ok ? 'text-ok' : 'text-line-strong')}
                    aria-hidden
                  />
                )}
              </li>
            )
          })}
        </ol>
      </div>
      {entries && entries.length === 0 && (
        <p className="mt-2 text-[12.5px] text-muted">The log is empty. Run an incident first; every event is appended here.</p>
      )}
    </div>
  )
}
