// Right-side slide-over: the tool call behind a number, shown like a receipt.
import { Braces, ChevronDown, FileSearch, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { AGENT_LABEL } from '../lib/format'
import { useStore } from '../lib/store'
import type { ToolResult } from '../types'
import { Badge, ErrorState, Skeleton } from './ui'

function Json(props: { value: unknown }) {
  return (
    <pre className="scroll-thin max-h-[42vh] overflow-auto rounded-lg border border-line bg-surface-muted p-3 font-mono text-[11.5px] leading-relaxed text-ink-2">
      {JSON.stringify(props.value, null, 2)}
    </pre>
  )
}

export default function ProvenanceDrawer() {
  const { provenance, closeProvenance } = useStore()
  const [state, setState] = useState<{ key: string; record?: ToolResult; error?: Error } | null>(null)
  const [showResult, setShowResult] = useState(true)
  const closeRef = useRef<HTMLButtonElement>(null)
  const key = provenance ? `${provenance.runId ?? ''}/${provenance.toolCallId}` : ''

  useEffect(() => {
    if (!provenance) return
    let live = true
    const load = provenance.runId
      ? api.runToolResult(provenance.runId, provenance.toolCallId)
      : api.toolResult(provenance.toolCallId)
    load.then(
      (record) => live && setState({ key, record }),
      (error: Error) => live && setState({ key, error }),
    )
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && closeProvenance()
    window.addEventListener('keydown', onKey)
    return () => {
      live = false
      window.removeEventListener('keydown', onKey)
    }
  }, [provenance, key, closeProvenance])

  if (!provenance) return null
  const current = state?.key === key ? state : null
  const record = current?.record
  return (
    <div className="fixed inset-0 z-[1500]" role="dialog" aria-modal="true" aria-label="Provenance">
      <button
        type="button"
        aria-label="Close provenance"
        onClick={closeProvenance}
        className="absolute inset-0 animate-fade cursor-default bg-forest-950/25"
      />
      <aside className="absolute inset-y-0 right-0 flex w-full max-w-[480px] animate-slide-in flex-col border-l border-line bg-surface shadow-[-24px_0_60px_rgb(9_39_31/0.12)]">
        <div className="flex items-start justify-between gap-4 border-b border-line px-6 py-5">
          <div>
            <p className="eyebrow">Provenance</p>
            <h2 className="mt-1 font-serif text-[26px] leading-tight text-ink">Where this number came from</h2>
            {provenance.label && <p className="mt-1 text-[13px] text-ink-2">{provenance.label}</p>}
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={closeProvenance}
            aria-label="Close"
            className="grid size-9 cursor-pointer place-items-center rounded-lg border border-line text-ink-2 hover:bg-forest-50"
          >
            <X className="size-4" />
          </button>
        </div>
        <div className="scroll-thin flex-1 space-y-5 overflow-y-auto px-6 py-5">
          {current?.error && <ErrorState error={current.error} />}
          {!current && (
            <div className="space-y-3">
              <Skeleton className="h-16" />
              <Skeleton className="h-40" />
            </div>
          )}
          {record && (
            <>
              <div className="rounded-xl border border-dashed border-line-strong bg-surface-muted p-4">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 font-mono text-[14px] font-semibold text-ink">
                    <FileSearch className="size-4 text-forest-800" aria-hidden />
                    {record.tool}()
                  </span>
                  <Badge tone="forest">{AGENT_LABEL[record.agent]}</Badge>
                </div>
                <dl className="mt-3 grid grid-cols-[96px_1fr] gap-y-1.5 text-[12.5px]">
                  <dt className="text-muted">Tool call</dt>
                  <dd className="font-mono text-ink">{record.id}</dd>
                  {provenance.runId && (
                    <>
                      <dt className="text-muted">Run</dt>
                      <dd className="font-mono text-ink">{provenance.runId}</dd>
                    </>
                  )}
                  <dt className="text-muted">Recorded</dt>
                  <dd className="num text-ink">{new Date(record.ts).toLocaleString('en-IN')}</dd>
                </dl>
                <p className="mt-3 border-t border-dashed border-line-strong pt-3 text-[12px] text-ink-2">
                  Deterministic engine output. The LLM never produces numbers; it can only call this tool.
                </p>
              </div>
              <section>
                <h3 className="mb-2 flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-[0.12em] text-ink-2">
                  <Braces className="size-3.5" aria-hidden /> Arguments
                </h3>
                {Object.keys(record.args).length ? (
                  <dl className="divide-y divide-line rounded-lg border border-line text-[12.5px]">
                    {Object.entries(record.args).map(([k, v]) => (
                      <div key={k} className="grid grid-cols-[40%_1fr] gap-3 px-3 py-2">
                        <dt className="font-mono text-muted">{k}</dt>
                        <dd className="break-all font-mono text-ink">{typeof v === 'string' ? v : JSON.stringify(v)}</dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <p className="text-[12.5px] text-muted">No arguments (uses the run's current state).</p>
                )}
              </section>
              <section>
                <button
                  type="button"
                  onClick={() => setShowResult((s) => !s)}
                  aria-expanded={showResult}
                  className="mb-2 flex cursor-pointer items-center gap-1.5 text-[12px] font-semibold uppercase tracking-[0.12em] text-ink-2"
                >
                  <ChevronDown className={`size-3.5 transition-transform ${showResult ? '' : '-rotate-90'}`} aria-hidden />
                  Result
                </button>
                {showResult && <Json value={record.result} />}
              </section>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}
