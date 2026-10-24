// Judge Mode: paste anything; see that only typed, cross-checked fields ever reach the planner.
import { ArrowRight, Check, FileText, FlaskConical, Fingerprint, Lock, Pencil, ScanSearch, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api'
import AuditChain from '../components/AuditChain'
import { useAudit } from '../lib/audit'
import { Badge, Button, Card, CardHeader, Empty, PageHeader, Skeleton } from '../components/ui'
import { cx } from '../lib/cx'
import { useStore } from '../lib/store'
import type { Advisory, QuarantinePreview } from '../types'

const FIELDS: { key: keyof Advisory; label: string; hint: RegExp }[] = [
  { key: 'cve_id', label: 'CVE', hint: /pinned feed|not in the feed|unknown cve/i },
  { key: 'vendor', label: 'Vendor', hint: /vendor/i },
  { key: 'product', label: 'Product', hint: /product/i },
  { key: 'firmware_family', label: 'Firmware family', hint: /firmware family|family/i },
  { key: 'affected_below', label: 'Affected below', hint: /affected_below|version/i },
  { key: 'cvss', label: 'CVSS', hint: /cvss/i },
]

function Highlighted(props: { text: string; spans: [number, number][] }) {
  const parts: { s: string; flagged: boolean }[] = []
  let at = 0
  for (const [a, b] of [...props.spans].sort((x, y) => x[0] - y[0])) {
    if (a > at) parts.push({ s: props.text.slice(at, a), flagged: false })
    parts.push({ s: props.text.slice(Math.max(a, at), b), flagged: true })
    at = Math.max(at, b)
  }
  if (at < props.text.length) parts.push({ s: props.text.slice(at), flagged: false })
  return (
    <p className="whitespace-pre-wrap break-words text-[13px] leading-relaxed text-ink-2">
      {parts.map((p, i) =>
        p.flagged ? (
          <mark
            key={i}
            className="animate-fade rounded-sm bg-danger-soft px-0.5 text-danger underline decoration-danger decoration-wavy decoration-1 underline-offset-4"
            title="Flagged: instruction-like text. It stays in quarantine."
          >
            {p.s}
          </mark>
        ) : (
          <span key={i}>{p.s}</span>
        ),
      )}
    </p>
  )
}

export default function JudgeScreen() {
  const { presets, health } = useStore()
  const [text, setText] = useState('')
  const [editing, setEditing] = useState(true)
  const [result, setResult] = useState<QuarantinePreview | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const audit = useAudit()
  const { load } = audit

  useEffect(() => {
    load()
    // load once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const run = async (value = text) => {
    if (!value.trim()) return
    setBusy(true)
    setError(null)
    try {
      setResult(await api.quarantinePreview(value))
      setEditing(false)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const fieldIssues = (key: keyof Advisory) =>
    (result?.discrepancies ?? []).filter((d) => FIELDS.find((f) => f.key === key)!.hint.test(d))

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Judge mode"
        title="Try to Break It"
        subtitle="Paste any advisory, including one written to hijack the agents. Whatever you paste, the right-hand side is all the planning agents can ever see."
      />

      <Card i={1} className="p-4">
        <p className="mb-2 text-[12px] font-medium text-ink-2">Start from a curated advisory</p>
        <div className="flex flex-wrap gap-1.5">
          {(presets.data ?? []).map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => {
                setText(p.text)
                run(p.text)
              }}
              className={cx(
                'flex cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12px] font-medium transition-colors',
                text === p.text ? 'border-forest-700 bg-forest-50 text-forest-900' : 'border-line text-ink-2 hover:bg-surface-muted',
              )}
            >
              <span className={cx('size-1.5 rounded-full', p.kind === 'normal' ? 'bg-ok' : p.kind === 'poisoned' ? 'bg-danger' : 'bg-warn')} />
              {p.title}
            </button>
          ))}
          {!presets.data && <Skeleton className="h-8 w-full" />}
        </div>
      </Card>

      <div className="grid items-stretch gap-4 xl:grid-cols-[minmax(0,1fr)_64px_minmax(0,1fr)]">
        <Card i={2} className="flex flex-col">
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <FileText className="size-4 text-muted" /> What you pasted
              </span>
            }
            sub="Raw text stays in quarantine: hashed, scanned, never forwarded"
            right={
              !editing && (
                <Button variant="ghost" icon={Pencil} onClick={() => setEditing(true)}>
                  Edit
                </Button>
              )
            }
          />
          <div className="hatch m-4 flex flex-1 flex-col rounded-lg border border-line p-3">
            {editing ? (
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Paste a vulnerability advisory, or a prompt injection disguised as one…"
                aria-label="Advisory text"
                className="min-h-[260px] flex-1 resize-none rounded-md border border-line bg-surface/90 p-3 font-mono text-[12.5px] leading-relaxed text-ink outline-none focus:border-forest-700"
              />
            ) : (
              <div className="scroll-thin max-h-[340px] min-h-[260px] overflow-y-auto rounded-md bg-surface/90 p-3">
                <Highlighted text={text} spans={result?.flagged_spans ?? []} />
              </div>
            )}
            <div className="mt-3 flex items-center justify-between gap-3">
              <span className="text-[11.5px] text-muted">
                {result ? (
                  <span className="flex items-center gap-1.5">
                    <Fingerprint className="size-3.5" /> sha256 <span className="font-mono">{result.source_sha256.slice(0, 16)}…</span>
                    {result.flagged_spans.length > 0 && (
                      <Badge tone="danger" className="ml-1">
                        {result.flagged_spans.length} flagged
                      </Badge>
                    )}
                  </span>
                ) : (
                  `${text.length} characters`
                )}
              </span>
              <Button icon={ScanSearch} onClick={() => run()} disabled={busy || !text.trim()}>
                {busy ? 'Quarantining…' : 'Run quarantine'}
              </Button>
            </div>
          </div>
        </Card>

        <div className="hidden flex-col items-center justify-center gap-2 text-center xl:flex">
          <div className={cx('grid size-11 place-items-center rounded-full border border-line bg-surface', busy && 'animate-pulse')}>
            <ArrowRight className="size-5 text-forest-800" />
          </div>
          <p className="text-[10.5px] leading-tight text-muted">
            1 tool-less
            <br />
            LLM call
            <br />→ 6 typed
            <br />
            fields
          </p>
        </div>

        <Card i={3} className="flex flex-col">
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                <Lock className="size-4 text-forest-800" /> What the planner sees
              </span>
            }
            sub={`Typed fields only, cross-checked against the pinned feed${health.data?.data === 'live' ? ' and the city inventory' : ''}`}
          />
          <div className="flex-1 p-4">
            {error && <p className="text-[12.5px] text-danger">{error}</p>}
            {busy && <Skeleton className="h-[260px]" />}
            {!busy && !result && !error && (
              <Empty icon={FlaskConical} title="Nothing extracted yet" className="h-full">
                Pick a preset or paste text and run the quarantine.
              </Empty>
            )}
            {!busy && result && (
              <div key={result.source_sha256} className="animate-rise">
                {result.advisory ? (
                  <dl className="divide-y divide-line overflow-hidden rounded-lg border border-line">
                    {FIELDS.map((f, i) => {
                      const issues = fieldIssues(f.key)
                      const value = result.advisory![f.key]
                      return (
                        <div
                          key={f.key}
                          className={cx('grid animate-rise grid-cols-[130px_1fr_22px] items-start gap-3 px-3 py-2.5', issues.length > 0 && 'bg-danger-soft/60')}
                          style={{ animationDelay: `${i * 70}ms` }}
                        >
                          <dt className="text-[12px] text-muted">{f.label}</dt>
                          <dd className="min-w-0">
                            <span className="font-mono text-[13px] font-semibold text-ink">{typeof value === 'number' ? value.toFixed(1) : value}</span>
                            {issues.map((d) => (
                              <span key={d} className="mt-0.5 block text-[11.5px] text-danger">
                                {d}
                              </span>
                            ))}
                          </dd>
                          {issues.length ? <X className="size-4 text-danger" aria-label="Disagrees" /> : <Check className="size-4 text-ok" aria-label="Consistent" />}
                        </div>
                      )
                    })}
                  </dl>
                ) : (
                  <div className="rounded-lg border border-danger/20 bg-danger-soft p-4 text-[13px] text-danger">
                    <p className="font-semibold">Nothing passed quarantine</p>
                    <p className="mt-1 text-ink-2">{result.error}</p>
                  </div>
                )}
                {result.advisory && (
                  <div
                    className={cx(
                      'mt-3 flex items-start gap-2 rounded-lg px-3 py-2.5 text-[12.5px]',
                      result.discrepancies.length ? 'bg-warn-soft text-[#8a6212]' : 'bg-ok-soft text-ok',
                    )}
                  >
                    {result.discrepancies.length ? <X className="mt-0.5 size-4 shrink-0" /> : <Check className="mt-0.5 size-4 shrink-0" />}
                    {result.discrepancies.length
                      ? `${result.discrepancies.length} field${result.discrepancies.length > 1 ? 's' : ''} disagree with the pinned sources: the Sentinel stops and asks a human before anything is planned.`
                      : result.flagged_spans.length
                        ? 'The injected instructions were flagged and dropped; the typed fields are still the true ones.'
                        : 'Consistent with the pinned feed and the inventory.'}
                  </div>
                )}
              </div>
            )}
          </div>
        </Card>
      </div>

      <Card i={4} className="pb-5">
        <CardHeader
          title="Tamper-evident audit log"
          sub="Every agent event is SHA-256 hash-chained and Ed25519-signed before it is shown. Edit one stored event, then verify."
        />
        <div className="px-5 pt-4">
          <AuditChain audit={audit} allowTamper />
          <p className="mt-2 text-[11.5px] text-muted">
            Tampering really edits the server's SQLite log (demo servers only, ALLOW_DEMO_TAMPER=1), so the chain stays broken until the
            database is reset.
          </p>
        </div>
      </Card>
    </div>
  )
}
