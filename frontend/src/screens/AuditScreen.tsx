// Audit Log: the signed hash chain behind every event, verifiable by anyone with the public key.
import { Copy, FileLock2, Hash, KeyRound, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, useLoad } from '../api'
import AuditChain from '../components/AuditChain'
import { useAudit } from '../lib/audit'
import { Badge, Card, CardHeader, Empty, ErrorState, Kpi, PageHeader, Skeleton } from '../components/ui'
import { int } from '../lib/format'
import { useStore } from '../lib/store'

export default function AuditScreen() {
  const { health } = useStore()
  const audit = useAudit()
  const key = useLoad(() => api.auditKey())
  const [copied, setCopied] = useState(false)
  const { runVerify } = audit

  useEffect(() => {
    runVerify()
    // verify once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const entries = audit.entries ?? []
  const latest = [...entries].reverse().slice(0, 200)
  const runs = new Set(entries.map((e) => e.event_id.split(':')[0]))

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Audit log"
        title="Nothing Happens Off the Record"
        subtitle="Each agent event is appended here before the dashboard shows it: SHA-256 chained to the previous entry and signed with Ed25519. If the log cannot be written, the run stops."
      />

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Kpi i={1} icon={FileLock2} label="Entries" value={audit.entries ? int(entries.length) : <Skeleton className="h-8 w-14" />} foot={`${runs.size} runs recorded`} />
        <Kpi i={2} icon={Hash} tone="info" label="Chain head" value={audit.verify?.head_seq != null ? `#${audit.verify.head_seq}` : '–'} foot={audit.verify?.head_hash ? `${audit.verify.head_hash.slice(0, 16)}…` : 'Empty log'} />
        <Kpi
          i={3}
          icon={ShieldCheck}
          tone={audit.verify ? (audit.verify.ok ? 'ok' : 'danger') : 'neutral'}
          label="Last verification"
          value={audit.verify ? (audit.verify.ok ? 'Intact' : 'Broken') : audit.busy === 'verify' ? '…' : '–'}
          foot={audit.verify && !audit.verify.ok ? `First bad entry #${audit.verify.first_bad_seq ?? '?'}` : 'Hashes, signatures, truncation'}
        />
        <Kpi
          i={4}
          icon={KeyRound}
          tone={health.data?.audit_key === 'fixed' ? 'forest' : 'warn'}
          label="Signing key"
          value={health.data?.audit_key === 'fixed' ? 'Fixed' : health.data ? 'Ephemeral' : '–'}
          foot={health.data?.audit_key === 'fixed' ? 'Verifies across restarts' : 'Set AUDIT_SIGNING_KEY to persist'}
        />
      </div>

      <Card i={5} className="pb-5">
        <CardHeader title="Chain" sub="Latest entries. Hover a block for its full hash and the previous hash it commits to." />
        <div className="px-5 pt-4">
          <AuditChain audit={audit} window={30} />
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card i={6} className="pb-2">
          <CardHeader title="Entries" sub={`Newest first${entries.length > 200 ? ' · latest 200 shown' : ''}`} />
          {audit.error && <ErrorState error={new Error(audit.error)} className="mx-5 mt-3" />}
          {audit.entries && !entries.length ? (
            <Empty icon={FileLock2} title="No entries yet">Run an incident on Response & Mitigation; every event lands here.</Empty>
          ) : (
            <div className="scroll-thin mt-3 max-h-[520px] overflow-auto px-3">
              <table className="w-full min-w-[720px] text-[12px]">
                <thead className="sticky top-0 bg-surface">
                  <tr className="border-b border-line text-left text-[11px] text-muted">
                    <th className="px-2 py-2 font-medium">Seq</th>
                    <th className="px-2 py-2 font-medium">Event</th>
                    <th className="px-2 py-2 font-medium">Payload SHA-256</th>
                    <th className="px-2 py-2 font-medium">Prev → hash</th>
                    <th className="px-2 py-2 font-medium">Signature</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {!audit.entries && (
                    <tr>
                      <td colSpan={5} className="p-2">
                        <Skeleton className="h-60" />
                      </td>
                    </tr>
                  )}
                  {latest.map((e) => {
                    const bad = audit.verify && !audit.verify.ok && audit.verify.first_bad_seq === e.seq
                    return (
                      <tr key={e.seq} className={bad ? 'bg-danger-soft' : 'border-b border-line/60 hover:bg-surface-muted'}>
                        <td className="num px-2 py-1.5 font-sans font-semibold text-ink">#{e.seq}</td>
                        <td className="px-2 py-1.5 text-ink-2">{e.event_id}</td>
                        <td className="px-2 py-1.5 text-muted">{e.payload_sha256.slice(0, 12)}…</td>
                        <td className="px-2 py-1.5 text-muted">
                          {e.prev_hash.slice(0, 6)} → <span className="text-ink">{e.hash.slice(0, 8)}</span>
                        </td>
                        <td className="px-2 py-1.5 text-muted">{e.signature.slice(0, 12)}…</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card i={7} className="pb-5">
          <CardHeader title="Verify it yourself" sub="The public key is all an outside auditor needs" />
          <div className="space-y-3 px-5 pt-4 text-[12.5px] text-ink-2">
            {key.error ? (
              <ErrorState error={key.error} />
            ) : (
              <div className="rounded-lg border border-line bg-surface-muted p-3">
                <p className="mb-1 flex items-center justify-between text-[11px] font-semibold uppercase tracking-[0.12em] text-muted">
                  Ed25519 public key
                  <button
                    type="button"
                    onClick={() => {
                      if (!key.data) return
                      navigator.clipboard?.writeText(key.data.verify_key_hex).then(() => {
                        setCopied(true)
                        window.setTimeout(() => setCopied(false), 1500)
                      })
                    }}
                    className="flex cursor-pointer items-center gap-1 normal-case tracking-normal text-forest-800"
                  >
                    <Copy className="size-3.5" /> {copied ? 'Copied' : 'Copy'}
                  </button>
                </p>
                <p className="break-all font-mono text-[11.5px] text-ink">{key.data?.verify_key_hex ?? '…'}</p>
              </div>
            )}
            <ol className="list-decimal space-y-1.5 pl-4">
              <li>Each entry stores the SHA-256 of the canonical event JSON.</li>
              <li>
                <span className="font-mono text-[11.5px]">hash = SHA-256(prev_hash ‖ payload_sha256 ‖ seq)</span> links it to the entry before.
              </li>
              <li>
                The hash is signed. An edited event no longer matches its payload hash; recomputing the hash breaks the signature and
                the next link.
              </li>
              <li>The server also remembers the highest head it published, so cutting entries off the end is caught too.</li>
            </ol>
            <Badge tone={health.data?.audit === 'ok' ? 'ok' : 'danger'}>Audit {health.data?.audit ?? '…'}</Badge>
          </div>
        </Card>
      </div>
    </div>
  )
}
