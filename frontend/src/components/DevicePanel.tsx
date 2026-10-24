// A device as a spec sheet: firmware, CVEs, simulated risk and the control options the planner may buy.
import { Check, X } from 'lucide-react'
import { riskById } from '../lib/derive'
import { CATEGORY_LABEL, CONTROL_LABEL, hours, inr, share } from '../lib/format'
import { useStore } from '../lib/store'
import type { Device } from '../types'
import { ShapeGlyph } from './CityMap'
import { C } from '../lib/colors'
import { Badge, Metric } from './ui'

export default function DevicePanel(props: { device: Device; onClose?: () => void; className?: string }) {
  const { risk, plans } = useStore()
  const d = props.device
  const base = riskById(risk.data?.baseline).get(d.id)
  const prot = riskById(risk.data?.protected).get(d.id)
  const cvar = risk.data?.histograms.find((h) => h.label === 'none')?.cvar
  const ours = plans.data?.find((p) => p.objective === 'cvar')
  const chosen = ours?.choices[d.id]
  const riskSource = risk.data?.tool_call_id
    ? { toolCallId: risk.data.tool_call_id, label: `${d.name}: simulated tail loss` }
    : null

  return (
    <div className={props.className}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-[12px] font-medium text-muted">
            <ShapeGlyph category={d.category} color={C.forest100} size={12} />
            {CATEGORY_LABEL[d.category]} · {d.zone}
          </p>
          <h3 className="mt-1 truncate text-[17px] font-semibold text-ink">{d.name}</h3>
          <p className="font-mono text-[12px] text-ink-2">
            {d.id} · {d.firmware}
          </p>
        </div>
        {props.onClose && (
          <button
            type="button"
            aria-label="Close device"
            onClick={props.onClose}
            className="grid size-8 shrink-0 cursor-pointer place-items-center rounded-lg border border-line text-ink-2 hover:bg-forest-50"
          >
            <X className="size-4" />
          </button>
        )}
      </div>
      <div className="mt-2.5 flex flex-wrap gap-1.5">
        {d.exposed && <Badge tone="danger">Internet-exposed</Badge>}
        {d.tags.includes('gateway') && <Badge tone="high">Gateway</Badge>}
        {d.tags.includes('ambulance_corridor') && <Badge tone="info">Ambulance corridor</Badge>}
        {d.tags.includes('decorative') && <Badge>Decorative</Badge>}
        <Badge tone="neutral">Criticality {d.criticality.toFixed(2)}</Badge>
      </div>

      {base && cvar ? (
        <div className="mt-4 grid grid-cols-3 gap-2">
          {[
            ['Worst-case share', <Metric key="Worst-case share" source={riskSource}>{share(base.tail_loss / cvar, 1)}</Metric>],
            ['With UrbanShield', <Metric key="With UrbanShield" source={riskSource}>{share((prot?.tail_loss ?? 0) / cvar, 1)}</Metric>],
            ['P(compromised)', <Metric key="P(compromised)" source={riskSource}>{share(base.p_compromised, 1)}</Metric>],
          ].map(([k, v], i) => (
            <div key={i} className="rounded-lg border border-line bg-surface-muted px-2.5 py-2">
              <p className="text-[11px] text-muted">{k}</p>
              <p className="mt-0.5 text-[15px] font-semibold text-ink">{v}</p>
            </div>
          ))}
        </div>
      ) : null}

      <h4 className="mt-4 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-2">Vulnerabilities</h4>
      <table className="mt-1.5 w-full text-[12.5px]">
        <thead>
          <tr className="text-left text-[11px] text-muted">
            <th className="py-1 font-medium">CVE</th>
            <th className="py-1 text-right font-medium">CVSS</th>
            <th className="py-1 text-right font-medium">EPSS</th>
            <th className="py-1 text-right font-medium">KEV</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {d.vulns.map((v) => (
            <tr key={v.cve_id}>
              <td className="py-1.5 font-mono text-[12px] text-ink">{v.cve_id}</td>
              <td className="num py-1.5 text-right">{v.cvss.toFixed(1)}</td>
              <td className="num py-1.5 text-right">{v.epss.toFixed(2)}</td>
              <td className="py-1.5 text-right">{v.kev ? <Badge tone="danger">KEV</Badge> : <span className="text-muted">–</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4 className="mt-4 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-2">Control options</h4>
      <table className="mt-1.5 w-full text-[12.5px]">
        <thead>
          <tr className="text-left text-[11px] text-muted">
            <th className="py-1 font-medium">Control</th>
            <th className="py-1 text-right font-medium">Cost</th>
            <th className="py-1 text-right font-medium">Down</th>
            <th className="py-1 text-right font-medium">Policy</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {d.controls.map((c) => (
            <tr key={c.kind} className={chosen === c.kind ? 'bg-forest-50' : undefined}>
              <td className="py-1.5 text-ink">
                <span className="flex items-center gap-1.5">
                  {chosen === c.kind ? (
                    <Check className="size-3.5 text-forest-800" aria-label="Chosen by UrbanShield" />
                  ) : (
                    <span className="w-3.5" />
                  )}
                  {CONTROL_LABEL[c.kind]}
                </span>
              </td>
              <td className="num py-1.5 text-right">{inr(c.cost_inr)}</td>
              <td className="num py-1.5 text-right">{hours(c.downtime_h)}</td>
              <td className="py-1.5 text-right">
                <Badge tone={c.autonomy === 'auto' ? 'ok' : 'warn'}>{c.autonomy === 'auto' ? 'AUTO' : 'APPROVAL'}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-[11.5px] text-muted">
        {chosen ? (
          <>
            UrbanShield buys <span className="font-semibold text-forest-800">{CONTROL_LABEL[chosen]}</span> here.
          </>
        ) : (
          'UrbanShield leaves this device as it is: its budget does more elsewhere.'
        )}
      </p>
    </div>
  )
}
