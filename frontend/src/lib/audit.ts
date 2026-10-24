// Audit log state shared by Judge Mode and the Audit Log screen: entries, verify and the demo tamper.
import { useState } from 'react'
import { api, ApiError } from '../api'
import type { AuditEntry, VerifyResult } from '../types'

export function useAudit() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [verify, setVerify] = useState<VerifyResult | null>(null)
  const [busy, setBusy] = useState<'load' | 'verify' | 'tamper' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tampered, setTampered] = useState<number | null>(null)

  const load = async () => {
    setBusy('load')
    setError(null)
    try {
      setEntries(await api.auditEntries())
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(null)
    }
  }
  const runVerify = async () => {
    setBusy('verify')
    setError(null)
    try {
      const [v, list] = await Promise.all([api.verifyAudit(), api.auditEntries()])
      setEntries(list)
      setVerify(v)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(null)
    }
  }
  const tamper = async (seq: number) => {
    setBusy('tamper')
    setError(null)
    try {
      await api.tamper(seq)
      setTampered(seq)
      setVerify(null)
    } catch (e) {
      setError(
        e instanceof ApiError && (e.status === 404 || e.status === 405)
          ? 'Tampering is disabled on this server. Start the API with ALLOW_DEMO_TAMPER=1 to try it.'
          : (e as Error).message,
      )
    } finally {
      setBusy(null)
    }
  }
  return { entries, verify, busy, error, tampered, load, runVerify, tamper }
}

export type Audit = ReturnType<typeof useAudit>
