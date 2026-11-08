import { Fragment, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Download, ExternalLink, RefreshCw, ShieldAlert } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''
const headers = () => ({ Authorization: `Bearer ${token()}` })

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch('/api/v1/container-images' + path, { headers: headers() })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'

interface ImageRow {
  id: string
  asset_id: string
  hostname: string | null
  image_ref: string
  distro: string | null
  containers: string[]
  package_count: number
  vuln_counts: Record<Severity, number>
  fixable: number
  sbom_at: string | null
  osv_at: string | null
}

interface Vuln {
  vuln_id: string
  osv_id: string | null
  pkg_name: string
  pkg_version: string
  ecosystem: string | null
  severity: Severity
  cvss: number | null
  fixed_version: string | null
  summary: string | null
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const SEV_BADGE: Record<Severity, string> = {
  CRITICAL: 'bg-red-900/70 text-red-200 border-red-700',
  HIGH:     'bg-orange-900/60 text-orange-200 border-orange-700',
  MEDIUM:   'bg-yellow-900/60 text-yellow-200 border-yellow-700',
  LOW:      'bg-gray-800 text-gray-300 border-gray-600',
  UNKNOWN:  'bg-gray-900 text-gray-500 border-gray-700',
}
const SEV_LABEL: Record<Severity, string> = {
  CRITICAL: 'kritisch', HIGH: 'hoch', MEDIUM: 'mittel', LOW: 'niedrig', UNKNOWN: 'unbewertet',
}

function Badge({ severity, children }: { severity: Severity; children: React.ReactNode }) {
  return <span className={`text-xs px-2 py-0.5 rounded border whitespace-nowrap ${SEV_BADGE[severity]}`}>{children}</span>
}

async function downloadBom(image: ImageRow) {
  const res = await fetch(`/api/v1/container-images/${image.id}/cyclonedx`, { headers: headers() })
  if (!res.ok) return
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `sbom-${image.image_ref.replace(/[^\w.-]+/g, '_')}.cdx.json`
  a.click()
  URL.revokeObjectURL(url)
}

function ImageDetail({ image }: { image: ImageRow }) {
  const [onlyFixable, setOnlyFixable] = useState(false)
  const { data: vulns = [], isLoading } = useQuery<Vuln[]>({
    queryKey: ['container-vulns', image.id, image.osv_at],
    queryFn: () => apiFetch(`/${image.id}/vulns`),
  })
  const shown = onlyFixable ? vulns.filter(v => v.fixed_version) : vulns

  return (
    <div className="px-4 py-3 bg-gray-950/50">
      <div className="flex items-center gap-4 mb-3 text-sm">
        <button onClick={() => downloadBom(image)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded text-gray-200">
          <Download size={14} /> SBOM (CycloneDX)
        </button>
        <label className="flex items-center gap-2 text-gray-400 cursor-pointer">
          <input type="checkbox" checked={onlyFixable} onChange={e => setOnlyFixable(e.target.checked)} />
          nur mit verfügbarem Fix
        </label>
        <span className="text-gray-600 text-xs ml-auto">
          OSV-Abgleich: {image.osv_at ? new Date(image.osv_at + 'Z').toLocaleString('de-DE') : 'läuft noch'}
        </span>
      </div>
      {isLoading ? <p className="text-gray-500 text-sm">Lädt…</p>
        : shown.length === 0 ? <p className="text-gray-500 text-sm">Keine Schwachstellen gefunden.</p>
        : (
          <table className="w-full text-xs">
            <thead className="text-gray-500 text-left">
              <tr>
                <th className="py-1 pr-3">Schweregrad</th>
                <th className="py-1 pr-3">ID</th>
                <th className="py-1 pr-3">Paket</th>
                <th className="py-1 pr-3">Version</th>
                <th className="py-1 pr-3">Fix</th>
                <th className="py-1">Beschreibung</th>
              </tr>
            </thead>
            <tbody>
              {shown.map(v => (
                <tr key={`${v.vuln_id}-${v.pkg_name}`} className="border-t border-gray-800/70 align-top">
                  <td className="py-1.5 pr-3">
                    <Badge severity={v.severity}>{SEV_LABEL[v.severity]}{v.cvss ? ` ${v.cvss.toFixed(1)}` : ''}</Badge>
                  </td>
                  <td className="py-1.5 pr-3 font-mono whitespace-nowrap">
                    <a href={`https://osv.dev/vulnerability/${v.osv_id || v.vuln_id}`} target="_blank" rel="noreferrer"
                      className="text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-1">
                      {v.vuln_id} <ExternalLink size={10} />
                    </a>
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-gray-300">{v.pkg_name}</td>
                  <td className="py-1.5 pr-3 font-mono text-gray-500">{v.pkg_version}</td>
                  <td className="py-1.5 pr-3 font-mono">
                    {v.fixed_version ? <span className="text-green-400">{v.fixed_version}</span> : <span className="text-gray-700">—</span>}
                  </td>
                  <td className="py-1.5 text-gray-400">{v.summary?.slice(0, 160) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
    </div>
  )
}

export default function ContainerImages({ filter }: { filter: string }) {
  const [open, setOpen] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const { data: images = [], isLoading } = useQuery<ImageRow[]>({
    queryKey: ['container-images'],
    queryFn: () => apiFetch(''),
  })

  async function rescan() {
    await fetch('/api/v1/container-images/scan', { method: 'POST', headers: headers() })
    setTimeout(() => queryClient.invalidateQueries({ queryKey: ['container-images'] }), 5000)
  }

  const f = filter.trim().toLowerCase()
  const shown = f
    ? images.filter(i => [i.hostname, i.image_ref, i.distro, ...i.containers].some(v => v?.toLowerCase().includes(f)))
    : images

  return (
    <section className="mb-8">
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert size={18} className="text-cyan-400" />
        <h2 className="text-base font-semibold text-gray-100">Images: SBOM &amp; Schwachstellen</h2>
        <button onClick={rescan} title="Alle Images neu gegen OSV abgleichen"
          className="ml-auto flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200">
          <RefreshCw size={12} /> neu abgleichen
        </button>
      </div>
      {isLoading ? <p className="text-gray-500 text-sm">Lädt…</p>
        : shown.length === 0 ? <p className="text-gray-500 text-sm">Noch keine Images gemeldet.</p>
        : (
          <div className="border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-800/50 text-gray-400 text-left">
                <tr>
                  <th className="px-4 py-2">Image</th>
                  <th className="px-4 py-2">Host</th>
                  <th className="px-4 py-2 text-right">Pakete</th>
                  <th className="px-4 py-2">Schwachstellen</th>
                  <th className="px-4 py-2 text-right">mit Fix</th>
                </tr>
              </thead>
              <tbody>
                {shown.map(i => {
                  const isOpen = open === i.id
                  const total = SEVERITIES.reduce((sum, s) => sum + i.vuln_counts[s], 0)
                  return (
                    <Fragment key={i.id}>
                      <tr onClick={() => setOpen(isOpen ? null : i.id)}
                        className="border-t border-gray-800 hover:bg-gray-800/40 cursor-pointer">
                        <td className="px-4 py-2">
                          <div className="flex items-start gap-1.5">
                            {isOpen ? <ChevronDown size={14} className="mt-1 text-gray-500" /> : <ChevronRight size={14} className="mt-1 text-gray-500" />}
                            <div>
                              <div className="font-mono text-xs text-gray-200">{i.image_ref}</div>
                              <div className="text-xs text-gray-500">{[i.containers.join(', '), i.distro].filter(Boolean).join(' · ')}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-2 text-gray-400">{i.hostname || '—'}</td>
                        <td className="px-4 py-2 text-right text-gray-300">{i.package_count}</td>
                        <td className="px-4 py-2">
                          <div className="flex flex-wrap gap-1">
                            {!i.osv_at ? <span className="text-xs text-gray-500">Abgleich läuft…</span>
                              : total === 0 ? <span className="text-xs text-green-400">keine</span>
                              : SEVERITIES.filter(s => i.vuln_counts[s] > 0).map(s => (
                                <Badge key={s} severity={s}>{i.vuln_counts[s]} {SEV_LABEL[s]}</Badge>
                              ))}
                          </div>
                        </td>
                        <td className="px-4 py-2 text-right text-gray-300">{i.fixable}</td>
                      </tr>
                      {isOpen && <tr className="border-t border-gray-800"><td colSpan={5} className="p-0"><ImageDetail image={i} /></td></tr>}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
    </section>
  )
}
