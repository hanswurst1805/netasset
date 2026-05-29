import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import Badge from '../components/Badge'
import { ArrowLeft, Package, Network } from 'lucide-react'

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: asset, isLoading } = useQuery({
    queryKey: ['asset', id],
    queryFn: () => api.assets.get(id!),
    enabled: !!id,
  })

  const { data: sbom = [] } = useQuery({
    queryKey: ['sbom', id],
    queryFn: () => api.sbom.get(id!),
    enabled: !!id,
  })

  if (isLoading) return <div className="text-gray-500 p-4">Laden…</div>
  if (!asset) return <div className="text-red-400 p-4">Asset nicht gefunden</div>

  return (
    <div className="max-w-4xl">
      <button
        onClick={() => navigate('/assets')}
        className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 mb-5 transition-colors"
      >
        <ArrowLeft size={14} /> Zurück
      </button>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">{asset.hostname ?? asset.ip_address}</h1>
          <p className="text-gray-500 text-sm mt-1">{asset.fqdn ?? asset.ip_address}</p>
        </div>
        <Badge value={asset.exposure_level} />
      </div>

      {/* Info Grid */}
      <div className="grid grid-cols-2 gap-3 mb-6">
        {[
          ['Typ', asset.asset_type],
          ['OS', `${asset.os_name ?? '—'} ${asset.os_version ?? ''}`],
          ['IP', asset.ip_address ?? '—'],
          ['MAC', asset.mac_address ?? '—'],
        ].map(([label, value]) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-xs text-gray-500 mb-1">{label}</div>
            <div className="text-sm font-medium">{value}</div>
          </div>
        ))}
      </div>

      {/* Tags */}
      {asset.tags && asset.tags.length > 0 && (
        <div className="flex gap-2 mb-6 flex-wrap">
          {asset.tags.map(tag => (
            <span key={tag} className="text-xs bg-gray-800 text-gray-400 px-2 py-1 rounded">{tag}</span>
          ))}
        </div>
      )}

      {/* Open Ports */}
      {asset.open_ports && asset.open_ports.length > 0 && (
        <section className="mb-6">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Network size={14} /> Offene Ports
          </h2>
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                  <th className="text-left px-4 py-2">Port</th>
                  <th className="text-left px-4 py-2">Protokoll</th>
                  <th className="text-left px-4 py-2">Erreichbar von</th>
                </tr>
              </thead>
              <tbody>
                {asset.open_ports.map(p => (
                  <tr key={p.port} className="border-b border-gray-800">
                    <td className="px-4 py-2 font-mono text-indigo-400">{p.port}</td>
                    <td className="px-4 py-2 text-gray-400">{p.proto}</td>
                    <td className="px-4 py-2">
                      {p.reachable_from.map(r => (
                        <span key={r} className={`text-xs mr-1 px-2 py-0.5 rounded ${
                          r === 'internet' ? 'bg-red-900 text-red-300' : 'bg-gray-800 text-gray-400'
                        }`}>{r}</span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* SBOM */}
      <section>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Package size={14} /> SBOM ({sbom.length} Pakete)
        </h2>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                <th className="text-left px-4 py-2">Paket</th>
                <th className="text-left px-4 py-2">Version</th>
                <th className="text-left px-4 py-2">Typ</th>
                <th className="text-left px-4 py-2">Quelle</th>
              </tr>
            </thead>
            <tbody>
              {sbom.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-600">Kein SBOM vorhanden</td></tr>
              )}
              {sbom.map(e => (
                <tr key={e.id} className="border-b border-gray-800">
                  <td className="px-4 py-2 font-medium">{e.pkg_name}</td>
                  <td className="px-4 py-2 font-mono text-gray-400">{e.pkg_version}</td>
                  <td className="px-4 py-2 text-gray-500">{e.pkg_type ?? '—'}</td>
                  <td className="px-4 py-2 text-gray-500">{e.source ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
