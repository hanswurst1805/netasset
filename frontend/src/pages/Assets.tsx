import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import Badge from '../components/Badge'
import { Search } from 'lucide-react'

const TYPES = ['', 'server', 'switch', 'router', 'firewall', 'client']
const EXPOSURES = ['', 'INTERN', 'DMZ', 'EXTERN']

export default function Assets() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [expFilter, setExpFilter] = useState('')

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['assets', typeFilter, expFilter],
    queryFn: () => api.assets.list({
      ...(typeFilter && { asset_type: typeFilter }),
      ...(expFilter && { exposure_level: expFilter }),
    }),
  })

  const filtered = assets.filter(a =>
    !search || [a.hostname, a.ip_address, a.fqdn].some(v =>
      v?.toLowerCase().includes(search.toLowerCase())
    )
  )

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Assets</h1>

      {/* Filter Bar */}
      <div className="flex gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded-md pl-8 pr-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="Hostname, IP, FQDN..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
        >
          {TYPES.map(t => <option key={t} value={t}>{t || 'Alle Typen'}</option>)}
        </select>
        <select
          className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
          value={expFilter}
          onChange={e => setExpFilter(e.target.value)}
        >
          {EXPOSURES.map(e => <option key={e} value={e}>{e || 'Alle Exposures'}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase tracking-wider">
              <th className="text-left px-4 py-3">Hostname / IP</th>
              <th className="text-left px-4 py-3">Typ</th>
              <th className="text-left px-4 py-3">OS</th>
              <th className="text-left px-4 py-3">Exposure</th>
              <th className="text-left px-4 py-3">Tags</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Laden…</td></tr>
            )}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Keine Assets gefunden</td></tr>
            )}
            {filtered.map(asset => (
              <tr
                key={asset.id}
                onClick={() => navigate(`/assets/${asset.id}`)}
                className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-100">{asset.hostname ?? '—'}</div>
                  <div className="text-xs text-gray-500">{asset.ip_address}</div>
                </td>
                <td className="px-4 py-3 text-gray-400">{asset.asset_type}</td>
                <td className="px-4 py-3 text-gray-400">
                  {asset.os_name} {asset.os_version}
                </td>
                <td className="px-4 py-3">
                  <Badge value={asset.exposure_level} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {asset.tags?.slice(0, 3).map(tag => (
                      <span key={tag} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{tag}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 text-xs text-gray-600 border-t border-gray-800">
          {filtered.length} Assets
        </div>
      </div>
    </div>
  )
}
