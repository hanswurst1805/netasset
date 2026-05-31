import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CreditCard, Download, Eye } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function fetchTemplates() {
  const res = await fetch('/api/v1/cards/templates', {
    headers: { Authorization: `Bearer ${token()}` },
  })
  if (!res.ok) throw new Error('Fehler')
  return res.json()
}

async function exportCards(templateId: string, format: string, filter: Record<string, string>) {
  const params = new URLSearchParams({ ...filter })
  const res = await fetch(`/api/v1/cards/export?${params}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ template_id: templateId, format }),
  })
  if (!res.ok) throw new Error(await res.text())
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `netasset_cards_${templateId}.zip`
  a.click()
  URL.revokeObjectURL(url)
}

const SECTION_LABELS: Record<string, string> = {
  header: 'Basis-Infos',
  network: 'Netzwerk',
  ports: 'Ports',
  software: 'SBOM',
  cve: 'CVE-Risiken',
  business: 'Business-Kontext',
  lynis: 'Lynis-Audit',
  meta: 'Metadaten',
}

const FORMAT_INFO: Record<string, { label: string; desc: string }> = {
  markdown: { label: 'Markdown', desc: 'Strukturierter Text, ideal für RAG-Embeddings' },
  json: { label: 'JSON + JSONL', desc: 'Strukturierte Daten + JSON-Lines für LLM-Training' },
  text: { label: 'Plaintext', desc: 'Reiner Text ohne Formatierung' },
}

export default function CardExport() {
  const [selectedTemplate, setSelectedTemplate] = useState('full')
  const [format, setFormat] = useState('markdown')
  const [exporting, setExporting] = useState(false)
  const [filter, setFilter] = useState({ asset_type: '', exposure_level: '', tag: '' })

  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: fetchTemplates })

  async function handleExport() {
    setExporting(true)
    try {
      const f: Record<string, string> = {}
      if (filter.asset_type) f.asset_type = filter.asset_type
      if (filter.exposure_level) f.exposure_level = filter.exposure_level
      if (filter.tag) f.tag = filter.tag
      await exportCards(selectedTemplate, format, f)
    } catch (e: any) {
      alert(`Fehler: ${e.message}`)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <CreditCard size={22} /> Karteikarten / RAG-Export
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Exportiere Asset-Daten als strukturierte Dokumente für RAG und LLM-Training
        </p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Konfiguration */}
        <div className="space-y-5">

          {/* Template auswählen */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <h2 className="text-sm font-semibold mb-3">Template</h2>
            <div className="space-y-2">
              {templates.map((t: any) => (
                <label key={t.id}
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    selectedTemplate === t.id
                      ? 'border-indigo-500 bg-indigo-950/30'
                      : 'border-gray-700 hover:border-gray-600'
                  }`}
                >
                  <input type="radio" name="template" value={t.id}
                    checked={selectedTemplate === t.id}
                    onChange={() => setSelectedTemplate(t.id)}
                    className="mt-0.5 accent-indigo-500" />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium">{t.name}</div>
                    <div className="text-xs text-gray-500 mt-0.5">{t.description}</div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {t.sections.map((s: string) => (
                        <span key={s} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">
                          {SECTION_LABELS[s] || s}
                        </span>
                      ))}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Format */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <h2 className="text-sm font-semibold mb-3">Ausgabe-Format</h2>
            <div className="space-y-2">
              {Object.entries(FORMAT_INFO).map(([key, info]) => (
                <label key={key}
                  className={`flex items-center gap-3 p-2.5 rounded-lg border cursor-pointer ${
                    format === key ? 'border-indigo-500 bg-indigo-950/30' : 'border-gray-700'
                  }`}
                >
                  <input type="radio" name="format" value={key}
                    checked={format === key} onChange={() => setFormat(key)}
                    className="accent-indigo-500" />
                  <div>
                    <div className="text-sm font-medium">{info.label}</div>
                    <div className="text-xs text-gray-500">{info.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Filter */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <h2 className="text-sm font-semibold mb-3">Filter (optional)</h2>
            <div className="space-y-2">
              <div>
                <label className="block text-xs text-gray-500 mb-1">Asset-Typ</label>
                <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={filter.asset_type} onChange={e => setFilter({ ...filter, asset_type: e.target.value })}>
                  <option value="">Alle Typen</option>
                  {['server','client','router','firewall','switch','printer'].map(t => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1">Exposure</label>
                <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={filter.exposure_level} onChange={e => setFilter({ ...filter, exposure_level: e.target.value })}>
                  <option value="">Alle</option>
                  <option value="INTERN">INTERN</option>
                  <option value="DMZ">DMZ</option>
                  <option value="EXTERN">EXTERN</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1">Tag</label>
                <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
                  placeholder="z.B. production, mikrotik"
                  value={filter.tag} onChange={e => setFilter({ ...filter, tag: e.target.value })} />
              </div>
            </div>
          </div>

          {/* Export-Button */}
          <button
            onClick={handleExport}
            disabled={exporting}
            className="w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white py-3 rounded-xl text-sm font-medium"
          >
            <Download size={16} />
            {exporting ? 'Exportiere...' : 'Als ZIP exportieren'}
          </button>

          <p className="text-xs text-gray-600 text-center">
            ZIP enthält eine Datei pro Asset + manifest.json + cards.jsonl
          </p>
        </div>

        {/* Vorschau */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Vorschau</h2>
            <span className="text-xs text-gray-600">Klick auf ein Asset → Tab „Karteikarte"</span>
          </div>
          {false ? null : (
            <div className="flex flex-col items-center justify-center h-48 text-gray-600 text-sm">
              <Eye size={24} className="mb-2 opacity-30" />
              <p>Öffne ein Asset und wähle</p>
              <p>den Tab „Karteikarte" für eine Vorschau</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
