import { Clock } from 'lucide-react'

function timeAgo(dateStr: string | null | undefined): { label: string; stale: boolean } {
  if (!dateStr) return { label: 'Nie', stale: true }

  const diff = Date.now() - new Date(dateStr).getTime()
  const mins  = Math.floor(diff / 60_000)
  const hours = Math.floor(diff / 3_600_000)
  const days  = Math.floor(diff / 86_400_000)

  let label: string
  if (mins < 2)        label = 'gerade eben'
  else if (mins < 60)  label = `vor ${mins} Min.`
  else if (hours < 24) label = `vor ${hours} Std.`
  else if (days < 7)   label = `vor ${days} Tag${days > 1 ? 'en' : ''}`
  else                 label = new Date(dateStr).toLocaleDateString('de')

  return { label, stale: hours >= 24 }
}

interface Props {
  date: string | null | undefined
  className?: string
  showIcon?: boolean
}

export default function LastSeen({ date, className = '', showIcon = true }: Props) {
  const { label, stale } = timeAgo(date)
  return (
    <span className={`flex items-center gap-1 text-xs ${stale ? 'text-red-400' : 'text-gray-500'} ${className}`}
      title={date ? new Date(date).toLocaleString('de') : 'Unbekannt'}>
      {showIcon && <Clock size={11} />}
      {label}
    </span>
  )
}
