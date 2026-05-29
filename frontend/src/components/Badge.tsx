const styles: Record<string, string> = {
  HIGH:    'bg-red-900 text-red-300 border border-red-700',
  MEDIUM:  'bg-yellow-900 text-yellow-300 border border-yellow-700',
  LOW:     'bg-green-900 text-green-300 border border-green-700',
  EXTERN:  'bg-red-900 text-red-300 border border-red-700',
  DMZ:     'bg-yellow-900 text-yellow-300 border border-yellow-700',
  INTERN:  'bg-blue-900 text-blue-300 border border-blue-700',
  CRITICAL:'bg-red-900 text-red-300 border border-red-700',
  default: 'bg-gray-800 text-gray-300 border border-gray-700',
}

export default function Badge({ value }: { value: string }) {
  const cls = styles[value?.toUpperCase()] ?? styles.default
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cls}`}>{value}</span>
}
