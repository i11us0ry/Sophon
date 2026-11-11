export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const exponent = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)))
  const scaled = value / 1024 ** exponent
  return `${scaled.toFixed(scaled >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

export function formatClock(value: string | Date | null | undefined): string {
  if (!value) {
    return '--:--:--'
  }
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return '--:--:--'
  }
  return date.toLocaleTimeString('en-GB', { hour12: false })
}

export function formatDuration(startedAt: string, finishedAt?: string | null): string {
  if (!finishedAt) {
    return '--'
  }
  const start = new Date(startedAt).getTime()
  const end = new Date(finishedAt).getTime()
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return '--'
  }
  const ms = end - start
  if (ms < 1000) {
    return `${ms}ms`
  }
  return `${(ms / 1000).toFixed(1)}s`
}

export function formatRelative(value: string | Date | null | undefined): string {
  if (!value) {
    return '-'
  }
  const date = value instanceof Date ? value : new Date(value)
  const diff = Date.now() - date.getTime()
  if (Number.isNaN(diff)) {
    return '-'
  }
  if (diff < 60000) {
    return `${Math.max(0, Math.round(diff / 1000))}s`
  }
  if (diff < 3600000) {
    return `${Math.round(diff / 60000)}m`
  }
  if (diff < 86400000) {
    return `${Math.round(diff / 3600000)}h`
  }
  return `${Math.round(diff / 86400000)}d`
}
