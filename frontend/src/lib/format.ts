export function parseUTC(timestamp: string): Date {
  if (!timestamp) return new Date(0);
  // If the timestamp doesn't have a timezone indicator, treat it as UTC by appending 'Z'
  const withTZ = timestamp.endsWith('Z') || timestamp.includes('+') || timestamp.includes('-') && timestamp.indexOf('T') !== -1 && timestamp.lastIndexOf('-') > timestamp.indexOf('T') 
    ? timestamp 
    : `${timestamp}Z`;
  return new Date(withTZ);
}

export function formatTime(timestamp: string | null): string {
  if (!timestamp) return "N/A";
  const date = parseUTC(timestamp);
  // Always format strictly as UTC to avoid hydration mismatches
  return date.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) + ' UTC';
}

export function formatDateTime(timestamp: string | null): string {
  if (!timestamp) return "N/A";
  const date = parseUTC(timestamp);
  return date.toLocaleString('en-US', { 
    year: 'numeric', 
    month: '2-digit', 
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false, 
    timeZone: 'UTC' 
  }) + ' UTC';
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "N/A";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return m > 0 ? `${m}m ${s}s` : `${seconds.toFixed(1)}s`;
}

export function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}
