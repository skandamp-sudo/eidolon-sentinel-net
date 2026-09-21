/**
 * Formatting utilities for the SOC dashboard.
 * All data originates from backend — these only format for display.
 */

import type { Severity } from '@/api/types';

/**
 * Format a Unix epoch timestamp to a locale datetime string.
 */
export function formatTimestamp(epoch: number | undefined): string {
  if (!epoch || epoch <= 0) return '—';
  return new Date(epoch * 1000).toLocaleString();
}

/**
 * Format a Unix epoch timestamp to a short time string.
 */
export function formatTime(epoch: number): string {
  if (!epoch || epoch <= 0) return '—';
  return new Date(epoch * 1000).toLocaleTimeString();
}

/**
 * Format seconds duration as Xd Xh Xm Xs.
 */
export function formatDuration(seconds: number | undefined): string {
  if (seconds === undefined || seconds < 0 || !isFinite(seconds)) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);

  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

/**
 * Format byte counts as KB/MB/GB.
 */
export function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined || bytes < 0 || !isFinite(bytes)) return '—';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format a number with locale separators.
 */
export function formatNumber(n: number | undefined): string {
  if (n === undefined || !isFinite(n)) return '—';
  return n.toLocaleString();
}

/**
 * Convert IANA protocol number to name.
 */
export function protocolName(proto: number | undefined): string {
  switch (proto) {
    case 1: return 'ICMP';
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 58: return 'ICMPv6';
    default: return proto !== undefined ? `Proto ${proto}` : '—';
  }
}

/**
 * Return a severity icon character.
 * Used alongside text labels for accessibility (not color-only).
 */
export function severityIcon(severity: Severity | string | undefined): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🔵';
    case 'info': return '⚪';
    default: return '⚪';
  }
}

/**
 * Get CSS class for severity badge.
 */
export function severityClass(severity: Severity | string): string {
  return `badge badge--${severity}`;
}

/**
 * Format anomaly score as percentage string.
 */
export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined || !isFinite(score)) return '—';
  return `${(score * 100).toFixed(1)}%`;
}
