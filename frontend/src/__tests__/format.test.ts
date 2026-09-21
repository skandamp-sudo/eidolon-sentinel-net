/**
 * Tests for formatting utilities.
 */

import { describe, it, expect } from 'vitest';
import {
  formatTimestamp,
  formatDuration,
  formatBytes,
  formatNumber,
  protocolName,
  severityIcon,
  severityClass,
  formatScore,
} from '@/utils/format';

describe('formatTimestamp', () => {
  it('returns dash for zero', () => {
    expect(formatTimestamp(0)).toBe('—');
  });

  it('formats valid epoch', () => {
    const result = formatTimestamp(1725201234.567);
    expect(result).toBeTruthy();
    expect(result).not.toBe('—');
  });

  it('returns dash for negative', () => {
    expect(formatTimestamp(-1)).toBe('—');
  });
});

describe('formatDuration', () => {
  it('formats seconds', () => {
    expect(formatDuration(45)).toBe('45s');
  });

  it('formats minutes and seconds', () => {
    expect(formatDuration(125)).toBe('2m 5s');
  });

  it('formats hours', () => {
    expect(formatDuration(3661)).toBe('1h 1m 1s');
  });

  it('formats days', () => {
    expect(formatDuration(90061)).toBe('1d 1h 1m 1s');
  });

  it('handles zero', () => {
    expect(formatDuration(0)).toBe('0s');
  });

  it('handles negative', () => {
    expect(formatDuration(-1)).toBe('—');
  });
});

describe('formatBytes', () => {
  it('formats bytes', () => {
    expect(formatBytes(500)).toBe('500 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(1024)).toBe('1.0 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(1048576)).toBe('1.0 MB');
  });

  it('handles zero', () => {
    expect(formatBytes(0)).toBe('0 B');
  });
});

describe('formatNumber', () => {
  it('formats with separators', () => {
    const result = formatNumber(1000000);
    expect(result).toBeTruthy();
  });

  it('handles Infinity', () => {
    expect(formatNumber(Infinity)).toBe('—');
  });
});

describe('protocolName', () => {
  it('maps TCP', () => expect(protocolName(6)).toBe('TCP'));
  it('maps UDP', () => expect(protocolName(17)).toBe('UDP'));
  it('maps ICMP', () => expect(protocolName(1)).toBe('ICMP'));
  it('maps ICMPv6', () => expect(protocolName(58)).toBe('ICMPv6'));
  it('maps unknown', () => expect(protocolName(99)).toBe('Proto 99'));
});

describe('severityIcon', () => {
  it('returns icon for critical', () => expect(severityIcon('critical')).toBe('🔴'));
  it('returns icon for high', () => expect(severityIcon('high')).toBe('🟠'));
  it('returns icon for medium', () => expect(severityIcon('medium')).toBe('🟡'));
  it('returns icon for low', () => expect(severityIcon('low')).toBe('🔵'));
  it('returns icon for info', () => expect(severityIcon('info')).toBe('⚪'));
});

describe('severityClass', () => {
  it('returns badge class', () => {
    expect(severityClass('critical')).toBe('badge badge--critical');
  });
});

describe('formatScore', () => {
  it('formats 0.85 as 85.0%', () => {
    expect(formatScore(0.85)).toBe('85.0%');
  });

  it('returns dash for null', () => {
    expect(formatScore(null)).toBe('—');
  });

  it('returns dash for undefined', () => {
    expect(formatScore(undefined)).toBe('—');
  });
});
