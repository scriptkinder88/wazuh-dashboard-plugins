/*
 * Reading ciscat-status (written by the master): times, scheduler health and
 * the list of recent runs.
 */
import { ListRecords } from '../../../../../../common/ciscat/store';

/** Scheduler ticks every 5 minutes: three missed ticks mean it is not running. */
export const SCHEDULER_STALE_MS = 15 * 60 * 1000;

/**
 * A master timestamp as a Date. Values with an offset are exact; values in
 * master local time ("2026-10-01T10:00:00") use the master's UTC offset
 * ("+0200") published by the scheduler.
 */
export const masterTime = (value: unknown, utcOffset?: unknown) => {
  const text = String(value || '');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(text)) {
    return undefined;
  }
  if (/([+-]\d{2}:?\d{2}|Z)$/.test(text)) {
    const date = new Date(text);
    return isNaN(date.getTime()) ? undefined : date;
  }
  const offset = /^([+-])(\d{2}):?(\d{2})$/.exec(String(utcOffset || ''));
  const iso = `${text.length === 16 ? `${text}:00` : text.slice(0, 19)}${
    offset ? `${offset[1]}${offset[2]}:${offset[3]}` : 'Z'
  }`;
  const date = new Date(iso);
  return isNaN(date.getTime()) ? undefined : date;
};

export const schedulerHealth = (status: ListRecords, now = new Date()) => {
  const scheduler = status.scheduler || {};
  const lastTick = masterTime(scheduler.last_tick, scheduler.utc_offset);
  if (!lastTick) {
    return { state: 'unknown' as const, lastTick };
  }
  const stale = now.getTime() - lastTick.getTime() > SCHEDULER_STALE_MS;
  return { state: stale ? ('stale' as const) : ('ok' as const), lastTick };
};

export interface RunView {
  key: string;
  label: string;
  state: string;
  lastRun?: Date;
  finishedAt?: Date;
  sent: number;
  failed: number;
  skipped: number;
  isRunNow: boolean;
}

export const recentRuns = (
  status: ListRecords,
  jobLabels: Record<string, string> = {},
): RunView[] => {
  const offset = status.scheduler?.utc_offset;
  return Object.entries(status)
    .filter(([key, rec]) => key.startsWith('job-') && rec.last_run)
    .map(([key, rec]) => {
      const job = key.slice(4);
      return {
        key: job,
        label:
          jobLabels[job] ||
          String(rec.label || (job.startsWith('r') ? 'Run now' : job)),
        state: String(rec.state || 'unknown'),
        lastRun: masterTime(rec.last_run, offset),
        finishedAt: masterTime(rec.finished_at, offset),
        sent: Number(rec.sent || 0),
        failed: Number(rec.failed || 0),
        skipped: Array.isArray(rec.skipped) ? rec.skipped.length : 0,
        isRunNow: job.startsWith('r'),
      };
    })
    .sort((a, b) => (b.lastRun?.getTime() || 0) - (a.lastRun?.getTime() || 0));
};

/** Requests written by the dashboard that the master has not handled yet. */
export const pendingRequests = (requests: ListRecords, status: ListRecords) => {
  const processed = new Set<string>(
    (status.requests?.processed as string[]) || [],
  );
  return Object.keys(requests)
    .filter(key => !key.startsWith('_') && !processed.has(key))
    .sort();
};
