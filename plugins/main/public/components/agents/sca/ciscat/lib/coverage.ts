/*
 * Reading ciscat-history (written by the master once a day): per OS, the agents
 * of its group (expected), those with a recent scan of its CIS-CAT policy
 * (assessed) and the disconnected ones among the others.
 */
import { ListRecords } from '../../../../../../common/ciscat/store';

export interface CoveragePoint {
  day: string; // YYYY-MM-DD, master time zone
  expected: number;
  assessed: number;
  disconnected: number;
  /** assessed / expected in %, undefined when no agent is expected */
  percent?: number;
}

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 24 * 60 * 60 * 1000;

const count = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : 0;

/** Days between two YYYY-MM-DD dates (b - a). */
export const daysBetween = (a: string, b: string) =>
  Math.round(
    (Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / DAY_MS,
  );

export const addDays = (day: string, days: number) =>
  new Date(Date.parse(`${day}T00:00:00Z`) + days * DAY_MS)
    .toISOString()
    .slice(0, 10);

/** OS keys present in the history, most recent day first. */
export const historyOsKeys = (history: ListRecords) => {
  const keys = new Set<string>();
  Object.keys(history)
    .filter(day => DAY_RE.test(day))
    .sort()
    .reverse()
    .forEach(day =>
      Object.keys(history[day]?.os || {}).forEach(k => keys.add(k)),
    );
  return Array.from(keys);
};

/**
 * Daily coverage of one OS ('*' adds every OS), for the `days` days ending on
 * the most recent recorded day. Days without a record are missing points, and
 * so are the days before an OS was first recorded.
 */
export const coverageSeries = (
  history: ListRecords,
  osKey: string,
  days: number,
): CoveragePoint[] => {
  const recorded = Object.keys(history)
    .filter(day => DAY_RE.test(day))
    .sort();
  if (!recorded.length) {
    return [];
  }
  const first = addDays(recorded[recorded.length - 1], 1 - days);
  const osOf = (day: string) =>
    (history[day]?.os || {}) as Record<
      string,
      Record<string, unknown> | undefined
    >;
  // a single OS starts on the first day it was recorded
  return recorded
    .filter(day => day >= first && (osKey === '*' || osOf(day)[osKey]))
    .map(day => {
      const perOs = osOf(day);
      const entries = osKey === '*' ? Object.values(perOs) : [perOs[osKey]];
      const point: CoveragePoint = {
        day,
        expected: 0,
        assessed: 0,
        disconnected: 0,
      };
      entries
        .filter(
          (e): e is Record<string, unknown> => !!e && typeof e === 'object',
        )
        .forEach(e => {
          point.expected += count(e.expected);
          point.assessed += Math.min(count(e.assessed), count(e.expected));
          point.disconnected += count(e.disconnected);
        });
      if (point.expected) {
        point.percent =
          Math.round((point.assessed / point.expected) * 1000) / 10;
      }
      return point;
    });
};
