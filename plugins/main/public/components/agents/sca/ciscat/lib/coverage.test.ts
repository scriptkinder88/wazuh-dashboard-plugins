/* eslint-disable camelcase */ // record fields are the snake_case wire format
import {
  addDays,
  coverageSeries,
  daysBetween,
  historyOsKeys,
} from './coverage';

const day = (os: Record<string, object>) => ({ v: 1, stale_days: 35, os });

const HISTORY = {
  '2026-09-29': day({ rhel7: { expected: 4, assessed: 1, disconnected: 2 } }),
  '2026-09-30': day({
    rhel7: { expected: 4, assessed: 2, disconnected: 1 },
    win: { expected: 1, assessed: 1, disconnected: 0 },
  }),
  // 2026-10-01 missing: the scheduler did not run
  '2026-10-02': day({
    rhel7: { expected: 4, assessed: 9, disconnected: 0 }, // capped to expected
    win: { expected: 0, assessed: 0, disconnected: 0 },
  }),
  'not-a-day': day({ rhel7: { expected: 1 } }),
};

describe('CIS-CAT coverage history', () => {
  it('computes the daily coverage of one OS', () => {
    expect(coverageSeries(HISTORY, 'rhel7', 30)).toEqual([
      {
        day: '2026-09-29',
        expected: 4,
        assessed: 1,
        disconnected: 2,
        percent: 25,
      },
      {
        day: '2026-09-30',
        expected: 4,
        assessed: 2,
        disconnected: 1,
        percent: 50,
      },
      {
        day: '2026-10-02',
        expected: 4,
        assessed: 4,
        disconnected: 0,
        percent: 100,
      },
    ]);
  });

  it('adds every OS, and has no percentage without expected agents', () => {
    const all = coverageSeries(HISTORY, '*', 30);
    expect(all[1]).toEqual({
      day: '2026-09-30',
      expected: 5,
      assessed: 3,
      disconnected: 1,
      percent: 60,
    });
    expect(coverageSeries(HISTORY, 'win', 30).map(p => p.percent)).toEqual([
      100,
      undefined,
    ]);
  });

  it('keeps the last days of the period', () => {
    expect(coverageSeries(HISTORY, 'rhel7', 3).map(p => p.day)).toEqual([
      '2026-09-30',
      '2026-10-02',
    ]);
    expect(coverageSeries({}, '*', 30)).toEqual([]);
  });

  it('lists the OSes and handles dates', () => {
    expect(historyOsKeys(HISTORY)).toEqual(['rhel7', 'win']);
    expect(daysBetween('2026-09-29', '2026-10-02')).toBe(3);
    expect(addDays('2026-10-02', -3)).toBe('2026-09-29');
  });
});
