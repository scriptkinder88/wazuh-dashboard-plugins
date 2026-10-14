/* eslint-disable camelcase */ // record fields are the snake_case wire format
import {
  masterTime,
  pendingRequests,
  recentRuns,
  schedulerHealth,
} from './status';

describe('CIS-CAT status', () => {
  it('reads master times with their offset', () => {
    expect(masterTime('2026-10-01T10:00:00', '+0200')?.toISOString()).toBe(
      '2026-10-01T08:00:00.000Z',
    );
    expect(masterTime('2026-10-01T10:00', '-0530')?.toISOString()).toBe(
      '2026-10-01T15:30:00.000Z',
    );
    expect(
      masterTime('2026-10-01T10:00:00+02:00', '+0000')?.toISOString(),
    ).toBe('2026-10-01T08:00:00.000Z');
    expect(masterTime('', '+0200')).toBeUndefined();
    expect(masterTime('yesterday')).toBeUndefined();
  });

  it('flags a scheduler that stopped ticking', () => {
    const status = {
      scheduler: { last_tick: '2026-10-01T10:00:00', utc_offset: '+0200' },
    };
    expect(
      schedulerHealth(status, new Date('2026-10-01T08:10:00Z')).state,
    ).toBe('ok');
    expect(
      schedulerHealth(status, new Date('2026-10-01T08:20:00Z')).state,
    ).toBe('stale');
    expect(schedulerHealth({}).state).toBe('unknown');
  });

  it('lists recent runs, newest first, with job labels', () => {
    const runs = recentRuns(
      {
        scheduler: { utc_offset: '+0000' },
        'job-jaaaaaaaaaaaa': {
          state: 'ok',
          last_run: '2026-10-01T10:00:00',
          sent: 5,
          failed: 1,
          skipped: ['003', '006'],
        },
        'job-r1700000000000abcd': {
          state: 'running',
          last_run: '2026-10-02T09:00:00+00:00',
        },
        'job-jbbbbbbbbbbbb': { next_run: '2026-11-01T10:00' },
      },
      { jaaaaaaaaaaaa: 'Month end' },
    );
    expect(runs.map(r => [r.label, r.state, r.isRunNow])).toEqual([
      ['Run now', 'running', true],
      ['Month end', 'ok', false],
    ]);
    expect([runs[1].sent, runs[1].failed, runs[1].skipped]).toEqual([5, 1, 2]);
  });

  it('finds requests the master has not handled', () => {
    expect(
      pendingRequests(
        { r1: { action: 'apply' }, r2: { action: 'run' }, _empty: { v: 1 } },
        { requests: { processed: ['r1'] } },
      ),
    ).toEqual(['r2']);
  });
});
