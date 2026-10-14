/* eslint-disable camelcase */ // record fields are the snake_case wire format
import { webcrypto } from 'crypto';
import { TextDecoder, TextEncoder } from 'util';
import { StoreError } from '../../../../../../common/ciscat/store';
import {
  buildRows,
  compareRules,
  composerStats,
  describeJob,
  describeTargets,
  makeExclusions,
  parseBench,
  profileLevelRole,
} from './composer';

// jsdom (the CI test environment) lacks Web Crypto and TextEncoder, which
// every browser has.
Object.assign(globalThis, { TextEncoder, TextDecoder });
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
}

const bench = parseBench(
  {
    _meta: {
      benchmark: 'demo',
      version: '1.0.0',
      profiles: ['L1_Server', 'L2_Server'],
    },
    '1.10': { t: 'Tenth', p: ['L1_Server', 'L2_Server'] },
    '1.2': { t: 'Second', p: ['L1_Server', 'L2_Server'], m: true },
    '2.1': { t: 'Level two only', p: ['L2_Server'] },
    '1.1.1': { t: 'Mount cramfs', p: ['L1_Server', 'L2_Server'] },
  },
  'rhel7',
);

const make = (over: Record<string, unknown> = {}) =>
  makeExclusions({
    osKey: 'rhel7',
    column: 'L1_Server',
    rules: ['1.1.1'],
    scope: 'os',
    values: [],
    reason: 'test',
    user: 'alice',
    now: new Date('2026-10-01T10:00:00Z'),
    ...over,
  });

describe('CIS-CAT exclusion composer', () => {
  it('reads the benchmark sheet in CIS order', () => {
    expect(bench.rules.map(r => r.rule)).toEqual([
      '1.1.1',
      '1.2',
      '1.10',
      '2.1',
    ]);
    expect(['1.10', '1.2', '1'].sort(compareRules)).toEqual([
      '1',
      '1.2',
      '1.10',
    ]);
    expect(bench.rules[1].manual).toBe(true);
  });

  it('maps profile columns to level and role', () => {
    expect(profileLevelRole('L1_Member_Server')).toEqual({
      level: 'L1',
      role: 'Member_Server',
    });
    expect(profileLevelRole('NG_Server')).toEqual({
      level: 'NG',
      role: 'Server',
    });
    expect(profileLevelRole('odd')).toEqual({ level: 'ALL', role: '' });
  });

  it('creates one validated record per rule and host, keyed like the master', async () => {
    const recs = await make({
      rules: ['1.1.1', '1.10'],
      scope: 'host',
      values: ['web-01, web-02', 'web-01'],
    });
    const list = Object.values(recs);
    expect(list).toHaveLength(4);
    expect(Object.keys(recs).every(k => /^e[0-9a-f]{16}$/.test(k))).toBe(true);
    expect(list[0]).toMatchObject({
      level: 'L1',
      role: 'Server',
      scope: 'host',
      updated_by: 'alice',
      updated_at: '2026-10-01T10:00:00.000Z',
    });
  });

  it('refuses incomplete exclusions', async () => {
    await expect(make({ reason: ' ' })).rejects.toThrow(StoreError);
    await expect(make({ scope: 'host', values: [] })).rejects.toThrow(
      'agent name',
    );
    await expect(make({ scope: 'app_group', values: ['a/b'] })).rejects.toThrow(
      'invalid name',
    );
    await expect(make({ rules: [] })).rejects.toThrow(StoreError);
  });

  it('shows which exclusions apply to the selected profile', async () => {
    const recs = {
      ...(await make()),
      ...(await make({ rules: ['1.10'], scope: 'host', values: ['web-01'] })),
      ...(await make({ rules: ['1.1.1'], column: 'L2_Server' })),
      ...(await make({ osKey: 'debian12', rules: ['1.2'] })),
    };
    const rows = buildRows(bench, recs, 'L1_Server');
    expect(rows.map(r => r.rule)).toEqual(['1.1.1', '1.2', '1.10']);
    const [mount, second, tenth] = rows;
    expect([mount.fleetWide, mount.exclusions.length]).toEqual([true, 1]);
    expect(second.exclusions).toEqual([]); // debian12 record
    expect([tenth.fleetWide, tenth.exclusions.length]).toEqual([false, 1]);
    expect(composerStats(rows)).toEqual({
      applicable: 3,
      fleetWide: 1,
      partial: 1,
      manual: 1,
      scored: 1,
    });
    expect(
      buildRows(bench, recs, 'L1_Server', { show: 'excluded' }).map(
        r => r.rule,
      ),
    ).toEqual(['1.1.1', '1.10']);
    expect(
      buildRows(bench, recs, 'L1_Server', { show: 'all', text: 'level' }).map(
        r => r.rule,
      ),
    ).toEqual(['2.1']);
    expect(
      buildRows(bench, recs, 'L1_Server', { text: '1.1' }).map(r => r.rule),
    ).toEqual(['1.1.1', '1.10']);
  });

  it('describes schedules for people', () => {
    const base = {
      v: 1,
      targets: ['*'],
      agents: [],
      groups: [],
      wave_size: 50,
      wave_pause_s: 300,
      enabled: true,
      label: '',
      created_by: '',
      created_at: '',
    };
    expect(describeJob({ ...base, type: 'once', at: '2026-10-31T22:00' })).toBe(
      'Once, 2026-10-31 22:00',
    );
    expect(
      describeJob({ ...base, type: 'monthly', day: 31, time: '02:00' }),
    ).toBe('Monthly on day 31 (or the last day) at 02:00');
    expect(
      describeJob({ ...base, type: 'monthly', day: -1, time: '02:00' }),
    ).toBe('Monthly on the last day at 02:00');
    expect(
      describeJob({ ...base, type: 'monthly', day: -3, time: '02:00' }),
    ).toBe('Monthly on the 3rd-last day at 02:00');
    expect(
      describeJob({ ...base, type: 'weekly', weekday: 6, time: '23:59' }),
    ).toBe('Every Sunday at 23:59');
    expect(describeTargets({ targets: ['*'] })).toBe('All active OS');
    expect(describeTargets({ targets: ['rhel7', 'windows_server_2025'] })).toBe(
      'rhel7, windows_server_2025',
    );
    expect(describeTargets({ targets: [], agents: ['003'] })).toBe('Agent 003');
    expect(
      describeTargets({
        targets: [],
        agents: ['001', '002', '003', '004', '005', '006', '007'],
      }),
    ).toBe('Agents 001, 002, 003, 004, 005 and 2 more');
    expect(
      describeTargets({ targets: [], groups: ['os-rhel7', 'web-prod'] }),
    ).toBe('Groups os-rhel7, web-prod');
  });
});
