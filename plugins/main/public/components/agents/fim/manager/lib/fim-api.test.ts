/* eslint-disable camelcase */ // Wazuh API field names
import { TextDecoder, TextEncoder } from 'util';
import { WzRequest } from '../../../../../react-services';
import { renderList } from '../../../../../../common/ciscat/store';
import {
  HISTORY_DEPTH,
  HISTORY_MAX_BYTES,
  HISTORY_MAX_ENTRIES,
  applyPlan,
  clearGroupConfCache,
  loadGroupConfs,
  mapLimited,
  pruneHistory,
  testPathOnAgents,
} from './fim-api';
import { AgentInfo, GroupStep } from './plan';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('../../../../../react-services', () => ({
  WzRequest: { apiReq: jest.fn() },
}));

const mockWriteList = jest.fn();
jest.mock('../../../sca/ciscat/lib/lists-api', () => ({
  existingLists: () => Promise.resolve(new Set()),
  readList: () =>
    Promise.resolve({ records: {}, errors: [], raw: '', exists: false }),
  writeList: (...args: unknown[]) => mockWriteList(...args),
}));

const apiReq = WzRequest.apiReq as jest.Mock;

beforeEach(() => {
  apiReq.mockReset();
  mockWriteList.mockReset().mockResolvedValue(undefined);
  clearGroupConfCache();
});

const version = (g: string, at: string, size = 10) => ({
  v: 1,
  g,
  at,
  x: 'x'.repeat(size),
});

describe('pruneHistory', () => {
  it(`keeps the last ${HISTORY_DEPTH} versions of each group`, () => {
    const records = Object.fromEntries(
      Array.from({ length: HISTORY_DEPTH + 2 }, (_, i) => [
        `h${i}`,
        version('web', `2026-10-01T00:00:${String(i).padStart(2, '0')}Z`),
      ]),
    );
    const out = pruneHistory({ ...records, _empty: { v: 1 } }, 'h11');
    expect(Object.keys(out)).toHaveLength(HISTORY_DEPTH);
    expect(out.h0).toBeUndefined();
    expect(out.h1).toBeUndefined();
    expect(out.h11).toBeDefined();
    expect(out._empty).toBeUndefined();
  });

  it(`keeps at most ${HISTORY_MAX_ENTRIES} versions in all`, () => {
    const records = Object.fromEntries(
      Array.from({ length: HISTORY_MAX_ENTRIES + 5 }, (_, i) => [
        `h${i}`,
        version(
          `group-${i}`,
          new Date(Date.UTC(2026, 0, 1, 0, i)).toISOString(),
        ),
      ]),
    );
    const out = pruneHistory(records, 'h0');
    expect(Object.keys(out)).toHaveLength(HISTORY_MAX_ENTRIES);
    // the oldest go first, but never the version being saved
    expect(out.h0).toBeDefined();
    expect(out.h1).toBeUndefined();
    expect(out[`h${HISTORY_MAX_ENTRIES + 4}`]).toBeDefined();
  });

  it('keeps the file under the size limit', () => {
    const big = Math.floor(HISTORY_MAX_BYTES / 6);
    const records = Object.fromEntries(
      Array.from({ length: 10 }, (_, i) => [
        `h${i}`,
        version(`g${i}`, `2026-10-01T00:00:0${i}Z`, big),
      ]),
    );
    const out = pruneHistory(records, 'h9');
    expect(renderList(out).length).toBeLessThanOrEqual(HISTORY_MAX_BYTES);
    expect(out.h9).toBeDefined();
    expect(out.h0).toBeUndefined();
  });
});

describe('mapLimited', () => {
  it('runs at most `limit` calls at once and keeps the order', async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimited([1, 2, 3, 4, 5, 6], 2, async value => {
      running++;
      peak = Math.max(peak, running);
      await new Promise(resolve => setTimeout(resolve, 5));
      running--;
      return value * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBe(2);
  });
});

const agent = (id: string): AgentInfo => ({
  id,
  name: `agent-${id}`,
  status: 'active',
  platform: 'ubuntu',
  groups: [],
  configStatus: 'synced',
});

/** Fake API: the inventory of every agent, and its last scan. */
function inventoryApi(files: string[], total: number, end?: string) {
  return (_method: string, path: string) => {
    if (path.endsWith('/last_scan')) {
      return Promise.resolve({
        data: { data: { affected_items: end ? [{ end }] : [] } },
      });
    }
    return Promise.resolve({
      data: {
        data: {
          affected_items: files.map(file => ({ file })),
          total_affected_items: total,
        },
      },
    });
  };
}

describe('testPathOnAgents', () => {
  it('counts only the entries under the path', async () => {
    apiReq.mockImplementation(
      inventoryApi(
        [
          '/etc/app/a.conf',
          '/etc/app',
          '/srv/etc/app/b.conf',
          '/etc/application',
        ],
        4,
        '2026-10-02',
      ),
    );
    const [result] = await testPathOnAgents('/etc/app', [agent('001')]);
    expect(result).toEqual(
      expect.objectContaining({
        files: 2,
        more: false,
        lastScan: '2026-10-02',
      }),
    );
  });

  it('marks a partial count and reports a rejected call per agent', async () => {
    apiReq.mockImplementation((_method: string, path: string) => {
      if (path.startsWith('/syscheck/002')) {
        return Promise.reject(new Error('Agent 002 is not active'));
      }
      return inventoryApi(['/etc/app/a'], 900)(_method, path);
    });
    const [first, second] = await testPathOnAgents('/etc/app', [
      agent('001'),
      agent('002'),
    ]);
    expect(first).toEqual(expect.objectContaining({ files: 1, more: true }));
    expect(second.error).toBe('Agent 002 is not active');
  });
});

describe('loadGroupConfs', () => {
  const conf = '<agent_config>\n</agent_config>\n';

  it('reads a group again only when its checksum changed', async () => {
    apiReq.mockResolvedValue({ data: conf });
    await loadGroupConfs([{ name: 'web', configSum: 'a' }]);
    await loadGroupConfs([{ name: 'web', configSum: 'a' }]);
    expect(apiReq).toHaveBeenCalledTimes(1);
    await loadGroupConfs([{ name: 'web', configSum: 'b' }]);
    expect(apiReq).toHaveBeenCalledTimes(2);
    await loadGroupConfs([{ name: 'web' }]);
    expect(apiReq).toHaveBeenCalledTimes(3);
  });

  it('marks a group whose file cannot be read', async () => {
    apiReq.mockRejectedValue(new Error('forbidden'));
    const out = await loadGroupConfs([{ name: 'web', configSum: 'a' }]);
    expect(out.web.error).toBe('cannot read agent.conf: forbidden');
  });
});

describe('applyPlan', () => {
  const step = (group: string): GroupStep => ({
    group,
    create: false,
    deleteGroup: false,
    before: 'old',
    after: 'new',
  });

  it('stops at the first failure and reports what was done', async () => {
    apiReq.mockImplementation((method: string) =>
      method === 'PUT'
        ? Promise.reject(new Error('XML syntax error'))
        : Promise.resolve({ data: 'old' }),
    );
    const progress = jest.fn();
    await expect(
      applyPlan([step('a'), step('b')], 'alice', 'note', progress),
    ).rejects.toThrow('a: XML syntax error');
    expect(progress).toHaveBeenCalledWith({
      group: 'a',
      done: ['previous version saved'],
    });
    expect(apiReq).not.toHaveBeenCalledWith(
      'GET',
      expect.stringContaining('/groups/b/'),
      expect.anything(),
    );
  });

  it('does not save the history when the history list cannot be written', async () => {
    apiReq.mockResolvedValue({ data: 'old' });
    mockWriteList.mockRejectedValue(new Error('changed by someone else'));
    await expect(applyPlan([step('a')], 'alice', 'note')).rejects.toThrow(
      'a: changed by someone else',
    );
    expect(apiReq).not.toHaveBeenCalledWith(
      'PUT',
      expect.anything(),
      expect.anything(),
    );
  });
});
