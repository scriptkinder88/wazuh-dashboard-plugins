import {
  ConcurrentChangeError,
  addRequest,
  existingLists,
  readList,
  writeList,
} from './lists-api';

// In-memory dashboard store: record id -> record (with an incrementing seqNo).
interface MockRecord {
  id: string;
  key: string;
  data: { records?: unknown };
  seqNo: number;
  primaryTerm: number;
  create?: boolean;
}
const mockRecords: Record<string, MockRecord> = {};
let mockSeq = 0;

jest.mock('../../../../../react-services', () => ({ WzRequest: {} }));

jest.mock('../../../../../services/dashboard-store', () => {
  const conflict = () =>
    Promise.reject(Object.assign(new Error('changed'), { status: 409 }));
  return {
    listStoreRecords: (_collection: string, q: { key?: string }) =>
      Promise.resolve(
        Object.values(mockRecords).filter(r => !q.key || r.key === q.key),
      ),
    putStoreRecord: (_collection: string, record: MockRecord) => {
      const current = mockRecords[record.id];
      if (record.create && current) {
        return conflict();
      }
      if (
        record.seqNo !== undefined &&
        (!current || current.seqNo !== record.seqNo)
      ) {
        return conflict();
      }
      mockSeq += 1;
      mockRecords[record.id] = { ...record, seqNo: mockSeq, primaryTerm: 1 };
      return Promise.resolve({ seqNo: mockSeq, primaryTerm: 1 });
    },
    fetchCurrentUserName: () => Promise.resolve(''),
  };
});

beforeEach(() => {
  Object.keys(mockRecords).forEach(k => delete mockRecords[k]);
});

describe('CIS-CAT lists on the dashboard store (Wazuh 5.0)', () => {
  it('reads a missing list as empty and creates it once', async () => {
    const empty = await readList('ciscat-exclusions');
    expect(empty).toEqual({ records: {}, errors: [], raw: '', exists: false });

    await writeList('ciscat-exclusions', { e1: { v: 1 } }, empty.raw);
    await expect(
      writeList('ciscat-exclusions', { e2: { v: 1 } }, empty.raw),
    ).rejects.toThrow(ConcurrentChangeError);

    const saved = await readList('ciscat-exclusions');
    expect(saved).toEqual({
      records: { e1: { v: 1 } },
      errors: [],
      raw: `${mockSeq}:1`,
      exists: true,
    });
    expect(await existingLists()).toEqual(new Set(['ciscat-exclusions']));
  });

  it('refuses to overwrite a list changed since it was read', async () => {
    await writeList('ciscat-schedule', { j1: { v: 1 } });
    const read = await readList('ciscat-schedule');
    await writeList('ciscat-schedule', { j2: { v: 1 } }, read.raw);
    await expect(
      writeList('ciscat-schedule', { j3: { v: 1 } }, read.raw),
    ).rejects.toThrow(/changed by someone else/);
  });

  it('adds a request and drops the processed ones', async () => {
    await writeList('ciscat-requests', { r1: { v: 1, action: 'apply' } });
    await addRequest('r2', { action: 'run' }, ['r1']);
    expect((await readList('ciscat-requests')).records).toEqual({
      r2: { v: 1, action: 'run' },
    });
  });

  it('reports a malformed record', async () => {
    mockRecords['ciscat-status'] = {
      id: 'ciscat-status',
      key: 'ciscat-status',
      data: { records: [] },
      seqNo: 1,
      primaryTerm: 1,
    };
    expect((await readList('ciscat-status')).errors).toEqual([
      'ciscat-status: records missing or not an object',
    ]);
  });
});
