/* eslint-disable camelcase */ // indexer API field names
import {
  StoreConflictError,
  deleteRecord,
  listRecords,
  putRecord,
} from './dashboard-store';

const conflict = () =>
  Object.assign(new Error('version_conflict_engine_exception'), {
    meta: { statusCode: 409 },
  });

interface FakeDoc {
  source: Record<string, unknown>;
  seq: number;
}

type Params = Record<string, unknown> & { id?: string; body?: unknown };

// Settles like the client: a function's throw becomes a rejected promise.
const settle = <T>(fn: () => T) =>
  jest.fn(() => {
    try {
      return Promise.resolve(fn());
    } catch (error) {
      return Promise.reject(error);
    }
  });

const fakeClient = () => {
  const indices = new Set<string>();
  const docs = new Map<string, FakeDoc>();
  let seq = 0;
  let last: Params = {};
  const call =
    <T>(fn: (p: Params) => T) =>
    (p: Params) => {
      last = p;
      return settle(() => fn(last))();
    };
  return {
    docs,
    indices: {
      exists: jest.fn(
        call(({ index }) => ({ body: indices.has(String(index)) })),
      ),
      create: jest.fn(
        call(({ index }) => {
          indices.add(String(index));
          return {};
        }),
      ),
    },
    search: jest.fn(
      call(({ body }) => {
        const query = (body as { query: { bool?: { filter?: unknown[] } } })
          .query;
        const terms = (query.bool?.filter || []).map(
          f => (f as { term: Record<string, unknown> }).term,
        );
        const hits = [...docs.entries()]
          .filter(([, d]) =>
            terms.every(t =>
              Object.entries(t).every(([k, v]) => d.source[k] === v),
            ),
          )
          .map(([id, d]) => ({
            _id: id,
            _source: d.source,
            _seq_no: d.seq,
            _primary_term: 1,
          }));
        return { body: { hits: { hits } } };
      }),
    ),
    index: jest.fn(
      call(params => {
        const current = docs.get(String(params.id));
        if (params.op_type === 'create' && current) {
          throw conflict();
        }
        if (
          params.if_seq_no !== undefined &&
          (!current || current.seq !== params.if_seq_no)
        ) {
          throw conflict();
        }
        seq += 1;
        docs.set(String(params.id), {
          source: params.body as Record<string, unknown>,
          seq,
        });
        return { body: { _seq_no: seq, _primary_term: 1 } };
      }),
    ),
    delete: jest.fn(
      call(params => {
        const current = docs.get(String(params.id));
        if (!current) {
          throw Object.assign(new Error('not_found'), {
            meta: { statusCode: 404 },
          });
        }
        if (
          params.if_seq_no !== undefined &&
          current.seq !== params.if_seq_no
        ) {
          throw conflict();
        }
        docs.delete(String(params.id));
        return { body: {} };
      }),
    ),
  };
};

describe('dashboard store', () => {
  it('creates the hidden index on the first write and lists records', async () => {
    const client = fakeClient();
    expect(await listRecords(client, 'fim-history')).toEqual([]);
    expect(client.search).not.toHaveBeenCalled();

    await putRecord(
      client,
      'fim-history',
      { id: 'h1', kind: 'history', key: 'web', data: { content: '<x/>' } },
      'alice',
      new Date('2026-10-01T10:00:00Z'),
    );
    const create = client.indices.create.mock.calls[0][0] as {
      index: string;
      body: {
        settings: { index: { hidden: boolean } };
        mappings: { properties: Record<string, unknown> };
      };
    };
    expect(create.index).toBe('wz-dashboard-store-fim-history');
    expect(create.body.settings.index.hidden).toBe(true);
    expect(create.body.mappings.properties.data).toEqual({
      type: 'object',
      enabled: false,
    });

    const [record] = await listRecords(client, 'fim-history', {
      kind: 'history',
      key: 'web',
    });
    expect(record).toEqual({
      id: 'h1',
      kind: 'history',
      key: 'web',
      data: { content: '<x/>' },
      updated_by: 'alice',
      updated_at: '2026-10-01T10:00:00.000Z',
      seqNo: 1,
      primaryTerm: 1,
    });
    expect(await listRecords(client, 'fim-history', { key: 'db' })).toEqual([]);
  });

  it('refuses to overwrite a record changed since it was read', async () => {
    const client = fakeClient();
    const first = await putRecord(
      client,
      'ciscat',
      { id: 'targets', kind: 'targets', key: 'all', data: { a: 1 } },
      'alice',
    );
    await putRecord(
      client,
      'ciscat',
      { id: 'targets', kind: 'targets', key: 'all', data: { a: 2 }, ...first },
      'bob',
    );
    await expect(
      putRecord(
        client,
        'ciscat',
        {
          id: 'targets',
          kind: 'targets',
          key: 'all',
          data: { a: 3 },
          ...first,
        },
        'carol',
      ),
    ).rejects.toThrow(StoreConflictError);
    await expect(
      putRecord(
        client,
        'ciscat',
        { id: 'targets', kind: 'targets', key: 'all', data: {}, create: true },
        'carol',
      ),
    ).rejects.toThrow(StoreConflictError);
    expect(client.docs.get('targets').source.data).toEqual({ a: 2 });
  });

  it('deletes records, ignoring missing ones', async () => {
    const client = fakeClient();
    const saved = await putRecord(
      client,
      'fim-history',
      { id: 'h1', kind: 'history', key: 'web', data: {} },
      'alice',
    );
    await expect(
      deleteRecord(client, 'fim-history', 'h1', { seqNo: 99, primaryTerm: 1 }),
    ).rejects.toThrow(StoreConflictError);
    await deleteRecord(client, 'fim-history', 'h1', saved);
    await deleteRecord(client, 'fim-history', 'h1');
    expect(client.docs.size).toBe(0);
  });
});
