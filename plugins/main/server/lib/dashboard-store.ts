/*
 * Dashboard-owned records in the Wazuh indexer (see common/dashboard-store.ts).
 * The index of a collection is created on its first write, hidden and with the record
 * payload stored but not indexed, so any shape of `data` is accepted.
 */
import {
  DASHBOARD_STORE_COLLECTIONS,
  DashboardStoreCollection,
  DashboardStoreRecord,
} from '../../common/dashboard-store';

/* eslint-disable camelcase */ // indexer API and stored field names

interface StoredSource {
  kind?: string;
  key?: string;
  data?: Record<string, unknown>;
  updated_by?: string;
  updated_at?: string;
}

interface SearchBody {
  hits?: {
    hits?: Array<{
      _id: string;
      _source?: StoredSource;
      _seq_no?: number;
      _primary_term?: number;
    }>;
  };
}

interface IndexBody {
  _seq_no?: number;
  _primary_term?: number;
}

// The subset of the OpenSearch client used here (asInternalUser or asCurrentUser).
export interface StoreClient {
  indices: {
    exists(params: { index: string }): Promise<{ body: boolean }>;
    create(params: { index: string; body: unknown }): Promise<unknown>;
  };
  search(params: {
    index: string;
    body: unknown;
    seq_no_primary_term?: boolean;
  }): Promise<{ body: SearchBody }>;
  index(params: Record<string, unknown>): Promise<{ body: IndexBody }>;
  delete(params: Record<string, unknown>): Promise<unknown>;
}

export class StoreConflictError extends Error {}

const MAPPINGS = {
  dynamic: 'strict',
  properties: {
    kind: { type: 'keyword' },
    key: { type: 'keyword' },
    data: { type: 'object', enabled: false },
    updated_by: { type: 'keyword' },
    updated_at: { type: 'date' },
  },
};

export const storeIndex = (collection: DashboardStoreCollection) =>
  DASHBOARD_STORE_COLLECTIONS[collection];

interface ClientError {
  message?: string;
  statusCode?: number;
  meta?: { statusCode?: number };
}

const statusOf = (error: unknown) =>
  (error as ClientError)?.meta?.statusCode ??
  (error as ClientError)?.statusCode;

const ensureIndex = async (client: StoreClient, index: string) => {
  const { body: exists } = await client.indices.exists({ index });
  if (exists) {
    return;
  }
  try {
    await client.indices.create({
      index,
      body: {
        settings: { index: { hidden: true, number_of_shards: 1 } },
        mappings: MAPPINGS,
      },
    });
  } catch (error) {
    // created meanwhile by another request
    if (
      statusOf(error) !== 400 ||
      !/resource_already_exists/.test(String((error as ClientError)?.message))
    ) {
      throw error;
    }
  }
};

export const listRecords = async (
  client: StoreClient,
  collection: DashboardStoreCollection,
  filter: { kind?: string; key?: string; size?: number } = {},
): Promise<DashboardStoreRecord[]> => {
  const index = storeIndex(collection);
  const { body: exists } = await client.indices.exists({ index });
  if (!exists) {
    return [];
  }
  const must = [
    ...(filter.kind ? [{ term: { kind: filter.kind } }] : []),
    ...(filter.key ? [{ term: { key: filter.key } }] : []),
  ];
  const { body } = await client.search({
    index,
    seq_no_primary_term: true,
    body: {
      size: Math.min(filter.size || 1000, 10000),
      query: must.length ? { bool: { filter: must } } : { match_all: {} },
      sort: [{ updated_at: { order: 'desc' } }],
    },
  });
  return (body?.hits?.hits || []).map(hit => ({
    id: hit._id,
    kind: hit._source?.kind || '',
    key: hit._source?.key || '',
    data: hit._source?.data || {},
    updated_by: hit._source?.updated_by || '',
    updated_at: hit._source?.updated_at || '',
    seqNo: hit._seq_no,
    primaryTerm: hit._primary_term,
  }));
};

export const putRecord = async (
  client: StoreClient,
  collection: DashboardStoreCollection,
  record: {
    id: string;
    kind: string;
    key: string;
    data: Record<string, unknown>;
    seqNo?: number;
    primaryTerm?: number;
    /** Fail if a record with this id exists. */
    create?: boolean;
  },
  user: string,
  now = new Date(),
) => {
  const index = storeIndex(collection);
  await ensureIndex(client, index);
  const concurrency =
    record.seqNo !== undefined && record.primaryTerm !== undefined
      ? { if_seq_no: record.seqNo, if_primary_term: record.primaryTerm }
      : {};
  try {
    const { body } = await client.index({
      index,
      id: record.id,
      refresh: 'wait_for',
      ...(record.create ? { op_type: 'create' } : {}),
      ...concurrency,
      body: {
        kind: record.kind,
        key: record.key,
        data: record.data,
        updated_by: user,
        updated_at: now.toISOString(),
      },
    });
    return { seqNo: body?._seq_no, primaryTerm: body?._primary_term };
  } catch (error) {
    if (statusOf(error) === 409) {
      throw new StoreConflictError(
        'The record was changed by someone else: reload and try again',
      );
    }
    throw error;
  }
};

export const deleteRecord = async (
  client: StoreClient,
  collection: DashboardStoreCollection,
  id: string,
  concurrency: { seqNo?: number; primaryTerm?: number } = {},
) => {
  try {
    await client.delete({
      index: storeIndex(collection),
      id,
      refresh: 'wait_for',
      ...(concurrency.seqNo !== undefined &&
      concurrency.primaryTerm !== undefined
        ? {
            if_seq_no: concurrency.seqNo,
            if_primary_term: concurrency.primaryTerm,
          }
        : {}),
    });
  } catch (error) {
    if (statusOf(error) === 404) {
      return;
    }
    if (statusOf(error) === 409) {
      throw new StoreConflictError(
        'The record was changed by someone else: reload and try again',
      );
    }
    throw error;
  }
};
