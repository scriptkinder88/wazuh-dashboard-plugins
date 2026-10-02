/*
 * Client of the dashboard store routes (server/routes/dashboard-store.ts): records the dashboard
 * keeps in the Wazuh indexer for its own features.
 */
import { getHttp } from '../../kibana-services';
import {
  DashboardStoreCollection,
  DashboardStoreRecord,
} from '../../../common/dashboard-store';

export class DashboardStoreError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
  }
}

const call = async <T>(promise: Promise<T>): Promise<T> => {
  try {
    return await promise;
  } catch (error) {
    const body = (error as { body?: { message?: string } })?.body;
    const status = (error as { response?: { status?: number } })?.response
      ?.status;
    throw new DashboardStoreError(
      body?.message || (error as Error).message || String(error),
      status,
    );
  }
};

export const listStoreRecords = async <T = Record<string, unknown>>(
  collection: DashboardStoreCollection,
  query: { kind?: string; key?: string; size?: number } = {},
): Promise<Array<DashboardStoreRecord<T>>> => {
  const response = await call(
    getHttp().get(`/api/dashboard-store/${collection}`, {
      query: Object.fromEntries(
        Object.entries(query).filter(([, v]) => v !== undefined),
      ),
    }),
  );
  return (response as { items: Array<DashboardStoreRecord<T>> }).items || [];
};

export const putStoreRecord = async (
  collection: DashboardStoreCollection,
  record: {
    id: string;
    kind: string;
    key: string;
    data: Record<string, unknown>;
    seqNo?: number;
    primaryTerm?: number;
    create?: boolean;
  },
): Promise<{ seqNo: number; primaryTerm: number }> => {
  const { id, ...body } = record;
  return (await call(
    getHttp().put(
      `/api/dashboard-store/${collection}/${encodeURIComponent(id)}`,
      { body: JSON.stringify(body) },
    ),
  )) as { seqNo: number; primaryTerm: number };
};

export const deleteStoreRecord = async (
  collection: DashboardStoreCollection,
  id: string,
  concurrency: { seqNo?: number; primaryTerm?: number } = {},
) => {
  await call(
    getHttp().delete(
      `/api/dashboard-store/${collection}/${encodeURIComponent(id)}`,
      {
        query: Object.fromEntries(
          Object.entries(concurrency).filter(([, v]) => v !== undefined),
        ),
      },
    ),
  );
};

/** Name of the logged-in dashboard user ('' when there is no security plugin). */
export const fetchCurrentUserName = async (): Promise<string> => {
  try {
    const response = (await getHttp().get('/api/dashboard-store-user')) as {
      username?: string;
    };
    return response?.username || '';
  } catch {
    return '';
  }
};
