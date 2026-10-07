/*
 * CIS-CAT bridge data on Wazuh 5.0. The 4.x bridge kept it in Wazuh CDB lists, which 5.0 no
 * longer has: each former list (ciscat-exclusions, ciscat-oskeys, ciscat-bench-<os>, ...) is now
 * one record of the dashboard store (collection "ciscat", kind "list", key = list name, data =
 * { records }) in the Wazuh indexer. The master bridge reads and writes the same records with its
 * own indexer credentials; each list keeps a single writer, as on 4.x
 * (tools/ciscat-bridge/CONTRACT.md). Agents and groups still come from the Wazuh server API.
 */
import { WzRequest } from '../../../../../react-services';
import {
  listStoreRecords,
  putStoreRecord,
} from '../../../../../services/dashboard-store';
import {
  CISCAT_LISTS,
  ListRecords,
} from '../../../../../../common/ciscat/store';

export { fetchCurrentUserName } from '../../../../../services/dashboard-store';

const COLLECTION = 'ciscat';
const KIND = 'list';

export interface LoadedList {
  records: ListRecords;
  errors: string[];
  /**
   * Version of the record as read ("seqNo:primaryTerm", '' when it does not exist), to detect a
   * concurrent change before writing.
   */
  raw: string;
  exists: boolean;
}

interface StoredList {
  records?: ListRecords;
}

const versionOf = (record?: { seqNo?: number; primaryTerm?: number }) =>
  record && record.seqNo !== undefined
    ? `${record.seqNo}:${record.primaryTerm}`
    : '';

/** Names of the CIS-CAT lists present in the store (`search` filters by prefix). */
export const existingLists = async (
  search = 'ciscat-',
): Promise<Set<string>> => {
  const records = await listStoreRecords<StoredList>(COLLECTION, {
    kind: KIND,
    size: 10000,
  });
  return new Set(
    records.map(r => r.key).filter(name => name.startsWith(search)),
  );
};

export const readList = async (
  name: string,
  existing?: Set<string>,
): Promise<LoadedList> => {
  if (existing && !existing.has(name)) {
    return { records: {}, errors: [], raw: '', exists: false };
  }
  const [record] = await listStoreRecords<StoredList>(COLLECTION, {
    kind: KIND,
    key: name,
    size: 1,
  });
  if (!record) {
    return { records: {}, errors: [], raw: '', exists: false };
  }
  const records = record.data?.records;
  const valid =
    records && typeof records === 'object' && !Array.isArray(records);
  return {
    records: valid ? records : {},
    errors: valid ? [] : [`${name}: records missing or not an object`],
    raw: versionOf(record),
    exists: true,
  };
};

export class ConcurrentChangeError extends Error {}

/**
 * Writes a dashboard-owned list. When `expectedRaw` is given, the write is refused if someone
 * else changed the list since it was read (or created it, when it did not exist).
 */
export const writeList = async (
  name: string,
  records: ListRecords,
  expectedRaw?: string,
) => {
  let concurrency = {};
  if (expectedRaw === '') {
    concurrency = { create: true };
  } else if (expectedRaw !== undefined) {
    const [seqNo, primaryTerm] = expectedRaw.split(':').map(Number);
    concurrency = { seqNo, primaryTerm };
  }
  try {
    await putStoreRecord(COLLECTION, {
      id: name,
      kind: KIND,
      key: name,
      data: { records },
      ...concurrency,
    });
  } catch (error) {
    if ((error as { status?: number }).status === 409) {
      throw new ConcurrentChangeError(
        `${name} was changed by someone else: reload before saving`,
      );
    }
    throw error;
  }
};

/** Adds a request for the master and drops requests it already processed. */
export const addRequest = async (
  key: string,
  request: Record<string, unknown>,
  processed: string[],
) => {
  const current = await readList(CISCAT_LISTS.requests);
  const keep = Object.fromEntries(
    Object.entries(current.records).filter(
      ([k]) => k !== '_empty' && !processed.includes(k),
    ),
  );
  keep[key] = { v: 1, ...request };
  await writeList(CISCAT_LISTS.requests, keep, current.raw);
};

const items = (response: unknown) =>
  (
    response as {
      data?: { data?: { affected_items?: Array<{ name?: string }> } };
    }
  )?.data?.data?.affected_items || [];

export const fetchAgentNames = async (): Promise<string[]> =>
  items(
    await WzRequest.apiReq('GET', '/agents', {
      params: { select: 'name', limit: 100000 },
    }),
  )
    .map(a => a.name || '')
    .filter(Boolean)
    .sort();

export const fetchGroupNames = async (): Promise<string[]> =>
  items(
    await WzRequest.apiReq('GET', '/groups', {
      params: { select: 'name', limit: 100000 },
    }),
  )
    .map(g => g.name || '')
    .filter(Boolean)
    .sort();
