/*
 * CIS-CAT bridge data through the Wazuh API: list files under etc/lists
 * (read and written with the same calls as the CDB lists editor), plus agents
 * and groups for the composer. No other endpoint is involved.
 */
import { WzRequest } from '../../../../../react-services';
import { getHttp } from '../../../../../kibana-services';
// eslint-disable-next-line max-len
import { ResourcesHandler } from '../../../../../controllers/management/components/management/common/resources-handler';
import {
  CISCAT_LISTS,
  ListRecords,
  parseList,
  renderList,
} from '../../../../../../common/ciscat/store';

const lists = new ResourcesHandler('lists');

export interface LoadedList {
  records: ListRecords;
  errors: string[];
  /** Raw content as read, to detect a concurrent change before writing. */
  raw: string;
  exists: boolean;
}

/** Names of the list files matching `search` (ciscat-* by default). */
export const existingLists = async (
  search = 'ciscat-',
): Promise<Set<string>> => {
  // /lists/files returns names only; /lists would return every list's items
  const response = await WzRequest.apiReq('GET', '/lists/files', {
    params: { search, limit: 500 },
  });
  const items = response?.data?.data?.affected_items || [];
  return new Set(
    items.map((item: { filename?: string }) => item.filename || ''),
  );
};

export const readList = async (
  name: string,
  existing?: Set<string>,
): Promise<LoadedList> => {
  const present = existing || (await existingLists());
  if (!present.has(name)) {
    return { records: {}, errors: [], raw: '', exists: false };
  }
  const raw = String((await lists.getFileContent(name)) || '');
  return { ...parseList(raw), raw, exists: true };
};

export class ConcurrentChangeError extends Error {}

/**
 * Writes a dashboard-owned list. When `expectedRaw` is given, the file is read
 * again first and the write is refused if someone else changed it meanwhile.
 */
export const writeList = async (
  name: string,
  records: ListRecords,
  expectedRaw?: string,
) => {
  if (expectedRaw !== undefined) {
    const current = await readList(name);
    if (current.raw !== expectedRaw) {
      throw new ConcurrentChangeError(
        `${name} was changed by someone else: reload before saving`,
      );
    }
  }
  const content = renderList(records);
  // An empty list file is rejected by the API: keep a placeholder record.
  await lists.updateFile(
    name,
    content || renderList({ _empty: { v: 1 } }),
    true,
  );
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

export const fetchAgentNames = async (): Promise<string[]> => {
  const response = await WzRequest.apiReq('GET', '/agents', {
    params: { select: 'name', limit: 100000, q: 'id!=000' },
  });
  return (response?.data?.data?.affected_items || [])
    .map((a: { name?: string }) => a.name || '')
    .filter(Boolean)
    .sort();
};

export const fetchGroupNames = async (): Promise<string[]> => {
  const response = await WzRequest.apiReq('GET', '/groups', {
    params: { select: 'name', limit: 100000 },
  });
  return (response?.data?.data?.affected_items || [])
    .map((g: { name?: string }) => g.name || '')
    .filter(Boolean)
    .sort();
};

/** Dashboard user for the audit fields; empty when no security plugin. */
export const fetchCurrentUserName = async (): Promise<string> => {
  try {
    const account = await getHttp().get('/api/v1/configuration/account');
    return String(account?.data?.user_name || '');
  } catch {
    return '';
  }
};
