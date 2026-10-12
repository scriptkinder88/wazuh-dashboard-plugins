/*
 * CIS-CAT bridge data through the Wazuh API: the ciscat-* list files, plus
 * agents and groups for the composer. No other endpoint is involved.
 */
import {
  LoadedList,
  existingLists as existingListFiles,
  readList as readListFile,
  writeList,
} from '../../../../../services/list-files';
import { CISCAT_LISTS } from '../../../../../../common/ciscat/store';
import { fetchAllAgents } from '../../../../../services/wazuh-inventory';

export type { LoadedList } from '../../../../../services/list-files';
export {
  ConcurrentChangeError,
  writeList,
} from '../../../../../services/list-files';
export {
  fetchAgentNames,
  fetchGroupNames,
} from '../../../../../services/wazuh-inventory';

/** Every agent but the manager, for the agents a run is sent to. */
export const fetchRunAgents = async () =>
  (
    await fetchAllAgents<{
      id: string;
      name?: string;
      os?: { platform?: string };
    }>(['id', 'name', 'os.platform'])
  )
    .map(a => ({ id: a.id, name: a.name || a.id, platform: a.os?.platform }))
    .sort((a, b) => a.id.localeCompare(b.id));
export { fetchCurrentUserName } from '../../../../../services/dashboard-user';

const CISCAT_PREFIX = 'ciscat-';

/** Names of the list files matching `search` (ciscat-* by default). */
export const existingLists = (search = CISCAT_PREFIX) =>
  existingListFiles(search);

/** A ciscat list file; `existing` saves a request when several are read. */
export const readList = async (
  name: string,
  existing?: Set<string>,
): Promise<LoadedList> =>
  readListFile(name, existing || (await existingListFiles(name)));

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
