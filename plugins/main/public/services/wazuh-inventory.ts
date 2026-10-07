/*
 * Agents and groups read in full through the Wazuh server API, for the
 * selectors of the management tabs.
 */
import { WzRequest } from '../react-services';

/** Largest page the Wazuh server API returns (its maximum `limit`). */
export const API_MAX_LIMIT = 100000;

interface ApiItems<T> {
  data?: { data?: { affected_items?: T[] } };
}

const items = <T>(response: unknown): T[] =>
  (response as ApiItems<T>)?.data?.data?.affected_items || [];

/** Every agent but the manager, with the fields in `select`. */
export const fetchAllAgents = async <T>(select: string[]): Promise<T[]> =>
  items<T>(
    await WzRequest.apiReq('GET', '/agents', {
      params: { select: select.join(','), q: 'id!=000', limit: API_MAX_LIMIT },
    }),
  );

/** Every group, with all its fields. */
export const fetchAllGroups = async <T>(): Promise<T[]> =>
  items<T>(
    await WzRequest.apiReq('GET', '/groups', {
      params: { limit: API_MAX_LIMIT },
    }),
  );

const sortedNames = (list: Array<{ name?: string }>) =>
  list
    .map(item => item.name || '')
    .filter(Boolean)
    .sort();

export const fetchAgentNames = async (): Promise<string[]> =>
  sortedNames(await fetchAllAgents<{ name?: string }>(['name']));

export const fetchGroupNames = async (): Promise<string[]> =>
  sortedNames(await fetchAllGroups<{ name?: string }>());
