/*
 * Wazuh API calls of the FIM manager: groups and their agent.conf, agents,
 * the configuration active on an agent, and the version history kept in the
 * fim-history list. Nothing runs on the manager besides the Wazuh API.
 */
import { WzRequest } from '../../../../../react-services';
import {
  ListRecord,
  ListRecords,
  renderList,
} from '../../../../../../common/ciscat/store';
import {
  existingLists,
  readList,
  writeList,
} from '../../../sca/ciscat/lib/lists-api';
import { editAgentConf } from './agent-conf';
import { AgentInfo, GroupConf, GroupStep, toGroupConf } from './plan';
import { isWithin } from './path-checks';

/** Part of GET /agents/{id}/config/syscheck/syscheck used here. */
export interface ActiveSyscheck {
  directories?: Array<{ dir?: string; directory?: string; opts?: string[] }>;
  registry?: Array<{ entry?: string; key?: string; arch?: string }>;
  windows_registry?: Array<{ entry?: string; key?: string; arch?: string }>;
}

/* eslint-disable camelcase */ // Wazuh API field names

export const HISTORY_LIST = 'fim-history';
/** Versions kept per group. */
export const HISTORY_DEPTH = 10;
/** Versions kept in all, the oldest dropped first. */
export const HISTORY_MAX_ENTRIES = 300;
/**
 * Size of the fim-history file, well below the default upload limit of the
 * Wazuh server API (max_upload_size, 10 MiB): above it the previous version
 * could not be saved, and every change would be refused.
 */
export const HISTORY_MAX_BYTES = 4 * 1024 * 1024;

interface ApiResponse<T> {
  data?: { data?: { affected_items?: T[]; syscheck?: unknown } };
}

const items = <T>(response: unknown): T[] =>
  (response as ApiResponse<T>)?.data?.data?.affected_items || [];

export const readAgentConf = async (group: string): Promise<string> => {
  const response = await WzRequest.apiReq(
    'GET',
    // same request as the groups editor of Server management
    `/groups/${encodeURIComponent(group)}/files/agent.conf?raw=true`,
    { params: { raw: true } },
  );
  const data = response?.data;
  return typeof data === 'string' ? data : String(data ?? '');
};

const writeAgentConf = (group: string, content: string) =>
  WzRequest.apiReq(
    'PUT',
    `/groups/${encodeURIComponent(group)}/configuration`,
    // origin 'xmleditor' makes the server send it as application/xml; the
    // manager validates the file before accepting it.
    { body: content, origin: 'xmleditor' },
  );

export interface GroupInfo {
  name: string;
  count: number;
  /** Checksum of the group's agent.conf, when the API returns it. */
  configSum?: string;
}

export const fetchGroups = async (): Promise<GroupInfo[]> =>
  items<{ name: string; count?: number; configSum?: string }>(
    await WzRequest.apiReq('GET', '/groups', {
      params: { limit: 100000 },
    }),
  ).map(g => ({
    name: g.name,
    count: g.count || 0,
    configSum: g.configSum || undefined,
  }));

// Groups are read in small batches and changes are applied one group at a
// time, in order, so that a failure leaves the remaining groups untouched.
/* eslint-disable no-await-in-loop */

/** Parsed agent.conf by group, reused while the group's checksum is the same. */
const confCache = new Map<string, { sum: string; conf: GroupConf }>();

export const clearGroupConfCache = () => confCache.clear();

/**
 * Every group with its parsed agent.conf, read a few at a time. A group whose
 * checksum did not change since the previous load is not read again.
 */
export const loadGroupConfs = async (
  groups: Array<Pick<GroupInfo, 'name' | 'configSum'>>,
): Promise<Record<string, GroupConf>> => {
  const out: Record<string, GroupConf> = {};
  const toRead = groups.filter(({ name, configSum }) => {
    const cached = confCache.get(name);
    if (configSum && cached?.sum === configSum) {
      out[name] = cached.conf;
      return false;
    }
    return true;
  });
  for (let i = 0; i < toRead.length; i += 8) {
    await Promise.all(
      toRead.slice(i, i + 8).map(async ({ name, configSum }) => {
        try {
          out[name] = toGroupConf(name, await readAgentConf(name));
          if (configSum && !out[name].error) {
            confCache.set(name, { sum: configSum, conf: out[name] });
          }
        } catch (error) {
          confCache.delete(name);
          out[name] = {
            name,
            raw: '',
            rules: [],
            error: `cannot read agent.conf: ${
              (error as Error).message || error
            }`,
          };
        }
      }),
    );
  }
  const known = new Set(groups.map(g => g.name));
  [...confCache.keys()]
    .filter(name => !known.has(name))
    .forEach(name => confCache.delete(name));
  return out;
};

interface RawAgent {
  id: string;
  name?: string;
  status?: string;
  os?: { platform?: string };
  group?: string[];
  group_config_status?: string;
}

export const fetchAgents = async (): Promise<AgentInfo[]> =>
  items<RawAgent>(
    await WzRequest.apiReq('GET', '/agents', {
      params: {
        select: 'id,name,status,os.platform,group,group_config_status',
        q: 'id!=000',
        limit: 100000,
      },
    }),
  ).map(a => ({
    id: String(a.id),
    name: String(a.name || ''),
    status: String(a.status || ''),
    platform: String(a.os?.platform || ''),
    groups: Array.isArray(a.group) ? a.group : [],
    configStatus: String(a.group_config_status || ''),
  }));

/** The syscheck configuration the agent is running (agent must be active). */
export const fetchActiveSyscheck = async (
  agentId: string,
): Promise<ActiveSyscheck> => {
  const response = await WzRequest.apiReq(
    'GET',
    `/agents/${agentId}/config/syscheck/syscheck`,
    {},
  );
  return ((response as ApiResponse<never>)?.data?.data?.syscheck ||
    {}) as ActiveSyscheck;
};

// --- path test (FIM inventory) ----------------------------------------------------

export interface PathTestResult {
  agent: AgentInfo;
  /** Entries of the FIM inventory under the path, undefined on error. */
  files?: number;
  /** More entries may exist under the path than the ones counted. */
  more?: boolean;
  lastScan?: string;
  error?: string;
}

/** Characters with a meaning in the q filter of the Wazuh API. */
const escapeQuery = (value: string) => value.replace(/([,;()\\])/g, '\\$1');

/** Inventory entries read per agent to count those under the path. */
export const PATH_TEST_SAMPLE = 500;
/** Agents tested at the same time. */
export const PATH_TEST_CONCURRENCY = 3;

/** Maps `values` with at most `limit` calls of `fn` running at once. */
export const mapLimited = async <T, R>(
  values: T[],
  limit: number,
  fn: (value: T) => Promise<R>,
): Promise<R[]> => {
  const out: R[] = new Array(values.length);
  let next = 0;
  const worker = async () => {
    while (next < values.length) {
      const index = next++;
      out[index] = await fn(values[index]);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, values.length) }, worker),
  );
  return out;
};

const testPathOnAgent = async (
  prefix: string,
  agent: AgentInfo,
): Promise<PathTestResult> => {
  try {
    const [inventory, scan] = await Promise.all([
      // "~" matches anywhere in the path: the entries are filtered below
      WzRequest.apiReq('GET', `/syscheck/${agent.id}`, {
        params: {
          q: `file~${escapeQuery(prefix)}`,
          limit: PATH_TEST_SAMPLE,
          select: 'file',
        },
      }),
      WzRequest.apiReq('GET', `/syscheck/${agent.id}/last_scan`, {}),
    ]);
    const entries = items<{ file?: string }>(inventory);
    const total =
      (inventory as { data?: { data?: { total_affected_items?: number } } })
        ?.data?.data?.total_affected_items || entries.length;
    const files = entries.filter(e =>
      isWithin(String(e.file || ''), prefix),
    ).length;
    const last = items<{ end?: string }>(scan)[0];
    return {
      agent,
      files,
      more: total > entries.length,
      lastScan: last?.end || '',
    };
  } catch (error) {
    return { agent, error: (error as Error).message || String(error) };
  }
};

/**
 * How many entries of each agent's FIM inventory are under a path, and when the
 * agent last finished a scan: whether the path exists and is monitored there.
 */
export const testPathOnAgents = (
  prefix: string,
  agents: AgentInfo[],
): Promise<PathTestResult[]> =>
  mapLimited(agents, PATH_TEST_CONCURRENCY, agent =>
    testPathOnAgent(prefix, agent),
  );

// --- history -------------------------------------------------------------------

export interface HistoryEntry {
  key: string;
  group: string;
  content: string;
  by: string;
  at: string;
  note: string;
}

export const readHistory = async (): Promise<HistoryEntry[]> => {
  const list = await readList(HISTORY_LIST, await existingLists(HISTORY_LIST));
  return Object.entries(list.records)
    .filter(([key]) => !key.startsWith('_'))
    .map(([key, r]) => ({
      key,
      group: String(r.g || ''),
      content: String(r.x || ''),
      by: String(r.by || ''),
      at: String(r.at || ''),
      note: String(r.note || ''),
    }))
    .sort((a, b) => b.at.localeCompare(a.at));
};

const historyKey = (at: string) =>
  `h${at.replace(/\D/g, '')}${Math.random().toString(36).slice(2, 6)}`;

type HistoryRecord = [string, ListRecord];

const byNewest = (a: HistoryRecord, b: HistoryRecord) =>
  String(b[1].at).localeCompare(String(a[1].at));

/**
 * The history with `keep` added, then trimmed: the last HISTORY_DEPTH versions
 * of each group, at most HISTORY_MAX_ENTRIES in all, and a file of at most
 * HISTORY_MAX_BYTES. The oldest versions go first; `keep` is never dropped.
 */
export const pruneHistory = (
  records: ListRecords,
  keep: string,
): ListRecords => {
  const perGroup = new Map<unknown, number>();
  const room = HISTORY_MAX_ENTRIES - (keep in records ? 1 : 0);
  let others = 0;
  const kept = Object.entries(records)
    .filter(([key]) => key !== '_empty')
    .sort(byNewest)
    .filter(([key, r]) => {
      const seen = (perGroup.get(r.g) || 0) + 1;
      perGroup.set(r.g, seen);
      return key === keep || seen <= HISTORY_DEPTH;
    })
    .filter(([key]) => key === keep || ++others <= room);
  const out = Object.fromEntries(kept);
  const droppable = kept.map(([key]) => key).filter(key => key !== keep);
  while (droppable.length && renderList(out).length > HISTORY_MAX_BYTES) {
    delete out[droppable.pop() as string];
  }
  return out;
};

/** Stores the version a group had before a change; keeps the last few. */
const saveHistory = async (
  group: string,
  content: string,
  by: string,
  note: string,
) => {
  const list = await readList(HISTORY_LIST, await existingLists(HISTORY_LIST));
  const at = new Date().toISOString();
  const key = historyKey(at);
  const records = pruneHistory(
    { ...list.records, [key]: { v: 1, g: group, x: content, by, at, note } },
    key,
  );
  await writeList(HISTORY_LIST, records, list.exists ? list.raw : undefined);
};

// --- applying a plan ---------------------------------------------------------------

export class ConcurrentConfChange extends Error {}

export interface StepResult {
  group: string;
  done: string[];
}

const applyStep = async (
  step: GroupStep,
  user: string,
  note: string,
  done: string[],
) => {
  if (step.create) {
    await WzRequest.apiReq('POST', '/groups', { group_id: step.group });
    done.push('group created');
    const fresh = await readAgentConf(step.group);
    await writeAgentConf(
      step.group,
      step.edit ? editAgentConf(fresh, step.edit) : step.after,
    );
    done.push('agent.conf written');
  } else {
    const fresh = await readAgentConf(step.group);
    if (fresh !== step.before) {
      throw new ConcurrentConfChange(
        `${step.group}: agent.conf was changed by someone else since the ` +
          'preview. Reload and try again.',
      );
    }
    await saveHistory(step.group, fresh, user, note);
    done.push('previous version saved');
    if (step.deleteGroup) {
      await WzRequest.apiReq('DELETE', '/groups', {
        params: { groups_list: step.group },
      });
      done.push('group deleted');
    } else {
      await writeAgentConf(step.group, step.after);
      done.push('agent.conf written');
    }
  }
  if (step.assign) {
    await WzRequest.apiReq(
      'PUT',
      `/agents/${step.assign}/group/${encodeURIComponent(step.group)}`,
      {},
    );
    done.push(`agent ${step.assign} added`);
  }
};

/**
 * Applies the steps one group at a time. Before writing, the group's
 * agent.conf is read again and the step is refused if it changed since the
 * preview; the previous version is saved to the history first. A failure
 * stops the plan: the following groups are not touched.
 */
export const applyPlan = async (
  steps: GroupStep[],
  user: string,
  note: string,
  onProgress?: (result: StepResult) => void,
): Promise<StepResult[]> => {
  const results: StepResult[] = [];
  for (const step of steps) {
    const result: StepResult = { group: step.group, done: [] };
    results.push(result);
    try {
      await applyStep(step, user, note, result.done);
    } catch (error) {
      // what was done before the failure is still reported
      if (result.done.length) {
        onProgress?.(result);
      }
      if (error instanceof ConcurrentConfChange) {
        throw error;
      }
      throw new Error(
        `${step.group}: ${(error as Error)?.message || String(error)}`,
      );
    }
    onProgress?.(result);
  }
  return results;
};
/* eslint-enable no-await-in-loop */
