/*
 * Wazuh API calls of the FIM manager: groups and their agent.conf, agents,
 * the configuration active on an agent, and the version history kept in the
 * fim-history list. Nothing runs on the manager besides the Wazuh API.
 */
import { WzRequest } from '../../../../../react-services';
import { ListRecords } from '../../../../../../common/ciscat/store';
import {
  existingLists,
  readList,
  writeList,
} from '../../../sca/ciscat/lib/lists-api';
import { editAgentConf } from './agent-conf';
import { AgentInfo, GroupConf, GroupStep, toGroupConf } from './plan';

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

export const fetchGroups = async (): Promise<
  Array<{ name: string; count: number }>
> =>
  items<{ name: string; count?: number }>(
    await WzRequest.apiReq('GET', '/groups', {
      params: { select: 'name,count', limit: 100000 },
    }),
  ).map(g => ({
    name: g.name,
    count: g.count || 0,
  }));

// Groups are read in small batches and changes are applied one group at a
// time, in order, so that a failure leaves the remaining groups untouched.
/* eslint-disable no-await-in-loop */

/** Every group with its parsed agent.conf, read a few at a time. */
export const loadGroupConfs = async (
  names: string[],
): Promise<Record<string, GroupConf>> => {
  const out: Record<string, GroupConf> = {};
  for (let i = 0; i < names.length; i += 8) {
    await Promise.all(
      names.slice(i, i + 8).map(async name => {
        try {
          out[name] = toGroupConf(name, await readAgentConf(name));
        } catch (error) {
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
  lastScan?: string;
  error?: string;
}

/** Characters with a meaning in the q filter of the Wazuh API. */
const escapeQuery = (value: string) => value.replace(/([,;()\\])/g, '\\$1');

/**
 * How many entries of each agent's FIM inventory are under a path, and when the
 * agent last finished a scan: whether the path exists and is monitored there.
 */
export const testPathOnAgents = (
  prefix: string,
  agents: AgentInfo[],
): Promise<PathTestResult[]> =>
  Promise.all(
    agents.map(async agent => {
      try {
        const [inventory, scan] = await Promise.all([
          WzRequest.apiReq('GET', `/syscheck/${agent.id}`, {
            params: {
              q: `file~${escapeQuery(prefix)}`,
              limit: 1,
              select: 'file',
            },
          }),
          WzRequest.apiReq('GET', `/syscheck/${agent.id}/last_scan`, {}),
        ]);
        const total = (
          inventory as { data?: { data?: { total_affected_items?: number } } }
        )?.data?.data?.total_affected_items;
        const last = items<{ end?: string }>(scan)[0];
        return { agent, files: Number(total || 0), lastScan: last?.end || '' };
      } catch (error) {
        return { agent, error: (error as Error).message || String(error) };
      }
    }),
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

/** Stores the version a group had before a change; keeps the last few. */
const saveHistory = async (
  group: string,
  content: string,
  by: string,
  note: string,
) => {
  const list = await readList(HISTORY_LIST, await existingLists(HISTORY_LIST));
  const at = new Date().toISOString();
  const records: ListRecords = {
    ...Object.fromEntries(
      Object.entries(list.records).filter(([key]) => key !== '_empty'),
    ),
    [historyKey(at)]: { v: 1, g: group, x: content, by, at, note },
  };
  const ofGroup = Object.entries(records)
    .filter(([, r]) => r.g === group)
    .sort(([, a], [, b]) => String(b.at).localeCompare(String(a.at)));
  ofGroup.slice(HISTORY_DEPTH).forEach(([key]) => delete records[key]);
  await writeList(HISTORY_LIST, records, list.exists ? list.raw : undefined);
};

// --- applying a plan ---------------------------------------------------------------

export class ConcurrentConfChange extends Error {}

export interface StepResult {
  group: string;
  done: string[];
}

/**
 * Applies the steps one group at a time. Before writing, the group's
 * agent.conf is read again and the step is refused if it changed since the
 * preview; the previous version is saved to the history first.
 */
export const applyPlan = async (
  steps: GroupStep[],
  user: string,
  note: string,
  onProgress?: (result: StepResult) => void,
): Promise<StepResult[]> => {
  const results: StepResult[] = [];
  for (const step of steps) {
    const done: string[] = [];
    const result = { group: step.group, done };
    results.push(result);
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
    onProgress?.(result);
  }
  return results;
};
/* eslint-enable no-await-in-loop */
