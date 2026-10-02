/*
 * Calls of the FIM manager: groups and their agent.conf and agents through the Wazuh server
 * API; the configuration an agent reported (wazuh-agent-config index) and the version history
 * kept by the dashboard in the indexer (dashboard store, collection fim-history). Wazuh 5.0 has
 * no CDB lists nor an agent configuration endpoint, which held these on 4.x.
 */
import { WzRequest } from '../../../../../react-services';
import {
  deleteStoreRecord,
  listStoreRecords,
  putStoreRecord,
} from '../../../../../services/dashboard-store';
import {
  clearAgentReportedConfigurationCache,
  getAgentReportedConfiguration,
} from '../../../../../controllers/management/components/management/configuration/utils/agent-config-service';
import { getDataPlugin } from '../../../../../kibana-services';
import { WAZUH_FIM_FILES_PATTERN } from '../../../../../../common/constants';
import { editAgentConf } from './agent-conf';
import { AgentInfo, GroupConf, GroupStep, toGroupConf } from './plan';

/** Part of the FIM (syscheck) configuration an agent reports, used here. */
export interface ActiveSyscheck {
  directories?: Array<{ dir?: string; directory?: string; opts?: string[] }>;
  registry?: Array<{ entry?: string; key?: string; arch?: string }>;
  windows_registry?: Array<{ entry?: string; key?: string; arch?: string }>;
}

/* eslint-disable camelcase */ // Wazuh API field names

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
}

export const fetchAgents = async (): Promise<AgentInfo[]> =>
  items<RawAgent>(
    await WzRequest.apiReq('GET', '/agents', {
      params: {
        select: 'id,name,status,os.platform,group',
        limit: 100000,
      },
    }),
  ).map(a => ({
    id: String(a.id),
    name: String(a.name || ''),
    status: String(a.status || ''),
    platform: String(a.os?.platform || ''),
    groups: Array.isArray(a.group) ? a.group : [],
    // Wazuh 5.0 does not report whether an agent runs its groups' latest configuration
    configStatus: '',
  }));

export interface ReportedSyscheck {
  syscheck: ActiveSyscheck;
  /** When the agent last reported its configuration; undefined when it never did. */
  reportedAt?: string;
}

/**
 * The FIM configuration the agent last reported. Agents report it only when configuration
 * reporting is enabled on them; `reportedAt` is undefined otherwise.
 */
export const fetchActiveSyscheck = async (
  agentId: string,
): Promise<ReportedSyscheck> => {
  clearAgentReportedConfigurationCache();
  const report = await getAgentReportedConfiguration(agentId);
  const fim = (report?.content?.fim || report?.content?.syscheck || {}) as {
    syscheck?: ActiveSyscheck;
  } & ActiveSyscheck;
  return {
    syscheck: fim.syscheck || fim,
    reportedAt: report ? report.modifiedAt || '' : undefined,
  };
};

// --- path test (FIM inventory) ----------------------------------------------------

export interface PathTestResult {
  agent: AgentInfo;
  /** Entries of the FIM inventory under the path, undefined on error. */
  files?: number;
  /** Most recent change of those entries (Wazuh 5.0 keeps no scan time). */
  lastChange?: string;
  error?: string;
}

interface InventoryResponse {
  hits?: { total?: number | { value?: number } };
  aggregations?: { last?: { value_as_string?: string } };
}

/**
 * How many entries of each agent's FIM inventory (wazuh-states-fim-files) are
 * under a path, and when the last of them changed: whether the path exists and
 * is monitored there.
 */
export const testPathOnAgents = (
  prefix: string,
  agents: AgentInfo[],
): Promise<PathTestResult[]> =>
  Promise.all(
    agents.map(async agent => {
      try {
        const indexPattern = await getDataPlugin().indexPatterns.get(
          WAZUH_FIM_FILES_PATTERN,
        );
        const searchSource = await getDataPlugin().search.searchSource.create();
        const response: InventoryResponse = await searchSource
          .setParent(undefined)
          .setField('index', indexPattern)
          .setField('size', 0)
          .setField('trackTotalHits', true)
          .setField('query', {
            language: 'lucene',
            query: {
              bool: {
                filter: [
                  { term: { 'wazuh.agent.id': agent.id } },
                  { prefix: { 'file.path': prefix } },
                ],
              },
            },
          })
          .setField('aggs', { last: { max: { field: 'state.modified_at' } } })
          .fetch();
        const total = response?.hits?.total;
        return {
          agent,
          files: Number(typeof total === 'number' ? total : total?.value || 0),
          lastChange: response?.aggregations?.last?.value_as_string || '',
        };
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

export const readHistory = async (): Promise<HistoryEntry[]> =>
  (
    await listStoreRecords<{ content?: string; note?: string }>('fim-history', {
      kind: 'history',
      size: 10000,
    })
  ).map(r => ({
    key: r.id,
    group: r.key,
    content: String(r.data.content || ''),
    by: r.updated_by,
    at: r.updated_at,
    note: String(r.data.note || ''),
  }));

const historyKey = (at: string) =>
  `h${at.replace(/\D/g, '')}${Math.random().toString(36).slice(2, 6)}`;

/** Stores the version a group had before a change; keeps the last few. */
const saveHistory = async (group: string, content: string, note: string) => {
  // who and when are recorded by the server
  await putStoreRecord('fim-history', {
    id: historyKey(new Date().toISOString()),
    kind: 'history',
    key: group,
    data: { content, note },
    create: true,
  });
  const versions = await listStoreRecords('fim-history', {
    kind: 'history',
    key: group,
    size: 1000,
  });
  for (const old of versions.slice(HISTORY_DEPTH)) {
    await deleteStoreRecord('fim-history', old.id);
  }
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
      await saveHistory(step.group, fresh, note);
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
