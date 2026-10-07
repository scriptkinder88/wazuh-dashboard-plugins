/*
 * "Manage" tab of Integrity monitoring: FIM rules (paths, registry keys and
 * exclusions) for groups and single servers, edited in the groups' agent.conf
 * through the Wazuh API. Only the <syscheck> rules are touched; every change is
 * previewed, and the previous version of each file is kept in fim-history.
 */
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { getToasts } from '../../../../kibana-services';
import { fetchCurrentUserName } from '../../sca/ciscat/lib/lists-api';
import {
  HistoryEntry,
  fetchAgents,
  fetchGroups,
  loadGroupConfs,
  readHistory,
} from './lib/fim-api';
import {
  AgentInfo,
  DEFAULT_AGENT_CONF,
  GroupConf,
  GroupStep,
  RuleChange,
  RuleRow,
  affectedAgents,
  aggregateRules,
  buildPlan,
  findConflicts,
  hostOfGroup,
} from './lib/plan';
import { RulesPanel } from './rules-panel';
import { RuleFlyout } from './rule-flyout';
import { isTerraformManaged } from './lib/path-checks';
import { PlanModal } from './plan-modal';
import { ActivePath, AgentsPanel } from './agents-panel';
import { HistoryPanel } from './history-panel';

interface FimData {
  groups: Record<string, GroupConf>;
  agents: AgentInfo[];
  history: HistoryEntry[];
}

interface PendingPlan {
  title: string;
  steps: GroupStep[];
  /** The plan restores a saved version. */
  restore?: boolean;
}

type TabId = 'rules' | 'agents' | 'history';

const TABS: Array<{ id: TabId; name: string }> = [
  { id: 'rules', name: 'Rules' },
  { id: 'agents', name: 'Agents' },
  { id: 'history', name: 'History' },
];

export const FimManagement = () => {
  const [tab, setTab] = useState<TabId>('rules');
  const [data, setData] = useState<FimData>();
  const [user, setUser] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<{ row?: RuleRow; preset?: RuleRow }>();
  const [plan, setPlan] = useState<PendingPlan>();

  // only the latest load updates the state, and none after unmounting
  const loadId = useRef(0);
  useEffect(
    () => () => {
      loadId.current = -1;
    },
    [],
  );

  const load = useCallback(async () => {
    const id = ++loadId.current;
    const current = () => loadId.current === id;
    setLoading(true);
    setError('');
    try {
      const [groupList, agents, history] = await Promise.all([
        fetchGroups(),
        fetchAgents(),
        readHistory(),
      ]);
      const groups = await loadGroupConfs(groupList);
      if (current()) {
        setData({ groups, agents, history });
      }
    } catch (e) {
      if (current()) {
        setError((e as Error).message || String(e));
      }
    } finally {
      if (current()) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    load();
    fetchCurrentUserName().then(name => {
      if (loadId.current >= 0) {
        setUser(name);
      }
    });
  }, [load]);

  const rows = useMemo(
    () => (data ? aggregateRules(Object.values(data.groups)) : []),
    [data],
  );
  const groupNames = useMemo(
    () =>
      Object.keys(data?.groups || {})
        .filter(g => !hostOfGroup(g))
        .sort(),
    [data],
  );

  const managedGroups = useMemo(
    () =>
      Object.values(data?.groups || {})
        .filter(g => isTerraformManaged(g.raw || ''))
        .map(g => g.name),
    [data],
  );

  const review = (title: string, change: RuleChange) => {
    try {
      setPlan({ title, steps: buildPlan(data!.groups, data!.agents, change) });
      setEditing(undefined);
    } catch (e) {
      getToasts().addDanger({
        title: 'This change cannot be prepared',
        text: (e as Error).message || String(e),
      });
    }
  };

  const restore = (entry: HistoryEntry) => {
    const current = data!.groups[entry.group];
    const host = hostOfGroup(entry.group);
    const agent = host && data!.agents.find(a => a.id === host);
    const when = entry.at.slice(0, 16).replace('T', ' ');
    const step: GroupStep = {
      group: entry.group,
      create: !current,
      deleteGroup: false,
      assign:
        agent && !agent.groups.includes(entry.group) ? agent.id : undefined,
      before: current ? current.raw : DEFAULT_AGENT_CONF,
      after: entry.content,
    };
    setPlan({
      title: `Restore ${entry.group} as of ${when}`,
      steps: current?.raw === entry.content ? [] : [step],
      restore: true,
    });
  };

  const ignoreLocal = (agent: AgentInfo, path: ActivePath) =>
    setEditing({
      preset: {
        key: '',
        rule: {
          kind: path.kind === 'windows_registry' ? 'registry_ignore' : 'ignore',
          path: path.path,
          attrs: {},
          filter: {},
        },
        groups: [],
        hostIds: [agent.id],
      },
    });

  return (
    <EuiPanel paddingSize='m' data-test-subj='fim-management'>
      <EuiFlexGroup alignItems='center' gutterSize='s' responsive={false}>
        <EuiFlexItem>
          <EuiTitle size='s'>
            <h2>FIM rules</h2>
          </EuiTitle>
          <EuiText size='xs' color='subdued'>
            Paths and registry keys monitored on groups of agents or on single
            servers. Changes are written to the groups&apos; agent.conf; agents
            apply them within a few minutes.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty
            iconType='refresh'
            onClick={load}
            isLoading={loading}
            data-test-subj='fim-reload'
          >
            Reload
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='s' />
      <EuiTabs size='s'>
        {TABS.map(t => (
          <EuiTab
            key={t.id}
            isSelected={tab === t.id}
            onClick={() => setTab(t.id)}
            data-test-subj={`fim-tab-${t.id}`}
          >
            {t.name}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size='m' />
      {error && (
        <>
          <EuiCallOut color='danger' iconType='alert' title='FIM rules'>
            <p>{error}</p>
          </EuiCallOut>
          <EuiSpacer size='m' />
        </>
      )}
      {!data && loading && <EuiLoadingSpinner size='l' />}
      {data && tab === 'rules' && (
        <RulesPanel
          rows={rows}
          groups={data.groups}
          agents={data.agents}
          onAdd={() => setEditing({})}
          onEdit={row => setEditing({ row })}
          onRemove={row =>
            review(`Remove ${row.rule.kind} ${row.rule.path}`, { before: row })
          }
        />
      )}
      {data && tab === 'agents' && (
        <AgentsPanel
          agents={data.agents}
          groups={data.groups}
          onIgnore={ignoreLocal}
        />
      )}
      {data && tab === 'history' && (
        <HistoryPanel entries={data.history} onRestore={restore} />
      )}
      {data && editing && (
        <RuleFlyout
          row={editing.row}
          preset={editing.preset}
          groups={groupNames}
          agents={data.agents}
          rules={rows}
          managedGroups={managedGroups}
          user={user}
          onClose={() => setEditing(undefined)}
          onSubmit={change =>
            review(
              `${editing.row ? 'Change' : 'Add'} ${change.after!.rule.kind} ${
                change.after!.rule.path
              }`,
              change,
            )
          }
        />
      )}
      {data && plan && (
        <PlanModal
          title={plan.title}
          steps={plan.steps}
          agents={data.agents}
          affected={affectedAgents(data.agents, plan.steps)}
          conflicts={findConflicts(data.groups, data.agents, plan.steps)}
          user={user}
          restore={plan.restore}
          onClose={changed => {
            setPlan(undefined);
            if (changed) {
              load();
            }
          }}
        />
      )}
    </EuiPanel>
  );
};
