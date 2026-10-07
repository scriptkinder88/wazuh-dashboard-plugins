/*
 * Agents and their FIM groups: whether each one runs the latest group
 * configuration, and what syscheck configuration it actually has, including
 * paths that come from its local ossec.conf.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiInMemoryTable,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFieldSearch,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiHealth,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { AgentInfo, GroupConf, hostGroup } from './lib/plan';
import { isMonitorKind } from './lib/agent-conf';
import { ActiveSyscheck, fetchActiveSyscheck } from './lib/fim-api';
import { WzButtonPermissions } from '../../../common/permissions/button';
import { FIM_WRITE_PERMISSIONS } from './lib/permissions';
import { messages } from './messages';

export interface ActivePath {
  kind: 'directories' | 'windows_registry';
  path: string;
  options: string[];
  /** Groups of the agent that define this path; empty means local. */
  groups: string[];
}

const normalize = (path: string, windows: boolean) => {
  const p = path.trim().replace(/[\\/]+$/, '');
  return windows ? p.toLowerCase() : p;
};

/** The active syscheck paths of an agent, each with the groups defining it. */
export const activePaths = (
  syscheck: ActiveSyscheck,
  agent: AgentInfo,
  groups: Record<string, GroupConf>,
): ActivePath[] => {
  const windows = /windows/i.test(agent.platform);
  const defined = new Map<string, string[]>();
  agent.groups.forEach(group => {
    (groups[group]?.rules || [])
      .filter(r => isMonitorKind(r.kind))
      .forEach(r =>
        r.path.split(',').forEach(p => {
          const key = `${r.kind}|${normalize(p, windows)}`;
          defined.set(key, [...(defined.get(key) || []), group]);
        }),
      );
  });
  const entries: ActivePath[] = [];
  (syscheck?.directories || []).forEach(d => {
    const path = String(d?.dir ?? d?.directory ?? '');
    entries.push({
      kind: 'directories',
      path,
      options: Array.isArray(d?.opts) ? d.opts : [],
      groups: defined.get(`directories|${normalize(path, windows)}`) || [],
    });
  });
  (syscheck?.registry || syscheck?.windows_registry || []).forEach(r => {
    const path = String(r?.entry ?? r?.key ?? '');
    entries.push({
      kind: 'windows_registry',
      path,
      options: r?.arch ? [r.arch] : [],
      groups: defined.get(`windows_registry|${normalize(path, windows)}`) || [],
    });
  });
  return entries;
};

const ActiveConfigFlyout = ({
  agent,
  groups,
  onClose,
  onIgnore,
}: {
  agent: AgentInfo;
  groups: Record<string, GroupConf>;
  onClose: () => void;
  onIgnore: (agent: AgentInfo, path: ActivePath) => void;
}) => {
  const [paths, setPaths] = useState<ActivePath[]>();
  const [error, setError] = useState('');
  useEffect(() => {
    fetchActiveSyscheck(agent.id)
      .then(syscheck => setPaths(activePaths(syscheck, agent, groups)))
      .catch(e => setError((e as Error).message || String(e)));
  }, [agent, groups]);

  return (
    <EuiFlyout
      onClose={onClose}
      size='m'
      ownFocus
      data-test-subj='fim-active-flyout'
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size='s'>
          <h3>{messages.activeTitle(agent.name, agent.id)}</h3>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiText size='s' color='subdued'>
          <p>{messages.activeDescription()}</p>
        </EuiText>
        <EuiSpacer size='m' />
        {error && (
          <EuiCallOut color='danger' title={messages.cannotReadActive()}>
            <p>{error}</p>
            <p>{messages.agentMustBeActive()}</p>
          </EuiCallOut>
        )}
        {!paths && !error && <EuiLoadingSpinner size='l' />}
        {paths && (
          <EuiBasicTable
            items={paths}
            columns={[
              {
                name: messages.columnPath(),
                render: (p: ActivePath) => <code>{p.path}</code>,
              },
              {
                name: messages.columnOptions(),
                render: (p: ActivePath) => (
                  <EuiText size='xs'>{p.options.join(', ')}</EuiText>
                ),
              },
              {
                name: messages.columnSource(),
                render: (p: ActivePath) =>
                  p.groups.length ? (
                    p.groups.map(g => (
                      <EuiBadge key={g} color='primary'>
                        {g}
                      </EuiBadge>
                    ))
                  ) : (
                    <EuiBadge color='warning'>{messages.local()}</EuiBadge>
                  ),
              },
              {
                name: '',
                width: '170px',
                render: (p: ActivePath) =>
                  !p.groups.length && (
                    <WzButtonPermissions
                      buttonType='empty'
                      permissions={FIM_WRITE_PERMISSIONS}
                      size='xs'
                      iconType='eyeClosed'
                      onClick={() => onIgnore(agent, p)}
                      data-test-subj='fim-ignore-local'
                    >
                      {messages.ignoreOnServer()}
                    </WzButtonPermissions>
                  ),
              },
            ]}
            noItemsMessage={messages.noMonitoredPaths()}
          />
        )}
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};

export const AgentsPanel = ({
  agents,
  groups,
  onIgnore,
}: {
  agents: AgentInfo[];
  groups: Record<string, GroupConf>;
  onIgnore: (agent: AgentInfo, path: ActivePath) => void;
}) => {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<AgentInfo>();
  const fimGroups = (a: AgentInfo) =>
    a.groups.filter(g => groups[g]?.rules.length);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter(
      a =>
        !q ||
        [a.name, a.id, a.platform, ...a.groups]
          .join(' ')
          .toLowerCase()
          .includes(q),
    );
  }, [agents, search]);

  return (
    <>
      <EuiFieldSearch
        fullWidth
        placeholder={messages.agentsSearch()}
        value={search}
        onChange={e => setSearch(e.target.value)}
      />
      <EuiSpacer size='m' />
      <EuiInMemoryTable
        items={shown}
        pagination={true}
        itemId='id'
        data-test-subj='fim-agents-table'
        columns={[
          {
            name: messages.columnServer(),
            render: (a: AgentInfo) => `${a.name} (${a.id})`,
          },
          {
            name: messages.columnStatus(),
            width: '120px',
            render: (a: AgentInfo) => (
              <EuiHealth color={a.status === 'active' ? 'success' : 'subdued'}>
                {a.status}
              </EuiHealth>
            ),
          },
          {
            name: messages.columnPlatform(),
            width: '110px',
            render: (a: AgentInfo) => a.platform,
          },
          {
            name: messages.columnFimGroups(),
            render: (a: AgentInfo) =>
              fimGroups(a).map(g => (
                <EuiBadge
                  key={g}
                  color={g === hostGroup(a.id) ? 'accent' : 'primary'}
                >
                  {g}
                </EuiBadge>
              )),
          },
          {
            name: messages.columnConfiguration(),
            width: '130px',
            render: (a: AgentInfo) =>
              a.configStatus === 'synced' ? (
                <EuiHealth color='success'>{messages.synced()}</EuiHealth>
              ) : (
                <EuiHealth color='warning'>
                  {a.configStatus || messages.unknownStatus()}
                </EuiHealth>
              ),
          },
          {
            name: '',
            width: '150px',
            render: (a: AgentInfo) => (
              <EuiButtonEmpty
                size='xs'
                iconType='inspect'
                onClick={() => setSelected(a)}
                isDisabled={a.status !== 'active'}
                data-test-subj='fim-agent-active'
              >
                {messages.activeConfig()}
              </EuiButtonEmpty>
            ),
          },
        ]}
        message={messages.noAgents()}
      />
      {selected && (
        <ActiveConfigFlyout
          agent={selected}
          groups={groups}
          onClose={() => setSelected(undefined)}
          onIgnore={(agent, path) => {
            setSelected(undefined);
            onIgnore(agent, path);
          }}
        />
      )}
    </>
  );
};
