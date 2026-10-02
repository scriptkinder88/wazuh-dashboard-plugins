/*
 * Every FIM rule found in the groups' agent.conf, with the groups and servers
 * it applies to. Rules can be added, changed and removed from here.
 */
import React, { useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiInMemoryTable,
  EuiButton,
  EuiButtonIcon,
  EuiCallOut,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { KIND_LABELS } from './lib/agent-conf';
import { AgentInfo, GroupConf, RuleRow } from './lib/plan';

const optionBadges = (row: RuleRow) => {
  const a = row.rule.attrs;
  const out: string[] = [];
  if (a.whodata === 'yes') {
    out.push('who-data');
  } else if (a.realtime === 'yes') {
    out.push('real time');
  }
  if (a.report_changes === 'yes') {
    out.push('report changes');
  }
  if (a.type) {
    out.push(a.type);
  }
  if (a.recursion_level) {
    out.push(`recursion ${a.recursion_level}`);
  }
  if (a.restrict) {
    out.push(`restrict ${a.restrict}`);
  }
  if (a.arch) {
    out.push(a.arch);
  }
  if (a.tags) {
    out.push(...a.tags.split(',').map(t => `tag ${t}`));
  }
  return out;
};

const filterText = (row: RuleRow) =>
  Object.entries(row.rule.filter)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');

export const RulesPanel = ({
  rows,
  groups,
  agents,
  onAdd,
  onEdit,
  onRemove,
}: {
  rows: RuleRow[];
  groups: Record<string, GroupConf>;
  agents: AgentInfo[];
  onAdd: () => void;
  onEdit: (row: RuleRow) => void;
  onRemove: (row: RuleRow) => void;
}) => {
  const [search, setSearch] = useState('');
  const agentName = (id: string) => agents.find(a => a.id === id)?.name || id;
  const unreadable = Object.values(groups).filter(g => g.error);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) {
      return rows;
    }
    return rows.filter(row =>
      [
        row.rule.path,
        KIND_LABELS[row.rule.kind],
        filterText(row),
        ...row.groups,
        ...row.hostIds.map(agentName),
        ...optionBadges(row),
        row.rule.meta?.reason || '',
        row.rule.meta?.ticket || '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [rows, search, agents]);

  const columns = [
    {
      name: 'Type',
      width: '130px',
      render: (row: RuleRow) => KIND_LABELS[row.rule.kind],
    },
    {
      name: 'Path',
      render: (row: RuleRow) => (
        <div>
          <code>{row.rule.path}</code>
          {filterText(row) && (
            <>
              {' '}
              <EuiBadge color='hollow'>{filterText(row)}</EuiBadge>
            </>
          )}
        </div>
      ),
    },
    {
      name: 'Options',
      render: (row: RuleRow) =>
        optionBadges(row).map(b => (
          <EuiBadge key={b} color='default'>
            {b}
          </EuiBadge>
        )),
    },
    {
      name: 'Applies to',
      render: (row: RuleRow) => (
        <div>
          {row.groups.map(g => (
            <EuiBadge key={`g${g}`} color='primary'>
              {g}
            </EuiBadge>
          ))}
          {row.hostIds.map(id => (
            <EuiBadge key={`h${id}`} color='accent' iconType='storage'>
              {agentName(id)}
            </EuiBadge>
          ))}
        </div>
      ),
    },
    {
      name: 'Audit',
      render: (row: RuleRow) => {
        const meta = row.rule.meta;
        if (!meta) {
          return (
            <EuiText size='xs' color='subdued'>
              Imported (no audit data)
            </EuiText>
          );
        }
        return (
          <EuiText size='xs'>
            {meta.reason}
            {meta.ticket ? ` · ${meta.ticket}` : ''}
            <br />
            <span style={{ opacity: 0.7 }}>
              {meta.by || 'unknown'} · {meta.at.slice(0, 16).replace('T', ' ')}
              {meta.owner ? ` · owner ${meta.owner}` : ''}
            </span>
          </EuiText>
        );
      },
    },
    {
      name: 'Actions',
      width: '80px',
      render: (row: RuleRow) => (
        <div>
          <EuiToolTip content='Change'>
            <EuiButtonIcon
              iconType='pencil'
              aria-label='Change'
              onClick={() => onEdit(row)}
              data-test-subj='fim-rule-edit'
            />
          </EuiToolTip>
          <EuiToolTip content='Remove'>
            <EuiButtonIcon
              iconType='trash'
              color='danger'
              aria-label='Remove'
              onClick={() => onRemove(row)}
              data-test-subj='fim-rule-remove'
            />
          </EuiToolTip>
        </div>
      ),
    },
  ];

  return (
    <>
      {unreadable.length > 0 && (
        <>
          <EuiCallOut
            color='warning'
            iconType='alert'
            title='Some groups cannot be managed here'
          >
            <ul>
              {unreadable.map(g => (
                <li key={g.name}>
                  {g.name}: {g.error}
                </li>
              ))}
            </ul>
          </EuiCallOut>
          <EuiSpacer size='m' />
        </>
      )}
      <EuiFlexGroup gutterSize='s' responsive={false}>
        <EuiFlexItem>
          <EuiFieldSearch
            fullWidth
            placeholder='Path, group, server, tag, reason…'
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            fill
            iconType='plusInCircle'
            onClick={onAdd}
            data-test-subj='fim-rule-add'
          >
            Add rule
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      <EuiInMemoryTable
        items={shown}
        pagination={true}
        itemId='key'
        columns={columns}
        message='No FIM rules in the groups yet'
        data-test-subj='fim-rules-table'
      />
    </>
  );
};
