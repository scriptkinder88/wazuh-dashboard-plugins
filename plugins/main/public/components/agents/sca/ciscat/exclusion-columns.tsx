/*
 * Columns of the controls table of the exclusions panel.
 */
import React from 'react';
import {
  EuiBadge,
  EuiButtonIcon,
  EuiCheckbox,
  EuiFlexGroup,
  EuiFlexItem,
  EuiToolTip,
} from '@elastic/eui';
import { RuleRow, describeScope } from './lib/composer';

export const ruleColumns = ({
  selected,
  toggle,
  removeExclusion,
  exclude,
}: {
  selected: Set<string>;
  toggle: (rule: string) => void;
  removeExclusion: (key: string) => void;
  /** Opens the exclusion flyout for these controls. */
  exclude: (rules: string[]) => void;
}) => [
  {
    field: 'rule',
    name: '',
    width: '36px',
    render: (rule: string, row: RuleRow) => (
      <EuiCheckbox
        id={`ciscat-select-${rule}`}
        checked={selected.has(rule)}
        disabled={!row.applicable}
        onChange={() => toggle(rule)}
        aria-label={`Select ${rule}`}
      />
    ),
  },
  {
    field: 'rule',
    name: 'CIS',
    width: '100px',
    render: (rule: string) => <strong>{rule}</strong>,
  },
  {
    field: 'title',
    name: 'Control',
    render: (title: string, row: RuleRow) => (
      <span>
        {title}{' '}
        {row.manual && (
          <EuiToolTip content='Manual control: CIS-CAT does not assess it, so it is never scored'>
            <EuiBadge color='hollow'>manual</EuiBadge>
          </EuiToolTip>
        )}
        {!row.applicable && <EuiBadge color='hollow'>not in profile</EuiBadge>}
      </span>
    ),
  },
  {
    field: 'exclusions',
    name: 'Excluded for',
    width: '32%',
    render: (list: RuleRow['exclusions']) => (
      <EuiFlexGroup gutterSize='xs' wrap responsive={false}>
        {list.map(({ key, exclusion }) => (
          <EuiFlexItem grow={false} key={key}>
            <EuiToolTip
              content={`${exclusion.reason} · ticket ${exclusion.ticket}${
                exclusion.updated_by ? ` · ${exclusion.updated_by}` : ''
              }`}
            >
              <EuiBadge
                color={
                  ['os', 'global'].includes(exclusion.scope)
                    ? 'warning'
                    : 'default'
                }
                iconType='cross'
                iconSide='right'
                iconOnClick={() => removeExclusion(key)}
                iconOnClickAriaLabel='Remove exclusion'
              >
                {describeScope(exclusion)}
              </EuiBadge>
            </EuiToolTip>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>
    ),
  },
  {
    name: '',
    width: '48px',
    render: (row: RuleRow) => (
      <EuiButtonIcon
        iconType='minusInCircle'
        aria-label={`Exclude ${row.rule}`}
        title='Exclude…'
        isDisabled={!row.applicable}
        onClick={() => exclude([row.rule])}
      />
    ),
  },
];
