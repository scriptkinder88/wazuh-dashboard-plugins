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
import { messages } from './messages';

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
        aria-label={messages.selectControl(rule)}
      />
    ),
  },
  {
    field: 'rule',
    name: messages.columnCis(),
    width: '100px',
    render: (rule: string) => <strong>{rule}</strong>,
  },
  {
    field: 'title',
    name: messages.columnControl(),
    render: (title: string, row: RuleRow) => (
      <span>
        {title}{' '}
        {row.manual && (
          <EuiToolTip content={messages.manualHelp()}>
            <EuiBadge color='hollow'>{messages.manual()}</EuiBadge>
          </EuiToolTip>
        )}
        {!row.applicable && (
          <EuiBadge color='hollow'>{messages.notInProfile()}</EuiBadge>
        )}
      </span>
    ),
  },
  {
    field: 'exclusions',
    name: messages.columnExcludedFor(),
    width: '32%',
    render: (list: RuleRow['exclusions']) => (
      <EuiFlexGroup gutterSize='xs' wrap responsive={false}>
        {list.map(({ key, exclusion }) => (
          <EuiFlexItem grow={false} key={key}>
            <EuiToolTip
              content={`${messages.exclusionTooltip(
                exclusion.reason,
                exclusion.ticket,
              )}${exclusion.updated_by ? ` · ${exclusion.updated_by}` : ''}`}
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
                iconOnClickAriaLabel={messages.removeExclusion()}
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
        aria-label={messages.excludeControl(row.rule)}
        title={messages.excludeTitle()}
        isDisabled={!row.applicable}
        onClick={() => exclude([row.rule])}
      />
    ),
  },
];
