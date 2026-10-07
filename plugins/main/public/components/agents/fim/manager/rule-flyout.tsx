/*
 * Form to add or change a FIM rule: what to monitor (or ignore), how, on which
 * platform, for which groups and servers, and why.
 */
/* eslint-disable camelcase */ // attribute names are the agent.conf ones
import React, { useMemo, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiComboBox,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTitle,
} from '@elastic/eui';
import {
  FimRule,
  KIND_LABELS,
  RULE_KINDS,
  RuleKind,
  isMonitorKind,
  isRegistryKind,
  validateRule,
} from './lib/agent-conf';
import { AgentInfo, RuleChange, RuleRow } from './lib/plan';
import {
  HintFix,
  managedHints,
  overlapHints,
  pathHints,
} from './lib/path-checks';
import {
  FormState,
  Mode,
  Platform,
  buildAttrs,
  buildFilter,
  initialState,
  platformOf,
} from './lib/rule-form';
import { HintList } from './hint-list';
import { PathTest, usePathTest } from './path-test';

const MODE_HELP: Record<Mode, string> = {
  scheduled: 'Checked at each periodic scan.',
  realtime: 'Real time applies to directories, not single files.',
  whodata: 'Who-data needs auditd on Linux and the audit policy on Windows.',
};

const PATH_HELP =
  'Several paths can be separated by commas. Environment variables such as ' +
  '%WINDIR% are expanded by the agent.';

export const RuleFlyout = ({
  row,
  preset,
  groups,
  agents,
  rules = [],
  managedGroups = [],
  user,
  onClose,
  onSubmit,
}: {
  /** The rule being changed; absent for a new rule. */
  row?: RuleRow;
  /** Initial values of a new rule. */
  preset?: RuleRow;
  groups: string[];
  agents: AgentInfo[];
  /** Rules already in the groups, to point out overlaps. */
  rules?: RuleRow[];
  /** Groups whose agent.conf is written by Terraform. */
  managedGroups?: string[];
  user: string;
  onClose: () => void;
  onSubmit: (change: RuleChange) => void;
}) => {
  const [form, setForm] = useState<FormState>(() =>
    initialState(row || preset),
  );
  const [tried, setTried] = useState(false);
  const update = (patch: Partial<FormState>) =>
    setForm(current => {
      const next = { ...current, ...patch };
      if (patch.kind && isRegistryKind(patch.kind) && next.platform === 'any') {
        next.platform = 'Windows';
      }
      return next;
    });

  const rule: FimRule = useMemo(
    () => ({
      kind: form.kind,
      path: form.path.trim(),
      attrs: buildAttrs(form, row?.rule),
      filter: buildFilter(form, row?.rule),
      meta: {
        reason: form.reason.trim(),
        ticket: form.ticket.trim(),
        owner: form.owner.trim(),
        by: user,
        at: new Date().toISOString(),
      },
    }),
    [form, row, user],
  );
  const errors = [
    ...validateRule(rule),
    ...(form.groups.length || form.hostIds.length
      ? []
      : ['choose at least one group or server']),
  ];

  const hints = pathHints({
    kind: form.kind,
    path: form.path,
    sregex: form.sregex,
    reportChanges: form.reportChanges,
    platform: form.platform === 'keep' ? '' : form.platform,
  });
  const overlaps = [
    ...managedHints(form.groups, managedGroups),
    ...overlapHints(
      {
        kind: rule.kind,
        path: rule.path,
        filter: rule.filter,
        sregex: form.sregex,
      },
      form.groups,
      form.hostIds,
      rules,
      row?.key,
    ),
  ];
  const applyFix = (fix: HintFix) => update(fix.patch);
  const { canTest, test, testLabel, runTest } = usePathTest(agents, form);

  const agentOptions = agents.map(a => ({
    label: `${a.name} (${a.id})`,
    value: a.id,
  }));
  const keepLabel = Object.entries(row?.rule.filter || {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');

  const submit = () => {
    setTried(true);
    if (errors.length) {
      return;
    }
    onSubmit({
      before: row,
      after: { rule, groups: form.groups, hostIds: form.hostIds },
    });
  };

  return (
    <EuiFlyout
      onClose={onClose}
      size='m'
      ownFocus
      data-test-subj='fim-rule-flyout'
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size='s'>
          <h3>{row ? 'Change FIM rule' : 'New FIM rule'}</h3>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm>
          <EuiFormRow label='Type'>
            <EuiSelect
              options={RULE_KINDS.map(k => ({
                value: k,
                text: KIND_LABELS[k],
              }))}
              value={form.kind}
              onChange={e => update({ kind: e.target.value as RuleKind })}
              data-test-subj='fim-rule-kind'
            />
          </EuiFormRow>
          <EuiFormRow
            label={isRegistryKind(form.kind) ? 'Registry key' : 'Path'}
            helpText={
              form.sregex
                ? 'Regular expression (sregex) matched against the full path.'
                : PATH_HELP
            }
          >
            <EuiFieldText
              value={form.path}
              onChange={e => update({ path: e.target.value })}
              placeholder={
                isRegistryKind(form.kind)
                  ? 'HKEY_LOCAL_MACHINE\\Software\\Vendor'
                  : '/etc/app'
              }
              data-test-subj='fim-rule-path'
            />
          </EuiFormRow>
          <HintList hints={hints} onFix={applyFix} testSubj='fim-rule-hints' />
          {hints.length > 0 && <EuiSpacer size='s' />}
          <EuiFormRow
            label='Platform'
            helpText='Agents whose operating system the rule applies to.'
          >
            <EuiSelect
              options={[
                { value: 'any', text: 'Any' },
                { value: 'Linux', text: 'Linux' },
                { value: 'Windows', text: 'Windows' },
                ...(keepLabel && platformOf(row!.rule.filter) === 'keep'
                  ? [{ value: 'keep', text: `As imported (${keepLabel})` }]
                  : []),
              ]}
              value={form.platform}
              onChange={e => update({ platform: e.target.value as Platform })}
              data-test-subj='fim-rule-platform'
            />
          </EuiFormRow>
          {form.kind === 'directories' && (
            <EuiFormRow label='Mode' helpText={MODE_HELP[form.mode]}>
              <EuiSelect
                options={[
                  { value: 'scheduled', text: 'Scheduled scan' },
                  { value: 'realtime', text: 'Real time' },
                  { value: 'whodata', text: 'Who-data (real time + user)' },
                ]}
                value={form.mode}
                onChange={e => update({ mode: e.target.value as Mode })}
                data-test-subj='fim-rule-mode'
              />
            </EuiFormRow>
          )}
          {isMonitorKind(form.kind) && (
            <>
              <EuiFormRow>
                <EuiSwitch
                  label='Report changes (content diff)'
                  checked={form.reportChanges}
                  onChange={e => update({ reportChanges: e.target.checked })}
                />
              </EuiFormRow>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label='Recursion level' helpText='Empty: default'>
                    <EuiFieldText
                      value={form.recursion}
                      onChange={e => update({ recursion: e.target.value })}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label='Tags' helpText='Added to the FIM events'>
                    <EuiFieldText
                      value={form.tags}
                      onChange={e => update({ tags: e.target.value })}
                      data-test-subj='fim-rule-tags'
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFormRow
                label='Restrict'
                helpText='Only files matching this regular expression'
              >
                <EuiFieldText
                  value={form.restrict}
                  onChange={e => update({ restrict: e.target.value })}
                />
              </EuiFormRow>
            </>
          )}
          {!isMonitorKind(form.kind) && (
            <EuiFormRow>
              <EuiSwitch
                label='The path is a regular expression (sregex)'
                checked={form.sregex}
                onChange={e => update({ sregex: e.target.checked })}
              />
            </EuiFormRow>
          )}
          {isRegistryKind(form.kind) && (
            <EuiFormRow label='Architecture'>
              <EuiSelect
                options={[
                  { value: '', text: 'Default (32bit)' },
                  { value: '64bit', text: '64bit' },
                  { value: 'both', text: 'Both' },
                ]}
                value={form.arch}
                onChange={e => update({ arch: e.target.value })}
              />
            </EuiFormRow>
          )}
          <EuiSpacer size='m' />
          <EuiTitle size='xxs'>
            <h4>Applies to</h4>
          </EuiTitle>
          <EuiFormRow label='Groups' helpText='Every agent of these groups'>
            <EuiComboBox
              options={groups.map(g => ({ label: g }))}
              selectedOptions={form.groups.map(g => ({ label: g }))}
              onChange={sel => update({ groups: sel.map(o => o.label) })}
              data-test-subj='fim-rule-groups'
            />
          </EuiFormRow>
          <EuiFormRow
            label='Servers'
            helpText='Single servers: each gets its own fim-host-<id> group'
          >
            <EuiComboBox
              options={agentOptions}
              selectedOptions={agentOptions.filter(o =>
                form.hostIds.includes(o.value),
              )}
              onChange={sel =>
                update({ hostIds: sel.map(o => String(o.value)) })
              }
              data-test-subj='fim-rule-hosts'
            />
          </EuiFormRow>
          <HintList
            hints={overlaps}
            onFix={applyFix}
            testSubj='fim-rule-overlaps'
          />
          <EuiSpacer size='s' />
          <EuiButtonEmpty
            size='xs'
            iconType='search'
            flush='left'
            isDisabled={!canTest}
            onClick={runTest}
            data-test-subj='fim-path-test-run'
          >
            {testLabel}
          </EuiButtonEmpty>
          {test && !test.results && <EuiLoadingSpinner size='m' />}
          {test?.results && (
            <PathTest results={test.results} prefix={test.prefix} />
          )}
          <EuiSpacer size='m' />
          <EuiTitle size='xxs'>
            <h4>Audit</h4>
          </EuiTitle>
          <EuiFormRow label='Reason'>
            <EuiFieldText
              value={form.reason}
              onChange={e => update({ reason: e.target.value })}
              data-test-subj='fim-rule-reason'
            />
          </EuiFormRow>
          <EuiFlexGroup>
            <EuiFlexItem>
              <EuiFormRow label='Ticket'>
                <EuiFieldText
                  value={form.ticket}
                  onChange={e => update({ ticket: e.target.value })}
                />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFormRow label='Owner'>
                <EuiFieldText
                  value={form.owner}
                  onChange={e => update({ owner: e.target.value })}
                />
              </EuiFormRow>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiForm>
        {tried && errors.length > 0 && (
          <>
            <EuiSpacer size='m' />
            <EuiCallOut color='danger' title='Check the rule'>
              <ul>
                {errors.map(e => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </EuiCallOut>
          </>
        )}
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent='spaceBetween'>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton fill onClick={submit} data-test-subj='fim-rule-review'>
              Review changes
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
