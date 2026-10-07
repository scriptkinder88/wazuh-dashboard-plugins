/*
 * Flyout to exclude controls: for the whole OS, globally, for agents or for
 * agent groups, with the reason, ticket and owner.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useEffect, useState } from 'react';
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
  EuiSpacer,
  EuiSuperSelect,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import {
  KeyedExclusions,
  ScopeChoice,
  makeExclusions,
  profileLevelRole,
} from './lib/composer';
import { fetchAgentNames, fetchGroupNames } from './lib/lists-api';
import { messages } from './messages';

const SCOPE_OPTIONS: Array<{ value: ScopeChoice; text: () => string }> = [
  { value: 'os', text: messages.scopeOs },
  { value: 'host', text: messages.scopeHost },
  { value: 'app_group', text: messages.scopeGroup },
  { value: 'global', text: messages.scopeGlobal },
];

interface FlyoutProps {
  osKey: string;
  column: string;
  rules: string[];
  user: string;
  onClose: () => void;
  onAdd: (records: KeyedExclusions) => void;
}

export const ExcludeFlyout = ({
  osKey,
  column,
  rules,
  user,
  onClose,
  onAdd,
}: FlyoutProps) => {
  const [scope, setScope] = useState<ScopeChoice>('os');
  const [values, setValues] = useState<Array<{ label: string }>>([]);
  const [options, setOptions] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [ticket, setTicket] = useState('');
  const [owner, setOwner] = useState('');
  const [error, setError] = useState('');
  const { level, role } = profileLevelRole(column);

  useEffect(() => {
    setValues([]);
    setOptions([]);
    const fetchers: Partial<Record<ScopeChoice, () => Promise<string[]>>> = {
      host: fetchAgentNames,
      app_group: fetchGroupNames,
    };
    fetchers[scope]?.()
      .then(setOptions)
      .catch(() => setOptions([]));
  }, [scope]);

  const submit = async () => {
    try {
      onAdd(
        await makeExclusions({
          osKey,
          column,
          rules,
          scope,
          values: values.map(v => v.label),
          reason,
          ticket,
          owner,
          user,
        }),
      );
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <EuiFlyout onClose={onClose} size='s' ownFocus>
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size='s'>
          <h3>
            {messages.excludeRules(
              rules.length === 1
                ? rules[0]
                : messages.controlsCount(rules.length),
            )}
          </h3>
        </EuiTitle>
        <EuiText size='xs' color='subdued'>
          {osKey} · {level} {role.replace(/_/g, ' ')}
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm component='form' onSubmit={e => e.preventDefault()}>
          <EuiFormRow label={messages.excludeFor()}>
            <EuiSuperSelect
              options={SCOPE_OPTIONS.map(o => ({
                value: o.value,
                inputDisplay: o.text(),
              }))}
              valueOfSelected={scope}
              onChange={v => setScope(v as ScopeChoice)}
            />
          </EuiFormRow>
          {(scope === 'host' || scope === 'app_group') && (
            <EuiFormRow
              label={
                scope === 'host' ? messages.agents() : messages.agentGroups()
              }
              helpText={messages.namesHelp()}
            >
              <EuiComboBox
                options={options.map(label => ({ label }))}
                selectedOptions={values}
                onChange={setValues}
                onCreateOption={(value: string) =>
                  setValues([
                    ...values,
                    ...value
                      .split(/[\s,;]+/)
                      .filter(Boolean)
                      .map(label => ({ label })),
                  ])
                }
                data-test-subj='ciscat-scope-values'
              />
            </EuiFormRow>
          )}
          <EuiFormRow
            label={messages.reason()}
            helpText={messages.reasonHelp()}
          >
            <EuiTextArea
              value={reason}
              onChange={e => setReason(e.target.value)}
              rows={3}
              data-test-subj='ciscat-reason'
            />
          </EuiFormRow>
          <EuiFormRow label={messages.ticket()}>
            <EuiFieldText
              value={ticket}
              onChange={e => setTicket(e.target.value)}
            />
          </EuiFormRow>
          <EuiFormRow label={messages.owner()}>
            <EuiFieldText
              value={owner}
              onChange={e => setOwner(e.target.value)}
            />
          </EuiFormRow>
        </EuiForm>
        {error && (
          <>
            <EuiSpacer size='s' />
            <EuiCallOut color='danger' size='s' title={error} />
          </>
        )}
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent='spaceBetween'>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose}>
              {messages.cancel()}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              onClick={submit}
              data-test-subj='ciscat-add-exclusion'
            >
              {messages.addExclusion()}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
