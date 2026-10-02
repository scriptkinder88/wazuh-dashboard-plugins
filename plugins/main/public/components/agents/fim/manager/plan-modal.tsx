/*
 * Preview of a change before it is written: the agent.conf diff of every
 * group, the agents that will restart, conflicts between groups. Applying
 * writes the groups one by one and shows what was done.
 */
import React, { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldText,
  EuiFormRow,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  AgentInfo,
  Conflict,
  GroupStep,
  diffHunks,
  diffLines,
  hostOfGroup,
} from './lib/plan';
import { StepResult, applyPlan } from './lib/fim-api';

const stepTitle = (step: GroupStep, agents: AgentInfo[]) => {
  const host = hostOfGroup(step.group);
  const agent = host && agents.find(a => a.id === host);
  const name = agent ? `${step.group} (${agent.name})` : step.group;
  if (step.create) {
    return `${name}: new group`;
  }
  return step.deleteGroup ? `${name}: no rules left, group deleted` : name;
};

export const PlanModal = ({
  title,
  steps,
  agents,
  affected,
  conflicts,
  user,
  onClose,
}: {
  title: string;
  steps: GroupStep[];
  agents: AgentInfo[];
  affected: AgentInfo[];
  conflicts: Conflict[];
  user: string;
  onClose: (changed: boolean) => void;
}) => {
  const [note, setNote] = useState('');
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<StepResult[]>([]);
  const [error, setError] = useState('');
  const finished = !running && (results.length > 0 || !!error);
  const names = affected.slice(0, 10).map(a => a.name);
  const more = affected.length > names.length ? '…' : '';
  const affectedNames = names.length ? `: ${names.join(', ')}${more}` : '';

  const apply = async () => {
    setRunning(true);
    setError('');
    try {
      await applyPlan(steps, user, note || title, r =>
        setResults(current => [...current.filter(x => x.group !== r.group), r]),
      );
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <EuiModal
      onClose={() => onClose(results.length > 0)}
      style={{ width: 860 }}
      data-test-subj='fim-plan-modal'
    >
      <EuiModalHeader>
        <EuiModalHeaderTitle>{title}</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {!steps.length && (
          <EuiCallOut title='Nothing to change' iconType='check' />
        )}
        {steps.length > 0 && (
          <EuiText size='s'>
            <p>
              {steps.length} group(s) change.{' '}
              <strong>{affected.length} agent(s)</strong> will download the new
              configuration and restart within a few minutes
              {affectedNames}.
            </p>
          </EuiText>
        )}
        {conflicts.length > 0 && (
          <>
            <EuiSpacer size='s' />
            <EuiCallOut
              color='warning'
              iconType='alert'
              title='The same path gets different options from several groups'
              data-test-subj='fim-plan-conflicts'
            >
              <p>The agent keeps the options of the group assigned last.</p>
              <ul>
                {conflicts.slice(0, 10).map(c => (
                  <li key={`${c.agent}${c.path}`}>
                    {c.agent}: {c.path} ({c.groups.join(', ')})
                  </li>
                ))}
              </ul>
            </EuiCallOut>
          </>
        )}
        {steps.map(step => {
          const result = results.find(r => r.group === step.group);
          return (
            <div key={step.group}>
              <EuiSpacer size='m' />
              <EuiTitle size='xxs'>
                <h4>
                  {stepTitle(step, agents)}
                  {step.assign ? ` — agent ${step.assign} added to it` : ''}
                  {result ? ` ✓ ${result.done.join(', ')}` : ''}
                </h4>
              </EuiTitle>
              {!step.deleteGroup && (
                <EuiCodeBlock
                  language='diff'
                  fontSize='s'
                  paddingSize='s'
                  overflowHeight={260}
                  isCopyable={false}
                >
                  {diffHunks(diffLines(step.before, step.after))
                    .map(l => `${l.op} ${l.text}`)
                    .join('\n')}
                </EuiCodeBlock>
              )}
            </div>
          );
        })}
        {steps.length > 0 && !finished && (
          <>
            <EuiSpacer size='m' />
            <EuiFormRow
              label='Change note (saved with the previous versions)'
              fullWidth
            >
              <EuiFieldText
                fullWidth
                value={note}
                onChange={e => setNote(e.target.value)}
                placeholder={title}
              />
            </EuiFormRow>
          </>
        )}
        {error && (
          <>
            <EuiSpacer size='m' />
            <EuiCallOut
              color='danger'
              iconType='alert'
              title='The change stopped'
              data-test-subj='fim-plan-error'
            >
              <p>{error}</p>
              <p>
                Groups marked ✓ were written; the others were not touched.
                Reload to see the current state.
              </p>
            </EuiCallOut>
          </>
        )}
        {finished && !error && (
          <>
            <EuiSpacer size='m' />
            <EuiCallOut
              color='success'
              iconType='check'
              title='Applied'
              data-test-subj='fim-plan-done'
            >
              <p>
                Agents pick up the new configuration within a few minutes. The
                Agents tab shows when each one is synchronized.
              </p>
            </EuiCallOut>
          </>
        )}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={() => onClose(results.length > 0)}>
          {finished ? 'Close' : 'Cancel'}
        </EuiButtonEmpty>
        {!finished && steps.length > 0 && (
          <EuiButton
            fill
            onClick={apply}
            isLoading={running}
            data-test-subj='fim-plan-apply'
          >
            Apply
          </EuiButton>
        )}
      </EuiModalFooter>
    </EuiModal>
  );
};
