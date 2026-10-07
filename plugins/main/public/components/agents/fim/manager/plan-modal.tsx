/*
 * Preview of a change before it is written: the agent.conf diff of every
 * group, the agents that will restart, conflicts between groups. Applying
 * writes the groups one by one and shows what was done.
 */
import React, { useState } from 'react';
import {
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
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
import { WzButtonPermissions } from '../../../common/permissions/button';
import { FIM_WRITE_PERMISSIONS } from './lib/permissions';
import { messages } from './messages';

const stepTitle = (step: GroupStep, agents: AgentInfo[]) => {
  const host = hostOfGroup(step.group);
  const agent = host && agents.find(a => a.id === host);
  const name = agent ? `${step.group} (${agent.name})` : step.group;
  if (step.create) {
    return messages.newGroup(name);
  }
  return step.deleteGroup ? messages.groupDeleted(name) : name;
};

export const PlanModal = ({
  title,
  steps,
  agents,
  affected,
  conflicts,
  user,
  restore = false,
  onClose,
}: {
  title: string;
  steps: GroupStep[];
  agents: AgentInfo[];
  affected: AgentInfo[];
  conflicts: Conflict[];
  user: string;
  /** The new content comes from a saved version (fim-history). */
  restore?: boolean;
  onClose: (changed: boolean) => void;
}) => {
  const [note, setNote] = useState('');
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<StepResult[]>([]);
  const [error, setError] = useState('');
  const [reviewed, setReviewed] = useState(false);
  const finished = !running && (results.length > 0 || !!error);
  const names = affected.slice(0, 10).map(a => a.name);
  const more = affected.length > names.length ? '…' : '';
  const affectedNames = names.length ? `: ${names.join(', ')}${more}` : '';

  // closing while the groups are written would hide the outcome
  const close = () => {
    if (!running) {
      onClose(results.length > 0);
    }
  };

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
      onClose={close}
      style={{ width: 860 }}
      data-test-subj='fim-plan-modal'
    >
      <EuiModalHeader>
        <EuiModalHeaderTitle>{title}</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {!steps.length && (
          <EuiCallOut title={messages.nothingToChange()} iconType='check' />
        )}
        {steps.length > 0 && (
          <EuiText size='s'>
            <p>
              {messages.groupsChange(steps.length)}{' '}
              <strong>{messages.agentsCount(affected.length)}</strong>{' '}
              {messages.willRestart(affectedNames)}
            </p>
          </EuiText>
        )}
        {restore && steps.length > 0 && !finished && (
          <>
            <EuiSpacer size='s' />
            <EuiCallOut
              color='warning'
              iconType='alert'
              title={messages.restoreWarningTitle()}
              data-test-subj='fim-plan-restore-warning'
            >
              <p>{messages.restoreWarning()}</p>
              <EuiCheckbox
                id='fim-plan-restore-reviewed'
                label={messages.restoreReviewed()}
                checked={reviewed}
                onChange={e => setReviewed(e.target.checked)}
                data-test-subj='fim-plan-restore-reviewed'
              />
            </EuiCallOut>
          </>
        )}
        {conflicts.length > 0 && (
          <>
            <EuiSpacer size='s' />
            <EuiCallOut
              color='warning'
              iconType='alert'
              title={messages.conflictsTitle()}
              data-test-subj='fim-plan-conflicts'
            >
              <p>{messages.conflictsHelp()}</p>
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
                  {step.assign ? messages.agentAdded(step.assign) : ''}
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
            <EuiFormRow label={messages.changeNote()} fullWidth>
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
              title={messages.stoppedTitle()}
              data-test-subj='fim-plan-error'
            >
              <p>{error}</p>
              <p>{messages.stoppedHelp()}</p>
            </EuiCallOut>
          </>
        )}
        {finished && !error && (
          <>
            <EuiSpacer size='m' />
            <EuiCallOut
              color='success'
              iconType='check'
              title={messages.appliedTitle()}
              data-test-subj='fim-plan-done'
            >
              <p>{messages.appliedHelp()}</p>
            </EuiCallOut>
          </>
        )}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty
          onClick={close}
          isDisabled={running}
          data-test-subj='fim-plan-close'
        >
          {finished ? messages.close() : messages.cancel()}
        </EuiButtonEmpty>
        {!finished && steps.length > 0 && (
          <WzButtonPermissions
            fill
            permissions={FIM_WRITE_PERMISSIONS}
            onClick={apply}
            isLoading={running}
            isDisabled={restore && !reviewed}
            data-test-subj='fim-plan-apply'
          >
            {messages.apply()}
          </WzButtonPermissions>
        )}
      </EuiModalFooter>
    </EuiModal>
  );
};
