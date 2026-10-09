/*
 * Flyout to create or change a CIS-CAT schedule, or to request a run now.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiComboBox,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiRadioGroup,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTitle,
} from '@elastic/eui';
import {
  AGENT_ID_RE,
  Job,
  MANAGED_GROUP_PREFIX,
  validateJob,
} from '../../../../../common/ciscat/store';
import { messages } from './messages';

/** An agent the run can be sent to. */
export interface RunAgent {
  id: string;
  name: string;
  platform?: string;
}

type Scope = 'os' | 'groups' | 'agents';
type Option = { label: string; value?: string; isGroupLabelOption?: boolean };

const agentLabel = (a: RunAgent) =>
  `${a.id} · ${a.name}${a.platform ? ` (${a.platform})` : ''}`;

/**
 * Agent ids of a pasted list of ids or names (commas, semicolons or spaces);
 * the entries that match no agent are returned apart.
 */
export const parseAgentList = (text: string, agents: RunAgent[]) => {
  const byName = new Map(agents.map(a => [a.name.toLowerCase(), a.id]));
  const known = new Set(agents.map(a => a.id));
  const ids: string[] = [];
  const unknown: string[] = [];
  for (const entry of text.split(/[\s,;]+/).filter(Boolean)) {
    const id = AGENT_ID_RE.test(entry)
      ? entry
      : byName.get(entry.toLowerCase());
    if (id && id !== '000' && (known.has(id) || !agents.length)) {
      ids.push(id);
    } else {
      unknown.push(entry);
    }
  }
  return { ids, unknown };
};

const WEEKDAYS = [
  messages.monday,
  messages.tuesday,
  messages.wednesday,
  messages.thursday,
  messages.friday,
  messages.saturday,
  messages.sunday,
];

interface JobFlyoutProps {
  initial?: Job;
  runNow?: boolean;
  osKeys: string[];
  /** Groups of the active OSes, then every Wazuh group. */
  osGroups?: string[];
  groups?: string[];
  agents?: RunAgent[];
  onClose: () => void;
  onSave: (job: Job) => void;
}

const today = () => new Date().toISOString().slice(0, 10);

export const JobFlyout = ({
  initial,
  runNow,
  osKeys,
  osGroups = [],
  groups = [],
  agents = [],
  onClose,
  onSave,
}: JobFlyoutProps) => {
  // the option standing for every active OS ("*")
  const allOs = messages.allActiveOs();
  const [label, setLabel] = useState(initial?.label || '');
  const [type, setType] = useState<Job['type']>(initial?.type || 'monthly');
  const [date, setDate] = useState((initial?.at || '').slice(0, 10) || today());
  const [time, setTime] = useState(
    initial?.time || (initial?.at || '').slice(11, 16) || '22:00',
  );
  const [fromEnd, setFromEnd] = useState((initial?.day ?? 1) < 0);
  const [day, setDay] = useState(Math.abs(initial?.day ?? 1));
  const [weekday, setWeekday] = useState(initial?.weekday ?? 5);
  const [targets, setTargets] = useState<Array<{ label: string }>>(
    (initial?.targets || ['*']).map(t => ({
      label: t === '*' ? allOs : t,
    })),
  );
  const [scope, setScope] = useState<Scope>(() => {
    if (initial?.agents?.length) {
      return 'agents';
    }
    return initial?.groups?.length ? 'groups' : 'os';
  });
  const [chosenGroups, setChosenGroups] = useState<Option[]>(
    (initial?.groups || []).map(g => ({ label: g })),
  );
  const agentById = new Map(agents.map(a => [a.id, a]));
  const agentOption = (id: string): Option => {
    const agent = agentById.get(id);
    return { label: agent ? agentLabel(agent) : id, value: id };
  };
  const [chosenAgents, setChosenAgents] = useState<Option[]>(
    (initial?.agents || []).map(agentOption),
  );
  const [waveSize, setWaveSize] = useState(initial?.wave_size ?? 50);
  const [pauseMin, setPauseMin] = useState(
    Math.round((initial?.wave_pause_s ?? 300) / 60),
  );
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState('');

  const ownGroups = new Set(osGroups);
  const customGroups = groups.filter(
    g => !ownGroups.has(g) && !g.startsWith(MANAGED_GROUP_PREFIX),
  );
  const groupOptions: Option[] = [
    ...(osGroups.length
      ? [{ label: messages.osGroupsLabel(), isGroupLabelOption: true }]
      : []),
    ...osGroups.map(label => ({ label })),
    ...(customGroups.length
      ? [{ label: messages.customGroupsLabel(), isGroupLabelOption: true }]
      : []),
    ...customGroups.map(label => ({ label })),
  ];

  const addPastedAgents = (text: string) => {
    const { ids, unknown } = parseAgentList(text, agents);
    const have = new Set(chosenAgents.map(o => o.value));
    setChosenAgents([
      ...chosenAgents,
      ...ids.filter(id => !have.has(id)).map(agentOption),
    ]);
    setError(unknown.length ? messages.unknownAgents(unknown.join(', ')) : '');
  };

  const runScope = () => {
    if (scope === 'agents') {
      return { targets: [], agents: chosenAgents.map(o => o.value || o.label) };
    }
    if (scope === 'groups') {
      return { targets: [], groups: chosenGroups.map(o => o.label) };
    }
    const chosen = targets.map(t => (t.label === allOs ? '*' : t.label));
    return { targets: chosen.includes('*') ? ['*'] : chosen };
  };

  const submit = () => {
    try {
      const picked = runScope();
      if (
        ![picked.targets, picked.agents || [], picked.groups || []].some(
          list => list.length,
        )
      ) {
        setError(messages.nothingSelected());
        return;
      }
      const job = validateJob({
        type: runNow ? 'once' : type,
        at: runNow ? '2000-01-01T00:00' : `${date}T${time}`,
        time,
        day: fromEnd ? -day : day,
        weekday,
        ...picked,
        wave_size: Number(waveSize),
        wave_pause_s: Number(pauseMin) * 60,
        enabled,
        label,
      });
      onSave(job);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <EuiFlyout onClose={onClose} size='s' ownFocus>
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size='s'>
          <h3>
            {runNow && messages.runCiscatNow()}
            {!runNow &&
              (initial ? messages.editSchedule() : messages.newSchedule())}
          </h3>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm component='form' onSubmit={e => e.preventDefault()}>
          <EuiFormRow label={messages.name()}>
            <EuiFieldText
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder={
                runNow ? messages.runNow() : messages.namePlaceholder()
              }
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow label={messages.when()}>
              <EuiRadioGroup
                idSelected={`ciscat-type-${type}`}
                onChange={id =>
                  setType(id.replace('ciscat-type-', '') as Job['type'])
                }
                options={[
                  { id: 'ciscat-type-once', label: messages.once() },
                  { id: 'ciscat-type-monthly', label: messages.everyMonth() },
                  { id: 'ciscat-type-weekly', label: messages.everyWeek() },
                ]}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'once' && (
            <EuiFormRow label={messages.date()} helpText='YYYY-MM-DD'>
              <EuiFieldText
                value={date}
                onChange={e => setDate(e.target.value)}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'monthly' && (
            <>
              <EuiFormRow label={messages.day()}>
                <EuiRadioGroup
                  idSelected={fromEnd ? 'ciscat-from-end' : 'ciscat-day'}
                  onChange={id => setFromEnd(id === 'ciscat-from-end')}
                  options={[
                    { id: 'ciscat-day', label: messages.dayOfMonth() },
                    {
                      id: 'ciscat-from-end',
                      label: messages.daysBeforeEnd(),
                    },
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow
                label={fromEnd ? messages.dayFromEnd() : messages.dayOfMonth()}
                helpText={fromEnd ? '1..28' : messages.dayOfMonthHelp()}
              >
                <EuiFieldNumber
                  min={1}
                  max={fromEnd ? 28 : 31}
                  value={day}
                  onChange={e => setDay(Number(e.target.value))}
                />
              </EuiFormRow>
            </>
          )}
          {!runNow && type === 'weekly' && (
            <EuiFormRow label={messages.dayOfWeek()}>
              <EuiSelect
                options={WEEKDAYS.map((text, value) => ({
                  value,
                  text: text(),
                }))}
                value={weekday}
                onChange={e => setWeekday(Number(e.target.value))}
              />
            </EuiFormRow>
          )}
          {!runNow && (
            <EuiFormRow label={messages.time()} helpText={messages.timeHelp()}>
              <EuiFieldText
                value={time}
                onChange={e => setTime(e.target.value)}
              />
            </EuiFormRow>
          )}
          <EuiFormRow label={messages.runOn()}>
            <EuiRadioGroup
              idSelected={`ciscat-scope-${scope}`}
              onChange={id => {
                setScope(id.replace('ciscat-scope-', '') as Scope);
                setError('');
              }}
              options={[
                { id: 'ciscat-scope-os', label: messages.runScopeOs() },
                { id: 'ciscat-scope-groups', label: messages.scopeGroups() },
                { id: 'ciscat-scope-agents', label: messages.scopeAgents() },
              ]}
            />
          </EuiFormRow>
          {scope === 'os' && (
            <EuiFormRow label={messages.operatingSystems()}>
              <EuiComboBox
                options={[
                  { label: allOs },
                  ...osKeys.map(label => ({ label })),
                ]}
                selectedOptions={targets}
                onChange={setTargets}
                data-test-subj='ciscat-run-os'
              />
            </EuiFormRow>
          )}
          {scope === 'groups' && (
            <EuiFormRow
              label={messages.runGroups()}
              helpText={messages.agentGroupsHelp()}
            >
              <EuiComboBox
                options={groupOptions}
                selectedOptions={chosenGroups}
                onChange={setChosenGroups}
                data-test-subj='ciscat-run-groups'
              />
            </EuiFormRow>
          )}
          {scope === 'agents' && (
            <EuiFormRow
              label={messages.runAgents()}
              helpText={messages.agentsHelp()}
            >
              <EuiComboBox
                options={agents.map(a => ({
                  label: agentLabel(a),
                  value: a.id,
                }))}
                selectedOptions={chosenAgents}
                onChange={options => setChosenAgents(options as Option[])}
                onCreateOption={addPastedAgents}
                data-test-subj='ciscat-run-agents'
              />
            </EuiFormRow>
          )}
          <EuiFormRow label={messages.agentsPerWave()}>
            <EuiFieldNumber
              min={1}
              value={waveSize}
              onChange={e => setWaveSize(Number(e.target.value))}
            />
          </EuiFormRow>
          <EuiFormRow label={messages.pauseBetweenWaves()}>
            <EuiFieldNumber
              min={0}
              value={pauseMin}
              onChange={e => setPauseMin(Number(e.target.value))}
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow>
              <EuiSwitch
                label={messages.enabled()}
                checked={enabled}
                onChange={e => setEnabled(e.target.checked)}
              />
            </EuiFormRow>
          )}
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
            <EuiButton fill onClick={submit} data-test-subj='ciscat-save-job'>
              {runNow ? messages.runNow() : messages.save()}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
