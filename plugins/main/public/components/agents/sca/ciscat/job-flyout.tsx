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
import { Job, validateJob } from '../../../../../common/ciscat/store';
import { messages } from './messages';

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
  onClose: () => void;
  onSave: (job: Job) => void;
}

const today = () => new Date().toISOString().slice(0, 10);

export const JobFlyout = ({
  initial,
  runNow,
  osKeys,
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
  const [waveSize, setWaveSize] = useState(initial?.wave_size ?? 50);
  const [pauseMin, setPauseMin] = useState(
    Math.round((initial?.wave_pause_s ?? 300) / 60),
  );
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState('');

  const submit = () => {
    try {
      const chosen = targets.map(t => (t.label === allOs ? '*' : t.label));
      const job = validateJob({
        type: runNow ? 'once' : type,
        at: runNow ? '2000-01-01T00:00' : `${date}T${time}`,
        time,
        day: fromEnd ? -day : day,
        weekday,
        targets: chosen.includes('*') ? ['*'] : chosen,
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
          <EuiFormRow label={messages.operatingSystems()}>
            <EuiComboBox
              options={[{ label: allOs }, ...osKeys.map(label => ({ label }))]}
              selectedOptions={targets}
              onChange={setTargets}
            />
          </EuiFormRow>
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
