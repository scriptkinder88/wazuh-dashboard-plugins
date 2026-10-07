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

const WEEKDAYS = [
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
  'Sunday',
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
      label: t === '*' ? 'All active OS' : t,
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
      const chosen = targets.map(t =>
        t.label === 'All active OS' ? '*' : t.label,
      );
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
            {runNow && 'Run CIS-CAT now'}
            {!runNow && (initial ? 'Edit schedule' : 'New schedule')}
          </h3>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm component='form' onSubmit={e => e.preventDefault()}>
          <EuiFormRow label='Name'>
            <EuiFieldText
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder={runNow ? 'Run now' : 'Month-end assessment'}
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow label='When'>
              <EuiRadioGroup
                idSelected={`ciscat-type-${type}`}
                onChange={id =>
                  setType(id.replace('ciscat-type-', '') as Job['type'])
                }
                options={[
                  { id: 'ciscat-type-once', label: 'Once' },
                  { id: 'ciscat-type-monthly', label: 'Every month' },
                  { id: 'ciscat-type-weekly', label: 'Every week' },
                ]}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'once' && (
            <EuiFormRow label='Date' helpText='YYYY-MM-DD'>
              <EuiFieldText
                value={date}
                onChange={e => setDate(e.target.value)}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'monthly' && (
            <>
              <EuiFormRow label='Day'>
                <EuiRadioGroup
                  idSelected={fromEnd ? 'ciscat-from-end' : 'ciscat-day'}
                  onChange={id => setFromEnd(id === 'ciscat-from-end')}
                  options={[
                    { id: 'ciscat-day', label: 'Day of the month' },
                    {
                      id: 'ciscat-from-end',
                      label: 'Days before the end of the month',
                    },
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow
                label={
                  fromEnd
                    ? 'Day from the end (1 = last day)'
                    : 'Day of the month'
                }
                helpText={
                  fromEnd
                    ? '1..28'
                    : '1..31; months without that day use their last day'
                }
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
            <EuiFormRow label='Day of the week'>
              <EuiSelect
                options={WEEKDAYS.map((text, value) => ({ value, text }))}
                value={weekday}
                onChange={e => setWeekday(Number(e.target.value))}
              />
            </EuiFormRow>
          )}
          {!runNow && (
            <EuiFormRow label='Time' helpText="HH:MM, manager's local time">
              <EuiFieldText
                value={time}
                onChange={e => setTime(e.target.value)}
              />
            </EuiFormRow>
          )}
          <EuiFormRow label='Operating systems'>
            <EuiComboBox
              options={[
                { label: 'All active OS' },
                ...osKeys.map(label => ({ label })),
              ]}
              selectedOptions={targets}
              onChange={setTargets}
            />
          </EuiFormRow>
          <EuiFormRow label='Agents per wave'>
            <EuiFieldNumber
              min={1}
              value={waveSize}
              onChange={e => setWaveSize(Number(e.target.value))}
            />
          </EuiFormRow>
          <EuiFormRow label='Pause between waves (minutes)'>
            <EuiFieldNumber
              min={0}
              value={pauseMin}
              onChange={e => setPauseMin(Number(e.target.value))}
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow>
              <EuiSwitch
                label='Enabled'
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
            <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton fill onClick={submit} data-test-subj='ciscat-save-job'>
              {runNow ? 'Run now' : 'Save'}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
