/*
 * Exclusion composer: pick an OS and a profile, tick controls, exclude them
 * for the whole OS, globally, for agents or for agent groups. Saving writes
 * ciscat-exclusions; "Save and apply" also asks the manager to regenerate the
 * policies.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCheckbox,
  EuiComboBox,
  EuiFieldSearch,
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
  EuiStat,
  EuiSuperSelect,
  EuiText,
  EuiTextArea,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { WzButtonPermissions } from '../../../common/permissions/button';
import { CISCAT_WRITE_PERMISSIONS } from './lib/permissions';
import {
  CISCAT_LISTS,
  benchListName,
  newRequestKey,
  validateExclusion,
  validateTarget,
} from '../../../../../common/ciscat/store';
import { getToasts } from '../../../../kibana-services';
import {
  Bench,
  KeyedExclusions,
  RuleRow,
  ScopeChoice,
  ShowFilter,
  buildRows,
  composerStats,
  describeScope,
  makeExclusions,
  parseBench,
  profileLevelRole,
} from './lib/composer';
import {
  addRequest,
  fetchAgentNames,
  fetchGroupNames,
  readList,
  writeList,
} from './lib/lists-api';
import type { CiscatData } from './ciscat-management';

const PAGE_SIZES = [25, 50, 100];

const SCOPE_OPTIONS: Array<{ value: ScopeChoice; text: string }> = [
  { value: 'os', text: 'All agents of this OS' },
  { value: 'host', text: 'Specific agents' },
  { value: 'app_group', text: 'Agent groups' },
  { value: 'global', text: 'Global (every OS with this number)' },
];

const validExclusions = (records: CiscatData['exclusions']['records']) =>
  Object.entries(records).reduce((acc, [key, rec]) => {
    if (!key.startsWith('_')) {
      try {
        acc[key] = validateExclusion(rec);
      } catch {
        // invalid records are reported by the manager, not edited here
      }
    }
    return acc;
  }, {} as KeyedExclusions);

/** Group each OS applies to: chosen here (ciscat-targets) or the master's default. */
const savedTargets = (data: CiscatData): Record<string, string> =>
  Object.fromEntries(
    Object.keys(data.oskeys).map(k => {
      const rec = data.targets.records[k];
      return [
        k,
        String((rec && rec.group) || data.oskeys[k].group || `os-${k}`),
      ];
    }),
  );

/** Benchmark name and version, e.g. "Red Hat Enterprise Linux 9 v2.0.0". */
const osTitle = (data: CiscatData, key: string) => {
  const os = data.oskeys[key];
  const title = String(os.title || key);
  return os.version && !title.includes(`v${os.version}`)
    ? `${title} v${os.version}`
    : title;
};

const toast = (title: string, color: 'success' | 'danger', text?: string) =>
  color === 'success'
    ? getToasts().addSuccess({ title, text })
    : getToasts().addDanger({ title, text });

interface FlyoutProps {
  osKey: string;
  column: string;
  rules: string[];
  user: string;
  onClose: () => void;
  onAdd: (records: KeyedExclusions) => void;
}

const ExcludeFlyout = ({
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
            Exclude {rules.length === 1 ? rules[0] : `${rules.length} controls`}
          </h3>
        </EuiTitle>
        <EuiText size='xs' color='subdued'>
          {osKey} · {level} {role.replace(/_/g, ' ')}
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm component='form' onSubmit={e => e.preventDefault()}>
          <EuiFormRow label='Exclude for'>
            <EuiSuperSelect
              options={SCOPE_OPTIONS.map(o => ({
                value: o.value,
                inputDisplay: o.text,
              }))}
              valueOfSelected={scope}
              onChange={v => setScope(v as ScopeChoice)}
            />
          </EuiFormRow>
          {(scope === 'host' || scope === 'app_group') && (
            <EuiFormRow
              label={scope === 'host' ? 'Agents' : 'Agent groups'}
              helpText='Pick from the list or type names (comma separated).'
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
          <EuiFormRow label='Reason' helpText='Kept for the audit trail.'>
            <EuiTextArea
              value={reason}
              onChange={e => setReason(e.target.value)}
              rows={3}
              data-test-subj='ciscat-reason'
            />
          </EuiFormRow>
          <EuiFormRow label='Ticket'>
            <EuiFieldText
              value={ticket}
              onChange={e => setTicket(e.target.value)}
            />
          </EuiFormRow>
          <EuiFormRow label='Owner'>
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
            <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              onClick={submit}
              data-test-subj='ciscat-add-exclusion'
            >
              Add exclusion
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};

interface Props {
  data: CiscatData;
  user: string;
  onSaved: () => void;
}

export const ExclusionsPanel = ({ data, user, onSaved }: Props) => {
  const osKeys = useMemo(
    () =>
      Object.keys(data.oskeys)
        .filter(k => data.oskeys[k].available)
        .sort(),
    [data.oskeys],
  );
  const [osKey, setOsKey] = useState(osKeys[0] || '');
  const [bench, setBench] = useState<Bench>();
  const [benchError, setBenchError] = useState('');
  const [column, setColumn] = useState('');
  const [draft, setDraft] = useState<KeyedExclusions>(() =>
    validExclusions(data.exclusions.records),
  );
  const [dirty, setDirty] = useState(false);
  const [text, setText] = useState('');
  const [show, setShow] = useState<ShowFilter>('applicable');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [page, setPage] = useState({ index: 0, size: 50 });
  const [flyoutRules, setFlyoutRules] = useState<string[]>();
  const [saving, setSaving] = useState(false);
  // Wazuh group each benchmark applies to (ciscat-targets), as edited here
  const [targets, setTargets] = useState<Record<string, string>>(() =>
    savedTargets(data),
  );
  const [groups, setGroups] = useState<string[]>([]);
  useEffect(() => {
    fetchGroupNames()
      .then(setGroups)
      .catch(() => setGroups([]));
  }, []);

  useEffect(() => {
    setDraft(validExclusions(data.exclusions.records));
    setTargets(savedTargets(data));
    setDirty(false);
  }, [data.exclusions]);

  useEffect(() => {
    if (!osKey) {
      return;
    }
    setBench(undefined);
    setBenchError('');
    setSelected(new Set());
    readList(benchListName(osKey))
      .then(list => {
        const b = parseBench(list.records, osKey);
        setBench(b);
        const entry = data.oskeys[osKey] || {};
        const preferred = `${((entry.levels as string[]) || ['L1'])[0]}_${
          entry.role || ''
        }`;
        setColumn(
          b.profiles.includes(preferred) ? preferred : b.profiles[0] || '',
        );
      })
      .catch(e => setBenchError((e as Error).message));
  }, [osKey, data.oskeys]);

  const rows = useMemo(
    () => (bench ? buildRows(bench, draft, column, { text, show }) : []),
    [bench, draft, column, text, show],
  );
  const stats = useMemo(
    () =>
      composerStats(
        bench ? buildRows(bench, draft, column, { show: 'all' }) : [],
      ),
    [bench, draft, column],
  );
  const pageRows = rows.slice(
    page.index * page.size,
    (page.index + 1) * page.size,
  );

  const removeExclusion = (key: string) => {
    const next = { ...draft };
    delete next[key];
    setDraft(next);
    setDirty(true);
  };

  const save = async (apply: boolean) => {
    setSaving(true);
    let exclusionsSaved = false;
    try {
      await writeList(CISCAT_LISTS.exclusions, draft, data.exclusions.raw);
      exclusionsSaved = true;
      const saved = savedTargets(data);
      if (Object.keys(targets).some(k => targets[k] !== saved[k])) {
        const records = { ...data.targets.records };
        delete records._empty;
        Object.entries(targets).forEach(([k, group]) => {
          if (group !== saved[k]) {
            records[k] = {
              ...validateTarget({
                group,
                updated_by: user,
                updated_at: new Date().toISOString(),
              }),
            };
          }
        });
        await writeList(CISCAT_LISTS.targets, records, data.targets.raw);
      }
      if (apply) {
        await addRequest(
          newRequestKey(),
          {
            action: 'apply',
            requested_by: user,
            requested_at: new Date().toISOString(),
          },
          (data.status.requests?.processed as string[]) || [],
        );
      }
      toast(
        apply ? 'Exclusions saved, apply requested' : 'Exclusions saved',
        'success',
        apply
          ? 'The manager regenerates the policies within 5 minutes.'
          : 'Use "Save and apply" to publish them to the agents.',
      );
      onSaved();
    } catch (e) {
      if (exclusionsSaved) {
        // the lists read before the save are outdated: reload them, or the
        // next save would be refused as a concurrent change
        toast(
          'Exclusions saved, the rest was not',
          'danger',
          (e as Error).message,
        );
        onSaved();
      } else {
        toast('Exclusions not saved', 'danger', (e as Error).message);
      }
    } finally {
      setSaving(false);
    }
  };

  const toggle = (rule: string) => {
    const next = new Set(selected);
    if (next.has(rule)) {
      next.delete(rule);
    } else {
      next.add(rule);
    }
    setSelected(next);
  };

  const columns = [
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
          {!row.applicable && (
            <EuiBadge color='hollow'>not in profile</EuiBadge>
          )}
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
          onClick={() => setFlyoutRules([row.rule])}
        />
      ),
    },
  ];

  if (!osKeys.length) {
    return (
      <EuiCallOut title='No benchmark available' iconType='iInCircle'>
        <p>
          The manager has not published any benchmark sheet yet, or no OS in its
          library has its benchmark file.
        </p>
      </EuiCallOut>
    );
  }

  return (
    <>
      <EuiFlexGroup gutterSize='m' wrap>
        <EuiFlexItem grow={false}>
          <EuiFormRow label='Operating system'>
            <EuiSelect
              options={osKeys.map(k => ({
                value: k,
                text: `${osTitle(data, k)}${
                  data.oskeys[k].active ? '' : ' (inactive)'
                }`,
              }))}
              value={osKey}
              onChange={e => {
                setOsKey(e.target.value);
                setPage({ ...page, index: 0 });
              }}
              data-test-subj='ciscat-os'
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ minWidth: 220 }}>
          <EuiFormRow
            label='Applies to group'
            helpText='Agents of this group get the benchmark at the next apply'
          >
            <EuiComboBox
              singleSelection={{ asPlainText: true }}
              isClearable={false}
              options={groups.map(g => ({ label: g }))}
              selectedOptions={
                targets[osKey] ? [{ label: targets[osKey] }] : []
              }
              onChange={sel => {
                if (sel[0]) {
                  setTargets({ ...targets, [osKey]: sel[0].label });
                  setDirty(true);
                }
              }}
              data-test-subj='ciscat-target-group'
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label='Profile'>
            <EuiSelect
              options={(bench?.profiles || []).map(p => ({
                value: p,
                text: p.replace(/_/g, ' '),
              }))}
              value={column}
              onChange={e => setColumn(e.target.value)}
              data-test-subj='ciscat-profile'
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label='Show'>
            <EuiSelect
              options={[
                { value: 'applicable', text: 'Controls in the profile' },
                { value: 'excluded', text: 'Excluded only' },
                { value: 'all', text: 'All controls' },
              ]}
              value={show}
              onChange={e => {
                setShow(e.target.value as ShowFilter);
                setPage({ ...page, index: 0 });
              }}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiFormRow label='Filter'>
            <EuiFieldSearch
              placeholder='CIS number or title'
              value={text}
              onChange={e => {
                setText(e.target.value);
                setPage({ ...page, index: 0 });
              }}
              fullWidth
            />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      <EuiFlexGroup gutterSize='l' responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiStat
            title={stats.applicable}
            description='In profile'
            titleSize='s'
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiStat
            title={stats.fleetWide}
            description='Excluded for the OS'
            titleColor='accent'
            titleSize='s'
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiStat
            title={stats.partial}
            description='Excluded for some agents'
            titleSize='s'
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiStat
            title={stats.scored}
            description='Scored (automated)'
            titleColor='primary'
            titleSize='s'
          />
        </EuiFlexItem>
        <EuiFlexItem />
        <EuiFlexItem grow={false}>
          <EuiButton
            size='s'
            iconType='minusInCircle'
            isDisabled={!selected.size}
            onClick={() => setFlyoutRules(Array.from(selected))}
          >
            Exclude selected ({selected.size})
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <WzButtonPermissions
            permissions={CISCAT_WRITE_PERMISSIONS}
            size='s'
            isDisabled={!dirty}
            isLoading={saving}
            onClick={() => save(false)}
            data-test-subj='ciscat-save'
          >
            Save
          </WzButtonPermissions>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <WzButtonPermissions
            permissions={CISCAT_WRITE_PERMISSIONS}
            size='s'
            fill
            isLoading={saving}
            onClick={() => save(true)}
            data-test-subj='ciscat-save-apply'
          >
            {dirty ? 'Save and apply' : 'Apply'}
          </WzButtonPermissions>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      {benchError && (
        <EuiCallOut color='danger' title='Cannot read the benchmark sheet'>
          <p>{benchError}</p>
        </EuiCallOut>
      )}
      {!bench && !benchError && <EuiLoadingSpinner size='l' />}
      {bench && (
        <>
          <EuiText size='xs' color='subdued'>
            {bench.benchmark} {bench.version}
            {dirty && ' · unsaved changes'}
          </EuiText>
          <EuiBasicTable
            items={pageRows}
            itemId='rule'
            columns={columns}
            pagination={{
              pageIndex: page.index,
              pageSize: page.size,
              totalItemCount: rows.length,
              pageSizeOptions: PAGE_SIZES,
            }}
            onChange={({
              page: p,
            }: {
              page?: { index: number; size: number };
            }) => p && setPage({ index: p.index, size: p.size })}
            tableLayout='auto'
            data-test-subj='ciscat-rules'
          />
        </>
      )}
      {flyoutRules && bench && (
        <ExcludeFlyout
          osKey={osKey}
          column={column}
          rules={flyoutRules}
          user={user}
          onClose={() => setFlyoutRules(undefined)}
          onAdd={records => {
            setDraft({ ...draft, ...records });
            setDirty(true);
            setSelected(new Set());
            setFlyoutRules(undefined);
          }}
        />
      )}
    </>
  );
};
