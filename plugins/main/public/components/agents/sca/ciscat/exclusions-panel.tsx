/*
 * Exclusion composer: pick an OS and a profile, tick controls, exclude them
 * for the whole OS, globally, for agents or for agent groups. Saving writes
 * ciscat-exclusions; "Save and apply" also asks the manager to regenerate the
 * policies.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBasicTable,
  EuiButton,
  EuiCallOut,
  EuiComboBox,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiSelect,
  EuiSpacer,
  EuiStat,
  EuiText,
} from '@elastic/eui';
import { WzButtonPermissions } from '../../../common/permissions/button';
import { CISCAT_WRITE_PERMISSIONS } from './lib/permissions';
import { benchListName } from '../../../../../common/ciscat/store';
import { getToasts } from '../../../../kibana-services';
import {
  Bench,
  KeyedExclusions,
  ShowFilter,
  buildRows,
  composerStats,
  parseBench,
} from './lib/composer';
import { fetchGroupNames, readList } from './lib/lists-api';
import {
  PartialSaveError,
  osTitle,
  saveExclusions,
  savedTargets,
  validExclusions,
} from './lib/exclusion-data';
import { ExcludeFlyout } from './exclude-flyout';
import { ruleColumns } from './exclusion-columns';
import type { CiscatData } from './ciscat-management';

const PAGE_SIZES = [25, 50, 100];
const toast = (title: string, color: 'success' | 'danger', text?: string) =>
  color === 'success'
    ? getToasts().addSuccess({ title, text })
    : getToasts().addDanger({ title, text });

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
    try {
      await saveExclusions({ data, draft, targets, user, apply });
      toast(
        apply ? 'Exclusions saved, apply requested' : 'Exclusions saved',
        'success',
        apply
          ? 'The manager regenerates the policies within 5 minutes.'
          : 'Use "Save and apply" to publish them to the agents.',
      );
      onSaved();
    } catch (e) {
      if (e instanceof PartialSaveError) {
        // the lists read before the save are outdated: reload them, or the
        // next save would be refused as a concurrent change
        toast('Exclusions saved, the rest was not', 'danger', e.message);
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
  const columns = ruleColumns({
    selected,
    toggle,
    removeExclusion,
    exclude: setFlyoutRules,
  });

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
