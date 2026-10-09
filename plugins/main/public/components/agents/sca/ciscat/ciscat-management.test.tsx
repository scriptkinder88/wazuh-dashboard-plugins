/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React from 'react';
import { webcrypto } from 'crypto';
import { TextDecoder, TextEncoder } from 'util';
import {
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import {
  ListRecords,
  parseList,
  renderList,
} from '../../../../../common/ciscat/store';
import { CiscatManagement } from './ciscat-management';

// OUI marks elements with data-test-subj
configure({ testIdAttribute: 'data-test-subj' });

// In-memory manager: list files as the Wazuh API would store them.
const files: Record<string, string> = {};
const writes: Array<[string, ListRecords]> = [];
/** Lists whose next write fails. */
const mockFailingWrites = new Set<string>();

jest.mock(
  '@osd/ui-shared-deps/theme',
  () => ({
    euiThemeVars: {
      euiColorPrimary: '#006BB4',
      euiColorLightShade: '#D3DAE6',
      euiColorDarkShade: '#69707D',
      euiColorEmptyShade: '#FFF',
      euiTextSubduedColor: '#6a717d',
    },
  }),
  { virtual: true },
);

// Permissions are granted; the mock exposes those each button requires.
jest.mock('../../../common/permissions/button', () => {
  const { createElement } = jest.requireActual('react');
  const eui = jest.requireActual('@elastic/eui');
  const buttons: Record<string, unknown> = {
    default: eui.EuiButton,
    icon: eui.EuiButtonIcon,
    switch: eui.EuiSwitch,
  };
  return {
    WzButtonPermissions: ({
      buttonType = 'default',
      permissions,
      ...props
    }: Record<string, unknown>) =>
      createElement(buttons[buttonType as string], {
        ...props,
        'data-permissions': JSON.stringify(permissions),
      }),
  };
});

const mockToasts = { addSuccess: jest.fn(), addDanger: jest.fn() };
jest.mock('../../../../kibana-services', () => ({
  getToasts: () => mockToasts,
  getHttp: () => ({ get: jest.fn() }),
}));

jest.mock('./lib/lists-api', () => {
  const store = jest.requireActual('../../../../../common/ciscat/store');
  const read = (name: string) => {
    const raw = files[name] || '';
    return Promise.resolve({
      ...store.parseList(raw),
      raw,
      exists: name in files,
    });
  };
  const write = (name: string, records: ListRecords, expectedRaw?: string) => {
    if (mockFailingWrites.has(name)) {
      mockFailingWrites.delete(name);
      return Promise.reject(new Error(`cannot write ${name}`));
    }
    if (expectedRaw !== undefined && (files[name] || '') !== expectedRaw) {
      return Promise.reject(new Error('changed by someone else'));
    }
    files[name] = store.renderList(records);
    writes.push([name, records]);
    return Promise.resolve();
  };
  return {
    existingLists: () => Promise.resolve(new Set(Object.keys(files))),
    readList: read,
    writeList: write,
    addRequest: async (key: string, request: object) => {
      const current = await read('ciscat-requests');
      await write('ciscat-requests', { ...current.records, [key]: request });
    },
    fetchAgentNames: () => Promise.resolve(['web-01', 'web-02']),
    fetchGroupNames: () =>
      Promise.resolve(['app-sap', 'ciscat-rhel7-base', 'os-rhel7']),
    fetchRunAgents: () =>
      Promise.resolve([
        { id: '001', name: 'web-01', platform: 'rhel' },
        { id: '003', name: 'play-cb-wxi001', platform: 'windows' },
      ]),
    fetchCurrentUserName: () => Promise.resolve('alice'),
  };
});

// jsdom (the CI test environment) lacks Web Crypto and TextEncoder, which
// every browser has.
Object.assign(globalThis, { TextEncoder, TextDecoder });
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
}

beforeEach(() => {
  writes.length = 0;
  mockToasts.addSuccess.mockClear();
  mockToasts.addDanger.mockClear();
  mockFailingWrites.clear();
  Object.keys(files).forEach(k => delete files[k]);
  files['ciscat-oskeys'] = renderList({
    rhel7: {
      v: 1,
      active: true,
      available: true,
      role: 'Server',
      levels: ['L1'],
      group: 'os-rhel7',
      title: 'Red Hat Enterprise Linux 7',
      version: '4.0.0',
    },
  });
  files['ciscat-bench-rhel7'] = renderList({
    _meta: {
      benchmark: 'demo_bench',
      version: '4.0.0',
      profiles: ['L1_Server', 'L2_Server'],
    },
    '1.1.1': { t: 'Ensure cramfs is disabled', p: ['L1_Server', 'L2_Server'] },
    '1.2': { t: 'Ensure updates are configured', p: ['L1_Server'], m: true },
  });
  files['ciscat-status'] = renderList({
    scheduler: {
      last_tick: '2026-10-01T10:00:00',
      utc_offset: '+0200',
      tz: 'CEST',
    },
  });
});

const lastWrite = (name: string) =>
  [...writes].reverse().find(([n]) => n === name)?.[1] || {};

describe('CIS-CAT management tab', () => {
  it('excludes a control for the OS and asks the manager to apply', async () => {
    render(<CiscatManagement />);
    const table = await screen.findByTestId('ciscat-rules');
    expect(within(table).getByText('Ensure cramfs is disabled')).toBeTruthy();
    expect(within(table).getByText('manual')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Exclude 1.1.1'));
    fireEvent.change(await screen.findByTestId('ciscat-reason'), {
      target: { value: 'Needed by the storage team' },
    });
    fireEvent.click(screen.getByTestId('ciscat-add-exclusion'));
    await screen.findByText('All agents of this OS');

    fireEvent.click(screen.getByTestId('ciscat-save-apply'));
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
        expect.objectContaining({ action: 'apply', requested_by: 'alice' }),
      ]),
    );
    // exclusions first, then the request; the targets did not change
    expect(writes.map(([name]) => name)).toEqual([
      'ciscat-exclusions',
      'ciscat-requests',
    ]);
    expect(mockToasts.addSuccess).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Exclusions saved, apply requested' }),
    );

    const saved = Object.values(lastWrite('ciscat-exclusions'));
    expect(saved).toEqual([
      expect.objectContaining({
        os_key: 'rhel7',
        scope: 'os',
        scope_value: 'rhel7',
        level: 'L1',
        role: 'Server',
        rule: '1.1.1',
        reason: 'Needed by the storage team',
        updated_by: 'alice',
      }),
    ]);
    // what was written parses back as the master will read it
    expect(parseList(files['ciscat-exclusions']).errors).toEqual([]);
  });

  it('reloads after a save that failed once the exclusions were written', async () => {
    render(<CiscatManagement />);
    await screen.findByTestId('ciscat-rules');
    fireEvent.click(screen.getByLabelText('Exclude 1.1.1'));
    fireEvent.change(await screen.findByTestId('ciscat-reason'), {
      target: { value: 'Needed by the storage team' },
    });
    fireEvent.click(screen.getByTestId('ciscat-add-exclusion'));
    await screen.findByText('All agents of this OS');

    mockFailingWrites.add('ciscat-requests');
    fireEvent.click(screen.getByTestId('ciscat-save-apply'));
    await waitFor(() =>
      expect(mockToasts.addDanger).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Exclusions saved, the rest was not',
          text: 'cannot write ciscat-requests',
        }),
      ),
    );
    expect(Object.values(lastWrite('ciscat-exclusions'))).toEqual([
      expect.objectContaining({ rule: '1.1.1' }),
    ]);
    // the reloaded panel has no unsaved change and applies without a false
    // concurrent change
    await waitFor(() =>
      expect(screen.getByTestId('ciscat-save-apply').textContent).toBe('Apply'),
    );
    fireEvent.click(screen.getByTestId('ciscat-save-apply'));
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
        expect.objectContaining({ action: 'apply' }),
      ]),
    );
    expect(mockToasts.addDanger).toHaveBeenCalledTimes(1);
  });

  it('requires lists:update for the buttons that change the lists', async () => {
    render(<CiscatManagement />);
    await screen.findByTestId('ciscat-rules');
    expect(
      JSON.parse(
        screen.getByTestId('ciscat-save').getAttribute('data-permissions') ||
          '[]',
      ),
    ).toEqual([{ action: 'lists:update', resource: 'list:file:*' }]);
    fireEvent.click(screen.getByTestId('ciscat-tab-schedule'));
    expect(
      (await screen.findByTestId('ciscat-run-now')).getAttribute(
        'data-permissions',
      ),
    ).toContain('lists:update');
  });

  it('shows the benchmark version and applies it to the chosen group', async () => {
    render(<CiscatManagement />);
    await screen.findByTestId('ciscat-rules');
    expect(
      screen.getByRole('option', { name: 'Red Hat Enterprise Linux 7 v4.0.0' }),
    ).toBeTruthy();
    const box = screen.getByTestId('ciscat-target-group');
    expect(within(box).getByText('os-rhel7')).toBeTruthy();
    fireEvent.click(within(box).getByTestId('comboBoxToggleListButton'));
    fireEvent.click(await screen.findByRole('option', { name: 'app-sap' }));
    fireEvent.click(screen.getByTestId('ciscat-save-apply'));
    await waitFor(() =>
      expect(lastWrite('ciscat-targets')).toEqual({
        rhel7: expect.objectContaining({
          group: 'app-sap',
          updated_by: 'alice',
        }),
      }),
    );
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
        expect.objectContaining({ action: 'apply' }),
      ]),
    );
  });

  it('sets a benchmark back to no group and warns about a shared group', async () => {
    files['ciscat-oskeys'] = renderList({
      ...parseList(files['ciscat-oskeys']).records,
      win: { v: 1, active: true, available: false, group: 'os-win' },
    });
    files['ciscat-targets'] = renderList({ rhel7: { v: 1, group: 'os-win' } });
    render(<CiscatManagement />);
    await screen.findByTestId('ciscat-rules');
    expect(
      (await screen.findByTestId('ciscat-group-shared')).textContent,
    ).toContain('Group os-win is also the group of win');
    const box = screen.getByTestId('ciscat-target-group');
    fireEvent.click(within(box).getByTestId('comboBoxToggleListButton'));
    expect(
      screen.queryByRole('option', { name: 'ciscat-rhel7-base' }),
    ).toBeNull();
    fireEvent.click(
      await screen.findByRole('option', {
        name: 'No group (not applied from here)',
      }),
    );
    expect(screen.queryByTestId('ciscat-group-shared')).toBeNull();
    fireEvent.click(screen.getByTestId('ciscat-save'));
    await waitFor(() => expect(lastWrite('ciscat-targets')).toEqual({}));
  });

  it('refuses an exclusion without a reason', async () => {
    render(<CiscatManagement />);
    await screen.findByTestId('ciscat-rules');
    fireEvent.click(screen.getByLabelText('Exclude 1.1.1'));
    fireEvent.click(await screen.findByTestId('ciscat-add-exclusion'));
    await screen.findByText(/reason: required/);
    expect(writes).toEqual([]);
  });

  it('creates a monthly schedule and shows the manager time zone', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-schedule'));
    expect(await screen.findByText(/CEST, UTC\+0200/)).toBeTruthy();
    fireEvent.click(screen.getByTestId('ciscat-new-schedule'));
    fireEvent.click(
      await screen.findByLabelText('Days before the end of the month'),
    );
    fireEvent.click(screen.getByTestId('ciscat-save-job'));
    await waitFor(() =>
      expect(Object.keys(lastWrite('ciscat-schedule'))).toHaveLength(1),
    );
    expect(mockToasts.addSuccess).toHaveBeenCalledWith({
      title: 'Schedule saved',
    });
    const [key, job] = Object.entries(lastWrite('ciscat-schedule'))[0];
    expect(key).toMatch(/^j[0-9a-f]{12}$/);
    expect(job).toEqual(
      expect.objectContaining({
        type: 'monthly',
        day: -1,
        time: '22:00',
        targets: ['*'],
        wave_size: 50,
        wave_pause_s: 300,
        created_by: 'alice',
      }),
    );
  });

  it('requests a run now with its waves', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-schedule'));
    fireEvent.click(await screen.findByTestId('ciscat-run-now'));
    fireEvent.click(await screen.findByTestId('ciscat-save-job'));
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
        expect.objectContaining({
          action: 'run',
          label: 'Run now',
          targets: ['*'],
          wave_size: 50,
          wave_pause_s: 300,
          requested_by: 'alice',
        }),
      ]),
    );
    expect(mockToasts.addSuccess).toHaveBeenCalledWith({
      title: 'Run requested',
      text: 'The manager starts it within 5 minutes.',
    });
    // nothing is scheduled: the run is a one-off request
    expect(lastWrite('ciscat-schedule')).toEqual({});
  });

  it('runs now on a pasted list of agents', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-schedule'));
    fireEvent.click(await screen.findByTestId('ciscat-run-now'));
    fireEvent.click(await screen.findByLabelText('Agents'));
    const box = await screen.findByTestId('ciscat-run-agents');
    const input = within(box).getByRole('textbox');
    // ids and names, the agents are read when the flyout opens
    await waitFor(() => {
      fireEvent.focus(input);
      fireEvent.change(input, { target: { value: '003, WEB-01 nope' } });
      fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
      expect(within(box).getByText('001 · web-01 (rhel)')).toBeTruthy();
    });
    expect(
      within(box).getByText('003 · play-cb-wxi001 (windows)'),
    ).toBeTruthy();
    expect(screen.getByText('Unknown agents: nope')).toBeTruthy();
    fireEvent.click(screen.getByTestId('ciscat-save-job'));
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
        expect.objectContaining({
          action: 'run',
          targets: [],
          agents: ['001', '003'],
          groups: [],
        }),
      ]),
    );
  });

  it('refuses a run without agents', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-schedule'));
    fireEvent.click(await screen.findByTestId('ciscat-run-now'));
    fireEvent.click(await screen.findByLabelText('Agents'));
    fireEvent.click(screen.getByTestId('ciscat-save-job'));
    expect(
      await screen.findByText(
        'Choose at least one operating system, group or agent',
      ),
    ).toBeTruthy();
    expect(writes).toEqual([]);
  });

  it('schedules a run on a custom group', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-schedule'));
    fireEvent.click(screen.getByTestId('ciscat-new-schedule'));
    fireEvent.click(await screen.findByLabelText('Agent groups'));
    const box = await screen.findByTestId('ciscat-run-groups');
    fireEvent.click(within(box).getByTestId('comboBoxToggleListButton'));
    expect(
      await screen.findByRole('option', { name: 'os-rhel7' }),
    ).toBeTruthy();
    // the bridge's own groups are not offered
    expect(
      screen.queryByRole('option', { name: 'ciscat-rhel7-base' }),
    ).toBeNull();
    fireEvent.click(screen.getByRole('option', { name: 'app-sap' }));
    fireEvent.click(screen.getByTestId('ciscat-save-job'));
    await waitFor(() =>
      expect(Object.values(lastWrite('ciscat-schedule'))).toEqual([
        expect.objectContaining({
          targets: [],
          groups: ['app-sap'],
          agents: [],
        }),
      ]),
    );
    expect(await screen.findByText('Group app-sap')).toBeTruthy();
  });

  it('shows the coverage trend per benchmark', async () => {
    files['ciscat-history'] = renderList({
      '2026-09-30': {
        v: 1,
        os: {
          rhel7: { expected: 4, assessed: 1, disconnected: 2 },
          win: { expected: 2, assessed: 2, disconnected: 0 },
        },
      },
      '2026-10-01': {
        v: 1,
        os: {
          rhel7: { expected: 4, assessed: 2, disconnected: 1 },
          win: { expected: 2, assessed: 2, disconnected: 0 },
        },
      },
    });
    render(<CiscatManagement />);
    const latest = await screen.findByTestId('ciscat-coverage-latest');
    expect(latest.textContent).toContain('66.7% (4 of 6 agents)');
    expect(latest.textContent).toContain('1 not assessed and disconnected');

    fireEvent.change(screen.getByTestId('ciscat-coverage-os'), {
      target: { value: 'rhel7' },
    });
    expect(screen.getByTestId('ciscat-coverage-latest').textContent).toContain(
      '50% (2 of 4 agents)',
    );
    expect(
      within(screen.getByTestId('ciscat-coverage-os')).getByText(
        'Red Hat Enterprise Linux 7',
      ),
    ).toBeTruthy();

    // the tooltip follows the pointer
    const hover = screen.getByTestId('ciscat-coverage-hover');
    hover.getBoundingClientRect = () =>
      ({ left: 0, width: 100, top: 0, height: 100 } as DOMRect);
    fireEvent.mouseMove(hover, { clientX: 100 });
    expect(screen.getByTestId('ciscat-coverage-tooltip').textContent).toContain(
      '50% (2 of 4 agents)',
    );
    fireEvent.mouseLeave(hover);
    expect(screen.queryByTestId('ciscat-coverage-tooltip')).toBeNull();
  });

  it('explains an empty coverage trend', async () => {
    render(<CiscatManagement />);
    expect(await screen.findByTestId('ciscat-coverage-empty')).toBeTruthy();
  });

  it('shows the scheduler state', async () => {
    render(<CiscatManagement />);
    fireEvent.click(await screen.findByTestId('ciscat-tab-status'));
    expect(await screen.findByText('Policies per OS')).toBeTruthy();
    expect(screen.getByText('CEST (UTC+0200)')).toBeTruthy();
  });
});
