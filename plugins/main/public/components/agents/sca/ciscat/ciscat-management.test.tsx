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

jest.mock('../../../../kibana-services', () => ({
  getToasts: () => ({ addSuccess: jest.fn(), addDanger: jest.fn() }),
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
    fetchGroupNames: () => Promise.resolve(['app-sap', 'os-rhel7']),
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
    await waitFor(() => expect(lastWrite('ciscat-requests')).not.toEqual({}));

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
    expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
      expect.objectContaining({ action: 'apply', requested_by: 'alice' }),
    ]);
    // what was written parses back as the master will read it
    expect(parseList(files['ciscat-exclusions']).errors).toEqual([]);
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
    await waitFor(() => expect(lastWrite('ciscat-requests')).not.toEqual({}));
    expect(lastWrite('ciscat-targets')).toEqual({
      rhel7: expect.objectContaining({ group: 'app-sap', updated_by: 'alice' }),
    });
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
    await waitFor(() => expect(lastWrite('ciscat-schedule')).not.toEqual({}));
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
    await waitFor(() => expect(lastWrite('ciscat-requests')).not.toEqual({}));
    expect(Object.values(lastWrite('ciscat-requests'))).toEqual([
      expect.objectContaining({
        action: 'run',
        targets: ['*'],
        wave_size: 50,
        wave_pause_s: 300,
      }),
    ]);
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
