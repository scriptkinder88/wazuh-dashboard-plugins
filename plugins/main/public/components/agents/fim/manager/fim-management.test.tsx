/* eslint-disable camelcase */ // Wazuh API field names
/* eslint-disable @typescript-eslint/no-explicit-any */ // loose fake API
import React from 'react';
import { TextDecoder, TextEncoder } from 'util';
import {
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { FimManagement } from './fim-management';
import { parseRules } from './lib/agent-conf';
import { DEFAULT_AGENT_CONF } from './lib/plan';

// OUI marks elements with data-test-subj
configure({ testIdAttribute: 'data-test-subj' });
Object.assign(globalThis, { TextEncoder, TextDecoder });

// In-memory manager: groups with their agent.conf, agents, list files.
const confs: Record<string, string> = {};
const agentGroups: Record<string, string[]> = {};
const mockLists: Record<string, string> = {};
const calls: string[] = [];
let activeSyscheck: object = {};

const CONF_WEB = `<agent_config>
  <syscheck>
    <frequency>43200</frequency>
    <directories realtime="yes">/etc/nginx</directories>
  </syscheck>
</agent_config>
`;

const AGENTS = [
  { id: '001', name: 'web-01', status: 'active', os: { platform: 'ubuntu' } },
  { id: '009', name: 'db-09', status: 'active', os: { platform: 'rhel' } },
];

const handle = (method: string, path: string, body: any) => {
  calls.push(`${method} ${path}`);
  const ok = (data: object) => ({ data: { data } });
  let m: RegExpMatchArray | null;
  if (method === 'GET' && path === '/groups') {
    return ok({ affected_items: Object.keys(confs).map(name => ({ name })) });
  }
  if ((m = path.match(/^\/groups\/([^/]+)\/files\/agent\.conf\?raw=true$/))) {
    return { data: confs[decodeURIComponent(m[1])] };
  }
  if (
    method === 'PUT' &&
    (m = path.match(/^\/groups\/([^/]+)\/configuration$/))
  ) {
    parseRules(body.body); // the manager validates the XML
    confs[decodeURIComponent(m[1])] = body.body;
    return ok({});
  }
  if (method === 'POST' && path === '/groups') {
    confs[body.group_id] = DEFAULT_AGENT_CONF;
    return ok({});
  }
  if (method === 'DELETE' && path === '/groups') {
    delete confs[body.params.groups_list];
    Object.values(agentGroups).forEach(g =>
      g.splice(0, g.length, ...g.filter(x => x !== body.params.groups_list)),
    );
    return ok({});
  }
  if (method === 'PUT' && (m = path.match(/^\/agents\/(\d+)\/group\/(.+)$/))) {
    agentGroups[m[1]].push(decodeURIComponent(m[2]));
    return ok({});
  }
  if (method === 'GET' && path === '/agents') {
    return ok({
      affected_items: AGENTS.map(a => ({
        ...a,
        group: agentGroups[a.id],
        group_config_status: 'synced',
      })),
    });
  }
  if (method === 'GET' && (m = path.match(/^\/syscheck\/(\d+)$/))) {
    const inventory: Record<string, string[]> = {
      '001': [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/mime.types',
        '/opt/backup/etc/nginx/nginx.conf',
      ],
    };
    const files = inventory[m[1]] || [];
    // "~" matches anywhere in the path, like the Wazuh server API
    const like = String(body.params.q).replace(/^file~/, '');
    const matching = files.filter(f => f.includes(like));
    return ok({
      affected_items: matching.map(file => ({ file })),
      total_affected_items: matching.length,
    });
  }
  if (method === 'GET' && (m = path.match(/^\/syscheck\/(\d+)\/last_scan$/))) {
    return ok({ affected_items: [{ end: '2026-10-02T10:00:00Z' }] });
  }
  if (method === 'GET' && path.endsWith('/config/syscheck/syscheck')) {
    return ok({ syscheck: activeSyscheck });
  }
  throw new Error(`unexpected ${method} ${path}`);
};

const mockApiReq = jest.fn((method: string, path: string, body: any) => {
  try {
    return Promise.resolve(handle(method, path, body));
  } catch (error) {
    return Promise.reject(error);
  }
});

jest.mock('../../../../react-services', () => ({
  WzRequest: { apiReq: (...args: any[]) => mockApiReq(...args) },
}));

// Permissions are granted; the mock exposes those each button requires.
jest.mock('../../../common/permissions/button', () => {
  const { createElement } = jest.requireActual('react');
  const eui = jest.requireActual('@elastic/eui');
  const buttons: Record<string, unknown> = {
    default: eui.EuiButton,
    empty: eui.EuiButtonEmpty,
    icon: eui.EuiButtonIcon,
  };
  return {
    WzButtonPermissions: ({
      buttonType = 'default',
      permissions,
      tooltip, // eslint-disable-line @typescript-eslint/no-unused-vars
      ...props
    }: any) =>
      createElement(buttons[buttonType], {
        ...props,
        'data-permissions': JSON.stringify(permissions),
      }),
  };
});

jest.mock('../../../../kibana-services', () => ({
  getToasts: () => ({ addSuccess: jest.fn(), addDanger: jest.fn() }),
  getHttp: () => ({ get: jest.fn() }),
}));

jest.mock('../../../../services/list-files', () => {
  const codec = jest.requireActual('../../../../../common/encoded-list');
  const read = (name: string) =>
    Promise.resolve({
      ...codec.parseList(mockLists[name] || ''),
      raw: mockLists[name] || '',
      exists: name in mockLists,
    });
  return {
    existingLists: () => Promise.resolve(new Set(Object.keys(mockLists))),
    readList: read,
    writeList: (name: string, records: object, expectedRaw?: string) => {
      if (
        expectedRaw !== undefined &&
        (mockLists[name] || '') !== expectedRaw
      ) {
        return Promise.reject(new Error('changed by someone else'));
      }
      mockLists[name] = codec.renderList(records);
      return Promise.resolve();
    },
  };
});

jest.mock('../../../../services/dashboard-user', () => ({
  fetchCurrentUserName: () => Promise.resolve('alice'),
}));

beforeEach(() => {
  calls.length = 0;
  [confs, mockLists, agentGroups].forEach(o =>
    Object.keys(o).forEach(k => delete (o as any)[k]),
  );
  confs.default = DEFAULT_AGENT_CONF;
  confs.web = CONF_WEB;
  agentGroups['001'] = ['default', 'web'];
  agentGroups['009'] = ['default'];
  activeSyscheck = {};
});

const pick = async (box: string, option: string) => {
  fireEvent.click(
    within(screen.getByTestId(box)).getByTestId('comboBoxToggleListButton'),
  );
  fireEvent.click(await screen.findByRole('option', { name: option }));
};

const history = () => {
  const store = jest.requireActual('../../../../../common/encoded-list');
  return Object.values(store.parseList(mockLists['fim-history'] || '').records);
};

describe('FIM rules management tab', () => {
  it('lists the rules found in the groups', async () => {
    render(<FimManagement />);
    const table = await screen.findByTestId('fim-rules-table');
    expect(within(table).getByText('/etc/nginx')).toBeTruthy();
    expect(within(table).getByText('real time')).toBeTruthy();
    expect(within(table).getByText('Imported (no audit data)')).toBeTruthy();
  });

  it('adds a rule for a single server in its own group', async () => {
    render(<FimManagement />);
    fireEvent.click(await screen.findByTestId('fim-rule-add'));
    fireEvent.change(screen.getByTestId('fim-rule-path'), {
      target: { value: '/opt/db/conf' },
    });
    fireEvent.change(screen.getByTestId('fim-rule-mode'), {
      target: { value: 'whodata' },
    });
    fireEvent.change(screen.getByTestId('fim-rule-reason'), {
      target: { value: 'DB config, CHG-42' },
    });
    await pick('fim-rule-hosts', 'db-09 (009)');
    fireEvent.click(screen.getByTestId('fim-rule-review'));

    const modal = await screen.findByTestId('fim-plan-modal');
    expect(
      within(modal).getByText(/fim-host-009 \(db-09\): new group/),
    ).toBeTruthy();
    fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
    await screen.findByTestId('fim-plan-done');

    expect(calls).toEqual(
      expect.arrayContaining([
        'POST /groups',
        'PUT /groups/fim-host-009/configuration',
        'PUT /agents/009/group/fim-host-009',
      ]),
    );
    const [rule] = parseRules(confs['fim-host-009']);
    expect(rule).toEqual(
      expect.objectContaining({
        kind: 'directories',
        path: '/opt/db/conf',
        attrs: { whodata: 'yes' },
        meta: expect.objectContaining({
          reason: 'DB config, CHG-42',
          by: 'alice',
        }),
      }),
    );
    expect(agentGroups['009']).toContain('fim-host-009');
  });

  it('points out a wildcard exclusion, fixes it and tests the path', async () => {
    render(<FimManagement />);
    fireEvent.click(await screen.findByTestId('fim-rule-add'));
    fireEvent.change(screen.getByTestId('fim-rule-kind'), {
      target: { value: 'ignore' },
    });
    fireEvent.change(screen.getByTestId('fim-rule-path'), {
      target: { value: '/etc/nginx/*' },
    });
    const hints = screen.getByTestId('fim-rule-hints');
    expect(hints.textContent).toMatch(/literal characters/);
    fireEvent.click(within(hints).getByText('Exclude the folder /etc/nginx'));
    expect(
      (screen.getByTestId('fim-rule-path') as HTMLInputElement).value,
    ).toBe('/etc/nginx');
    expect(screen.queryByTestId('fim-rule-hints')).toBeNull();

    await pick('fim-rule-groups', 'web');
    expect(screen.getByTestId('fim-rule-overlaps').textContent).toContain(
      'This exclusion stops the monitoring of /etc/nginx (Monitor rule in web).',
    );

    fireEvent.click(screen.getByTestId('fim-path-test-run'));
    const test = await screen.findByTestId('fim-path-test');
    expect(test.textContent).toContain('web-01 (001): 2 entries');
    expect(calls).toContain('GET /syscheck/001');
  });

  it('removes a rule and keeps the previous version', async () => {
    render(<FimManagement />);
    const table = await screen.findByTestId('fim-rules-table');
    fireEvent.click(within(table).getByTestId('fim-rule-remove'));
    const modal = await screen.findByTestId('fim-plan-modal');
    expect(within(modal).getByText(/1 agent\(s\)/)).toBeTruthy();
    fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
    await screen.findByTestId('fim-plan-done');

    expect(confs.web).not.toContain('/etc/nginx');
    expect(confs.web).toContain('<frequency>43200</frequency>');
    expect(history()).toEqual([
      expect.objectContaining({ g: 'web', x: CONF_WEB, by: 'alice' }),
    ]);
  });

  it('refuses to overwrite a file changed after the preview', async () => {
    render(<FimManagement />);
    const table = await screen.findByTestId('fim-rules-table');
    fireEvent.click(within(table).getByTestId('fim-rule-remove'));
    const modal = await screen.findByTestId('fim-plan-modal');
    confs.web = CONF_WEB.replace('43200', '3600');
    fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
    expect(
      await within(modal).findByText(/changed by someone else/),
    ).toBeTruthy();
    expect(confs.web).toContain('/etc/nginx');
    expect(mockLists['fim-history']).toBeUndefined();
  });

  it('shows local paths of an agent and offers to ignore them', async () => {
    activeSyscheck = {
      directories: [
        { dir: '/etc/nginx', opts: ['realtime'] },
        { dir: '/usr/local/bin', opts: ['check_all'] },
      ],
    };
    render(<FimManagement />);
    fireEvent.click(await screen.findByTestId('fim-tab-agents'));
    const rows = await screen.findAllByTestId('fim-agent-active');
    fireEvent.click(rows[0]);
    const flyout = await screen.findByTestId('fim-active-flyout');
    await within(flyout).findByText('/usr/local/bin');
    expect(within(flyout).getByText('local')).toBeTruthy();
    fireEvent.click(within(flyout).getByTestId('fim-ignore-local'));

    const form = await screen.findByTestId('fim-rule-flyout');
    expect(
      (within(form).getByTestId('fim-rule-path') as HTMLInputElement).value,
    ).toBe('/usr/local/bin');
    expect(
      (within(form).getByTestId('fim-rule-kind') as HTMLSelectElement).value,
    ).toBe('ignore');
    expect(within(form).getByText('web-01 (001)')).toBeTruthy();
  });

  it('restores a saved version', async () => {
    render(<FimManagement />);
    const table = await screen.findByTestId('fim-rules-table');
    fireEvent.click(within(table).getByTestId('fim-rule-remove'));
    fireEvent.click(
      within(await screen.findByTestId('fim-plan-modal')).getByTestId(
        'fim-plan-apply',
      ),
    );
    await screen.findByTestId('fim-plan-done');
    fireEvent.click(screen.getByText('Close'));
    await waitFor(() =>
      expect(screen.queryByTestId('fim-plan-modal')).toBeNull(),
    );

    fireEvent.click(await screen.findByTestId('fim-tab-history'));
    fireEvent.click(await screen.findByTestId('fim-history-restore'));
    const modal = await screen.findByTestId('fim-plan-modal');
    expect(within(modal).getByTestId('fim-plan-restore-warning')).toBeTruthy();
    const apply = within(modal).getByTestId(
      'fim-plan-apply',
    ) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    fireEvent.click(
      within(modal).getByLabelText('I checked the changes below'),
    );
    expect(apply.disabled).toBe(false);
    fireEvent.click(apply);
    await screen.findByTestId('fim-plan-done');
    expect(confs.web).toBe(CONF_WEB);
  });

  it('requires write permissions for the buttons that change rules', async () => {
    render(<FimManagement />);
    const table = await screen.findByTestId('fim-rules-table');
    const required = JSON.parse(
      within(table)
        .getByTestId('fim-rule-remove')
        .getAttribute('data-permissions') || '[]',
    );
    expect(required).toEqual(
      expect.arrayContaining([
        { action: 'group:update_config', resource: 'group:id:*' },
        { action: 'lists:update', resource: 'list:file:*' },
      ]),
    );
    expect(
      screen.getByTestId('fim-rule-add').getAttribute('data-permissions'),
    ).toContain('group:update_config');
  });

  it('cannot be closed while the change is applied', async () => {
    let release: () => void = () => undefined;
    const pending = new Promise<void>(resolve => {
      release = resolve;
    });
    const real = mockApiReq.getMockImplementation()!;
    mockApiReq.mockImplementation((method: string, path: string, body: any) =>
      method === 'PUT' && path.endsWith('/configuration')
        ? pending.then(() => real(method, path, body))
        : real(method, path, body),
    );
    try {
      render(<FimManagement />);
      const table = await screen.findByTestId('fim-rules-table');
      fireEvent.click(within(table).getByTestId('fim-rule-remove'));
      const modal = await screen.findByTestId('fim-plan-modal');
      fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
      const close = within(modal).getByTestId(
        'fim-plan-close',
      ) as HTMLButtonElement;
      await waitFor(() => expect(close.disabled).toBe(true));
      fireEvent.keyDown(modal, { key: 'Escape', code: 'Escape' });
      expect(screen.getByTestId('fim-plan-modal')).toBeTruthy();

      release();
      await screen.findByTestId('fim-plan-done');
      expect(close.disabled).toBe(false);
    } finally {
      mockApiReq.mockImplementation(real);
    }
  });

  it('reports what was done when a write is rejected', async () => {
    const real = mockApiReq.getMockImplementation()!;
    mockApiReq.mockImplementation((method: string, path: string, body: any) =>
      method === 'PUT' && path.endsWith('/configuration')
        ? Promise.reject(new Error('Wazuh API error 1113: XML syntax error'))
        : real(method, path, body),
    );
    try {
      render(<FimManagement />);
      const table = await screen.findByTestId('fim-rules-table');
      fireEvent.click(within(table).getByTestId('fim-rule-remove'));
      const modal = await screen.findByTestId('fim-plan-modal');
      fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
      const error = await within(modal).findByTestId('fim-plan-error');
      expect(error.textContent).toContain('web: Wazuh API error 1113');
      expect(within(modal).getByText(/previous version saved/)).toBeTruthy();
      expect(confs.web).toBe(CONF_WEB);
    } finally {
      mockApiReq.mockImplementation(real);
    }
  });

  it('shows why the rules cannot be loaded', async () => {
    const real = mockApiReq.getMockImplementation()!;
    mockApiReq.mockImplementation((method: string, path: string, body: any) =>
      path === '/groups'
        ? Promise.reject(new Error('Permission denied'))
        : real(method, path, body),
    );
    try {
      render(<FimManagement />);
      expect(await screen.findByText('Permission denied')).toBeTruthy();
    } finally {
      mockApiReq.mockImplementation(real);
    }
  });
});
