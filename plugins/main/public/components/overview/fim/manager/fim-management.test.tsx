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
// dashboard store records (indexer), by id
const mockStore: Record<string, any> = {};
let mockReported: any = {};
const calls: string[] = [];

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
      })),
    });
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

// FIM inventory (wazuh-states-fim-files) of the path test
const mockInventory: Record<string, string[]> = {
  '001': ['/etc/nginx/nginx.conf', '/etc/nginx/mime.types'],
};
const mockSearches: any[] = [];

jest.mock('../../../../kibana-services', () => ({
  getToasts: () => ({ addSuccess: jest.fn(), addDanger: jest.fn() }),
  getHttp: () => ({ get: jest.fn() }),
  getDataPlugin: () => ({
    indexPatterns: { get: (id: string) => Promise.resolve({ id }) },
    search: {
      searchSource: {
        create: () => {
          const fields: Record<string, any> = {};
          const source = {
            setParent: () => source,
            setField: (k: string, v: any) => {
              fields[k] = v;
              return source;
            },
            fetch: () => {
              mockSearches.push(fields);
              const [agent, prefix] = fields.query.query.bool.filter;
              const files = (
                mockInventory[agent.term['wazuh.agent.id']] || []
              ).filter(f => f.startsWith(prefix.prefix['file.path']));
              return Promise.resolve({
                hits: { total: { value: files.length } },
                aggregations: {
                  last: { value_as_string: '2026-10-02T10:00:00Z' },
                },
              });
            },
          };
          return Promise.resolve(source);
        },
      },
    },
  }),
}));

jest.mock('../../../../services/dashboard-store', () => ({
  listStoreRecords: (_c: string, q: any) =>
    Promise.resolve(
      Object.values(mockStore)
        .filter(
          r => (!q.kind || r.kind === q.kind) && (!q.key || r.key === q.key),
        )
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at)),
    ),
  putStoreRecord: (_c: string, r: any) => {
    mockStore[r.id] = {
      ...r,
      updated_by: 'alice',
      updated_at: new Date().toISOString(),
    };
    return Promise.resolve({ seqNo: 1, primaryTerm: 1 });
  },
  deleteStoreRecord: (_c: string, id: string) => {
    delete mockStore[id];
    return Promise.resolve();
  },
  fetchCurrentUserName: () => Promise.resolve('alice'),
}));

jest.mock(
  '../../../../controllers/management/components/management/configuration/utils/agent-config-service',
  () => ({
    clearAgentReportedConfigurationCache: () => undefined,
    getAgentReportedConfiguration: () => Promise.resolve(mockReported),
  }),
);

beforeEach(() => {
  calls.length = 0;
  [confs, mockStore, agentGroups].forEach(o =>
    Object.keys(o).forEach(k => delete (o as any)[k]),
  );
  confs.default = DEFAULT_AGENT_CONF;
  confs.web = CONF_WEB;
  agentGroups['001'] = ['default', 'web'];
  agentGroups['009'] = ['default'];
  mockReported = {
    content: { fim: { syscheck: {} } },
    modules: ['fim'],
    modifiedAt: '2026-10-01T10:00:00Z',
  };
});

const pick = async (box: string, option: string) => {
  fireEvent.click(
    within(screen.getByTestId(box)).getByTestId('comboBoxToggleListButton'),
  );
  fireEvent.click(await screen.findByRole('option', { name: option }));
};

const history = () => Object.values(mockStore);

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
    expect(test.textContent).toContain('last change');
    expect(mockSearches[0].index).toEqual({ id: 'wazuh-states-fim-files*' });
    expect(calls.some(c => c.includes('/syscheck'))).toBe(false);
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
      expect.objectContaining({
        kind: 'history',
        key: 'web',
        data: { content: CONF_WEB, note: expect.any(String) },
        updated_by: 'alice',
      }),
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
    expect(history()).toEqual([]);
  });

  it('shows local paths of an agent and offers to ignore them', async () => {
    mockReported.content.fim.syscheck = {
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

  it('says when an agent has not reported its configuration', async () => {
    mockReported = null;
    render(<FimManagement />);
    fireEvent.click(await screen.findByTestId('fim-tab-agents'));
    fireEvent.click((await screen.findAllByTestId('fim-agent-active'))[0]);
    expect(await screen.findByTestId('fim-not-reported')).toBeTruthy();
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
    fireEvent.click(within(modal).getByTestId('fim-plan-apply'));
    await screen.findByTestId('fim-plan-done');
    expect(confs.web).toBe(CONF_WEB);
  });
});
