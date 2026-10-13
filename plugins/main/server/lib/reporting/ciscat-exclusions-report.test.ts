import { TextDecoder, TextEncoder } from 'util';
import { renderList } from '../../../common/encoded-list';
import {
  addExclusionRegisterToReport,
  fetchExclusionRegister,
  parseExclusionRegister,
} from './ciscat-exclusions-report';

// jsdom (the test environment) lacks TextEncoder, which every browser and Node have
Object.assign(globalThis, { TextEncoder, TextDecoder });

const exclusion = (rule: string, extra: Record<string, string> = {}) => ({
  v: 1,
  os_key: 'rhel7',
  scope: 'os',
  scope_value: 'rhel7',
  level: 'L1',
  role: '',
  rule,
  reason: 'needed by the application',
  ticket: 'CHG-1',
  owner: 'unix team',
  updated_by: 'alice',
  updated_at: '2026-10-01T10:00:00+02:00',
  ...extra,
});

const raw = renderList({
  _empty: { v: 1 },
  a: exclusion('1.1.10'),
  b: exclusion('1.1.2'),
  c: exclusion('2.2.1', { os_key: 'windows_server_2025', scope_value: 'x' }),
  d: exclusion('3.1', { scope: 'host', scope_value: 'web-01' }),
  bad: { os_key: 'rhel7', scope: 'nowhere', rule: '1' },
});

const fakePrinter = () => {
  const calls: Array<[string, any]> = [];
  return {
    calls,
    addContent: (c: any) => calls.push(['content', c]),
    addNewLine: () => calls.push(['newline', null]),
    addContentWithNewLine: (c: any) => calls.push(['content', c]),
    addSimpleTable: (t: any) => calls.push(['table', t]),
  };
};

describe('CIS-CAT exclusion register report', () => {
  it('keeps the valid records, sorted by OS, scope, target and rule', () => {
    const { exclusions, rejected } = parseExclusionRegister(raw);
    expect(rejected).toBe(1);
    expect(exclusions.map(e => `${e.os_key}:${e.scope}:${e.rule}`)).toEqual([
      'rhel7:host:3.1',
      'rhel7:os:1.1.2',
      'rhel7:os:1.1.10',
      'windows_server_2025:os:2.2.1',
    ]);
  });

  it('prints a summary and one table per benchmark with every audit field', () => {
    const printer = fakePrinter();
    addExclusionRegisterToReport(
      printer,
      parseExclusionRegister(raw),
      '1 Oct 2026',
    );
    const tables = printer.calls.filter(c => c[0] === 'table').map(c => c[1]);
    expect(tables).toHaveLength(3);
    expect(tables[0].items).toEqual(
      expect.arrayContaining([
        { item: 'Exclusions', value: 4 },
        { item: 'Invalid records not shown', value: 1 },
      ]),
    );
    const rhel = tables[1];
    expect(rhel.columns.map((c: any) => c.label)).toEqual([
      'Rule',
      'Scope',
      'Applies to',
      'Level',
      'Role',
      'Reason',
      'Ticket',
      'Owner',
      'Changed by',
      'Changed at',
    ]);
    expect(rhel.items).toHaveLength(3);
    expect(rhel.items[0]).toMatchObject({
      rule: '3.1',
      scope: 'Agent',
      target: 'web-01',
      ticket: 'CHG-1',
      updated_by: 'alice',
    });
    // the register is never cut: every record is in the table
    expect(tables[2].items).toHaveLength(1);
  });

  it('says so when there are no exclusions', () => {
    const printer = fakePrinter();
    addExclusionRegisterToReport(
      printer,
      { exclusions: [], rejected: 0 },
      'now',
    );
    expect(JSON.stringify(printer.calls)).toContain('No exclusions');
  });

  it('reads the list through the API as the current user', async () => {
    const request = jest
      .fn()
      .mockResolvedValueOnce({
        data: { data: { affected_items: [{ filename: 'ciscat-exclusions' }] } },
      })
      .mockResolvedValueOnce({ data: raw });
    const context = {
      wazuh: { api: { client: { asCurrentUser: { request } } } },
    };
    const register = await fetchExclusionRegister(context, 'api1');
    expect(register.exclusions).toHaveLength(4);
    expect(request).toHaveBeenLastCalledWith(
      'GET',
      '/lists/files/ciscat-exclusions',
      { params: { raw: true } },
      { apiHostID: 'api1' },
    );
  });

  it('fails rather than reporting no exclusions when the list is not visible', async () => {
    const request = jest
      .fn()
      .mockResolvedValue({ data: { data: { affected_items: [] } } });
    const context = {
      wazuh: { api: { client: { asCurrentUser: { request } } } },
    };
    await expect(fetchExclusionRegister(context, 'api1')).rejects.toThrow(
      'lists:read',
    );
    expect(request).toHaveBeenCalledTimes(1);
  });
});
