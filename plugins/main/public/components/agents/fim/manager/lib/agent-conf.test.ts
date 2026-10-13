/* eslint-disable camelcase */ // agent.conf attribute names
import { TextDecoder, TextEncoder } from 'util';
import {
  AgentConfError,
  FimRule,
  decodeMeta,
  editAgentConf,
  encodeMeta,
  parseRules,
  ruleKey,
  validateRule,
} from './agent-conf';

Object.assign(global, { TextEncoder, TextDecoder });

const CONF = `<agent_config>
  <!-- Shared agent configuration here -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/app.log</location>
  </localfile>
  <syscheck>
    <frequency>43200</frequency>
    <directories realtime="yes" report_changes="yes">/etc/app</directories>
    <ignore type="sregex">.log$</ignore>
  </syscheck>
</agent_config>

<agent_config os="Windows">
  <syscheck>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\\Software\\App</windows_registry>
  </syscheck>
</agent_config>
`;

const meta = {
  reason: 'PCI 11.5 — config files',
  ticket: 'CHG-1',
  owner: 'ops',
  by: 'alice',
  at: '2026-10-01T10:00:00Z',
};

const rule = (over: Partial<FimRule> = {}): FimRule => ({
  kind: 'directories',
  path: '/opt/app/conf',
  attrs: { whodata: 'yes' },
  filter: {},
  meta,
  ...over,
});

describe('parseRules', () => {
  it('finds the FIM rules with their block filter', () => {
    const rules = parseRules(CONF);
    expect(rules.map(r => [r.kind, r.path, r.attrs, r.filter])).toEqual([
      [
        'directories',
        '/etc/app',
        { realtime: 'yes', report_changes: 'yes' },
        {},
      ],
      ['ignore', '.log$', { type: 'sregex' }, {}],
      [
        'windows_registry',
        'HKEY_LOCAL_MACHINE\\Software\\App',
        { arch: 'both' },
        { os: 'Windows' },
      ],
    ]);
  });

  it('reports malformed files with the line', () => {
    expect(() =>
      parseRules('<agent_config>\n<syscheck>\n</agent_config>'),
    ).toThrow(/line 3: unexpected <\/agent_config>/);
    expect(() => parseRules('<agent_config>')).toThrow(AgentConfError);
  });

  it('reads the audit comment of a rule', () => {
    const text = editAgentConf(CONF, { add: [rule()] });
    const added = parseRules(text).find(r => r.path === '/opt/app/conf');
    expect(added?.meta).toEqual(meta);
  });
});

describe('meta comment', () => {
  it('round-trips unicode and never contains "--"', () => {
    const encoded = encodeMeta({ ...meta, reason: '-- ü --' });
    expect(encoded).not.toContain('--');
    expect(decodeMeta(encoded)?.reason).toBe('-- ü --');
    expect(decodeMeta('%%%')).toBeUndefined();
  });
});

describe('editAgentConf', () => {
  it('adds a rule to the existing syscheck section and keeps the rest', () => {
    const out = editAgentConf(CONF, { add: [rule()] });
    expect(out).toContain(
      '    <ignore type="sregex">.log$</ignore>\n    <!-- wz-fim ',
    );
    expect(out).toContain(
      '    <directories whodata="yes">/opt/app/conf</directories>\n  </syscheck>',
    );
    // Removing it gives back the original file byte for byte.
    expect(editAgentConf(out, { remove: [ruleKey(rule())] })).toBe(CONF);
  });

  it('creates the filtered block when missing and drops it when emptied', () => {
    const linux = rule({ filter: { os: 'Linux' } });
    const out = editAgentConf(CONF, { add: [linux] });
    expect(out).toContain(
      '<agent_config os="Linux">\n  <syscheck>\n    <!-- wz-fim ',
    );
    expect(editAgentConf(out, { remove: [ruleKey(linux)] })).toBe(CONF);
  });

  it('adds a syscheck section to a block without one', () => {
    const base = '<agent_config>\n  <labels/>\n</agent_config>\n';
    const out = editAgentConf(base, { add: [rule({ meta: undefined })] });
    expect(out).toBe(
      '<agent_config>\n  <labels/>\n  <syscheck>\n' +
        '    <directories whodata="yes">/opt/app/conf</directories>\n' +
        '  </syscheck>\n</agent_config>\n',
    );
    expect(editAgentConf(out, { remove: [ruleKey(rule())] })).toBe(base);
  });

  it('removes imported rules and keeps other syscheck settings', () => {
    const [dir] = parseRules(CONF);
    const out = editAgentConf(CONF, { remove: [ruleKey(dir)] });
    expect(out).not.toContain('/etc/app');
    expect(out).toContain('<frequency>43200</frequency>');
    expect(out).toContain('<localfile>');
  });

  it('removes a section emptied of rules, keeps the generic block', () => {
    const base =
      '<agent_config>\n  <syscheck>\n    <ignore>/tmp</ignore>\n  </syscheck>\n</agent_config>\n';
    const [only] = parseRules(base);
    expect(editAgentConf(base, { remove: [ruleKey(only)] })).toBe(
      '<agent_config>\n</agent_config>\n',
    );
  });

  it('updates the options of a rule (remove + add)', () => {
    const [dir] = parseRules(CONF);
    const changed = { ...dir, attrs: { whodata: 'yes' }, meta };
    const out = editAgentConf(CONF, { remove: [ruleKey(dir)], add: [changed] });
    const rules = parseRules(out).filter(r => r.path === '/etc/app');
    expect(rules).toHaveLength(1);
    expect(rules[0].attrs).toEqual({ whodata: 'yes' });
  });

  it('does not duplicate a rule already present', () => {
    const [dir] = parseRules(CONF);
    expect(editAgentConf(CONF, { add: [{ ...dir }] })).toBe(CONF);
  });

  it('refuses values that would break the XML', () => {
    expect(() =>
      editAgentConf(CONF, { add: [rule({ path: '/a<b' })] }),
    ).toThrow(/cannot contain/);
    expect(() =>
      editAgentConf(CONF, { add: [rule({ attrs: { tags: 'a"b' } })] }),
    ).toThrow(/invalid attribute tags/);
  });
});

describe('special characters', () => {
  it('keeps "&" and entities as they are, like the Wazuh XML reader', () => {
    const imported = `<agent_config>
  <syscheck>
    <directories restrict="a&amp;b|c&d">C:\\R&D</directories>
  </syscheck>
</agent_config>
`;
    const [dir] = parseRules(imported);
    expect(dir.path).toBe('C:\\R&D');
    expect(dir.attrs.restrict).toBe('a&amp;b|c&d');
    expect(validateRule({ ...dir, meta })).toEqual([]);

    // changing an option rewrites the values unchanged
    const changed = editAgentConf(imported, {
      remove: [ruleKey(dir)],
      add: [{ ...dir, attrs: { ...dir.attrs, realtime: 'yes' }, meta }],
    });
    const [after] = parseRules(changed);
    expect(after.path).toBe('C:\\R&D');
    expect(after.attrs).toEqual({ realtime: 'yes', restrict: 'a&amp;b|c&d' });
    expect(changed).toContain('restrict="a&amp;b|c&d"');
  });

  it('writes a path with "&" that reads back the same', () => {
    const out = editAgentConf(CONF, {
      add: [rule({ path: '/srv/R&D/"quoted"' })],
    });
    expect(parseRules(out).map(r => r.path)).toContain('/srv/R&D/"quoted"');
  });

  it('refuses characters that would end the value', () => {
    expect(validateRule(rule({ path: '/a>b' }))).toEqual([
      'the path cannot contain < > or line breaks',
    ]);
    expect(validateRule(rule({ attrs: { restrict: 'a"b' } }))).toEqual([
      'invalid attribute restrict',
    ]);
  });
});

describe('validateRule', () => {
  it('checks path, recursion level, tags and reason', () => {
    expect(validateRule(rule())).toEqual([]);
    expect(validateRule(rule({ path: ' ' }))).toEqual(['the path is required']);
    expect(validateRule(rule({ attrs: { recursion_level: '999' } }))).toEqual([
      'recursion level must be 320 or less',
    ]);
    expect(validateRule(rule({ attrs: { tags: 'a b' } }))).toHaveLength(1);
    expect(validateRule(rule({ meta: { ...meta, reason: '' } }))).toEqual([
      'the reason is required',
    ]);
  });
});
