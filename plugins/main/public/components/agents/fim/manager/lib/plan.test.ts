import { TextDecoder, TextEncoder } from 'util';
import { FimRule, editAgentConf, parseRules } from './agent-conf';
import {
  AgentInfo,
  DEFAULT_AGENT_CONF,
  aggregateRules,
  buildPlan,
  diffHunks,
  diffLines,
  findConflicts,
  toGroupConf,
} from './plan';

Object.assign(global, { TextEncoder, TextDecoder });

const conf = (body: string) =>
  `<agent_config>\n  <syscheck>\n${body}  </syscheck>\n</agent_config>\n`;

const groups = Object.fromEntries(
  [
    toGroupConf(
      'web',
      conf('    <directories realtime="yes">/etc/nginx</directories>\n'),
    ),
    toGroupConf(
      'db',
      conf('    <directories realtime="yes">/etc/nginx</directories>\n'),
    ),
    toGroupConf(
      'fim-host-007',
      conf('    <ignore>/etc/nginx/cache</ignore>\n'),
    ),
    toGroupConf('broken', '<agent_config>'),
  ].map(g => [g.name, g]),
);

const agents: AgentInfo[] = [
  {
    id: '001',
    name: 'web-01',
    status: 'active',
    platform: 'ubuntu',
    groups: ['default', 'web'],
    configStatus: 'synced',
  },
  {
    id: '007',
    name: 'web-07',
    status: 'active',
    platform: 'ubuntu',
    groups: ['web', 'fim-host-007'],
    configStatus: 'synced',
  },
  {
    id: '009',
    name: 'db-09',
    status: 'active',
    platform: 'rhel',
    groups: ['db'],
    configStatus: 'synced',
  },
];

const meta = {
  reason: 'r',
  ticket: '',
  owner: '',
  by: 'alice',
  at: '2026-10-01T10:00:00Z',
};
const newRule: FimRule = {
  kind: 'directories',
  path: '/srv/app',
  attrs: {},
  filter: {},
  meta,
};

describe('aggregateRules', () => {
  it('merges the same rule across groups and maps host groups to agents', () => {
    const rows = aggregateRules(Object.values(groups));
    expect(rows.map(r => [r.rule.path, r.groups, r.hostIds])).toEqual([
      ['/etc/nginx', ['web', 'db'], []],
      ['/etc/nginx/cache', [], ['007']],
    ]);
    expect(groups.broken.error).toMatch(/not closed/);
  });
});

describe('buildPlan', () => {
  it('adds a rule to groups and to a new host group', () => {
    const steps = buildPlan(groups, agents, {
      after: { rule: newRule, groups: ['web'], hostIds: ['009'] },
    });
    expect(
      steps.map(s => [s.group, s.create, s.assign, s.deleteGroup]),
    ).toEqual([
      ['fim-host-009', true, '009', false],
      ['web', false, undefined, false],
    ]);
    expect(steps[0].before).toBe(DEFAULT_AGENT_CONF);
    expect(steps[0].edit?.add).toEqual([newRule]);
    expect(parseRules(steps[1].after).map(r => r.path)).toEqual([
      '/etc/nginx',
      '/srv/app',
    ]);
  });

  it('moves a rule between targets and deletes an emptied host group', () => {
    const [nginx, cache] = aggregateRules(Object.values(groups));
    const moved = buildPlan(groups, agents, {
      before: nginx,
      after: { rule: nginx.rule, groups: ['web'], hostIds: [] },
    });
    expect(moved.map(s => s.group)).toEqual(['db']);
    expect(parseRules(moved[0].after)).toEqual([]);

    const removed = buildPlan(groups, agents, { before: cache });
    expect(removed.map(s => [s.group, s.deleteGroup])).toEqual([
      ['fim-host-007', true],
    ]);
  });

  it('leaves a group alone when only the author or time would change', () => {
    const withAudit = Object.fromEntries(
      [
        toGroupConf(
          'web',
          editAgentConf(DEFAULT_AGENT_CONF, { add: [newRule] }),
        ),
        toGroupConf('db', DEFAULT_AGENT_CONF),
      ].map(g => [g.name, g]),
    );
    const [row] = aggregateRules(Object.values(withAudit));
    const resaved = {
      ...newRule,
      meta: { ...meta, by: 'bob', at: '2026-10-05T08:00:00Z' },
    };
    const steps = buildPlan(withAudit, agents, {
      before: row,
      after: { rule: resaved, groups: ['web', 'db'], hostIds: [] },
    });
    expect(steps.map(s => s.group)).toEqual(['db']);

    const nothing = buildPlan(withAudit, agents, {
      before: row,
      after: { rule: resaved, groups: ['web'], hostIds: [] },
    });
    expect(nothing).toEqual([]);
  });

  it('rewrites a rule whose audit fields changed', () => {
    const withAudit = {
      web: toGroupConf(
        'web',
        editAgentConf(DEFAULT_AGENT_CONF, { add: [newRule] }),
      ),
    };
    const [row] = aggregateRules(Object.values(withAudit));
    const steps = buildPlan(withAudit, agents, {
      before: row,
      after: {
        rule: { ...newRule, meta: { ...meta, ticket: 'CHG-7' } },
        groups: ['web'],
        hostIds: [],
      },
    });
    expect(steps.map(s => s.group)).toEqual(['web']);
    expect(parseRules(steps[0].after)[0].meta?.ticket).toBe('CHG-7');
  });

  it('refuses to touch a group whose agent.conf cannot be parsed', () => {
    expect(() =>
      buildPlan(groups, agents, {
        after: { rule: newRule, groups: ['broken'], hostIds: [] },
      }),
    ).toThrow(/broken/);
  });
});

describe('findConflicts', () => {
  it('reports a path defined with different options for the same agent', () => {
    const steps = buildPlan(groups, agents, {
      after: {
        rule: { ...newRule, path: '/etc/nginx', attrs: { whodata: 'yes' } },
        groups: [],
        hostIds: ['001'],
      },
    });
    expect(findConflicts(groups, agents, steps)).toEqual([
      { agent: 'web-01', path: '/etc/nginx', groups: ['web', 'fim-host-001'] },
    ]);
  });
});

describe('diff', () => {
  it('shows only the changed lines with context', () => {
    const a = ['1', '2', '3', '4', '5', '6', '7', '8'].join('\n');
    const b = ['1', '2', '3', '4', 'x', '5', '6', '7', '8'].join('\n');
    expect(diffHunks(diffLines(a, b), 1)).toEqual([
      { op: ' ', text: '4' },
      { op: '+', text: 'x' },
      { op: ' ', text: '5' },
    ]);
  });
});
