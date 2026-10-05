import {
  inventoryPrefix,
  isTerraformManaged,
  managedHints,
  isWithin,
  overlapHints,
  pathHints,
  wildcardFixes,
} from './path-checks';
import { RuleRow } from './plan';

const form = (patch: object) => ({
  kind: 'directories' as const,
  path: '',
  sregex: false,
  reportChanges: false,
  platform: 'any',
  ...patch,
});
const ids = (hints: Array<{ id: string }>) => hints.map(h => h.id);

describe('FIM path checks', () => {
  it('points out wildcards in exclusions and proposes what they can become', () => {
    const [hint] = pathHints(
      form({ kind: 'ignore', path: '/opt/vault/tls/*' }),
    );
    expect(hint.id).toBe('wildcard-exclusion');
    expect(hint.fixes).toEqual([
      {
        label: 'Exclude the folder /opt/vault/tls',
        patch: { path: '/opt/vault/tls', sregex: false },
      },
    ]);
    expect(wildcardFixes('*.log')).toEqual([
      { label: 'Use the sregex .log$', patch: { path: '.log$', sregex: true } },
    ]);
    expect(wildcardFixes('/var/log/*.log').map(f => f.patch)).toEqual([
      { path: '/var/log', sregex: false },
      { path: '.log$', sregex: true },
    ]);
    expect(wildcardFixes('/tmp/app*')).toEqual([
      {
        label: 'Use the sregex ^/tmp/app',
        patch: { path: '^/tmp/app', sregex: true },
      },
    ]);
    expect(wildcardFixes('/a/*/b/*.x')).toEqual([]);
    // an sregex with * is wrong too
    expect(
      pathHints(form({ kind: 'nodiff', path: '*.key', sregex: true }))[0]
        .message,
    ).toMatch(/no wildcard/);
    // wildcards are fine in a monitor rule
    expect(pathHints(form({ path: '/home/*/.ssh' }))).toEqual([]);
  });

  it('proposes to monitor a folder instead of folder/*', () => {
    const [hint] = pathHints(form({ path: '/opt/vault/tls/*, /etc' }));
    expect(hint.id).toBe('trailing-star');
    expect(hint.fixes![0].patch).toEqual({ path: '/opt/vault/tls,/etc' });
    expect(pathHints(form({ path: 'C:\\Data\\*' }))[0].fixes![0].patch).toEqual(
      { path: 'C:\\Data' },
    );
  });

  it('checks the path against the platform', () => {
    expect(
      ids(pathHints(form({ path: 'C:\\Windows', platform: 'Linux' }))),
    ).toEqual(['platform-format']);
    expect(ids(pathHints(form({ path: '/etc', platform: 'Windows' })))).toEqual(
      ['platform-format'],
    );
    expect(ids(pathHints(form({ path: 'etc/app' })))).toEqual([
      'relative-path',
    ]);
    expect(
      pathHints(form({ path: '%WINDIR%\\System32', platform: 'Windows' })),
    ).toEqual([]);
    expect(
      ids(
        pathHints(form({ kind: 'windows_registry', path: 'Software\\Vendor' })),
      ),
    ).toEqual(['registry-format']);
    expect(
      pathHints(
        form({
          kind: 'windows_registry',
          path: 'HKEY_LOCAL_MACHINE\\Software',
        }),
      ),
    ).toEqual([]);
    // an sregex is not a path
    expect(
      pathHints(form({ kind: 'ignore', path: '.log$', sregex: true })),
    ).toEqual([]);
  });

  it('warns about content diffs of keys and certificates', () => {
    const [hint] = pathHints(
      form({ path: '/opt/vault/tls', reportChanges: true }),
    );
    expect(hint.id).toBe('sensitive-diff');
    expect(hint.fixes![0].patch).toEqual({ reportChanges: false });
    expect(
      pathHints(form({ path: '/etc/nginx', reportChanges: true })),
    ).toEqual([]);
    expect(
      ids(
        pathHints(form({ path: '/etc/app/server.key', reportChanges: true })),
      ),
    ).toEqual(['sensitive-diff']);
  });

  it('finds the rules of the same groups the new rule overlaps with', () => {
    const row = (
      kind: string,
      path: string,
      groups: string[],
      filter = {},
    ): RuleRow => ({
      key: `${kind}:${path}`,
      rule: { kind, path, attrs: {}, filter } as RuleRow['rule'],
      groups,
      hostIds: [],
    });
    const rows = [
      row('directories', '/opt/vault', ['web']),
      row('ignore', '/opt/vault/tls/old', ['web']),
      row('ignore', '/srv', ['db']),
      row('directories', 'C:\\Data', ['web'], { os: 'Windows' }),
    ];
    const check = (kind: string, path: string, groups = ['web'], filter = {}) =>
      overlapHints(
        { kind: kind as 'directories', path, filter },
        groups,
        [],
        rows,
      ).map(h => h.message);

    expect(check('directories', '/opt/vault/tls')).toEqual([
      '/opt/vault/tls is already monitored by /opt/vault in web: this rule ' +
        'only changes the options for /opt/vault/tls (the most specific path wins).',
    ]);
    expect(check('directories', '/opt/vault/tls/old/x')[1]).toMatch(
      /excluded by the Ignore rule \/opt\/vault\/tls\/old in web/,
    );
    expect(check('ignore', '/opt')).toEqual([
      'This exclusion stops the monitoring of /opt/vault (Monitor rule in web).',
    ]);
    expect(check('directories', '/opt/vault/')[0]).toMatch(
      /already has a rule of this type in web/,
    );
    expect(check('directories', '/srv/app')).toEqual([]); // other group
    expect(check('directories', '/srv/app', ['db'])[0]).toMatch(/excluded/);
    expect(
      check('directories', 'c:\\data\\x', ['web'], { os: 'Linux' }),
    ).toEqual([]); // other platform
    expect(
      check('directories', 'c:\\data\\x', ['web'], { os: 'Windows' })[0],
    ).toMatch(/C:\\Data/);
    // the rule being changed is not an overlap with itself
    expect(
      overlapHints(
        { kind: 'directories', path: '/opt/vault', filter: {} },
        ['web'],
        [],
        rows,
        'directories:/opt/vault',
      ),
    ).toEqual([]);
  });

  it('compares paths and finds the literal prefix', () => {
    expect(isWithin('/opt/vault/tls', '/opt/vault')).toBe(true);
    expect(isWithin('/opt/vaultx', '/opt/vault')).toBe(false);
    expect(isWithin('C:\\DATA\\x', 'c:\\data\\')).toBe(true);
    expect(inventoryPrefix('/home/*/.ssh')).toBe('/home');
    expect(inventoryPrefix('/opt/vault/tls/')).toBe('/opt/vault/tls');
  });

  it('points out groups written by Terraform', () => {
    expect(
      isTerraformManaged(
        '<!-- Managed by Terraform (group b): x -->\n<agent_config>',
      ),
    ).toBe(true);
    expect(isTerraformManaged('<agent_config>')).toBe(false);
    expect(
      managedHints(['web', 'baseline-linux'], ['baseline-linux'])[0].message,
    ).toMatch(/^baseline-linux is managed by Terraform/);
    expect(managedHints(['web'], ['baseline-linux'])).toEqual([]);
  });
});
