/*
 * Checks on a FIM rule being written, shown as hints in the form: rules the
 * manager accepts but that do not do what they seem to (a "*" in an exclusion,
 * a path of the wrong platform...), and rules that overlap with the ones
 * already in the chosen groups.
 *
 * Wazuh 4.x semantics (syscheck reference):
 * - <directories> and <windows_registry> accept the wildcards * and ?,
 *   expanded at each scheduled scan; several paths can be comma-separated;
 * - <ignore>, <nodiff> and <registry_ignore> compare the path literally, or as
 *   an sregex with type="sregex". An sregex only knows ^ (start), $ (end) and
 *   | (or): there is no wildcard, and every other character is literal.
 */
import { FimRule, RuleKind } from './agent-conf';
import { RuleRow } from './plan';

export interface HintFix {
  label: string;
  patch: { path?: string; sregex?: boolean; reportChanges?: boolean };
}

export interface Hint {
  id: string;
  message: string;
  fixes?: HintFix[];
}

const EXCLUSIONS: RuleKind[] = ['ignore', 'nodiff', 'registry_ignore'];
const WILDCARD = /[*?]/;
const SENSITIVE = new RegExp(
  [
    '\\.(key|pem|p12|pfx|jks|keystore)$',
    '[\\\\/](tls|ssl|private|secrets?|\\.ssh|\\.gnupg|vault)([\\\\/]|$)',
    'g?shadow$',
  ].join('|'),
  'i',
);

export const isExclusion = (kind: RuleKind) => EXCLUSIONS.includes(kind);
const isRegistry = (kind: RuleKind) => kind.includes('registry');

/** The paths of a rule: monitor rules accept several, comma-separated. */
export const rulePaths = (kind: RuleKind, path: string) =>
  (kind === 'directories' || kind === 'windows_registry'
    ? path.split(',')
    : [path]
  )
    .map(p => p.trim())
    .filter(Boolean);

const isWindowsPath = (p: string) =>
  /^[A-Za-z]:(\\|$)/.test(p) || /^%\w+%/.test(p) || p.startsWith('\\\\');

/** Path without trailing separators; Windows paths compare case-insensitively. */
const normalize = (p: string) => {
  const trimmed = p.replace(/[\\/]+$/, '') || p;
  return isWindowsPath(trimmed) ? trimmed.toLowerCase() : trimmed;
};

/** True when `child` is `parent` or inside it. */
export const isWithin = (child: string, parent: string) => {
  const c = normalize(child);
  const p = normalize(parent);
  return c === p || c.startsWith(`${p}/`) || c.startsWith(`${p}\\`);
};

/**
 * What an exclusion written with wildcards can become. An sregex has no
 * wildcard, so only patterns anchored at one end translate exactly.
 */
export const wildcardFixes = (path: string): HintFix[] => {
  const p = path.trim();
  const dir = /^(.*[\\/])\*$/.exec(p);
  if (dir && !WILDCARD.test(dir[1])) {
    const folder = dir[1].replace(/[\\/]+$/, '');
    return [
      {
        label: `Exclude the folder ${folder}`,
        patch: { path: folder, sregex: false },
      },
    ];
  }
  const parts = p.split('*');
  if (p.includes('?') || parts.length > 2) {
    return [];
  }
  const [head, tail] = parts;
  const fixes: HintFix[] = [];
  if (!head && tail) {
    fixes.push({
      label: `Use the sregex ${tail}$`,
      patch: { path: `${tail}$`, sregex: true },
    });
  } else if (head && !tail) {
    fixes.push({
      label: `Use the sregex ^${head}`,
      patch: { path: `^${head}`, sregex: true },
    });
  } else if (head && tail) {
    const folder = head.replace(/[\\/][^\\/]*$/, '');
    if (folder && /[\\/]$/.test(head)) {
      fixes.push({
        label: `Exclude the folder ${folder}`,
        patch: { path: folder, sregex: false },
      });
    }
    fixes.push({
      label: `Exclude every path ending in ${tail} (sregex ${tail}$)`,
      patch: { path: `${tail}$`, sregex: true },
    });
  }
  return fixes;
};

export interface RuleForm {
  kind: RuleKind;
  path: string;
  sregex: boolean;
  reportChanges: boolean;
  /** 'Linux', 'Windows', or anything else for no OS filter. */
  platform: string;
}

/** Hints about the path and options of the rule itself. */
export const pathHints = (form: RuleForm): Hint[] => {
  const hints: Hint[] = [];
  const paths = rulePaths(form.kind, form.path);
  if (!paths.length) {
    return hints;
  }

  if (isExclusion(form.kind) && paths.some(p => WILDCARD.test(p))) {
    hints.push({
      id: 'wildcard-exclusion',
      message: form.sregex
        ? 'An sregex has no wildcard: "*" and "?" are literal characters. ' +
          'Use ^ (start), $ (end) and | (or), for example .log$|.tmp$'
        : 'In an exclusion "*" and "?" are literal characters, so this rule ' +
          'matches nothing. Exclude a folder, or use an sregex with ^ (start), ' +
          '$ (end) and | (or).',
      fixes: wildcardFixes(paths[0]),
    });
  }

  if (form.kind === 'directories') {
    const stars = paths.filter(p => /[\\/]\*$/.test(p));
    if (stars.length) {
      const fixed = paths.map(p =>
        /[\\/]\*$/.test(p) ? p.replace(/[\\/]\*$/, '') : p,
      );
      hints.push({
        id: 'trailing-star',
        message:
          'A folder is monitored with all its content without "/*". Without ' +
          'the wildcard, new files are detected at once and real time and ' +
          'who-data watch the folder itself; with it, the list of paths is ' +
          'only refreshed at each scheduled scan.',
        fixes: [
          {
            label: `Monitor ${fixed.join(', ')}`,
            patch: { path: fixed.join(',') },
          },
        ],
      });
    }
  }

  if (!(isExclusion(form.kind) && form.sregex)) {
    if (isRegistry(form.kind)) {
      const bad = paths.filter(p => !/^HKEY_/i.test(p));
      if (bad.length) {
        hints.push({
          id: 'registry-format',
          message:
            'Registry keys start with the hive name, for example ' +
            `HKEY_LOCAL_MACHINE\\Software: check ${bad.join(', ')}`,
        });
      }
    } else {
      const windows = paths.filter(isWindowsPath);
      const relative = paths.filter(
        p => !isWindowsPath(p) && !p.startsWith('/'),
      );
      if (form.platform === 'Linux' && windows.length) {
        hints.push({
          id: 'platform-format',
          message: `Windows path in a rule for Linux agents: ${windows.join(
            ', ',
          )}`,
        });
      } else if (
        form.platform === 'Windows' &&
        paths.some(p => p.startsWith('/'))
      ) {
        hints.push({
          id: 'platform-format',
          message:
            'Linux path in a rule for Windows agents: Windows paths start ' +
            'with a drive (C:\\) or a variable (%WINDIR%).',
        });
      }
      if (relative.length) {
        hints.push({
          id: 'relative-path',
          message:
            'Use absolute paths (/... on Linux, C:\\... or %VAR% on ' +
            `Windows): ${relative.join(', ')}`,
        });
      }
    }
  }

  if (
    (form.kind === 'directories' || form.kind === 'windows_registry') &&
    form.reportChanges &&
    paths.some(p => SENSITIVE.test(p))
  ) {
    hints.push({
      id: 'sensitive-diff',
      message:
        'Report changes saves the changed content on the manager and shows it ' +
        'in the alerts: avoid it on keys, certificates and secrets.',
      fixes: [
        { label: 'Turn off report changes', patch: { reportChanges: false } },
      ],
    });
  }
  return hints;
};

const sharedTargets = (row: RuleRow, groups: string[], hostIds: string[]) => [
  ...row.groups.filter(g => groups.includes(g)),
  ...row.hostIds.filter(h => hostIds.includes(h)).map(h => `server ${h}`),
];

const platformsMeet = (a: Record<string, string>, b: Record<string, string>) =>
  !a.os || !b.os || a.os === b.os;

/** Hints about the rules already in the groups and servers the rule targets. */
export const overlapHints = (
  rule: Pick<FimRule, 'kind' | 'path' | 'filter'> & { sregex?: boolean },
  groups: string[],
  hostIds: string[],
  rows: RuleRow[],
  editingKey?: string,
): Hint[] => {
  const hints: Hint[] = [];
  const paths = rulePaths(rule.kind, rule.path).filter(p => !WILDCARD.test(p));
  if (!paths.length || (isExclusion(rule.kind) && rule.sregex)) {
    return hints;
  }
  const seen = new Set<string>();
  rows.forEach(row => {
    if (row.key === editingKey) {
      return;
    }
    const where = sharedTargets(row, groups, hostIds);
    if (!where.length || !platformsMeet(rule.filter, row.rule.filter)) {
      return;
    }
    const other = row.rule;
    if (other.attrs.type === 'sregex') {
      return;
    }
    const otherPaths = rulePaths(other.kind, other.path).filter(
      p => !WILDCARD.test(p),
    );
    const at = where.join(', ');
    paths.forEach(p =>
      otherPaths.forEach(o => {
        let message = '';
        if (other.kind === rule.kind && normalize(p) === normalize(o)) {
          message = `${o} already has a rule of this type in ${at}.`;
        } else if (
          rule.kind === 'directories' &&
          other.kind === 'directories' &&
          isWithin(p, o)
        ) {
          message =
            `${p} is already monitored by ${o} in ${at}: this rule only ` +
            `changes the options for ${p} (the most specific path wins).`;
        } else if (
          rule.kind === 'directories' &&
          other.kind === 'ignore' &&
          isWithin(p, o)
        ) {
          message =
            `${p} is excluded by the Ignore rule ${o} in ${at}: ` +
            'its agents will not monitor it.';
        } else if (
          rule.kind === 'ignore' &&
          other.kind === 'directories' &&
          isWithin(o, p)
        ) {
          message = `This exclusion stops the monitoring of ${o} (Monitor rule in ${at}).`;
        } else if (
          rule.kind === 'windows_registry' &&
          other.kind === 'registry_ignore' &&
          isWithin(p, o)
        ) {
          message = `${p} is excluded by the Ignore rule ${o} in ${at}.`;
        } else if (
          rule.kind === 'registry_ignore' &&
          other.kind === 'windows_registry' &&
          isWithin(o, p)
        ) {
          message = `This exclusion stops the monitoring of ${o} (Monitor rule in ${at}).`;
        }
        if (message && !seen.has(message)) {
          seen.add(message);
          hints.push({ id: 'overlap', message });
        }
      }),
    );
  });
  return hints;
};

/** The literal part of a path to look up in the FIM inventory (before any wildcard). */
export const inventoryPrefix = (path: string) => {
  const p = path.trim();
  const i = p.search(WILDCARD);
  return (i < 0 ? p : p.slice(0, i)).replace(/[\\/]+$/, '');
};
