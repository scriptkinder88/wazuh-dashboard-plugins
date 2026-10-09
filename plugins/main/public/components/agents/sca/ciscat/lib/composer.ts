/*
 * Exclusion composer logic: benchmark rows for one profile, which exclusions
 * apply to them, and new exclusion records. The React panels only render it.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import {
  Exclusion,
  Job,
  ListRecords,
  NAME_RE,
  StoreError,
  exclusionKey,
  validateExclusion,
} from '../../../../../../common/ciscat/store';

export interface BenchRule {
  rule: string;
  title: string;
  profiles: string[];
  manual: boolean;
}

export interface Bench {
  osKey: string;
  benchmark: string;
  version: string;
  profiles: string[];
  rules: BenchRule[];
}

export type KeyedExclusions = Record<string, Exclusion>;

export type ShowFilter = 'applicable' | 'all' | 'excluded';

export interface RuleRow extends BenchRule {
  applicable: boolean;
  exclusions: Array<{ key: string; exclusion: Exclusion }>;
  /** Excluded for every agent of the OS (os or global scope). */
  fleetWide: boolean;
}

export const compareRules = (a: string, b: string) => {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? -1) - (pb[i] ?? -1);
    if (diff) {
      return diff;
    }
  }
  return 0;
};

export const parseBench = (records: ListRecords, osKey: string): Bench => {
  const meta = (records._meta || {}) as Record<string, unknown>;
  const rules = Object.entries(records)
    .filter(([key]) => key !== '_meta')
    .map(([rule, rec]) => ({
      rule,
      title: String(rec.t || ''),
      profiles: Array.isArray(rec.p) ? (rec.p as string[]) : [],
      manual: rec.m === true,
    }))
    .sort((a, b) => compareRules(a.rule, b.rule));
  return {
    osKey,
    benchmark: String(meta.benchmark || ''),
    version: String(meta.version || ''),
    profiles: Array.isArray(meta.profiles) ? (meta.profiles as string[]) : [],
    rules,
  };
};

/** Profile column of the benchmark sheet (L1_Member_Server) to level + role. */
export const profileLevelRole = (column: string) => {
  const match = /^(L1|L2|NG)_(.+)$/.exec(column || '');
  return match
    ? { level: match[1], role: match[2] }
    : { level: 'ALL', role: '' };
};

export const exclusionAppliesToProfile = (e: Exclusion, column: string) => {
  const { level, role } = profileLevelRole(column);
  return (
    (e.level === 'ALL' || e.level === level) &&
    (!e.role || e.role.toLowerCase() === role.toLowerCase())
  );
};

export const buildRows = (
  bench: Bench,
  exclusions: KeyedExclusions,
  column: string,
  filter: { text?: string; show?: ShowFilter } = {},
): RuleRow[] => {
  const byRule: Record<
    string,
    Array<{ key: string; exclusion: Exclusion }>
  > = {};
  Object.entries(exclusions).forEach(([key, exclusion]) => {
    if (
      exclusion.os_key === bench.osKey &&
      exclusionAppliesToProfile(exclusion, column)
    ) {
      (byRule[exclusion.rule] = byRule[exclusion.rule] || []).push({
        key,
        exclusion,
      });
    }
  });
  const text = (filter.text || '').trim().toLowerCase();
  const show = filter.show || 'applicable';
  return bench.rules
    .map(rule => {
      const list = byRule[rule.rule] || [];
      return {
        ...rule,
        applicable: rule.profiles.includes(column),
        exclusions: list,
        fleetWide: list.some(({ exclusion }) =>
          ['os', 'global'].includes(exclusion.scope),
        ),
      };
    })
    .filter(row => {
      if (show === 'applicable' && !row.applicable && !row.exclusions.length) {
        return false;
      }
      if (show === 'excluded' && !row.exclusions.length) {
        return false;
      }
      return (
        !text ||
        row.rule.toLowerCase().startsWith(text) ||
        row.title.toLowerCase().includes(text)
      );
    });
};

export const composerStats = (rows: RuleRow[]) => {
  const applicable = rows.filter(r => r.applicable);
  const fleetWide = applicable.filter(r => r.fleetWide).length;
  const partial = applicable.filter(
    r => !r.fleetWide && r.exclusions.length,
  ).length;
  const manual = applicable.filter(r => r.manual && !r.fleetWide).length;
  return {
    applicable: applicable.length,
    fleetWide,
    partial,
    manual,
    scored: applicable.length - fleetWide - manual,
  };
};

export type ScopeChoice = 'os' | 'global' | 'host' | 'app_group';

export interface NewExclusionInput {
  osKey: string;
  column: string;
  rules: string[];
  scope: ScopeChoice;
  /** Agent names (host) or group names (app_group); a list becomes one record each. */
  values: string[];
  reason: string;
  ticket?: string;
  owner?: string;
  user?: string;
  now?: Date;
}

/** Validated records keyed as the master expects; throws StoreError. */
export const makeExclusions = async (
  input: NewExclusionInput,
): Promise<KeyedExclusions> => {
  if (!input.rules.length) {
    throw new StoreError('select at least one control');
  }
  if (!input.reason.trim()) {
    throw new StoreError('reason: required for the audit trail');
  }
  const { level, role } = profileLevelRole(input.column);
  const needsValue = input.scope === 'host' || input.scope === 'app_group';
  const names = input.values
    .flatMap(v => v.split(/[\s,;]+/))
    .map(v => v.trim())
    .filter(Boolean);
  const values = needsValue ? Array.from(new Set(names)) : [''];
  if (needsValue && !values.length) {
    throw new StoreError(
      input.scope === 'host'
        ? 'enter at least one agent name'
        : 'enter at least one group',
    );
  }
  const bad = values.filter(v => needsValue && !NAME_RE.test(v));
  if (bad.length) {
    throw new StoreError(`invalid name: ${bad.join(', ')}`);
  }
  const records = input.rules.flatMap(rule =>
    values.map(value =>
      validateExclusion({
        os_key: input.osKey,
        scope: input.scope,
        scope_value: value,
        level,
        role,
        rule,
        reason: input.reason,
        ticket: input.ticket || '',
        owner: input.owner || '',
        updated_by: input.user || '',
        updated_at: (input.now || new Date()).toISOString(),
      }),
    ),
  );
  const keys = await Promise.all(records.map(exclusionKey));
  return keys.reduce((acc, key, i) => {
    acc[key] = records[i];
    return acc;
  }, {} as KeyedExclusions);
};

export const describeScope = (e: Exclusion) => {
  switch (e.scope) {
    case 'os':
      return 'All agents of this OS';
    case 'global':
      return 'Global';
    case 'host':
      return `Agent ${e.scope_value}`;
    default:
      return `Group ${e.scope_value}`;
  }
};

const WEEKDAYS = [
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
  'Sunday',
];

const ordinal = (n: number) => {
  const teen = n % 100 >= 11 && n % 100 <= 13;
  const suffix = teen ? 'th' : { 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th';
  return `${n}${suffix}`;
};

export const describeJob = (job: Job) => {
  if (job.type === 'once') {
    return `Once, ${(job.at || '').replace('T', ' ')}`;
  }
  if (job.type === 'weekly') {
    return `Every ${WEEKDAYS[job.weekday ?? 0]} at ${job.time}`;
  }
  const day = job.day ?? 1;
  if (day > 0) {
    return `Monthly on day ${day}${day > 28 ? ' (or the last day)' : ''} at ${
      job.time
    }`;
  }
  return `Monthly on the ${
    day === -1 ? 'last' : `${ordinal(-day)}-last`
  } day at ${job.time}`;
};

const listed = (names: string[], max = 5) =>
  names.length > max
    ? `${names.slice(0, max).join(', ')} and ${names.length - max} more`
    : names.join(', ');

/** Who a job or a run reaches: OSes, chosen agents or chosen groups. */
export const describeTargets = ({
  targets,
  agents = [],
  groups = [],
}: Pick<Job, 'targets'> & Partial<Pick<Job, 'agents' | 'groups'>>) => {
  if (agents.length) {
    return `${agents.length === 1 ? 'Agent' : 'Agents'} ${listed(agents)}`;
  }
  if (groups.length) {
    return `${groups.length === 1 ? 'Group' : 'Groups'} ${listed(groups)}`;
  }
  return targets.includes('*') ? 'All active OS' : listed(targets, 10);
};
