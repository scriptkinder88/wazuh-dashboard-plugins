/*
 * CIS-CAT bridge records kept in Wazuh CDB list files (etc/lists/ciscat-*).
 *
 * Mirror of tools/ciscat-bridge/bin/ciscat_store.py; the contract is in
 * tools/ciscat-bridge/CONTRACT.md and both sides are checked against
 * contract-vectors.json. The records are encoded as in ../encoded-list.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import { EncodedListError as StoreError, ListRecord } from '../encoded-list';

export {
  EncodedListError as StoreError,
  decodeRecord,
  encodeRecord,
  parseList,
  renderList,
} from '../encoded-list';
export type { ListRecord, ListRecords } from '../encoded-list';

export const CISCAT_LISTS = {
  exclusions: 'ciscat-exclusions',
  schedule: 'ciscat-schedule',
  requests: 'ciscat-requests',
  status: 'ciscat-status',
  oskeys: 'ciscat-oskeys',
  targets: 'ciscat-targets',
  history: 'ciscat-history',
};
export const CISCAT_BENCH_PREFIX = 'ciscat-bench-';
export const CISCAT_SCHEMA_VERSION = 1;
/** Largest wave of agents a job can trigger at once (same bound as ciscat_store.py). */
export const MAX_WAVE_SIZE = 100000;

export const SCOPES = ['os', 'global', 'host', 'app_group'] as const;
export const LEVELS = ['L1', 'L2', 'NG', 'ALL'] as const;
export const JOB_TYPES = ['once', 'monthly', 'weekly'] as const;

export type Scope = (typeof SCOPES)[number];
export type Level = (typeof LEVELS)[number];
export type JobType = (typeof JOB_TYPES)[number];

export interface Exclusion {
  v: number;
  os_key: string;
  scope: Scope;
  scope_value: string;
  level: Level;
  role: string;
  rule: string;
  reason: string;
  ticket: string;
  owner: string;
  updated_by: string;
  updated_at: string;
}

export interface Job {
  v: number;
  type: JobType;
  at?: string;
  time?: string;
  day?: number;
  weekday?: number;
  /** One of targets (os keys, or ['*']), agents (agent ids) or groups is set. */
  targets: string[];
  agents: string[];
  groups: string[];
  wave_size: number;
  wave_pause_s: number;
  enabled: boolean;
  label: string;
  created_by: string;
  created_at: string;
}

export const OS_KEY_RE = /^[a-z0-9_]{1,64}$/;
const RULE_RE = /^[0-9]+(?:\.[0-9]+){0,9}$/;
const ROLE_RE = /^[A-Za-z0-9_ -]{0,64}$/;
// not "." or "..": group names are joined to folders on the master
export const NAME_RE = /^(?!\.+$)[A-Za-z0-9._-]{1,255}$/;
export const AGENT_ID_RE = /^[0-9]{3,8}$/;
/** Groups the bridge creates and owns (ciscat-<os>-<combo>): never chosen by hand. */
export const MANAGED_GROUP_PREFIX = 'ciscat-';
export const MAX_RUN_AGENTS = 1000;
export const MAX_RUN_GROUPS = 64;
const TIME_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const AT_RE =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9])$/;

export const benchListName = (osKey: string) => {
  if (!OS_KEY_RE.test(osKey || '')) {
    throw new StoreError(`invalid os_key: ${osKey}`);
  }
  return CISCAT_BENCH_PREFIX + osKey;
};

// --- validation (same rules as ciscat_store.py) -------------------------------

const text = (
  rec: ListRecord,
  field: string,
  limit: number,
  required = false,
  fallback = '',
): string => {
  const raw = rec[field] ?? fallback;
  if (typeof raw !== 'string') {
    throw new StoreError(`${field}: text expected`);
  }
  // str.split() + join in Python: collapse any whitespace run
  const value = raw.split(/\s+/).filter(Boolean).join(' ');
  if (value.length > limit) {
    throw new StoreError(`${field}: longer than ${limit} characters`);
  }
  if (required && !value) {
    throw new StoreError(`${field}: required`);
  }
  return value;
};

const integer = (
  rec: ListRecord,
  field: string,
  low: number,
  high: number,
  fallback?: number,
): number => {
  const value = rec[field] === undefined ? fallback : rec[field];
  if (!Number.isInteger(value) || Number(value) < low || Number(value) > high) {
    throw new StoreError(`${field}: integer ${low}..${high} expected`);
  }
  return Number(value);
};

export const validateExclusion = (rec: ListRecord): Exclusion => {
  if (!rec || typeof rec !== 'object') {
    throw new StoreError('record must be an object');
  }
  const osKey = text(rec, 'os_key', 64, true);
  if (!OS_KEY_RE.test(osKey)) {
    throw new StoreError('os_key: invalid');
  }
  const scope = text(rec, 'scope', 16, true).toLowerCase() as Scope;
  if (!SCOPES.includes(scope)) {
    throw new StoreError(`scope: one of ${SCOPES.join(', ')}`);
  }
  let scopeValue = text(rec, 'scope_value', 255);
  if (scope === 'os') {
    scopeValue = osKey;
  } else if (scope === 'global') {
    scopeValue = 'all';
  } else if (!NAME_RE.test(scopeValue)) {
    throw new StoreError('scope_value: agent or group name expected');
  }
  const level = (text(rec, 'level', 3, false, 'ALL').toUpperCase() ||
    'ALL') as Level;
  if (!LEVELS.includes(level)) {
    throw new StoreError(`level: one of ${LEVELS.join(', ')}`);
  }
  const role = text(rec, 'role', 64);
  if (!ROLE_RE.test(role)) {
    throw new StoreError('role: invalid');
  }
  const rule = text(rec, 'rule', 64, true);
  if (!RULE_RE.test(rule)) {
    throw new StoreError(
      'rule: CIS recommendation number expected (e.g. 1.1.1)',
    );
  }
  return {
    v: CISCAT_SCHEMA_VERSION,
    os_key: osKey,
    scope,
    scope_value: scopeValue,
    level,
    role,
    rule,
    reason: text(rec, 'reason', 500) || 'n/a',
    ticket: text(rec, 'ticket', 128) || 'n/a',
    owner: text(rec, 'owner', 128) || 'n/a',
    updated_by: text(rec, 'updated_by', 128),
    updated_at: text(rec, 'updated_at', 40),
  };
};

const sha1Hex = async (value: string): Promise<string> => {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-1',
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

export const exclusionKey = async (rec: Exclusion): Promise<string> => {
  const ident = [
    rec.os_key,
    rec.scope,
    rec.scope_value.toLowerCase(),
    rec.level,
    rec.role.toLowerCase(),
    rec.rule,
  ].join('|');
  return 'e' + (await sha1Hex(ident)).slice(0, 16);
};

const validDate = (at: string) => {
  const m = AT_RE.exec(at);
  if (!m) {
    return false;
  }
  const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
};

const nameList = (
  rec: ListRecord,
  field: string,
  limit: number,
  pattern: RegExp,
  what: string,
): string[] => {
  const value = rec[field] ?? [];
  if (!Array.isArray(value) || value.length > limit) {
    throw new StoreError(`${field}: list of at most ${limit} ${what} expected`);
  }
  for (const v of value) {
    if (!(typeof v === 'string' && pattern.test(v))) {
      throw new StoreError(`${field}: ${what} expected`);
    }
  }
  return Array.from(new Set(value as string[])).sort();
};

/**
 * Which agents a job or a run applies to: exactly one of targets (os keys,
 * or ['*'] for every active OS), agents (agent ids) or groups (an OS group or
 * any custom one). A record with none of them runs every active OS.
 */
export const validateRunScope = (
  rec: ListRecord,
): Pick<Job, 'targets' | 'agents' | 'groups'> => {
  const agents = nameList(
    rec,
    'agents',
    MAX_RUN_AGENTS,
    AGENT_ID_RE,
    'agent ids',
  );
  if (agents.includes('000')) {
    throw new StoreError('agents: 000 is the manager');
  }
  const groups = nameList(
    rec,
    'groups',
    MAX_RUN_GROUPS,
    NAME_RE,
    'Wazuh group names',
  );
  if (groups.some(g => g.startsWith(MANAGED_GROUP_PREFIX))) {
    throw new StoreError(
      'groups: the ciscat-* groups are managed by the bridge',
    );
  }
  const targets = (rec.targets ??
    (agents.length || groups.length ? [] : ['*'])) as unknown[];
  if (!Array.isArray(targets) || targets.length > 64) {
    throw new StoreError('targets: list of os keys expected');
  }
  for (const t of targets) {
    if (t !== '*' && !(typeof t === 'string' && OS_KEY_RE.test(t))) {
      throw new StoreError('targets: os keys or * expected');
    }
  }
  if ([targets, agents, groups].filter(x => x.length).length !== 1) {
    throw new StoreError('exactly one of targets, agents or groups expected');
  }
  return {
    targets: Array.from(new Set(targets as string[])).sort(),
    agents,
    groups,
  };
};

export const validateJob = (rec: ListRecord): Job => {
  if (!rec || typeof rec !== 'object') {
    throw new StoreError('record must be an object');
  }
  const type = text(rec, 'type', 16, true) as JobType;
  if (!JOB_TYPES.includes(type)) {
    throw new StoreError(`type: one of ${JOB_TYPES.join(', ')}`);
  }
  const out: Partial<Job> = { v: CISCAT_SCHEMA_VERSION, type };
  if (type === 'once') {
    out.at = text(rec, 'at', 16, true);
    if (!validDate(out.at)) {
      throw new StoreError('at: YYYY-MM-DDTHH:MM expected (master local time)');
    }
  } else {
    out.time = text(rec, 'time', 5, true);
    if (!TIME_RE.test(out.time)) {
      throw new StoreError('time: HH:MM expected');
    }
    if (type === 'monthly') {
      const day = Number(rec.day);
      if (
        !Number.isInteger(rec.day) ||
        !((day >= 1 && day <= 31) || (day >= -28 && day <= -1))
      ) {
        throw new StoreError(
          'day: 1..31, or -1..-28 counted from the end of the month',
        );
      }
      out.day = day;
    } else {
      out.weekday = integer(rec, 'weekday', 0, 6);
    }
  }
  Object.assign(out, validateRunScope(rec));
  out.wave_size = integer(rec, 'wave_size', 1, MAX_WAVE_SIZE, 50);
  out.wave_pause_s = integer(rec, 'wave_pause_s', 0, 86400, 300);
  const enabled = rec.enabled === undefined ? true : rec.enabled;
  if (typeof enabled !== 'boolean') {
    throw new StoreError('enabled: true/false expected');
  }
  out.enabled = enabled;
  out.label = text(rec, 'label', 80);
  out.created_by = text(rec, 'created_by', 128);
  out.created_at = text(rec, 'created_at', 40);
  return out as Job;
};

export interface Target {
  v: number;
  group: string;
  updated_by: string;
  updated_at: string;
}

/** Wazuh group an OS (benchmark) applies to, chosen in the dashboard; keyed by os key. */
export const validateTarget = (rec: ListRecord): Target => {
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
    throw new StoreError('record must be an object');
  }
  const group = text(rec, 'group', 255, true);
  if (!NAME_RE.test(group)) {
    throw new StoreError('group: Wazuh group name expected');
  }
  if (group.startsWith(MANAGED_GROUP_PREFIX)) {
    throw new StoreError(
      'group: the ciscat-* groups are managed by the bridge',
    );
  }
  return {
    v: CISCAT_SCHEMA_VERSION,
    group,
    updated_by: text(rec, 'updated_by', 128),
    updated_at: text(rec, 'updated_at', 40),
  };
};

const randomHex = (bytes: number) =>
  Array.from(globalThis.crypto.getRandomValues(new Uint8Array(bytes)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

export const newJobKey = () => 'j' + randomHex(6);
export const newRequestKey = (now = Date.now()) => `r${now}${randomHex(2)}`;
