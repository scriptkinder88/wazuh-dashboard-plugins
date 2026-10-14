/*
 * FIM rules across groups: the table rows, and the per-group steps (with a
 * preview of each new agent.conf) needed to add, change or remove a rule.
 *
 * Rules for a single server live in a dedicated group, fim-host-<agent id>,
 * so that a change only restarts that server's agent.
 */
import {
  AgentConfEdit,
  FimRule,
  LocatedRule,
  RuleMeta,
  editAgentConf,
  parseRules,
  ruleKey,
  targetKey,
} from './agent-conf';

export const HOST_GROUP_PREFIX = 'fim-host-';

/** What the manager writes into a new group's agent.conf. */
export const DEFAULT_AGENT_CONF =
  '<agent_config>\n\n  <!-- Shared agent configuration here -->\n\n</agent_config>\n';

export const hostGroup = (agentId: string) => `${HOST_GROUP_PREFIX}${agentId}`;

export const hostOfGroup = (group: string) =>
  group.startsWith(HOST_GROUP_PREFIX)
    ? group.slice(HOST_GROUP_PREFIX.length)
    : undefined;

export interface GroupConf {
  name: string;
  /** agent.conf as read, to detect a concurrent change before writing. */
  raw: string;
  rules: LocatedRule[];
  /** Set when the file could not be read or parsed: the group is read-only. */
  error?: string;
}

export interface AgentInfo {
  id: string;
  name: string;
  status: string;
  platform: string;
  groups: string[];
  configStatus: string;
}

export interface RuleRow {
  key: string;
  rule: FimRule;
  /** Ordinary groups holding the rule. */
  groups: string[];
  /** Agent ids whose fim-host group holds the rule. */
  hostIds: string[];
}

export const toGroupConf = (name: string, raw: string): GroupConf => {
  try {
    return { name, raw, rules: parseRules(raw) };
  } catch (error) {
    return { name, raw, rules: [], error: (error as Error).message };
  }
};

/** One row per distinct rule, with every group (or host) that holds it. */
export const aggregateRules = (groups: GroupConf[]): RuleRow[] => {
  const rows = new Map<string, RuleRow>();
  groups.forEach(group => {
    group.rules.forEach(rule => {
      const key = ruleKey(rule);
      const plain: FimRule = {
        kind: rule.kind,
        path: rule.path,
        attrs: rule.attrs,
        filter: rule.filter,
        meta: rule.meta,
      };
      const row = rows.get(key) || {
        key,
        rule: plain,
        groups: [],
        hostIds: [],
      };
      if (!row.rule.meta && plain.meta) {
        row.rule = plain;
      }
      const host = hostOfGroup(group.name);
      const list = host ? row.hostIds : row.groups;
      const id = host || group.name;
      if (!list.includes(id)) {
        list.push(id);
      }
      rows.set(key, row);
    });
  });
  return [...rows.values()].sort(
    (a, b) =>
      a.rule.path.localeCompare(b.rule.path) ||
      a.rule.kind.localeCompare(b.rule.kind),
  );
};

export interface RuleTargets {
  groups: string[];
  hostIds: string[];
}

export interface RuleChange {
  /** The rule being changed or removed; absent when adding. */
  before?: RuleRow;
  /** The rule and where it applies; absent when removing. */
  after?: { rule: FimRule } & RuleTargets;
}

export interface GroupStep {
  group: string;
  /** The group does not exist yet (a new fim-host group). */
  create: boolean;
  /** A fim-host group left without rules is deleted. */
  deleteGroup: boolean;
  /** Agent to add to the group. */
  assign?: string;
  before: string;
  after: string;
  /** Re-applied to the content of a group created by this plan. */
  edit?: AgentConfEdit;
}

/**
 * Same audit fields typed in the form. The author and time are stamped on each
 * save, so they are left out: a rule whose options and audit fields did not
 * change is not rewritten, and its agents do not restart.
 */
const sameAudit = (a?: RuleMeta, b?: RuleMeta) =>
  JSON.stringify(a ? [a.reason, a.ticket, a.owner] : null) ===
  JSON.stringify(b ? [b.reason, b.ticket, b.owner] : null);

const targetGroups = (t?: RuleTargets) =>
  t ? [...t.groups, ...t.hostIds.map(hostGroup)] : [];

export const buildPlan = (
  groups: Record<string, GroupConf>,
  agents: AgentInfo[],
  change: RuleChange,
): GroupStep[] => {
  const was = new Set(change.before ? targetGroups(change.before) : []);
  const will = new Set(targetGroups(change.after));
  const steps: GroupStep[] = [];
  [...new Set([...was, ...will])].sort().forEach(group => {
    const existing = groups[group];
    if (existing?.error) {
      throw new Error(`${group}: ${existing.error}`);
    }
    const before = existing ? existing.raw : DEFAULT_AGENT_CONF;
    const unchanged =
      was.has(group) &&
      will.has(group) &&
      change.before!.key === ruleKey(change.after!.rule) &&
      sameAudit(change.before!.rule.meta, change.after!.rule.meta);
    const edit: AgentConfEdit = {};
    if (!unchanged) {
      edit.remove = change.before && was.has(group) ? [change.before.key] : [];
      edit.add = change.after && will.has(group) ? [change.after.rule] : [];
    }
    const after = editAgentConf(before, edit);
    const host = hostOfGroup(group);
    const agent = host ? agents.find(a => a.id === host) : undefined;
    const step: GroupStep = {
      group,
      create: !existing,
      deleteGroup: !!host && !!existing && !parseRules(after).length,
      assign:
        agent && will.has(group) && !agent.groups.includes(group)
          ? agent.id
          : undefined,
      before,
      after,
      edit: existing ? undefined : edit,
    };
    if (
      step.after !== step.before ||
      step.create ||
      step.deleteGroup ||
      step.assign
    ) {
      steps.push(step);
    }
  });
  return steps;
};

/** Agents that reload their configuration (and restart) after the steps. */
export const affectedAgents = (agents: AgentInfo[], steps: GroupStep[]) => {
  const touched = new Set(steps.map(s => s.group));
  return agents.filter(
    a =>
      a.groups.some(g => touched.has(g)) || steps.some(s => s.assign === a.id),
  );
};

export interface Conflict {
  agent: string;
  path: string;
  groups: string[];
}

/**
 * Agents that would get the same path from several groups with different
 * options: the agent keeps the one from the group assigned last.
 */
export const findConflicts = (
  groups: Record<string, GroupConf>,
  agents: AgentInfo[],
  steps: GroupStep[],
): Conflict[] => {
  const after: Record<string, LocatedRule[]> = {};
  Object.values(groups).forEach(g => {
    after[g.name] = g.rules;
  });
  steps.forEach(s => {
    after[s.group] = s.deleteGroup ? [] : parseRules(s.after);
  });
  const conflicts: Conflict[] = [];
  affectedAgents(agents, steps).forEach(agent => {
    const memberOf = [
      ...agent.groups,
      ...steps.filter(s => s.assign === agent.id).map(s => s.group),
    ];
    const byTarget = new Map<string, Map<string, string[]>>();
    memberOf.forEach(group => {
      (after[group] || []).forEach(rule => {
        const variants = byTarget.get(targetKey(rule)) || new Map();
        const key = ruleKey(rule);
        variants.set(key, [...(variants.get(key) || []), group]);
        byTarget.set(targetKey(rule), variants);
      });
    });
    byTarget.forEach((variants, target) => {
      if (variants.size > 1) {
        conflicts.push({
          agent: agent.name,
          path: JSON.parse(target)[1],
          groups: [...new Set([...variants.values()].flat())],
        });
      }
    });
  });
  return conflicts;
};

export type DiffLine = { op: ' ' | '+' | '-'; text: string };

/** Line diff (longest common subsequence); agent.conf files are small. */
export const diffLines = (a: string, b: string): DiffLine[] => {
  const x = a.split('\n');
  const y = b.split('\n');
  if (x.length * y.length > 4000000) {
    return [
      ...x.map(text => ({ op: '-' as const, text })),
      ...y.map(text => ({ op: '+' as const, text })),
    ];
  }
  const lcs: number[][] = Array.from({ length: x.length + 1 }, () =>
    new Array(y.length + 1).fill(0),
  );
  for (let i = x.length - 1; i >= 0; i--) {
    for (let j = y.length - 1; j >= 0; j--) {
      lcs[i][j] =
        x[i] === y[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < x.length || j < y.length) {
    if (i < x.length && j < y.length && x[i] === y[j]) {
      out.push({ op: ' ', text: x[i] });
      i++;
      j++;
    } else if (
      j < y.length &&
      (i >= x.length || lcs[i][j + 1] >= lcs[i + 1][j])
    ) {
      out.push({ op: '+', text: y[j] });
      j++;
    } else {
      out.push({ op: '-', text: x[i] });
      i++;
    }
  }
  return out;
};

/** Changed lines with `context` unchanged lines around them. */
export const diffHunks = (lines: DiffLine[], context = 2): DiffLine[] => {
  const keep = new Set<number>();
  lines.forEach((line, index) => {
    if (line.op !== ' ') {
      for (let k = index - context; k <= index + context; k++) {
        keep.add(k);
      }
    }
  });
  const out: DiffLine[] = [];
  lines.forEach((line, index) => {
    if (keep.has(index)) {
      if (out.length && !keep.has(index - 1)) {
        out.push({ op: ' ', text: '…' });
      }
      out.push(line);
    }
  });
  return out;
};
