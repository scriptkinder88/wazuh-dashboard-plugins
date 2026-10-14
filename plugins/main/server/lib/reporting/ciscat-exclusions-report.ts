/*
 * CIS-CAT exclusion register as a PDF section: every check excluded from the
 * CIS-CAT assessment, with the reason, ticket and owner recorded in the
 * dashboard. Read from the ciscat-exclusions list through the Wazuh server
 * API with the user's own rights, so the report shows what the user may read.
 */
import { parseList } from '../../../common/encoded-list';
import {
  CISCAT_LISTS,
  Exclusion,
  validateExclusion,
} from '../../../common/ciscat/store';

export interface ExclusionRegister {
  exclusions: Exclusion[];
  rejected: number;
}

const SCOPE_LABELS: Record<string, string> = {
  os: 'Operating system',
  global: 'Every benchmark',
  host: 'Agent',
  app_group: 'Group',
};

const ruleParts = (rule: string) => rule.split('.').map(p => Number(p));

const compareRules = (a: string, b: string) => {
  const pa = ruleParts(a);
  const pb = ruleParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? -1) - (pb[i] ?? -1);
    if (diff) {
      return diff;
    }
  }
  return 0;
};

/** Valid exclusions of the list text, sorted by OS, scope, target and rule. */
export const parseExclusionRegister = (raw: string): ExclusionRegister => {
  const { records, errors } = parseList(raw);
  let rejected = errors.length;
  const exclusions: Exclusion[] = [];
  for (const [key, record] of Object.entries(records)) {
    if (key === '_empty') {
      continue;
    }
    try {
      exclusions.push(validateExclusion(record));
    } catch {
      rejected++;
    }
  }
  exclusions.sort(
    (a, b) =>
      a.os_key.localeCompare(b.os_key) ||
      a.scope.localeCompare(b.scope) ||
      a.scope_value.toLowerCase().localeCompare(b.scope_value.toLowerCase()) ||
      compareRules(a.rule, b.rule),
  );
  return { exclusions, rejected };
};

export const fetchExclusionRegister = async (
  context: any,
  apiId: string,
): Promise<ExclusionRegister> => {
  const api = context.wazuh.api.client.asCurrentUser;
  const name = CISCAT_LISTS.exclusions;
  const files = await api.request(
    'GET',
    '/lists/files',
    { params: { search: name } },
    { apiHostID: apiId },
  );
  const exists = (files?.data?.data?.affected_items || []).some(
    (item: { filename?: string }) => item.filename === name,
  );
  // The bridge installer creates the list: when it is not visible, the user
  // may not read it, and an empty register would be false evidence.
  if (!exists) {
    throw new Error(
      `${name} cannot be read: check that your Wazuh API role allows lists:read on it`,
    );
  }
  const content = await api.request(
    'GET',
    `/lists/files/${name}`,
    { params: { raw: true } },
    { apiHostID: apiId },
  );
  return parseExclusionRegister(String(content?.data || ''));
};

const countBy = (items: Exclusion[], field: keyof Exclusion) =>
  items.reduce((acc, item) => {
    const value = String(item[field]);
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

/** Adds the register to a report: a summary, then one table per OS. */
export const addExclusionRegisterToReport = (
  printer: any,
  register: ExclusionRegister,
  generatedAt: string,
) => {
  const { exclusions, rejected } = register;
  printer.addContent({ text: 'CIS-CAT exclusion register', style: 'h1' });
  printer.addNewLine();
  printer.addContentWithNewLine({
    text:
      'Checks of the CIS benchmarks that are not assessed on the scope ' +
      'shown, with the reason, ticket and owner recorded in the CIS-CAT ' +
      'page of the dashboard. Excluded checks are left out of the tailored ' +
      'benchmark and of the score.',
    style: 'standard',
  });
  printer.addContentWithNewLine({
    text: `Generated: ${generatedAt}. Source: Wazuh list ${CISCAT_LISTS.exclusions}.`,
    style: 'standard',
  });

  const byOs = countBy(exclusions, 'os_key');
  const byScope = countBy(exclusions, 'scope');
  printer.addSimpleTable({
    title: 'Summary',
    columns: [
      { id: 'item', label: 'Item' },
      { id: 'value', label: 'Value' },
    ],
    items: [
      { item: 'Exclusions', value: exclusions.length },
      { item: 'Benchmarks with exclusions', value: Object.keys(byOs).length },
      ...Object.entries(byScope).map(([scope, n]) => ({
        item: `Scope: ${SCOPE_LABELS[scope] || scope}`,
        value: n,
      })),
      ...(rejected
        ? [{ item: 'Invalid records not shown', value: rejected }]
        : []),
    ],
  });

  for (const osKey of Object.keys(byOs).sort()) {
    printer.addContent({
      text: `Benchmark ${osKey}: ${byOs[osKey]} exclusion(s)`,
      style: 'h3',
      pageBreak: 'before',
      pageOrientation: 'landscape',
    });
    printer.addNewLine();
    printer.addSimpleTable({
      columns: [
        { id: 'rule', label: 'Rule' },
        { id: 'scope', label: 'Scope' },
        { id: 'target', label: 'Applies to' },
        { id: 'level', label: 'Level' },
        { id: 'role', label: 'Role' },
        { id: 'reason', label: 'Reason' },
        { id: 'ticket', label: 'Ticket' },
        { id: 'owner', label: 'Owner' },
        { id: 'updated_by', label: 'Changed by' },
        { id: 'updated_at', label: 'Changed at' },
      ],
      items: exclusions
        .filter(e => e.os_key === osKey)
        .map(e => ({
          rule: e.rule,
          scope: SCOPE_LABELS[e.scope] || e.scope,
          target: e.scope === 'global' ? 'all' : e.scope_value,
          level: e.level,
          role: e.role || 'any',
          reason: e.reason,
          ticket: e.ticket,
          owner: e.owner,
          updated_by: e.updated_by || '-',
          updated_at: e.updated_at || '-',
        })),
      widths: [40, 55, 70, 30, 55, '*', 55, 60, 60, 75],
      fontSize: 7,
      maxTextLength: 200,
    });
  }

  if (!exclusions.length) {
    printer.addContentWithNewLine({
      text: 'No exclusions: every check of the benchmarks is assessed.',
      style: 'standard',
    });
  }
};
