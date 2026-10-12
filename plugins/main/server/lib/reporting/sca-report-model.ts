/*
 * Counters, result labels and the records the SCA report aggregates.
 */

export const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

const flattenComplianceValue = (value: unknown): string[] => {
  if (value === null || typeof value === 'undefined') {
    return [];
  }

  if (Array.isArray(value)) {
    return value.flatMap(flattenComplianceValue);
  }

  if (typeof value === 'object') {
    return Object.values(value).flatMap(flattenComplianceValue);
  }

  return String(value)
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
};

export const formatCompliance = (compliance: unknown): string => {
  if (!compliance) {
    return '-';
  }

  if (Array.isArray(compliance)) {
    const rows = compliance
      .map(item => {
        if (!item || typeof item !== 'object') {
          return String(item || '');
        }

        const { key, value } = item as { key?: string; value?: unknown };
        const values = flattenComplianceValue(value);
        return [key || '', values.join(', ')].filter(Boolean).join(': ');
      })
      .filter(Boolean);

    return rows.length ? rows.join('\n') : '-';
  }

  if (typeof compliance === 'object') {
    const rows = Object.entries(compliance)
      .map(([key, value]) => {
        const values = flattenComplianceValue(value);
        return values.length ? `${key}: ${values.join(', ')}` : '';
      })
      .filter(Boolean);

    return rows.length ? rows.join('\n') : '-';
  }

  return String(compliance || '-');
};

export const formatResult = (result: unknown): string => {
  switch (
    String(result || '')
      .trim()
      .toLowerCase()
      .replace(/_/g, ' ')
  ) {
    case 'pass':
    case 'passed':
      return 'Passed';
    case 'fail':
    case 'failed':
      return 'Failed';
    case 'invalid':
    case 'not applicable':
      return 'Not applicable';
    default:
      return String(result || '-');
  }
};

export interface ResultCounters {
  passed: number;
  failed: number;
  notApplicable: number;
  other: number;
}

export const createPolicyCounters = (): ResultCounters => ({
  passed: 0,
  failed: 0,
  notApplicable: 0,
  other: 0,
});

export const addResultToCounters = (
  counters: ResultCounters,
  result: string,
) => {
  if (result === 'Passed') {
    counters.passed++;
  } else if (result === 'Failed') {
    counters.failed++;
  } else if (result === 'Not applicable') {
    counters.notApplicable++;
  } else {
    counters.other++;
  }
};

export const getCountersTotal = (counters: ResultCounters) =>
  counters.passed + counters.failed + counters.notApplicable + counters.other;

export const getCountersScore = (counters: ResultCounters) => {
  const denominator = counters.passed + counters.failed;

  return denominator > 0
    ? Math.round((counters.passed / denominator) * 100)
    : null;
};

export interface ScaReportOptions {
  /**
   * Adds the per-server, per-control tables. Off by default because they grow
   * with servers x checks.
   */
  details?: boolean;
}

export interface FailedControl {
  checkId: string;
  reference?: string;
  family?: string;
  title: string;
  agents: Set<string>;
}

// Key for checks without a CIS recommendation number.
export const UNMAPPED_FAMILY = '';

/** Counters of one selected server. */
export interface ServerSummary extends ResultCounters {
  id: string;
  name: string;
  ip: string;
}

/** Counters of one policy across the selected servers. */
export interface PolicySummary extends ResultCounters {
  key: string;
  policy: string;
  policyId?: string;
  agents: Set<string>;
  /** Family titles carried by the checks, by family number. */
  familyTitles?: Map<string, string>;
}

export type CoverageStatus = 'complete' | 'incomplete' | 'unverified';

/** Checks found for a policy on a server, against its latest scan. */
export interface PolicyCoverage extends ResultCounters {
  agentId: string;
  policyKey: string;
  policy: string;
  observed: number;
  expected: number | null;
  status: CoverageStatus;
}
