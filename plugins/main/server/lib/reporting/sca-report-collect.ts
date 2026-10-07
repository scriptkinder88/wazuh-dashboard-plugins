/*
 * First pass of the SCA report: the latest state of every check of the
 * selected servers, counted by server, policy and family, and checked against
 * the latest scan summary of each policy.
 */
import { resolveCisReference } from '../../../common/sca/cis-reference';
import { forEachLatestScaCheck } from './sca-request';
import {
  FailedControl,
  PolicyCoverage,
  PolicySummary,
  ResultCounters,
  ServerSummary,
  UNMAPPED_FAMILY,
  addResultToCounters,
  createPolicyCounters,
  formatResult,
} from './sca-report-model';
import {
  OpenSearchQuery,
  ScaAgentInfo,
  ScaPolicySummary,
  ScaSearchContext,
} from './sca-types';

export interface ServerCoverage {
  instances: PolicyCoverage[];
  complete: boolean;
  label: string;
}

export interface ScaResults {
  overallCounters: ResultCounters;
  serverSummaries: Map<string, ServerSummary>;
  policySummaries: Map<string, PolicySummary>;
  /** Coverage by `${agentId}::${policyKey}`. */
  policyInstanceCoverage: Map<string, PolicyCoverage>;
  /** policyKey -> family -> counters */
  familyCounters: Map<string, Map<string, ResultCounters>>;
  /** policyKey -> checkId -> failed control with the servers it fails on */
  failedControls: Map<string, Map<string, FailedControl>>;
  getServerCoverage: (agentId: string) => ServerCoverage;
}

export async function collectScaResults(
  context: ScaSearchContext,
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  normalizedAgentIds: string[],
  inventory: Map<string, ScaAgentInfo>,
  latestPolicySummaries: Map<string, ScaPolicySummary>,
): Promise<ScaResults> {
  const overallCounters = createPolicyCounters();
  const serverSummaries = new Map<string, ServerSummary>();
  const policySummaries = new Map<string, PolicySummary>();
  const policyInstanceCoverage = new Map<string, PolicyCoverage>();
  // policyKey -> family -> counters
  const familyCounters = new Map<string, Map<string, ResultCounters>>();
  // policyKey -> checkId -> failed control with the servers it fails on
  const failedControls = new Map<string, Map<string, FailedControl>>();

  for (const agentId of normalizedAgentIds) {
    const agent = inventory.get(agentId);
    serverSummaries.set(agentId, {
      id: agentId,
      name: agent?.name || 'Unknown server',
      ip: agent?.ip || '-',
      ...createPolicyCounters(),
    });
  }

  await forEachLatestScaCheck(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
    ({ key, source }) => {
      const agentId = String(key?.agent_id || source?.agent?.id || '');
      const policy = String(source?.data?.sca?.policy || 'Unknown SCA policy');
      const policyKey = String(
        key?.policy ||
          source?.data?.sca?.policy ||
          source?.data?.sca?.policy_id ||
          policy,
      );
      const rawResult =
        source?.data?.sca?.check?.result ||
        source?.data?.sca?.check?.status ||
        '-';
      const result = formatResult(rawResult);

      if (!agentId) {
        return;
      }

      if (!serverSummaries.has(agentId)) {
        serverSummaries.set(agentId, {
          id: agentId,
          name: source?.agent?.name || 'Unknown server',
          ip: source?.agent?.ip || '-',
          ...createPolicyCounters(),
        });
      }

      const serverSummary = serverSummaries.get(agentId)!;
      addResultToCounters(serverSummary, result);
      addResultToCounters(overallCounters, result);

      const instanceKey = `${agentId}::${policyKey}`;
      if (!policyInstanceCoverage.has(instanceKey)) {
        policyInstanceCoverage.set(instanceKey, {
          agentId,
          policyKey,
          policy,
          observed: 0,
          expected: null,
          status: 'unverified',
          ...createPolicyCounters(),
        });
      }
      const instanceCoverage = policyInstanceCoverage.get(instanceKey)!;
      instanceCoverage.observed++;
      addResultToCounters(instanceCoverage, result);

      if (!policySummaries.has(policyKey)) {
        policySummaries.set(policyKey, {
          key: policyKey,
          policy,
          agents: new Set<string>(),
          ...createPolicyCounters(),
        });
      }

      const policySummary = policySummaries.get(policyKey)!;
      policySummary.agents.add(agentId);
      if (!policySummary.policyId && source?.data?.sca?.policy_id) {
        policySummary.policyId = String(source.data.sca.policy_id);
      }
      addResultToCounters(policySummary, result);

      const check = source?.data?.sca?.check || {};
      const cis = resolveCisReference(check);
      const family = cis.family || UNMAPPED_FAMILY;
      if (cis.familyTitle) {
        if (!policySummary.familyTitles) {
          policySummary.familyTitles = new Map<string, string>();
        }
        if (!policySummary.familyTitles.has(family)) {
          policySummary.familyTitles.set(family, cis.familyTitle);
        }
      }
      if (!familyCounters.has(policyKey)) {
        familyCounters.set(policyKey, new Map());
      }
      const policyFamilies = familyCounters.get(policyKey)!;
      if (!policyFamilies.has(family)) {
        policyFamilies.set(family, createPolicyCounters());
      }
      addResultToCounters(policyFamilies.get(family)!, result);

      if (result === 'Failed') {
        const checkId = String(key?.check_id || check.id || '-');
        if (!failedControls.has(policyKey)) {
          failedControls.set(policyKey, new Map());
        }
        const policyFailed = failedControls.get(policyKey)!;
        if (!policyFailed.has(checkId)) {
          policyFailed.set(checkId, {
            checkId,
            reference: cis.reference,
            family: cis.family,
            title: cis.title || '-',
            agents: new Set<string>(),
          });
        }
        policyFailed.get(checkId)!.agents.add(agentId);
      }
    },
  );

  for (const [instanceKey, latestSummary] of latestPolicySummaries) {
    if (!policyInstanceCoverage.has(instanceKey)) {
      policyInstanceCoverage.set(instanceKey, {
        agentId: latestSummary.agentId,
        policyKey: latestSummary.policyKey,
        policy: latestSummary.policy || latestSummary.policyKey,
        observed: 0,
        expected: latestSummary.totalChecks,
        status: 'unverified',
        ...createPolicyCounters(),
      });
    }

    const coverage = policyInstanceCoverage.get(instanceKey)!;
    coverage.expected = latestSummary.totalChecks;
    const summaryCountsMatch =
      coverage.passed === latestSummary.passed &&
      coverage.failed === latestSummary.failed &&
      coverage.notApplicable === latestSummary.invalid &&
      coverage.other === 0;
    coverage.status =
      typeof latestSummary.totalChecks === 'number'
        ? coverage.observed === latestSummary.totalChecks && summaryCountsMatch
          ? 'complete'
          : 'incomplete'
        : 'unverified';

    if (!policySummaries.has(latestSummary.policyKey)) {
      policySummaries.set(latestSummary.policyKey, {
        key: latestSummary.policyKey,
        policy: latestSummary.policy || latestSummary.policyKey,
        agents: new Set<string>(),
        ...createPolicyCounters(),
      });
    }
    policySummaries
      .get(latestSummary.policyKey)!
      .agents.add(latestSummary.agentId);
  }

  const getServerCoverage = (agentId: string): ServerCoverage => {
    const instances = Array.from(policyInstanceCoverage.values()).filter(
      coverage => coverage.agentId === agentId,
    );

    if (!instances.length) {
      return {
        instances,
        complete: false,
        label: 'No indexed SCA data',
      };
    }

    const completeCount = instances.filter(
      coverage => coverage.status === 'complete',
    ).length;
    const incompleteCount = instances.filter(
      coverage => coverage.status === 'incomplete',
    ).length;
    const unverifiedCount = instances.length - completeCount - incompleteCount;

    if (completeCount === instances.length) {
      return {
        instances,
        complete: true,
        label: `Complete (${instances.length} ${
          instances.length === 1 ? 'policy' : 'policies'
        })`,
      };
    }

    if (incompleteCount) {
      return {
        instances,
        complete: false,
        label: `Incomplete history (${incompleteCount} ${
          incompleteCount === 1 ? 'policy' : 'policies'
        })`,
      };
    }

    return {
      instances,
      complete: false,
      label: `Unverified (${unverifiedCount} ${
        unverifiedCount === 1 ? 'policy' : 'policies'
      })`,
    };
  };

  return {
    overallCounters,
    serverSummaries,
    policySummaries,
    policyInstanceCoverage,
    familyCounters,
    failedControls,
    getServerCoverage,
  };
}
