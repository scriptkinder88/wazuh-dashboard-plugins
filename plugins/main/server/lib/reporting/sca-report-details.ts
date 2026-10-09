/*
 * Optional part of the SCA report: for every selected server, each policy
 * with all its controls.
 */
import { resolveCisReference } from '../../../common/sca/cis-reference';
import { ReportPrinter } from './printer';
import { forEachLatestScaCheck } from './sca-request';
import {
  PolicyCoverage,
  addResultToCounters,
  createPolicyCounters,
  formatCompliance,
  formatResult,
  getCountersScore,
} from './sca-report-model';
import { OpenSearchQuery, ScaAgentInfo, ScaSearchContext } from './sca-types';

/** A row of the controls table of a policy. */
interface DetailRow {
  reference: string;
  result: string;
  title: string;
  rationale: string;
  remediation: string;
  description: string;
  compliance: string;
}

function addAgentSectionHeader(
  printer: ReportPrinter,
  agentId: string,
  agent: ScaAgentInfo | undefined,
  addPageBreak: boolean,
) {
  if (addPageBreak) {
    printer.addContent({
      text: '',
      pageBreak: 'before',
      pageOrientation: 'landscape',
    });
  }

  const agentName = agent?.name || 'Unknown server';

  printer.addContentWithNewLine({
    text: `Server ${agentName} (${agentId})`,
    style: 'h2',
  });

  const details = [
    agent?.ip ? `IP: ${agent.ip}` : '',
    agent?.timestamp ? `Latest indexed SCA event: ${agent.timestamp}` : '',
  ]
    .filter(Boolean)
    .join(' | ');

  if (details) {
    printer.addContentWithNewLine({
      text: details,
      style: 'standard',
    });
  }
}

export async function addScaDetailSections(
  context: ScaSearchContext,
  printer: ReportPrinter,
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  normalizedAgentIds: string[],
  inventory: Map<string, ScaAgentInfo>,
  policyInstanceCoverage: Map<string, PolicyCoverage>,
) {
  printer.addContent({
    text: 'Detailed results by selected server',
    style: 'h2',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();

  const seenAgents = new Set<string>();
  let activeAgentId = '';
  let activePolicy = '';
  let activePolicyKey = '';
  let activeAgent: ScaAgentInfo | null = null;
  let activeItems: DetailRow[] = [];
  let counters = createPolicyCounters();
  let renderedAgents = 0;

  const flushPolicy = () => {
    if (!activeAgentId || !activePolicy) {
      return;
    }

    const coverage = policyInstanceCoverage.get(
      `${activeAgentId}::${activePolicyKey}`,
    );
    const coverageComplete = coverage?.status === 'complete';
    const score = coverageComplete ? getCountersScore(counters) : null;

    printer.addContentWithNewLine({
      text:
        activePolicy ||
        (activePolicyKey ? `Policy ${activePolicyKey}` : 'SCA policy'),
      style: 'h3',
    });

    const coverageText =
      coverage?.status === 'complete'
        ? `Coverage: Complete (${coverage.observed}/${coverage.expected} checks)`
        : coverage?.status === 'incomplete'
        ? `Coverage: Incomplete (${coverage.observed}/${coverage.expected} checks)`
        : 'Coverage: Unverified (no indexed scan summary)';

    const summary = [
      coverageText,
      score !== null ? `Score: ${score}%` : '',
      `Passed: ${counters.passed}`,
      `Failed: ${counters.failed}`,
      `Not applicable: ${counters.notApplicable}`,
      counters.other ? `Other: ${counters.other}` : '',
    ]
      .filter(Boolean)
      .join(' | ');

    printer.addContentWithNewLine({
      text: summary,
      style: 'standard',
    });

    printer.addSimpleTable({
      title: `Controls (${activeItems.length})`,
      columns: [
        { id: 'reference', label: 'CIS' },
        { id: 'result', label: 'Result' },
        { id: 'title', label: 'Control' },
        { id: 'rationale', label: 'Rationale' },
        { id: 'remediation', label: 'Remediation' },
        { id: 'description', label: 'Description' },
        { id: 'compliance', label: 'Compliance' },
      ],
      items: activeItems,
      widths: [32, 44, 110, 108, 142, 152, 142],
      fontSize: 6.5,
      maxTextLength: 34,
      cellPadding: 1,
    });

    activeItems = [];
    counters = createPolicyCounters();
  };

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

      if (!agentId) {
        return;
      }

      if (agentId !== activeAgentId) {
        flushPolicy();

        activeAgentId = agentId;
        activePolicy = '';
        activePolicyKey = '';
        activeAgent = {
          ...(inventory.get(agentId) || {}),
          ...(source?.agent || {}),
          timestamp:
            source?.timestamp || inventory.get(agentId)?.timestamp || undefined,
        };

        addAgentSectionHeader(
          printer,
          agentId,
          activeAgent,
          renderedAgents > 0,
        );
        renderedAgents++;
        seenAgents.add(agentId);
      }

      if (policyKey !== activePolicyKey) {
        flushPolicy();
        activePolicy = policy;
        activePolicyKey = policyKey;
      }

      const rawResult =
        source?.data?.sca?.check?.result ||
        source?.data?.sca?.check?.status ||
        '-';
      const result = formatResult(rawResult);

      addResultToCounters(counters, result);

      const cis = resolveCisReference(source?.data?.sca?.check || {});
      activeItems.push({
        reference:
          cis.reference ||
          `ID ${String(key?.check_id || source?.data?.sca?.check?.id || '-')}`,
        result,
        title: cis.title || '-',
        rationale: source?.data?.sca?.check?.rationale || '-',
        remediation: source?.data?.sca?.check?.remediation || '-',
        description: source?.data?.sca?.check?.description || '-',
        compliance: formatCompliance(source?.data?.sca?.check?.compliance),
      });
    },
  );

  flushPolicy();

  for (const agentId of normalizedAgentIds) {
    if (seenAgents.has(agentId)) {
      continue;
    }

    addAgentSectionHeader(
      printer,
      agentId,
      inventory.get(agentId),
      renderedAgents > 0,
    );
    renderedAgents++;

    printer.addContentWithNewLine({
      text: 'No indexed SCA controls were found for this server.',
      style: 'standard',
    });
  }
}
