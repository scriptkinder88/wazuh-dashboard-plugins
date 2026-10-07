import { ReportPrinter } from './printer';
import {
  getLatestScaPolicySummaries,
  getScaAgentInventory,
} from './sca-request';
import {
  ScaReportOptions,
  getCountersScore,
  getCountersTotal,
  normalizeAgentIds,
} from './sca-report-model';
import { collectScaResults } from './sca-report-collect';
import {
  addExecutiveKpiRow,
  addExecutiveStatus,
  addGroupedScaOverview,
} from './sca-report-summary';
import { addScaFamilySections } from './sca-report-families';
import { addScaDetailSections } from './sca-report-details';
import { OpenSearchQuery, ScaSearchContext } from './sca-types';

export type { ScaReportOptions } from './sca-report-model';

export async function addScaChecksToReport(
  context: ScaSearchContext,
  printer: ReportPrinter,
  agentIds: string | string[],
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  options: ScaReportOptions = {},
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  printer.logger.debug(
    `Fetching indexed SCA controls for ${normalizedAgentIds.length} selected agents from ${pattern}`,
  );

  const inventory = await getScaAgentInventory(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
  );

  const latestPolicySummaries = await getLatestScaPolicySummaries(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
  );

  const {
    overallCounters,
    serverSummaries,
    policySummaries,
    policyInstanceCoverage,
    familyCounters,
    failedControls,
    getServerCoverage,
  } = await collectScaResults(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
    inventory,
    latestPolicySummaries,
  );

  const serversWithData = normalizedAgentIds.filter(
    agentId => getServerCoverage(agentId).instances.length > 0,
  ).length;
  const verifiedServers = normalizedAgentIds.filter(
    agentId => getServerCoverage(agentId).complete,
  ).length;
  const coverageIssues = normalizedAgentIds.length - verifiedServers;
  const allSelectedCoverageComplete =
    normalizedAgentIds.length > 0 &&
    verifiedServers === normalizedAgentIds.length;
  const overallScore = allSelectedCoverageComplete
    ? getCountersScore(overallCounters)
    : null;

  printer.addContentWithNewLine({
    text: 'Executive summary',
    style: 'h2',
  });

  printer.addContentWithNewLine({
    text: 'Current indexed SCA posture for the selected server scope. Scores are shown only where the latest indexed scan is complete and internally consistent.',
    style: 'standard',
  });

  printer.addContentWithNewLine({
    text: 'Assessment scope',
    style: 'h4',
  });

  addExecutiveKpiRow(printer, [
    { label: 'Selected servers', value: normalizedAgentIds.length },
    { label: 'With SCA data', value: serversWithData },
    { label: 'Verified', value: verifiedServers },
    { label: 'Policies', value: policySummaries.size },
  ]);

  printer.addContentWithNewLine({
    text: 'Control outcome',
    style: 'h4',
  });

  addExecutiveKpiRow(printer, [
    { label: 'Controls', value: getCountersTotal(overallCounters) },
    { label: 'Passed', value: overallCounters.passed },
    { label: 'Failed', value: overallCounters.failed },
    { label: 'N/A', value: overallCounters.notApplicable },
    { label: 'Score', value: overallScore === null ? '-' : `${overallScore}%` },
  ]);

  const coverageStatus =
    coverageIssues === 0
      ? 'Coverage verified: all selected servers match their latest indexed SCA scan summary.'
      : `Coverage requires attention: ${coverageIssues} selected server${
          coverageIssues === 1 ? '' : 's'
        } ${
          coverageIssues === 1 ? 'has' : 'have'
        } incomplete, unverified or missing indexed SCA coverage. Scores are withheld wherever coverage is not complete.`;

  printer.addContentWithNewLine({
    text: 'Coverage',
    style: 'h4',
  });
  addExecutiveStatus(printer, coverageStatus, coverageIssues > 0);

  printer.addContent({
    text: 'Security configuration assessment controls',
    style: 'h1',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();

  printer.addContentWithNewLine({
    text: 'Indexed SCA state is reconstructed from check events and verified against the latest scan total_checks. Scores are withheld when coverage is incomplete or unverified.',
    style: 'standard',
  });

  addGroupedScaOverview(printer, {
    selected: normalizedAgentIds.length,
    withData: serversWithData,
    verified: verifiedServers,
    coverageIssues,
    controls: getCountersTotal(overallCounters),
    passed: overallCounters.passed,
    failed: overallCounters.failed,
    notApplicable: overallCounters.notApplicable,
    score: overallScore === null ? '-' : `${overallScore}%`,
  });

  printer.addSimpleTable({
    title: `Selected server results (${normalizedAgentIds.length})`,
    columns: [
      { id: 'id', label: 'ID' },
      { id: 'name', label: 'Server' },
      { id: 'score', label: 'Score' },
      { id: 'passed', label: 'Passed' },
      { id: 'failed', label: 'Failed' },
      { id: 'notApplicable', label: 'N/A' },
      { id: 'controls', label: 'Controls' },
      { id: 'sca', label: 'Indexed SCA data' },
    ],
    items: normalizedAgentIds.map(agentId => {
      // every selected server has a summary, with zero counters if no data
      const summary = serverSummaries.get(agentId)!;
      const controls = getCountersTotal(summary);
      const coverage = getServerCoverage(agentId);
      const score = coverage.complete ? getCountersScore(summary) : null;

      return {
        id: agentId,
        name: summary?.name || 'Unknown server',
        score: score === null ? '-' : `${score}%`,
        passed: summary?.passed || 0,
        failed: summary?.failed || 0,
        notApplicable: summary?.notApplicable || 0,
        controls,
        sca: coverage.label,
      };
    }),
    widths: [42, 150, 52, 52, 52, 52, 60, '*'],
    fontSize: 7,
    maxTextLength: 32,
  });

  if (policySummaries.size) {
    printer.addSimpleTable({
      title: `Grouped by policy (${policySummaries.size})`,
      columns: [
        { id: 'policy', label: 'Policy' },
        { id: 'servers', label: 'Servers' },
        { id: 'controls', label: 'Controls' },
        { id: 'passed', label: 'Passed' },
        { id: 'failed', label: 'Failed' },
        { id: 'notApplicable', label: 'N/A' },
        { id: 'coverage', label: 'Coverage' },
        { id: 'score', label: 'Score' },
      ],
      items: Array.from(policySummaries.values())
        .sort((a, b) => String(a.policy).localeCompare(String(b.policy)))
        .map(summary => {
          const instances = Array.from(policyInstanceCoverage.values()).filter(
            coverage => coverage.policyKey === summary.key,
          );
          const completeInstances = instances.filter(
            coverage => coverage.status === 'complete',
          ).length;
          const complete =
            instances.length > 0 && completeInstances === instances.length;
          const score = complete ? getCountersScore(summary) : null;

          return {
            policy: summary.policy,
            servers: summary.agents.size,
            controls: getCountersTotal(summary),
            passed: summary.passed,
            failed: summary.failed,
            notApplicable: summary.notApplicable,
            coverage: `${completeInstances}/${instances.length} complete`,
            score: score === null ? '-' : `${score}%`,
          };
        }),
      widths: ['*', 48, 55, 48, 48, 48, 80, 48],
      fontSize: 7,
      maxTextLength: 44,
    });
  }

  addScaFamilySections(printer, {
    policySummaries,
    policyInstanceCoverage,
    familyCounters,
    failedControls,
    serverSummaries,
  });

  if (!options.details) {
    return;
  }

  await addScaDetailSections(
    context,
    printer,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
    inventory,
    policyInstanceCoverage,
  );
}
