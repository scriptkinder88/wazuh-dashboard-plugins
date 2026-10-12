/*
 * Results by benchmark family: per policy, a bar chart, a table by family and
 * the failed controls with the servers they fail on.
 */
import { compareCisReferences } from '../../../common/sca/cis-reference';
import { ReportPrinter } from './printer';
import {
  FailedControl,
  ResultCounters,
  UNMAPPED_FAMILY,
  getCountersScore,
  getCountersTotal,
} from './sca-report-model';
import {
  buildFamilyBarsSvg,
  compareFamilies,
  getFamilyLabel,
} from './sca-report-charts';

const MAX_LISTED_SERVERS = 5;

const compareCheckIds = (a: string, b: string) =>
  a.localeCompare(b, undefined, { numeric: true });

// Numbered controls first, in recommendation order; the rest by check ID.
const compareFailedControls = (a: FailedControl, b: FailedControl) => {
  if (a.reference && b.reference) {
    return (
      compareCisReferences(a.reference, b.reference) ||
      compareCheckIds(a.checkId, b.checkId)
    );
  }
  if (a.reference) {
    return -1;
  }
  if (b.reference) {
    return 1;
  }
  return compareCheckIds(a.checkId, b.checkId);
};

export const addScaFamilySections = (
  printer: ReportPrinter,
  {
    policySummaries,
    policyInstanceCoverage,
    familyCounters,
    failedControls,
    serverSummaries,
  }: {
    policySummaries: Map<
      string,
      {
        key: string;
        policy: string;
        policyId?: string;
        familyTitles?: Map<string, string>;
      }
    >;
    policyInstanceCoverage: Map<string, { policyKey: string; status: string }>;
    familyCounters: Map<string, Map<string, ResultCounters>>;
    failedControls: Map<string, Map<string, FailedControl>>;
    serverSummaries: Map<string, { name?: string }>;
  },
) => {
  const policies = Array.from(policySummaries.values())
    .filter(summary => familyCounters.has(summary.key))
    .sort((a, b) => String(a.policy).localeCompare(String(b.policy)));

  if (!policies.length) {
    return;
  }

  printer.addContent({
    text: 'Results by benchmark family',
    style: 'h1',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();
  printer.addContentWithNewLine({
    text:
      'Controls are grouped by the first level of their CIS recommendation ' +
      'number (family 1 holds 1.1.1, 1.2, ...). The number comes from the ' +
      'check title for CIS-CAT Pro imports and from the policy CIS ' +
      'compliance mapping for Wazuh policies. Family titles come from the ' +
      'checks when a CIS-CAT bridge adds them, otherwise from the CIS ' +
      'family index for the policy; unknown families show the number only.',
    style: 'standard',
  });

  for (const summary of policies) {
    const instances = Array.from(policyInstanceCoverage.values()).filter(
      coverage => coverage.policyKey === summary.key,
    );
    const complete =
      instances.length > 0 &&
      instances.every(coverage => coverage.status === 'complete');
    const families = Array.from(familyCounters.get(summary.key)!.entries())
      .map(([family, counters]) => ({ family, counters }))
      .sort((a, b) => compareFamilies(a.family, b.family));

    printer.addContentWithNewLine({
      text: summary.policy,
      style: 'h2',
    });

    if (!complete) {
      printer.addContentWithNewLine({
        text:
          'Pass rates are withheld: indexed coverage for this policy is ' +
          'incomplete or unverified.',
        style: 'standard',
      });
    }

    printer.addContent({
      svg: buildFamilyBarsSvg(families, summary.policyId, summary.familyTitles),
      margin: [0, 0, 0, 6],
    });

    printer.addSimpleTable({
      title: `Results by family (${families.length})`,
      columns: [
        { id: 'family', label: 'Family' },
        { id: 'controls', label: 'Controls' },
        { id: 'passed', label: 'Passed' },
        { id: 'failed', label: 'Failed' },
        { id: 'notApplicable', label: 'N/A' },
        { id: 'passRate', label: 'Pass rate' },
      ],
      items: families.map(({ family, counters }) => {
        const score = complete ? getCountersScore(counters) : null;

        return {
          family: getFamilyLabel(
            family,
            summary.policyId,
            summary.familyTitles,
          ),
          controls: getCountersTotal(counters),
          passed: counters.passed,
          failed: counters.failed,
          notApplicable: counters.notApplicable + counters.other,
          passRate: score === null ? '-' : `${score}%`,
        };
      }),
      widths: ['*', 60, 60, 60, 60, 60],
      fontSize: 7,
      maxTextLength: 44,
    });

    const failed = Array.from(
      failedControls.get(summary.key)?.values() || [],
    ).sort(compareFailedControls);

    if (!failed.length) {
      continue;
    }

    printer.addContentWithNewLine({
      text: `Failed controls by family (${failed.length})`,
      style: 'h3',
    });

    const byFamily = new Map<string, FailedControl[]>();
    for (const control of failed) {
      const family = control.family || UNMAPPED_FAMILY;
      if (!byFamily.has(family)) {
        byFamily.set(family, []);
      }
      byFamily.get(family)!.push(control);
    }

    for (const family of Array.from(byFamily.keys()).sort(compareFamilies)) {
      const controls = byFamily.get(family)!;

      printer.addSimpleTable({
        title: `${getFamilyLabel(
          family,
          summary.policyId,
          summary.familyTitles,
        )} (${controls.length})`,
        columns: [
          { id: 'reference', label: 'CIS' },
          { id: 'title', label: 'Control' },
          { id: 'affected', label: 'Servers' },
          { id: 'servers', label: 'Affected servers' },
        ],
        items: controls.map(control => {
          const names = Array.from(control.agents)
            .sort()
            .map(agentId => {
              const name = serverSummaries.get(agentId)?.name;
              return `${name || 'Unknown server'} (${agentId})`;
            });
          const extra = names.length - MAX_LISTED_SERVERS;

          return {
            reference: control.reference || `ID ${control.checkId}`,
            title: control.title,
            affected: names.length,
            servers:
              names.slice(0, MAX_LISTED_SERVERS).join(', ') +
              (extra > 0 ? `, +${extra} more` : ''),
          };
        }),
        widths: [52, '*', 44, 230],
        fontSize: 7,
        maxTextLength: 60,
      });
    }
  }
};
