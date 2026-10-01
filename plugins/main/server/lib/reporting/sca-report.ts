/*
 * Wazuh app - SCA PDF report content
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import {
  REPORTS_PRIMARY_COLOR,
  WAZUH_SCA_PATTERN,
} from '../../../common/constants';
import {
  compareCisReferences,
  resolveCisReference,
} from '../../../common/sca/cis-reference';
import { getCisFamilyTitle } from '../../../common/compliance-requirements/cis-families';
import { ReportPrinter } from './printer';
import {
  forEachScaCheck,
  getScaAgentInventory,
  getScaPolicySummaries,
  normalizeAgentIds,
  normalizeScaResult,
  ScaStateDocument,
} from './sca-states-request';

const flattenComplianceValue = (value: any): string[] => {
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

const formatCompliance = compliance => {
  if (!compliance) {
    return '-';
  }

  if (Array.isArray(compliance)) {
    const rows = compliance
      .map(item => {
        if (!item || typeof item !== 'object') {
          return String(item || '');
        }

        const key = item.key || '';
        const values = flattenComplianceValue(item.value);
        return [key, values.join(', ')].filter(Boolean).join(': ');
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

function addAgentSectionHeader(
  printer: ReportPrinter,
  agentId: string,
  agent: any,
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
    agent?.timestamp ? `Latest SCA state change: ${agent.timestamp}` : '',
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

const createPolicyCounters = () => ({
  passed: 0,
  failed: 0,
  notApplicable: 0,
  other: 0,
});

const addResultToCounters = (counters, result: string) => {
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

const getCountersTotal = counters =>
  counters.passed + counters.failed + counters.notApplicable + counters.other;

const getCountersScore = counters => {
  const denominator = counters.passed + counters.failed;

  return denominator > 0
    ? Math.round((counters.passed / denominator) * 100)
    : null;
};

const addExecutiveKpiRow = (
  printer: ReportPrinter,
  items: Array<{ label: string; value: string | number }>,
) => {
  printer.addContent({
    columns: items.map((item, index) => ({
      width: '*',
      margin: [index === 0 ? 0 : 4, 0, index === items.length - 1 ? 0 : 4, 0],
      table: {
        widths: ['*'],
        body: [
          [
            {
              stack: [
                {
                  text: String(item.value),
                  alignment: 'center',
                  bold: true,
                  fontSize: 18,
                  color: REPORTS_PRIMARY_COLOR,
                },
                {
                  text: item.label,
                  alignment: 'center',
                  fontSize: 8,
                  color: '#333',
                  margin: [0, 4, 0, 0],
                },
              ],
              margin: [6, 10, 6, 10],
            },
          ],
        ],
      },
      layout: {
        fillColor: () => '#F7F9FC',
        hLineColor: () => '#D3DAE6',
        vLineColor: () => '#D3DAE6',
        hLineWidth: () => 1,
        vLineWidth: () => 1,
      },
    })),
    margin: [0, 4, 0, 10],
  });
};

const addExecutiveStatus = (
  printer: ReportPrinter,
  text: string,
  needsAttention: boolean,
) => {
  printer.addContent({
    table: {
      widths: ['*'],
      body: [
        [
          {
            text,
            bold: true,
            fontSize: 9,
            color: '#333',
            margin: [10, 10, 10, 10],
          },
        ],
      ],
    },
    layout: {
      fillColor: () => (needsAttention ? '#FFF7E6' : '#F0F9F4'),
      hLineColor: () => (needsAttention ? '#E6A700' : '#2E7D32'),
      vLineColor: () => (needsAttention ? '#E6A700' : '#2E7D32'),
      hLineWidth: () => 1,
      vLineWidth: () => 1,
    },
    margin: [0, 4, 0, 10],
  });
};

const SCA_RESULT_COLORS = {
  passed: '#00A69B',
  failed: '#FF645C',
  notApplicable: '#5C6773',
};

const buildScaDonutSvg = counters => {
  const values = [
    { value: counters.passed, color: SCA_RESULT_COLORS.passed },
    { value: counters.failed, color: SCA_RESULT_COLORS.failed },
    {
      value: counters.notApplicable,
      color: SCA_RESULT_COLORS.notApplicable,
    },
  ];
  const total = values.reduce((sum, item) => sum + item.value, 0);
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  const segments =
    total > 0
      ? values
          .filter(item => item.value > 0)
          .map(item => {
            const length = (item.value / total) * circumference;
            const segment = `<circle cx="52" cy="52" r="${radius}" fill="none" stroke="${
              item.color
            }" stroke-width="18" stroke-dasharray="${length} ${
              circumference - length
            }" stroke-dashoffset="${-offset}" />`;
            offset += length;
            return segment;
          })
          .join('')
      : `<circle cx="52" cy="52" r="${radius}" fill="none" stroke="#D3DAE6" stroke-width="18" />`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="164" height="116" viewBox="0 0 164 116"><g transform="rotate(-90 52 52)">${segments}</g><text x="52" y="49" text-anchor="middle" font-size="17" font-weight="bold" fill="#333">${total}</text><text x="52" y="64" text-anchor="middle" font-size="8" fill="#666">controls</text></svg>`;
};

const addGroupedScaOverview = (
  printer: ReportPrinter,
  summary: Record<string, string | number>,
) => {
  const columns = [
    { id: 'selected', label: 'Selected' },
    { id: 'withData', label: 'With data' },
    { id: 'verified', label: 'Verified' },
    { id: 'coverageIssues', label: 'Coverage issues' },
    { id: 'controls', label: 'Controls' },
    { id: 'passed', label: 'Passed' },
    { id: 'failed', label: 'Failed' },
    { id: 'notApplicable', label: 'N/A' },
    { id: 'score', label: 'Score' },
  ];
  const widths = [48, 52, 52, 72, 56, 46, 46, 46, 46];
  const header = columns.map(column => ({
    text: column.label,
    style: 'whiteColor',
    border: [0, 0, 0, 0],
  }));
  const row = columns.map(column => ({
    text: String(summary[column.id]),
    style: 'standard',
  }));

  printer.addContentWithNewLine({
    text: 'Grouped SCA result',
    style: 'h4',
  });

  printer.addContent({
    id: 'sca-grouped-overview',
    columns: [
      {
        width: 510,
        table: {
          headerRows: 1,
          widths,
          body: [header, row],
        },
        layout: {
          fillColor: index => (index === 0 ? REPORTS_PRIMARY_COLOR : null),
          hLineColor: () => REPORTS_PRIMARY_COLOR,
          hLineWidth: () => 1,
          vLineWidth: () => 0,
          paddingLeft: () => 2,
          paddingRight: () => 2,
          paddingTop: () => 2,
          paddingBottom: () => 2,
        },
      },
      {
        width: '*',
        margin: [14, 0, 0, 0],
        stack: [
          {
            text: 'Control outcome',
            style: 'h4',
            margin: [0, 0, 0, 2],
          },
          {
            svg: buildScaDonutSvg(summary),
            width: 164,
            alignment: 'center',
          },
          {
            columns: [
              {
                width: '*',
                text: [
                  { text: '● ', color: SCA_RESULT_COLORS.passed },
                  `Passed (${summary.passed})`,
                ],
                fontSize: 7,
              },
              {
                width: '*',
                text: [
                  { text: '● ', color: SCA_RESULT_COLORS.failed },
                  `Failed (${summary.failed})`,
                ],
                fontSize: 7,
              },
            ],
          },
          {
            text: [
              { text: '● ', color: SCA_RESULT_COLORS.notApplicable },
              `Not applicable (${summary.notApplicable})`,
            ],
            fontSize: 7,
            margin: [0, 3, 0, 0],
          },
        ],
      },
    ],
    columnGap: 10,
    margin: [0, 0, 0, 8],
  });
};

export interface ScaReportOptions {
  /**
   * Adds the per-server, per-control tables. Off by default because they grow
   * with servers x checks.
   */
  details?: boolean;
}

type ResultCounters = ReturnType<typeof createPolicyCounters>;

interface FailedControl {
  checkId: string;
  reference?: string;
  family?: string;
  title: string;
  agents: Set<string>;
}

// Key for checks without a CIS recommendation number.
const UNMAPPED_FAMILY = '';
const MAX_LISTED_SERVERS = 5;

const compareCheckIds = (a: string, b: string) =>
  a.localeCompare(b, undefined, { numeric: true });

type CisSortable = Pick<FailedControl, 'checkId' | 'reference'>;

// Numbered controls first, in recommendation order; the rest by check ID.
const compareFailedControls = (a: CisSortable, b: CisSortable) => {
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

const escapeSvgText = (value: string) =>
  value.replace(/[&<>"']/g, char => `&#${char.charCodeAt(0)};`);

const svgText = (x: number, y: number, text: string) =>
  `<text x="${x}" y="${y}" font-size="8" fill="#333">` +
  `${escapeSvgText(text)}</text>`;

const svgRect = (
  x: number,
  y: number,
  width: number,
  height: number,
  color: string,
) =>
  `<rect x="${x}" y="${y}" width="${width}" height="${height}" ` +
  `fill="${color}" />`;

const compareFamilies = (a: string, b: string) => {
  if (a === b) {
    return 0;
  }
  if (a === UNMAPPED_FAMILY) {
    return 1;
  }
  if (b === UNMAPPED_FAMILY) {
    return -1;
  }
  return compareCisReferences(a, b);
};

// Family titles carried by the checks (`cis_family` compliance, from the
// benchmark itself) win; then the CIS family index, per policy; unknown ones
// show the number only.
const getFamilyLabel = (
  family: string,
  policyId?: string,
  checkFamilyTitles?: Map<string, string>,
) => {
  if (family === UNMAPPED_FAMILY) {
    return 'Not mapped to a family';
  }
  const title =
    checkFamilyTitles?.get(family) || getCisFamilyTitle(policyId, family);

  return title ? `Family ${family} - ${title}` : `Family ${family}`;
};

const MAX_CHART_LABEL_LENGTH = 48;

const truncateLabel = (label: string) =>
  label.length > MAX_CHART_LABEL_LENGTH
    ? `${label.slice(0, MAX_CHART_LABEL_LENGTH - 3)}...`
    : label;

const buildFamilyBarsSvg = (
  families: Array<{ family: string; counters: ResultCounters }>,
  policyId?: string,
  checkFamilyTitles?: Map<string, string>,
) => {
  const rowHeight = 16;
  const labelWidth = 230;
  const barWidth = 440;
  const height = families.length * rowHeight + 4;
  const rows = families
    .map(({ family, counters }, index) => {
      const total = getCountersTotal(counters);
      const y = index * rowHeight + 2;
      let x = labelWidth;
      const segments = [
        { value: counters.passed, color: SCA_RESULT_COLORS.passed },
        { value: counters.failed, color: SCA_RESULT_COLORS.failed },
        {
          value: counters.notApplicable + counters.other,
          color: SCA_RESULT_COLORS.notApplicable,
        },
      ]
        .filter(segment => segment.value > 0 && total > 0)
        .map(segment => {
          const width = (segment.value / total) * barWidth;
          const rect = svgRect(x, y, width, rowHeight - 5, segment.color);
          x += width;
          return rect;
        })
        .join('');

      return (
        svgText(
          0,
          y + 9,
          truncateLabel(getFamilyLabel(family, policyId, checkFamilyTitles)),
        ) +
        segments +
        svgText(
          labelWidth + barWidth + 6,
          y + 9,
          `${counters.failed}/${total} failed`,
        )
      );
    })
    .join('');
  const width = labelWidth + barWidth + 80;

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" ` +
    `height="${height}" viewBox="0 0 ${width} ${height}">${rows}</svg>`
  );
};

const addScaFamilySections = (
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
      'check name when it starts with it, as in CIS-CAT bridge policies ' +
      '("1.1.1 Ensure ..."); other checks are not mapped to a family. ' +
      'Family titles come from the checks when a CIS-CAT bridge adds them, ' +
      'otherwise from the CIS family index for the policy; unknown ' +
      'families show the number only.',
    style: 'standard',
  });

  for (const summary of policies) {
    const instances = Array.from(policyInstanceCoverage.values()).filter(
      coverage => coverage.policyKey === summary.key,
    );
    const complete =
      instances.length > 0 &&
      instances.every(coverage => coverage.status === 'complete');
    const families = Array.from(familyCounters.get(summary.key).entries())
      .map(([family, counters]) => ({ family, counters }))
      .sort((a, b) => compareFamilies(a.family, b.family));

    printer.addContentWithNewLine({
      text: summary.policy,
      style: 'h2',
    });

    if (!complete) {
      printer.addContentWithNewLine({
        text:
          'Pass rates are withheld: the SCA state of this policy is ' +
          'inconsistent or unverified on at least one server.',
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
      byFamily.get(family).push(control);
    }

    for (const family of Array.from(byFamily.keys()).sort(compareFamilies)) {
      const controls = byFamily.get(family);

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

const firstValue = (value: unknown) =>
  Array.isArray(value) ? value.filter(Boolean).join(', ') : value;

/**
 * Maps a document of the SCA states index (and its composite key) to the
 * values used by the report.
 */
const readScaState = (
  key: Record<string, string>,
  source: ScaStateDocument,
) => {
  const agent = source?.wazuh?.agent || {};
  const check = source?.check || {};
  const policyKey = String(key?.policyId || source?.policy?.id || '');

  return {
    agentId: String(key?.agentId || agent.id || ''),
    agentName: agent.name ? String(agent.name) : '',
    agentIp: String(firstValue(agent.host?.ip) || ''),
    policyKey,
    policyId: source?.policy?.id ? String(source.policy.id) : undefined,
    policy: String(source?.policy?.name || policyKey || 'Unknown SCA policy'),
    checkId: String(key?.checkId || check.id || '-'),
    check,
    result: normalizeScaResult(check.result),
    cis: resolveCisReference({
      title: check.name,
      compliance: check.compliance,
    }),
    timestamp: source?.state?.modified_at,
  };
};

/**
 * Adds the SCA content of the selected agents to the report, read from the
 * Wazuh 5.0 SCA states index.
 */
export async function addScaChecksToReport(
  context,
  printer: ReportPrinter,
  agentIds: string | string[],
  options: ScaReportOptions = {},
  pattern: string = WAZUH_SCA_PATTERN,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  printer.logger.debug(
    `Fetching SCA states for ${normalizedAgentIds.length} selected agents from ${pattern}`,
  );

  const inventory = await getScaAgentInventory(
    context,
    normalizedAgentIds,
    pattern,
  );

  const indexedPolicySummaries = await getScaPolicySummaries(
    context,
    normalizedAgentIds,
    pattern,
  );

  const overallCounters = createPolicyCounters();
  const serverSummaries = new Map<string, any>();
  const policySummaries = new Map<string, any>();
  const policyInstanceCoverage = new Map<string, any>();
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

  await forEachScaCheck(
    context,
    normalizedAgentIds,
    ({ key, source }) => {
      const state = readScaState(key, source);
      const { agentId, policyKey, policy, result, cis } = state;

      if (!agentId || !policyKey) {
        return;
      }

      if (!serverSummaries.has(agentId)) {
        serverSummaries.set(agentId, {
          id: agentId,
          name: state.agentName || 'Unknown server',
          ip: state.agentIp || '-',
          ...createPolicyCounters(),
        });
      }

      const serverSummary = serverSummaries.get(agentId);
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
      const instanceCoverage = policyInstanceCoverage.get(instanceKey);
      instanceCoverage.observed++;
      addResultToCounters(instanceCoverage, result);

      if (!policySummaries.has(policyKey)) {
        policySummaries.set(policyKey, {
          key: policyKey,
          policy,
          policyId: state.policyId,
          agents: new Set<string>(),
          ...createPolicyCounters(),
        });
      }

      const policySummary = policySummaries.get(policyKey);
      policySummary.agents.add(agentId);
      if (!policySummary.policyId && state.policyId) {
        policySummary.policyId = state.policyId;
      }
      addResultToCounters(policySummary, result);

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
      const policyFamilies = familyCounters.get(policyKey);
      if (!policyFamilies.has(family)) {
        policyFamilies.set(family, createPolicyCounters());
      }
      addResultToCounters(policyFamilies.get(family), result);

      if (result === 'Failed') {
        const { checkId } = state;
        if (!failedControls.has(policyKey)) {
          failedControls.set(policyKey, new Map());
        }
        const policyFailed = failedControls.get(policyKey);
        if (!policyFailed.has(checkId)) {
          policyFailed.set(checkId, {
            checkId,
            reference: cis.reference,
            family: cis.family,
            title: cis.title || '-',
            agents: new Set<string>(),
          });
        }
        policyFailed.get(checkId).agents.add(agentId);
      }
    },
    pattern,
  );

  // The checks read one by one must match the totals computed by the indexer
  // for every agent and policy; otherwise the scores are withheld.
  for (const [instanceKey, indexedSummary] of indexedPolicySummaries) {
    if (!policyInstanceCoverage.has(instanceKey)) {
      policyInstanceCoverage.set(instanceKey, {
        agentId: indexedSummary.agentId,
        policyKey: indexedSummary.policyKey,
        policy: indexedSummary.policy || indexedSummary.policyKey,
        observed: 0,
        expected: indexedSummary.totalChecks,
        status: 'unverified',
        ...createPolicyCounters(),
      });
    }

    const coverage = policyInstanceCoverage.get(instanceKey);
    coverage.expected = indexedSummary.totalChecks;
    const summaryCountsMatch =
      coverage.passed === indexedSummary.passed &&
      coverage.failed === indexedSummary.failed &&
      coverage.notApplicable === indexedSummary.notApplicable &&
      coverage.other === indexedSummary.other;
    coverage.status =
      typeof indexedSummary.totalChecks === 'number'
        ? coverage.observed === indexedSummary.totalChecks && summaryCountsMatch
          ? 'complete'
          : 'incomplete'
        : 'unverified';

    if (!policySummaries.has(indexedSummary.policyKey)) {
      policySummaries.set(indexedSummary.policyKey, {
        key: indexedSummary.policyKey,
        policy: indexedSummary.policy || indexedSummary.policyKey,
        policyId: indexedSummary.policyKey,
        agents: new Set<string>(),
        ...createPolicyCounters(),
      });
    }
    policySummaries
      .get(indexedSummary.policyKey)
      .agents.add(indexedSummary.agentId);
  }

  const getServerCoverage = (agentId: string) => {
    const instances = Array.from(policyInstanceCoverage.values()).filter(
      coverage => coverage.agentId === agentId,
    );

    if (!instances.length) {
      return {
        instances,
        complete: false,
        label: 'No SCA data',
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
        label: `Inconsistent (${incompleteCount} ${
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
    text:
      'Current SCA posture of the selected servers, read from the SCA ' +
      'states index. Scores are shown only where the SCA state of the ' +
      'servers is complete and consistent.',
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
      ? 'Coverage verified: the SCA state of every selected server is ' +
        'complete and matches the per-policy totals of the index.'
      : `Coverage requires attention: ${coverageIssues} selected server${
          coverageIssues === 1 ? '' : 's'
        } ${
          coverageIssues === 1 ? 'has' : 'have'
        } no, inconsistent or unverified SCA data. Scores are withheld ` +
        'wherever coverage is not complete.';

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
    text:
      'Each control is the current state of one SCA check on one server. ' +
      'The controls read are verified against the per-policy totals of the ' +
      'SCA states index; scores are withheld when they differ or when a ' +
      'server has no SCA data.',
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
      { id: 'sca', label: 'SCA data' },
    ],
    items: normalizedAgentIds.map(agentId => {
      const summary = serverSummaries.get(agentId);
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
  let activeItems: any[] = [];
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
      text: activePolicy,
      style: 'h3',
    });

    const coverageText =
      coverage?.status === 'complete'
        ? `Coverage: Complete (${coverage.observed}/${coverage.expected} checks)`
        : coverage?.status === 'incomplete'
        ? `Coverage: Inconsistent (${coverage.observed}/${coverage.expected} checks)`
        : 'Coverage: Unverified (no policy totals in the index)';

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
        { id: 'cis', label: 'CIS' },
        { id: 'result', label: 'Result' },
        { id: 'title', label: 'Control' },
        { id: 'rationale', label: 'Rationale' },
        { id: 'remediation', label: 'Remediation' },
        { id: 'description', label: 'Description' },
        { id: 'compliance', label: 'Compliance' },
      ],
      items: activeItems.sort(compareFailedControls),
      widths: [32, 44, 110, 108, 142, 152, 142],
      fontSize: 6.5,
      maxTextLength: 34,
      cellPadding: 1,
    });

    activeItems = [];
    counters = createPolicyCounters();
  };

  await forEachScaCheck(
    context,
    normalizedAgentIds,
    ({ key, source }) => {
      const state = readScaState(key, source);
      const { agentId, policyKey, check, cis, result } = state;

      if (!agentId || !policyKey) {
        return;
      }

      if (agentId !== activeAgentId) {
        flushPolicy();

        activeAgentId = agentId;
        activePolicy = '';
        activePolicyKey = '';
        const inventoryAgent = inventory.get(agentId);

        addAgentSectionHeader(
          printer,
          agentId,
          {
            ...(inventoryAgent || {}),
            name: inventoryAgent?.name || state.agentName,
            ip: inventoryAgent?.ip || state.agentIp,
            timestamp: inventoryAgent?.timestamp || state.timestamp,
          },
          renderedAgents > 0,
        );
        renderedAgents++;
        seenAgents.add(agentId);
      }

      if (policyKey !== activePolicyKey) {
        flushPolicy();
        activePolicy = state.policy;
        activePolicyKey = policyKey;
      }

      addResultToCounters(counters, result);

      activeItems.push({
        reference: cis.reference,
        checkId: state.checkId,
        cis: cis.reference || `ID ${state.checkId}`,
        result,
        title: cis.title || '-',
        rationale: check.rationale || '-',
        remediation: check.remediation || '-',
        description: check.description || '-',
        compliance: formatCompliance(check.compliance),
      });
    },
    pattern,
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
      text: 'No SCA checks were found for this server.',
      style: 'standard',
    });
  }
}
