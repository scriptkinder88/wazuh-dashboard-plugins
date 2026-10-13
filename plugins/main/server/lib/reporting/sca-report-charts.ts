/*
 * SVG charts of the SCA report and the family labels they show.
 */
import { compareCisReferences } from '../../../common/sca/cis-reference';
import { getCisFamilyTitle } from '../../../common/compliance-requirements/cis-families';
import {
  ResultCounters,
  UNMAPPED_FAMILY,
  getCountersTotal,
} from './sca-report-model';

export const SCA_RESULT_COLORS = {
  passed: '#00A69B',
  failed: '#FF645C',
  notApplicable: '#5C6773',
};

export const buildScaDonutSvg = (
  counters: Pick<ResultCounters, 'passed' | 'failed' | 'notApplicable'>,
) => {
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

export const compareFamilies = (a: string, b: string) => {
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
export const getFamilyLabel = (
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

export const buildFamilyBarsSvg = (
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
