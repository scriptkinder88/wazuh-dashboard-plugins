/*
 * Executive summary blocks of the SCA report: KPI tiles, the coverage status
 * and the grouped result with its outcome chart.
 */
import { REPORTS_PRIMARY_COLOR } from '../../../common/constants';
import { ReportPrinter } from './printer';
import { SCA_RESULT_COLORS, buildScaDonutSvg } from './sca-report-charts';

export const addExecutiveKpiRow = (
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

export const addExecutiveStatus = (
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

/** Figures of the grouped result, one table column each. */
export interface GroupedOverview {
  selected: number;
  withData: number;
  verified: number;
  coverageIssues: number;
  controls: number;
  passed: number;
  failed: number;
  notApplicable: number;
  score: string;
}

export const addGroupedScaOverview = (
  printer: ReportPrinter,
  summary: GroupedOverview,
) => {
  const columns: Array<{ id: keyof GroupedOverview; label: string }> = [
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
          fillColor: (index: number) =>
            index === 0 ? REPORTS_PRIMARY_COLOR : null,
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
