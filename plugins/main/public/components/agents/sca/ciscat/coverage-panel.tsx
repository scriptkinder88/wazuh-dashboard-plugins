/*
 * Coverage trend of the CIS-CAT assessments: per day, the share of the agents of
 * the OS groups that have a recent scan of their CIS-CAT policy (ciscat-history,
 * recorded by the master once a day).
 */
import React, { useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiBasicTable,
  EuiButtonGroup,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTextColor,
  EuiTitle,
} from '@elastic/eui';
import { euiThemeVars } from '@osd/ui-shared-deps/theme';
import {
  COVERAGE_WINDOW_DAYS,
  CoveragePoint,
  coverageSeries,
  addDays,
  daysBetween,
  historyOsKeys,
} from './lib/coverage';
import type { CiscatData } from './ciscat-management';
import { messages } from './messages';

const PERIODS = [
  { id: '30', label: messages.coverage30Days },
  { id: '90', label: messages.coverage90Days },
  { id: '365', label: messages.coverageYear },
];

// chart geometry (viewBox units; the chart scales with its container)
const W = 800;
const H = 200;
const PAD = { top: 12, right: 16, bottom: 24, left: 44 };
const PLOT_W = W - PAD.left - PAD.right;
const PLOT_H = H - PAD.top - PAD.bottom;

const formatDay = (day: string) =>
  new Date(`${day}T12:00:00Z`).toLocaleDateString(undefined, {
    day: 'numeric',
    month: 'short',
  });

const describe = (p: CoveragePoint) =>
  p.percent === undefined
    ? messages.coverageNoAgents()
    : messages.coveragePoint(p.percent, p.assessed, p.expected);

/** Line segments of consecutive recorded days (a missing day breaks the line). */
const segments = (
  points: CoveragePoint[],
  x: (p: CoveragePoint) => number,
  y: (v: number) => number,
) => {
  const out: string[] = [];
  let current: string[] = [];
  points.forEach((p, i) => {
    const prev = points[i - 1];
    if (p.percent === undefined || (prev && daysBetween(prev.day, p.day) > 1)) {
      if (current.length) {
        out.push(current.join(' '));
      }
      current = [];
    }
    if (p.percent !== undefined) {
      const command = current.length ? 'L' : 'M';
      current.push(`${command}${x(p).toFixed(1)},${y(p.percent).toFixed(1)}`);
    }
  });
  if (current.length) {
    out.push(current.join(' '));
  }
  return out;
};

const CoverageChart = ({
  points,
  days,
}: {
  points: CoveragePoint[];
  days: number;
}) => {
  const [hover, setHover] = useState<number>();
  const last = points[points.length - 1].day;
  const span = Math.max(days - 1, 1);
  const x = (p: CoveragePoint) =>
    PAD.left + ((span - daysBetween(p.day, last)) / span) * PLOT_W;
  const y = (v: number) => PAD.top + (1 - v / 100) * PLOT_H;
  const paths = segments(points, x, y);
  const single = points.filter(p => p.percent !== undefined);

  const onMove = (event: React.MouseEvent<SVGRectElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const vx = PAD.left + ((event.clientX - rect.left) / rect.width) * PLOT_W;
    let best = 0;
    points.forEach((p, i) => {
      if (Math.abs(x(p) - vx) < Math.abs(x(points[best]) - vx)) {
        best = i;
      }
    });
    setHover(best);
  };
  const hovered = hover === undefined ? undefined : points[hover];
  const first = points[0].day;

  return (
    <div
      style={{ position: 'relative' }}
      data-test-subj='ciscat-coverage-chart'
    >
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width='100%'
        role='img'
        aria-label={messages.coverageAria(
          first,
          last,
          describe(points[points.length - 1]),
        )}
      >
        {[0, 25, 50, 75, 100].map(v => (
          <g key={v}>
            <line
              x1={PAD.left}
              x2={W - PAD.right}
              y1={y(v)}
              y2={y(v)}
              stroke={euiThemeVars.euiColorLightShade}
              strokeWidth={1}
            />
            <text
              x={PAD.left - 8}
              y={y(v) + 4}
              textAnchor='end'
              fontSize={11}
              fill={euiThemeVars.euiTextSubduedColor}
            >
              {v}%
            </text>
          </g>
        ))}
        <text
          x={PAD.left}
          y={H - 6}
          fontSize={11}
          fill={euiThemeVars.euiTextSubduedColor}
        >
          {formatDay(addDays(last, -span))}
        </text>
        <text
          x={W - PAD.right}
          y={H - 6}
          fontSize={11}
          textAnchor='end'
          fill={euiThemeVars.euiTextSubduedColor}
        >
          {formatDay(last)}
        </text>
        {paths.map(d => (
          <path
            key={d}
            d={d}
            fill='none'
            stroke={euiThemeVars.euiColorPrimary}
            strokeWidth={2}
            strokeLinejoin='round'
            strokeLinecap='round'
          />
        ))}
        {single.length === 1 && (
          <circle
            cx={x(single[0])}
            cy={y(single[0].percent as number)}
            r={4}
            fill={euiThemeVars.euiColorPrimary}
          />
        )}
        {hovered && (
          <g>
            <line
              x1={x(hovered)}
              x2={x(hovered)}
              y1={PAD.top}
              y2={PAD.top + PLOT_H}
              stroke={euiThemeVars.euiColorDarkShade}
              strokeWidth={1}
              strokeDasharray='3 3'
            />
            {hovered.percent !== undefined && (
              <circle
                cx={x(hovered)}
                cy={y(hovered.percent)}
                r={5}
                fill={euiThemeVars.euiColorPrimary}
                stroke={euiThemeVars.euiColorEmptyShade}
                strokeWidth={2}
              />
            )}
          </g>
        )}
        <rect
          x={PAD.left}
          y={PAD.top}
          width={PLOT_W}
          height={PLOT_H}
          fill='transparent'
          onMouseMove={onMove}
          onMouseLeave={() => setHover(undefined)}
          data-test-subj='ciscat-coverage-hover'
        />
      </svg>
      {hovered && (
        <div
          className='euiToolTip'
          style={{
            position: 'absolute',
            // away from the line: below it when the point is high, above when low
            top: `${
              (((hovered.percent ?? 0) > 50 ? y(25) : y(100)) / H) * 100
            }%`,
            left: `${(x(hovered) / W) * 100}%`,
            transform: `translateX(${x(hovered) > W / 2 ? '-105%' : '5%'})`,
            pointerEvents: 'none',
            whiteSpace: 'nowrap',
          }}
          data-test-subj='ciscat-coverage-tooltip'
        >
          <strong>{formatDay(hovered.day)}</strong>
          <div>{describe(hovered)}</div>
          {hovered.disconnected > 0 && (
            <div>{messages.coverageDisconnected(hovered.disconnected)}</div>
          )}
        </div>
      )}
    </div>
  );
};

export const CoveragePanel = ({ data }: { data: CiscatData }) => {
  const [osKey, setOsKey] = useState('*');
  const [period, setPeriod] = useState('90');
  const days = Number(period);
  const osKeys = useMemo(() => historyOsKeys(data.history), [data.history]);
  const points = useMemo(
    () => coverageSeries(data.history, osKey, days),
    [data.history, osKey, days],
  );
  const latest = points[points.length - 1];
  const title = (key: string) => String(data.oskeys[key]?.title || key);

  return (
    <div data-test-subj='ciscat-coverage'>
      <EuiFlexGroup alignItems='center' gutterSize='m' responsive wrap>
        <EuiFlexItem>
          <EuiTitle size='xs'>
            <h3>{messages.coverageTitle(COVERAGE_WINDOW_DAYS)}</h3>
          </EuiTitle>
          {latest && (
            <EuiText size='s' data-test-subj='ciscat-coverage-latest'>
              <strong>{describe(latest)}</strong>
              {latest.disconnected > 0 &&
                ` · ${messages.coverageDisconnected(latest.disconnected)}`}
              <EuiTextColor color='subdued'>
                {` · ${formatDay(latest.day)}`}
              </EuiTextColor>
            </EuiText>
          )}
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiSelect
            compressed
            aria-label={messages.coverageBenchmark()}
            value={osKey}
            onChange={e => setOsKey(e.target.value)}
            options={[
              { value: '*', text: messages.coverageAllBenchmarks() },
              ...osKeys.map(k => ({ value: k, text: title(k) })),
            ]}
            data-test-subj='ciscat-coverage-os'
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend={messages.coveragePeriod()}
            buttonSize='compressed'
            options={PERIODS.map(p => ({ id: p.id, label: p.label() }))}
            idSelected={period}
            onChange={setPeriod}
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='s' />
      {points.length ? (
        <>
          <CoverageChart points={points} days={days} />
          <EuiAccordion
            id='ciscat-coverage-table'
            buttonContent={
              <EuiText size='xs'>{messages.coverageShowData()}</EuiText>
            }
            paddingSize='s'
          >
            <EuiBasicTable
              items={[...points].reverse()}
              columns={[
                { field: 'day', name: messages.coverageDay() },
                { field: 'assessed', name: messages.coverageAssessed() },
                { field: 'expected', name: messages.coverageAgents() },
                {
                  field: 'percent',
                  name: messages.coverageColumn(),
                  render: (v?: number) => (v === undefined ? '—' : `${v}%`),
                },
                {
                  field: 'disconnected',
                  name: messages.coverageNotAssessedDisconnected(),
                },
              ]}
            />
          </EuiAccordion>
        </>
      ) : (
        <EuiText
          size='s'
          color='subdued'
          data-test-subj='ciscat-coverage-empty'
        >
          {messages.coverageEmpty()}
        </EuiText>
      )}
    </div>
  );
};
