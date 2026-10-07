/* eslint-disable camelcase */ // Wazuh API field names
import React from 'react';
import {
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ScaReportAgentSelector } from './sca-report-agent-selector';
import { WzRequest } from '../../../../react-services';
import { SCA_REPORT_MAX_AGENTS } from '../../../../../common/sca/report-limits';

configure({ testIdAttribute: 'data-test-subj' });

jest.mock('../../../../react-services', () => ({
  WzRequest: { apiReq: jest.fn() },
}));

const agents = (count: number) =>
  Array.from({ length: count }, (_, i) => ({
    id: String(i + 1).padStart(3, '0'),
    name: `server-${i + 1}`,
    status: 'active',
  }));

const mockAgents = (items: object[]) =>
  (WzRequest.apiReq as jest.Mock).mockResolvedValue({
    data: {
      data: { affected_items: items, total_affected_items: items.length },
    },
  });

describe('ScaReportAgentSelector', () => {
  beforeEach(() => jest.clearAllMocks());

  it('generates a report for the selected servers', async () => {
    mockAgents(agents(2));
    const onGenerate = jest.fn();
    render(
      <ScaReportAgentSelector
        initialAgentId='001'
        onCancel={jest.fn()}
        onGenerate={onGenerate}
      />,
    );
    await screen.findByText('server-1');
    fireEvent.click(screen.getByTestId('sca-report-generate'));
    await waitFor(() =>
      expect(onGenerate).toHaveBeenCalledWith(['001'], { details: false }),
    );
  });

  it(`refuses more than ${SCA_REPORT_MAX_AGENTS} servers`, async () => {
    // a single page so that the selector loads them with one request
    mockAgents(agents(SCA_REPORT_MAX_AGENTS + 1));
    const onGenerate = jest.fn();
    render(
      <ScaReportAgentSelector onCancel={jest.fn()} onGenerate={onGenerate} />,
    );
    await screen.findByText('server-1');
    fireEvent.click(screen.getByText(/Select all filtered/));
    expect(
      await screen.findByTestId('sca-report-too-many-agents'),
    ).toBeTruthy();
    expect(
      (screen.getByTestId('sca-report-generate') as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(onGenerate).not.toHaveBeenCalled();
  });

  it('shows why the servers cannot be listed', async () => {
    (WzRequest.apiReq as jest.Mock).mockRejectedValue(new Error('forbidden'));
    render(
      <ScaReportAgentSelector onCancel={jest.fn()} onGenerate={jest.fn()} />,
    );
    expect(await screen.findByText('forbidden')).toBeTruthy();
  });
});
