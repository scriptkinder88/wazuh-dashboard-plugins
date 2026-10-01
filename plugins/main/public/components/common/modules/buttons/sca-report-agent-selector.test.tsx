/* eslint-disable camelcase -- Wazuh API responses */
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ScaReportAgentSelector } from './sca-report-agent-selector';
import { WzRequest } from '../../../../react-services';

jest.mock('../../../../react-services', () => ({
  WzRequest: { apiReq: jest.fn() },
}));

const AGENTS = [
  { id: '001', name: 'web-01', status: 'active', os: { name: 'RHEL' } },
  { id: '002', name: 'db-01', status: 'active', os: { name: 'Ubuntu' } },
];

const renderSelector = (props = {}) => {
  const onGenerate = jest.fn();
  const onCancel = jest.fn();

  render(
    <ScaReportAgentSelector
      initialAgentId='001'
      onCancel={onCancel}
      onGenerate={onGenerate}
      {...props}
    />,
  );

  return { onGenerate, onCancel };
};

const getGenerateButton = () =>
  screen.getByRole('button', { name: /Generate report/ }) as HTMLButtonElement;

describe('ScaReportAgentSelector', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (WzRequest.apiReq as jest.Mock).mockResolvedValue({
      data: {
        data: { affected_items: AGENTS, total_affected_items: AGENTS.length },
      },
    });
  });

  it('generates the detailed report by default', async () => {
    const { onGenerate } = renderSelector();

    await waitFor(() => expect(getGenerateButton().disabled).toBe(false));
    expect(
      (screen.getByLabelText(/^Detailed report/) as HTMLInputElement).checked,
    ).toBe(true);

    fireEvent.click(getGenerateButton());

    await waitFor(() =>
      expect(onGenerate).toHaveBeenCalledWith(['001'], {
        type: 'detailed',
        details: false,
      }),
    );
  });

  it('includes the detailed results by server on request', async () => {
    const { onGenerate } = renderSelector();

    await waitFor(() => expect(getGenerateButton().disabled).toBe(false));
    fireEvent.click(
      screen.getByLabelText(/Include detailed results by server/),
    );
    fireEvent.click(screen.getByLabelText('Select db-01'));
    fireEvent.click(getGenerateButton());

    await waitFor(() =>
      expect(onGenerate).toHaveBeenCalledWith(['001', '002'], {
        type: 'detailed',
        details: true,
      }),
    );
  });

  it('keeps the dashboard snapshot as a second choice', async () => {
    const { onGenerate } = renderSelector();

    await waitFor(() => expect(getGenerateButton().disabled).toBe(false));
    const details = screen.getByLabelText(
      /Include detailed results by server/,
    ) as HTMLInputElement;
    fireEvent.click(details);
    fireEvent.click(screen.getByLabelText(/^Dashboard snapshot/));

    expect(details.disabled).toBe(true);
    expect(details.checked).toBe(false);

    fireEvent.click(getGenerateButton());

    await waitFor(() =>
      expect(onGenerate).toHaveBeenCalledWith(['001'], {
        type: 'snapshot',
        details: false,
      }),
    );
  });

  it('disables the dashboard snapshot when it is not available', async () => {
    renderSelector({ isSnapshotAvailable: false });

    await waitFor(() => expect(getGenerateButton().disabled).toBe(false));
    expect(
      (screen.getByLabelText(/^Dashboard snapshot/) as HTMLInputElement)
        .disabled,
    ).toBe(true);
  });
});
