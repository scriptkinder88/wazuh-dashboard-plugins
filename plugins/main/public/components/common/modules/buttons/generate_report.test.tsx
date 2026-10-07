/* eslint-disable camelcase -- Wazuh API responses */
import React from 'react';
import { Provider } from 'react-redux';
import { createStore } from 'redux';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ButtonModuleGenerateReport } from './generate_report';

const mockReportingService = {
  generateInContextPDFReport: jest.fn(),
  generateScaDetailedPDFReport: jest.fn(),
  generateScaMultiServerPDFReport: jest.fn(),
};

jest.mock('../../../../react-services', () => ({
  ReportingService: jest.fn(() => mockReportingService),
  WzRequest: {
    apiReq: jest.fn().mockResolvedValue({
      data: {
        data: {
          affected_items: [{ id: '001', name: 'web-01', status: 'active' }],
          total_affected_items: 1,
        },
      },
    }),
  },
}));

jest.mock('../../hooks', () =>
  jest.requireActual('../../hooks/use_async_action'),
);

jest.mock('../../../common/buttons', () => ({
  WzButton: ({ children, onClick, isDisabled }) => (
    <button onClick={onClick} disabled={isDisabled}>
      {children}
    </button>
  ),
}));

const renderButton = (dataSourceSearchContext: any) =>
  render(
    <Provider
      store={createStore(() => ({
        reportingReducers: { dataSourceSearchContext },
      }))}
    >
      <ButtonModuleGenerateReport moduleID='sca' agent={{ id: '001' }} />
    </Provider>,
  );

const generateFromSelector = async () => {
  fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));
  const generate = await screen.findByRole('button', {
    name: /Generate report \(1\)/,
  });
  await waitFor(() =>
    expect((generate as HTMLButtonElement).disabled).toBe(false),
  );
  return generate;
};

describe('ButtonModuleGenerateReport for SCA', () => {
  beforeEach(() => jest.clearAllMocks());

  it('downloads the detailed report without a dashboard search context', async () => {
    renderButton({ isSearching: false });

    const generate = await generateFromSelector();
    expect(
      (screen.getByLabelText(/^Dashboard snapshot/) as HTMLInputElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(
      screen.getByLabelText(/Include detailed results by server/),
    );
    fireEvent.click(generate);

    await waitFor(() =>
      expect(
        mockReportingService.generateScaDetailedPDFReport,
      ).toHaveBeenCalledWith(['001'], { details: true }),
    );
    expect(
      mockReportingService.generateScaMultiServerPDFReport,
    ).not.toHaveBeenCalled();
  });

  it('keeps the dashboard snapshot report', async () => {
    renderButton({
      isSearching: false,
      indexPattern: { id: 'wazuh-states-sca' },
      overviewDashboardSavedObjectId: 'sca-overview-dashboard',
    });

    const generate = await generateFromSelector();
    fireEvent.click(screen.getByLabelText(/^Dashboard snapshot/));
    fireEvent.click(generate);

    await waitFor(() =>
      expect(
        mockReportingService.generateScaMultiServerPDFReport,
      ).toHaveBeenCalledWith(['001']),
    );
    expect(
      mockReportingService.generateScaDetailedPDFReport,
    ).not.toHaveBeenCalled();
  });

  it('is disabled while the dashboard is searching', () => {
    renderButton({ isSearching: true });

    expect(
      (
        screen.getByRole('button', {
          name: 'Generate report',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});
