/*
 * Wazuh app - Component for the module generate reports
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import React, { useState } from 'react';
import { useAsyncAction } from '../../hooks';
import { ReportingService } from '../../../../react-services';
import { WzButton } from '../../../common/buttons';
import { connect } from 'react-redux';
import {
  SCA_REPORT_TYPE_SNAPSHOT,
  ScaReportAgentSelector,
  ScaReportOptions,
} from './sca-report-agent-selector';

const mapStateToProps = state => ({
  dataSourceSearchContext: state.reportingReducers.dataSourceSearchContext,
});

export const ButtonModuleGenerateReport = connect(mapStateToProps)(
  ({ agent, moduleID, dataSourceSearchContext }) => {
    const [isScaSelectorOpen, setIsScaSelectorOpen] = useState(false);
    const isScaReport = moduleID === 'sca';

    // The detailed SCA report is built server-side from the selected agents;
    // only the dashboard snapshot needs the dashboard search context.
    const isScaSnapshotAvailable = Boolean(
      dataSourceSearchContext?.indexPattern &&
        dataSourceSearchContext?.overviewDashboardSavedObjectId,
    );
    const disabledReport = isScaReport
      ? Boolean(dataSourceSearchContext?.isSearching)
      : ![
          !dataSourceSearchContext?.isSearching,
          dataSourceSearchContext?.totalResults,
          dataSourceSearchContext?.indexPattern,
        ].every(Boolean);

    const totalResults = dataSourceSearchContext?.totalResults;
    const action = useAsyncAction(
      async (scaAgentIds: string[] = [], scaOptions?: ScaReportOptions) => {
        const reportingService = new ReportingService();

        if (isScaReport) {
          if (scaOptions?.type === SCA_REPORT_TYPE_SNAPSHOT) {
            await reportingService.generateScaMultiServerPDFReport(scaAgentIds);
            return;
          }

          await reportingService.generateScaDetailedPDFReport(scaAgentIds, {
            details: scaOptions?.details === true,
          });
          return;
        }

        await reportingService.generateInContextPDFReport();
      },
      [agent, moduleID],
    );

    return (
      <>
        <WzButton
          buttonType='empty'
          iconType='document'
          isLoading={action.running}
          onClick={isScaReport ? () => setIsScaSelectorOpen(true) : action.run}
          isDisabled={disabledReport}
          tooltip={
            disabledReport && !isScaReport && totalResults === 0
              ? {
                  position: 'top',
                  content: 'No results match for this search criteria.',
                }
              : undefined
          }
        >
          Generate report
        </WzButton>

        {isScaReport && isScaSelectorOpen && (
          <ScaReportAgentSelector
            initialAgentId={agent?.id}
            isSnapshotAvailable={isScaSnapshotAvailable}
            onCancel={() => setIsScaSelectorOpen(false)}
            onGenerate={async (agentIds, options) => {
              await action.run(agentIds, options);
              setIsScaSelectorOpen(false);
            }}
          />
        )}
      </>
    );
  },
);
