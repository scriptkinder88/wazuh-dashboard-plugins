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
import { getUiSettings } from '../../../../kibana-services';
import { ReportingService } from '../../../../react-services';
import $ from 'jquery';
import { WzButton } from '../../../common/buttons';
import { connect } from 'react-redux';
import { ScaReportAgentSelector } from './sca-report-agent-selector';

const mapStateToProps = state => ({
  dataSourceSearchContext: state.reportingReducers.dataSourceSearchContext,
});

export const ButtonModuleGenerateReport = connect(mapStateToProps)(
  ({ agent, moduleID, dataSourceSearchContext }) => {
    const [isScaSelectorOpen, setIsScaSelectorOpen] = useState(false);
    const isScaReport = moduleID === 'sca';
    const disabledReport = isScaReport
      ? false
      : ![
          !dataSourceSearchContext?.isSearching,
          dataSourceSearchContext?.totalResults,
          dataSourceSearchContext?.indexPattern,
        ].every(Boolean);
    const totalResults = dataSourceSearchContext?.totalResults;

    const action = useAsyncAction(
      async (scaAgentIds: string[] = []) => {
        const reportingService = new ReportingService();

        if (isScaReport) {
          await reportingService.startScaReport(scaAgentIds);
          return;
        }

        const generateReport = () =>
          reportingService.startVis2Png(moduleID, agent?.id || false);
        const isDarkModeTheme = getUiSettings().get('theme:darkMode');

        if (isDarkModeTheme) {
          //Patch to fix white text in dark-mode pdf reports
          const defaultTextColor = '#DFE5EF';

          //Patch to fix dark backgrounds in visualizations dark-mode pdf reports
          const $labels = $(
            '.euiButtonEmpty__text, .echLegendItem, div.mtrVis__value ~ div',
          );
          const $vizBackground = $('.echChartBackground');
          const defaultVizBackground = $vizBackground.css('background-color');

          try {
            $labels.css('color', 'black');
            $vizBackground.css('background-color', 'transparent');
            await generateReport();
            $vizBackground.css('background-color', defaultVizBackground);
            $labels.css('color', defaultTextColor);
          } catch (e) {
            $labels.css('color', defaultTextColor);
            $vizBackground.css('background-color', defaultVizBackground);
          }
        } else {
          await generateReport();
        }
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
            disabledReport && totalResults === 0
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
            onCancel={() => setIsScaSelectorOpen(false)}
            onGenerate={async agentIds => {
              await action.run(agentIds);
              setIsScaSelectorOpen(false);
            }}
          />
        )}
      </>
    );
  },
);
