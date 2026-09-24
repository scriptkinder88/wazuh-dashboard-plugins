import fs from 'fs';
import path from 'path';

describe('SCA multi-server report wiring', () => {
  it('routes multi-server SCA reporting through OpenSearch instead of per-agent SCA API calls', () => {
    const buttonSource = fs.readFileSync(
      path.resolve(
        __dirname,
        '../../../public/components/common/modules/buttons/generate_report.tsx',
      ),
      'utf8',
    );
    const selectorSource = fs.readFileSync(
      path.resolve(
        __dirname,
        '../../../public/components/common/modules/buttons/sca-report-agent-selector.tsx',
      ),
      'utf8',
    );
    const reportingSource = fs.readFileSync(
      path.resolve(__dirname, '../../../public/react-services/reporting.js'),
      'utf8',
    );
    const controllerSource = fs.readFileSync(
      path.resolve(__dirname, '../../controllers/wazuh-reporting.ts'),
      'utf8',
    );
    const scaSource = fs.readFileSync(
      path.resolve(__dirname, 'sca-report.ts'),
      'utf8',
    );
    const scaRequestSource = fs.readFileSync(
      path.resolve(__dirname, 'sca-request.ts'),
      'utf8',
    );
    const printerSource = fs.readFileSync(
      path.resolve(__dirname, 'printer.ts'),
      'utf8',
    );

    expect(buttonSource).toContain('<ScaReportAgentSelector');
    expect(buttonSource).toContain('await action.run(agentIds)');
    expect(buttonSource).toContain(
      'await reportingService.startScaReport(scaAgentIds)',
    );

    expect(selectorSource).toContain('selectedAgentIds');
    expect(selectorSource).toContain('Select all filtered');
    expect(selectorSource).toContain('await onGenerate(selectedAgentIds)');

    expect(reportingSource).toContain('async startScaReport(agentIds)');
    expect(reportingSource).toContain(
      'DATA_SOURCE_FILTER_CONTROLLED_PINNED_AGENT',
    );
    expect(reportingSource).toContain(
      'const serverSideQuery = buildOpenSearchQuery',
    );
    expect(reportingSource).toContain(
      'indexPatternTitle: dataSourceContext.indexPattern.title',
    );

    expect(controllerSource).toContain(
      "moduleID === 'sca' && Array.isArray(agents) ? false : agents",
    );
    expect(controllerSource).toContain("time && moduleID !== 'sca'");
    expect(controllerSource).toContain(
      'await addScaChecksToReport(',
    );

    expect(scaSource).toContain('forEachLatestScaCheck');
    expect(scaSource).toContain('getScaAgentInventory');
    expect(scaSource).toContain("widths: [42, 72, '*', 220]");
    expect(scaSource).toContain("pageOrientation: 'landscape'");
    expect(scaSource).not.toContain('/sca/${agentId}');

    expect(scaRequestSource).toContain(
      'context.core.opensearch.client.asCurrentUser.search',
    );
    expect(scaRequestSource).toContain("'rule.groups': 'sca'");
    expect(scaRequestSource).toContain("'agent.id': normalizedAgentIds");
    expect(scaRequestSource).toContain('composite');
    expect(scaRequestSource).not.toContain(
      'context.wazuh.api.client.asCurrentUser.request',
    );

    expect(printerSource).toContain('widths: requestedWidths');
    expect(printerSource).toContain('maxTextLength = 60');
  });

  it('accepts an array of validated agent IDs on the reporting route', () => {
    const routeSource = fs.readFileSync(
      path.resolve(__dirname, '../../routes/wazuh-reporting.ts'),
      'utf8',
    );

    expect(routeSource).toContain('schema.arrayOf(agentIDValidation)');
  });

  it('keeps SCA reports on the shared configurable branding pipeline', () => {
    const printerSource = fs.readFileSync(
      path.resolve(__dirname, 'printer.ts'),
      'utf8',
    );

    expect(printerSource).toContain("'customization.logo.reports'");
    expect(printerSource).toContain("'customization.reports.header'");
    expect(printerSource).toContain("'customization.reports.footer'");
  });
});
