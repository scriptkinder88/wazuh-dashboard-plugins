import fs from 'fs';
import path from 'path';

describe('SCA multi-server report wiring', () => {
  it('passes the selected server list from the selector to the reporting service', () => {
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
    const requestSource = fs.readFileSync(
      path.resolve(__dirname, '../../../public/react-services/wz-request.ts'),
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
    expect(selectorSource).toContain('const AGENTS_PAGE_SIZE = 100');
    expect(selectorSource).toContain(
      "select: 'id,name,status,os.name,os.version'",
    );

    expect(reportingSource).toContain('async startScaReport(agentIds)');
    expect(reportingSource).toContain('30 * 60 * 1000');
    expect(reportingSource).toContain('timeout: reportTimeout');
    expect(requestSource).toContain('timeout?: number');

    expect(controllerSource).toContain(
      "moduleID === 'sca' && Array.isArray(agents) ? false : agents",
    );
    expect(controllerSource).toContain('Array.isArray(agents)');
    expect(controllerSource).toContain(
      'await addScaChecksToReport(context, printer, agents, apiId)',
    );

    expect(scaSource).toContain('const SCA_REPORT_PAGE_SIZE = 500');
    expect(scaSource).toContain('const AGENT_METADATA_BATCH_SIZE = 100');
    expect(scaSource).toContain('const SCA_API_MIN_INTERVAL_MS');
    expect(scaSource).toContain('isRateLimitError');
    expect(scaSource).toContain("agents_list: agentBatch.join(',')");
    expect(scaSource).toContain("widths: [42, 72, '*', 220]");

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
